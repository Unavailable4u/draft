import json
import os
import re
import time

import docker
from docker.errors import NotFound

INTERNAL = "minilocker-internal"   # no route to the internet
EXTERNAL = "minilocker-egress"     # only the proxy lives here
PROXY = "minilocker-egress-proxy"
ALIAS = "egress-proxy"
PORT = 3128


SERVICE_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def broker_from_env(environ=None) -> dict:
    """Credential broker services from the environment.

        MINILOCKER_BROKER=github=api.github.com,openai=api.openai.com:authorization
        MINILOCKER_BROKER_TOKEN_GITHUB=<the real token>

    Each entry is `name=host` or `name=host:header` (default header `Authorization`, sent as `Bearer <token>`; any other header
    carries the bare token). A service with no token is skipped, and so is anything that is not a plain name and a public-looking
    host name. Returns {name: {"host", "header", "prefix", "token", "placeholder"}}; the tokens stay in the proxy."""
    env = os.environ if environ is None else environ
    out = {}
    for entry in (env.get("MINILOCKER_BROKER") or "").split(","):
        name, _, rest = entry.strip().partition("=")
        host, _, header = rest.partition(":")
        name, host, header = name.strip().lower(), host.strip().lower(), (header.strip() or "Authorization")
        token = env.get("MINILOCKER_BROKER_TOKEN_" + name.upper(), "")
        if not (SERVICE_RE.match(name) and HOST_RE.match(host) and re.match(r"^[A-Za-z][A-Za-z0-9-]*$", header) and len(token) >= 8):
            continue
        out[name] = {"host": host, "header": header, "token": token,
                     "prefix": "Bearer " if header.lower() == "authorization" else "",
                     "placeholder": f"mlk_placeholder_{name}"}
    return out


class EgressManager:
    internal_network = INTERNAL

    def __init__(self, allowed_hosts, image="python:3.12-slim", packaged=False, broker=None):
        """packaged=True: the proxy code ships inside `image` (module minilocker.egress.proxy_server).
        Required when the control plane itself runs in a container: bind-mounting a file from
        this process's filesystem would name a path that does not exist on the Docker host."""
        self.client = docker.from_env()
        self.allowed = list(allowed_hosts)
        self.packaged = packaged
        self.image = image
        self.container = None
        self.broker = dict(broker or {})        # see broker_from_env; the real tokens go to the proxy container only

    def _ensure_network(self, name, internal):
        try:
            self.client.networks.get(name)
        except NotFound:
            self.client.networks.create(name, driver="bridge", internal=internal,
                                        labels={"minilocker": "net"})

    def start(self):
        self.stop()
        self._ensure_network(INTERNAL, True)
        self._ensure_network(EXTERNAL, False)
        if self.packaged:
            code = {"command": ["python", "-u", "-m", "minilocker.egress.proxy_server"]}
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_server.py")
            code = {"command": ["python", "-u", "/proxy.py"],
                    "volumes": {script: {"bind": "/proxy.py", "mode": "ro"}}}
        self.container = self.client.containers.run(
            self.image, name=PROXY, detach=True,
            network=EXTERNAL,
            **code,
            environment={"ALLOWED_HOSTS": ",".join(self.allowed), "PROXY_ALIAS": ALIAS,
                         **({"BROKER_SERVICES": json.dumps(self.broker)} if self.broker else {})},
            user="65534:65534", read_only=True, cap_drop=["ALL"],
            security_opt=["no-new-privileges"], pids_limit=64, mem_limit="128m",
            labels={"minilocker": "proxy"})
        self.client.networks.get(INTERNAL).connect(self.container, aliases=[ALIAS])
        deadline = time.time() + 15
        while time.time() < deadline:
            if b'"listening"' in self.container.logs():
                return self
            time.sleep(0.2)
        raise RuntimeError("egress proxy failed to start: "
                           + self.container.logs().decode(errors="replace"))

    def stop(self):
        try:
            self.client.containers.get(PROXY).remove(force=True)
        except NotFound:
            pass
        self.container = None

    def broker_services(self) -> dict:
        """{name: host} of the brokered services, for telling the agent what exists. No tokens."""
        return {n: s["host"] for n, s in self.broker.items()}

    def proxy_env(self):
        url = f"http://{ALIAS}:{PORT}"
        env = {"HTTPS_PROXY": url, "https_proxy": url, "HTTP_PROXY": url,
               "http_proxy": url, "NO_PROXY": "", "no_proxy": ""}
        if self.broker:           # placeholders only: the real token exists nowhere a sandbox can reach
            env["MINILOCKER_BROKER_URL"] = f"{url}/_broker"
            env.update({f"MINILOCKER_TOKEN_{n.upper()}": s["placeholder"] for n, s in self.broker.items()})
        return env

    def events_for(self, client_ip, since):
        raw = self.container.logs(since=int(since) - 1).decode(errors="replace")
        out = []
        for line in raw.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("client") == client_ip and e.get("ts", 0) >= since:
                out.append(e)
        return out
