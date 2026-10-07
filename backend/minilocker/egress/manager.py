import json
import os
import time

import docker
from docker.errors import NotFound

INTERNAL = "minilocker-internal"   # no route to the internet
EXTERNAL = "minilocker-egress"     # only the proxy lives here
PROXY = "minilocker-egress-proxy"
ALIAS = "egress-proxy"
PORT = 3128


class EgressManager:
    internal_network = INTERNAL

    def __init__(self, allowed_hosts, image="python:3.12-slim"):
        self.client = docker.from_env()
        self.allowed = list(allowed_hosts)
        self.image = image
        self.container = None

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
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_server.py")
        self.container = self.client.containers.run(
            self.image, ["python", "-u", "/proxy.py"], name=PROXY, detach=True,
            network=EXTERNAL,
            volumes={script: {"bind": "/proxy.py", "mode": "ro"}},
            environment={"ALLOWED_HOSTS": ",".join(self.allowed)},
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

    def proxy_env(self):
        url = f"http://{ALIAS}:{PORT}"
        return {"HTTPS_PROXY": url, "https_proxy": url, "HTTP_PROXY": url,
                "http_proxy": url, "NO_PROXY": "", "no_proxy": ""}

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
