"""Code paths the container deployment depends on. No Docker, no network."""
from types import SimpleNamespace as NS

import pytest
from docker.errors import NotFound

import minilocker.api.app as app_mod
import minilocker.egress.manager as mgr


class FakeNet:
    def connect(self, container, aliases=None):
        self.connected = (container, aliases)


class FakeClient:
    def __init__(self):
        self.run_kwargs = None
        self.containers = NS(run=self._run, get=self._get)
        self.networks = NS(get=lambda name: FakeNet(), create=lambda *a, **k: None)

    def _run(self, image, *args, **kw):
        self.run_kwargs = {"image": image, "args": args, **kw}
        return NS(logs=lambda: b'{"listening": true}')

    def _get(self, name):
        raise NotFound("none")


def manager(monkeypatch, **kw):
    fake = FakeClient()
    monkeypatch.setattr(mgr.docker, "from_env", lambda: fake)
    return mgr.EgressManager(["pypi.org"], **kw), fake


def test_dev_mode_still_bind_mounts_the_proxy_script(monkeypatch):
    m, fake = manager(monkeypatch)
    m.start()
    kw = fake.run_kwargs
    assert kw["command"] == ["python", "-u", "/proxy.py"]
    (host_path, spec), = kw["volumes"].items()
    assert host_path.endswith("proxy_server.py") and spec == {"bind": "/proxy.py", "mode": "ro"}


def test_packaged_mode_mounts_nothing_from_this_filesystem(monkeypatch):
    m, fake = manager(monkeypatch, image="minilocker-api:latest", packaged=True)
    m.start()
    kw = fake.run_kwargs
    assert kw["image"] == "minilocker-api:latest"
    assert kw["command"] == ["python", "-u", "-m", "minilocker.egress.proxy_server"]
    assert "volumes" not in kw                        # a host path would not exist on the Docker host
    # the hardening is identical in both modes
    assert kw["read_only"] and kw["cap_drop"] == ["ALL"] and kw["user"] == "65534:65534"
    assert kw["environment"] == {"ALLOWED_HOSTS": "pypi.org", "PROXY_ALIAS": mgr.ALIAS}      # no broker: no tokens


def test_default_egress_reads_the_image_from_the_environment(monkeypatch):
    seen = {}

    class Spy:
        def __init__(self, allow, **kw):
            seen.update(allow=allow, **kw)

        def start(self):
            return self

    monkeypatch.setattr(mgr, "EgressManager", Spy)
    monkeypatch.delenv("MINILOCKER_PROXY_IMAGE", raising=False)
    app_mod._default_egress()
    assert "packaged" not in seen
    monkeypatch.setenv("MINILOCKER_PROXY_IMAGE", "minilocker-api:latest")
    monkeypatch.setenv("MINILOCKER_ALLOW", "a.org,b.org")
    app_mod._default_egress()
    assert seen["image"] == "minilocker-api:latest" and seen["packaged"] is True and seen["allow"] == ["a.org", "b.org"]


def flaky(monkeypatch, failures):
    import minilocker.artifacts as arts
    calls = {"n": 0}

    def from_env():
        calls["n"] += 1
        if calls["n"] <= failures:
            raise ConnectionError("storage not up yet")
        return "STORE"

    monkeypatch.setattr(arts.S3ArtifactStore, "from_env", staticmethod(from_env))
    return calls


def test_artifact_store_attach_survives_a_slow_starting_storage(monkeypatch):
    calls, naps = flaky(monkeypatch, failures=3), []
    assert app_mod._default_artifacts(sleep=naps.append) == ("STORE", None)
    assert calls["n"] == 4 and len(naps) == 3


def test_artifact_store_gives_up_and_says_why(monkeypatch):
    calls = flaky(monkeypatch, failures=99)
    assert app_mod._default_artifacts(tries=4, sleep=lambda s: None) == (None, "ConnectionError")
    assert calls["n"] == 4


def test_unconfigured_storage_is_not_retried(monkeypatch):
    import minilocker.artifacts as arts
    calls = {"n": 0}
    monkeypatch.setattr(arts.S3ArtifactStore, "from_env",
                        staticmethod(lambda: calls.__setitem__("n", calls["n"] + 1)))   # returns None
    assert app_mod._default_artifacts(sleep=lambda s: pytest.fail("must not sleep")) == (None, None)
    assert calls["n"] == 1


def test_broker_tokens_go_to_the_proxy_container_only(monkeypatch):
    m, fake = manager(monkeypatch, image="minilocker-api:latest", packaged=True,
                      broker=mgr.broker_from_env({"MINILOCKER_BROKER": "github=api.github.com",
                                                  "MINILOCKER_BROKER_TOKEN_GITHUB": "ghp_abcdefghijkl"}))
    m.start()
    import json as _json
    env = fake.run_kwargs["environment"]
    assert _json.loads(env["BROKER_SERVICES"])["github"]["token"] == "ghp_abcdefghijkl"
    sandbox_env = m.proxy_env()
    assert "ghp_abcdefghijkl" not in _json.dumps(sandbox_env)
