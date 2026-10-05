import os
import docker
from airlock.sandbox.docker_provider import Sandbox

CANARY = os.path.expanduser("~/airlock_host_canary.txt")


def setup_module():
    with open(CANARY, "w") as f:
        f.write("host data")


def host_intact():
    return os.path.exists(CANARY) and open(CANARY).read() == "host data"


def run(cmd, timeout_s=10):
    sb = Sandbox()
    try:
        return sb.exec(cmd, timeout_s)
    finally:
        sb.destroy()


def test_rm_rf():
    r = run("touch /workspace/x; rm -rf --no-preserve-root /usr /bin /etc /var /opt /home /root /tmp/* /workspace/* 2>&1 | tail -3; ls /workspace; echo done")
    print(r)
    assert host_intact()


def test_fork_bomb():
    r = run('python3 -c "import os\nwhile True:\n    try: os.fork()\n    except OSError: pass"', 5)
    print(r)
    assert host_intact()


def test_cpu_loop_times_out():
    r = run("while true; do :; done", 3)
    assert r.timed_out


def test_no_network():
    r = run("python3 -c \"import urllib.request;urllib.request.urlopen('http://1.1.1.1',timeout=3)\"")
    assert r.exit_code != 0


def test_no_leaked_containers():
    run("echo hi")
    leaked = docker.from_env().containers.list(all=True, filters={"label": "airlock=sandbox"})
    assert leaked == []


def test_pid_limit_enforced():
    r = run("python3 -c \"import os\nn=0\nwhile True:\n    try:\n        if os.fork()==0:\n            import time; time.sleep(20)\n        n+=1\n    except OSError:\n        print('blocked_at', n); break\"", 15)
    print(r)
    assert "blocked_at" in r.stdout
    assert host_intact()


def test_workspace_writable():
    r = run("echo hi > /workspace/a.txt && cat /workspace/a.txt")
    assert r.stdout.strip() == "hi"
    assert r.stderr == ""


def test_rm_rf_wipes_workspace_but_not_system():
    r = run("echo data > /workspace/x; rm -rf /workspace/* /usr /bin /etc 2>/dev/null; "
            "ls /workspace | wc -l; test -d /usr && echo usr_exists")
    print(r)
    assert r.stdout.split()[0] == "0"      # workspace really was wiped
    assert "usr_exists" in r.stdout        # read-only system survived
    assert host_intact()
