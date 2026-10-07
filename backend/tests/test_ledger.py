from minilocker.ledger.chain import Ledger


def make():
    l = Ledger("t1")
    l.append("agent", "tool.call", {"cmd": "ls"})
    l.append("policy", "decision", {"result": "allow"})
    l.append("egress", "egress.blocked", {"host": "evil.example"})
    return l


def test_verifies():
    assert make().verify()[0]


def test_tamper_payload():
    l = make()
    l.events[1]["payload"]["result"] = "deny"
    assert not l.verify()[0]


def test_delete_middle():
    l = make()
    del l.events[1]
    assert not l.verify()[0]


def test_reorder():
    l = make()
    l.events[1], l.events[2] = l.events[2], l.events[1]
    assert not l.verify()[0]


def test_persist_and_reload(tmp_path):
    p = str(tmp_path / "t1.jsonl")
    l = Ledger("t1", p)
    l.append("a", "x", {"n": 1})
    l.append("a", "y", {"n": 2})
    assert Ledger("t1", p).verify()[0]
