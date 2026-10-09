"""Policy engine: static shell analysis + profiles + budgets.

IMPORTANT: this is UX and early warning, NOT the security boundary. Regexes are
trivially bypassable (python -c, encoded payloads, ...). The sandbox is what
contains damage; the 'observe' profile exists to prove exactly that."""
import posixpath
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/var", "/opt", "/boot",
               "/dev", "/proc", "/sys", "/root", "/home", "/srv", "/run", "/mnt", "/media")
SCRATCH_DIRS = ("/workspace", "/tmp")
ROOTISH = {"/", "/*", "/.", "/..", "/./", "/../"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
WRAPPERS = {"sudo", "env", "command", "nohup", "time", "nice", "xargs", "exec", "stdbuf", "timeout"}
_PUNCT = set("();<>|&")
_ASSIGN = re.compile(r"^\w+=")

_RULES = [
    (100, r"[\w:]+\s*\(\s*\)\s*\{[^}]*\|[^}]*&", "fork bomb pattern"),
    (90, r"\bmkfs(\.\w+)?\b", "formats a filesystem"),
    (90, r"\bdd\b[^;|&]*\bof=/dev/", "raw write to a block device"),
    (90, r"docker\.sock", "touches the Docker socket"),
    (90, r"\b(nc|ncat|netcat)\b[^;|&]*\s-\w*e\b", "reverse-shell style netcat"),
    (90, r"\bfind\s+(/|~)[^;|&]*(-delete|-exec\s+rm)", "mass delete via find"),
    (80, r"/dev/(tcp|udp)/", "raw network socket via /dev/tcp"),
    (80, r"\b(curl|wget)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "downloads and pipes into a shell"),
    (80, r"\b(curl|wget)\b[^;&]*\|\s*python3?\b", "downloads and pipes into python"),
    (70, r"base64\s+(-d|--decode)[^;&]*\|\s*(ba|z|da)?sh\b", "decodes and executes a payload"),
    (70, r"\b(nc|ncat|netcat)\b", "netcat usage"),
    (60, r"/etc/shadow|/etc/sudoers", "reads credential files"),
    (60, r"\.ssh/|id_rsa|id_ed25519", "touches SSH keys"),
    (60, r"\.aws/|\.config/gcloud|\.kube/config", "touches cloud credentials"),
    (60, r"/proc/[^\s/]*/environ", "reads another process's environment"),
    (60, r"\b(nsenter|unshare|chroot|capsh|setcap|insmod|modprobe)\b", "container-escape tooling"),
    (60, r"\bmount\s+(-t|--bind|-o)\b", "mounts a filesystem"),
    (60, r"--(extra-)?index-url|--trusted-host", "package install from a non-default index"),
    (60, r"\bpip3?\s+install\b[^;&|]*(git\+|https?://|\s-i\s)", "package install from a non-default source"),
    (50, r"\b(strace|ltrace|gdb)\b|\bptrace\b", "process tracing"),
    (30, r"\b(sudo|su)\b", "privilege escalation attempt"),
    (25, r"\b(printenv|env)\b\s*($|[|;&>])", "dumps environment variables"),
]
RULES = [(s, re.compile(rx), why) for s, rx, why in _RULES]


@dataclass(frozen=True)
class Budgets:
    max_steps: int = 12
    max_tokens: int = 40000
    exec_timeout_s: int = 30
    task_deadline_s: float = 300
    max_output_chars: int = 2000
    max_denials: int = 5


@dataclass(frozen=True)
class Profile:
    name: str
    on_high: str
    on_medium: str
    on_low: str = "allow"


PROFILES = {
    # strict: risky -> blocked or approval
    "strict": Profile("strict", on_high="deny", on_medium="require_approval"),
    # observe: risky actions run inside the sandbox on purpose, fully logged
    "observe": Profile("observe", on_high="allow_in_sandbox", on_medium="allow_in_sandbox"),
}


@dataclass
class Decision:
    action: str
    risk: str
    score: int
    reasons: list
    profile: str
    tainted: bool = False     # untrusted web content was read earlier in this task
    injected: bool = False    # ...and a page was flagged as a likely injection attempt

    def payload(self, cmd):
        p = {"cmd": cmd[:300], "action": self.action, "risk": self.risk,
             "score": self.score, "reasons": self.reasons, "profile": self.profile}
        if self.tainted:
            p["tainted"] = True
        if self.injected:
            p["injected"] = True
        return p


def _under(path, dirs):
    return any(path == d or path.startswith(d + "/") for d in dirs)


def _split_segments(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    segs, cur = [], []
    for tok in lex:
        if tok and set(tok) <= _PUNCT:
            if cur:
                segs.append(cur)
                cur = []
        else:
            cur.append(tok)
    if cur:
        segs.append(cur)
    return segs


def _rm_target(t):
    if t in ROOTISH or (t.startswith("/") and posixpath.normpath(t) == "/"):
        return 100, "recursive delete of the filesystem root"
    if t in ("~", "$HOME", "${HOME}") or t.startswith(("~/", "$HOME/", "${HOME}/")):
        return 60, "recursive delete of the home directory"
    if t in ("*", "."):
        return 30, "recursive delete of the whole working directory"
    if t == "..":
        return 40, "recursive delete of the parent directory"
    if t.startswith("/"):
        n = posixpath.normpath(t)
        first = n.split("/")[1] if n.count("/") >= 1 else ""
        if any(c in first for c in "*?["):
            return 100, "glob at the filesystem root"
        if _under(n, SYSTEM_DIRS):
            return 100, f"recursive delete of system path {t}"
        if _under(n, SCRATCH_DIRS):
            return 10, "recursive delete inside scratch space"
        return 70, "recursive delete outside the workspace"
    return 10, "recursive delete of a relative path"


def _rm(args, out):
    longs = {a for a in args if a.startswith("--")}
    shorts = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    targets = [a for a in args if not a.startswith("-")]
    if "--no-preserve-root" in longs:
        out.append((100, "rm --no-preserve-root"))
    if not ("r" in shorts.lower() or "--recursive" in longs):
        return
    if not targets:
        out.append((40, "recursive rm with targets supplied indirectly"))
        return
    for t in targets:
        out.append(_rm_target(t))


def _analyze_tokens(toks, depth, out):
    toks = list(toks)
    while toks and _ASSIGN.match(toks[0]):
        toks.pop(0)
    while toks and posixpath.basename(toks[0]) in WRAPPERS:
        toks.pop(0)
        while toks and (toks[0].startswith("-") or _ASSIGN.match(toks[0]) or toks[0].isdigit()):
            toks.pop(0)
    if not toks:
        return
    name, args = posixpath.basename(toks[0]), toks[1:]
    if name in SHELLS:
        for i, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a and i + 1 < len(args):
                out.extend(_findings(args[i + 1], depth + 1))
                break
    elif name == "rm":
        _rm(args, out)
    elif name in ("chmod", "chown", "chgrp"):
        shorts = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        if "R" in shorts or "--recursive" in args:
            for t in (a for a in args if not a.startswith("-")):
                if t in ROOTISH or (t.startswith("/") and _under(posixpath.normpath(t), SYSTEM_DIRS)):
                    out.append((80, "recursive permission change on a system path"))


def _findings(cmd, depth=0):
    out = [(s, why) for s, rx, why in RULES if rx.search(cmd)]
    if depth < 3:
        try:
            segs = _split_segments(cmd)
        except ValueError:
            out.append((20, "unparseable shell syntax"))
            segs = []
        for seg in segs:
            _analyze_tokens(seg, depth, out)
    return out


def analyze_shell(cmd):
    fs = _findings(cmd)
    score = max((s for s, _ in fs), default=0)
    reasons = []
    for s, why in sorted(fs, key=lambda x: -x[0]):
        if s >= 20 and why not in reasons:
            reasons.append(why)
    return score, reasons


# After the agent has read untrusted web content, anything that reaches the network or touches
# secrets deserves a second look: that is exactly what an injected instruction asks for. Plain
# `pip install <name>` is deliberately not here (the default index is the agent's normal job).
# A heuristic on the command text, so a payload hidden in a script file sails past it: the
# sandbox and the egress allowlist are what contain that, as the Attack Lab shows.
_TAINT_NET = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|ssh|scp|sftp|ftp|telnet|socat|rsync)\b|/dev/(tcp|udp)/|"
    r"\bgit\s+(clone|fetch|pull|push|remote)\b|"
    r"\b(urllib|urlopen|requests|httpx|http\.client|aiohttp|websockets?|socket)\b")
_TAINT_SECRET = re.compile(
    r"\b(printenv|env)\b|/proc/[^\s/]*/environ|\.env\b|\.ssh\b|id_rsa|\.aws\b|"
    r"\b(credentials?|api[_-]?key|secrets?|tokens?|passwd|shadow)\b", re.I)
TAINT_FLOOR, INJECTED_FLOOR = 40, 80   # medium: ask a human / high: strict profile denies


class PolicyEngine:
    def __init__(self, profile="strict", budgets=None):
        self.profile = PROFILES[profile] if isinstance(profile, str) else profile
        self.budgets = budgets or Budgets()

    def _decide(self, score, reasons, tainted=False, injected=False):
        risk = "high" if score >= 80 else "medium" if score >= 40 else "low"
        action = getattr(self.profile, f"on_{risk}")
        return Decision(action, risk, score, reasons, self.profile.name, tainted, injected)

    def evaluate_shell(self, cmd, tainted=False, injected=False):
        score, reasons = analyze_shell(cmd)
        flagged = False
        if (tainted or injected) and (_TAINT_NET.search(cmd) or _TAINT_SECRET.search(cmd)):
            floor = INJECTED_FLOOR if injected else TAINT_FLOOR
            why = ("network or secret access right after a page was flagged as a prompt-injection attempt"
                   if injected else "network or secret access after reading untrusted web content")
            if score < floor:
                score = floor
            reasons = [why] + [r for r in reasons if r != why]
            flagged = True
        return self._decide(score, reasons, tainted and flagged, injected and flagged)

    def evaluate_browse(self, action, url="", tainted=False, injected=False):
        """Early-warning checks for a browser action. The worker re-validates the scheme and the
        egress proxy decides what can actually be reached."""
        score, reasons, because_injected = 0, [], False
        if action == "goto":
            try:
                u = urlsplit(url or "")
                scheme, creds = u.scheme.lower(), bool(u.username or u.password)
            except ValueError:
                scheme, creds = "", False
            if scheme not in ("http", "https"):
                score, reasons = 90, [f"{scheme or 'no'}: URLs are not allowed in the browser"]
            elif creds:
                score, reasons = 50, ["credentials embedded in the URL"]
            elif injected:
                score, because_injected = 50, True
                reasons = ["navigation after a page was flagged as a prompt-injection attempt"]
        return self._decide(score, reasons, tainted and because_injected, because_injected)
