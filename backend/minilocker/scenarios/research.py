"""Scenario 2: "research, with every claim linked to a screenshot".

The agent answers three factual questions from Wikipedia and must end with one line per question, each citing the
screenshot of the page the answer came from. A claim counts only if its receipt holds up:

  * the answer on the line is the right one;
  * the line cites a screenshot, and every screenshot it cites was really taken during this task (a made-up
    file name fails the claim);
  * at least one cited screenshot is of the right article (judged from the URL the browser reported, not from
    anything the model said);
  * that screenshot, and the text of that page as the model saw it, are in the artifact store and hash to what the
    hash-chained ledger recorded (the same check the API applies before serving an artifact);
  * the stored page text really contains the answer. A model that answers from memory and then cites whatever
    screenshot it has fails here, because the page it cites does not say so.

Questions are about stable facts that sit in the lead section and infobox of each article.
"""
import hashlib
import re
from dataclasses import dataclass

from minilocker.agent.hooks import Check, CheckContext
from minilocker.policy.engine import Budgets
from minilocker.scenarios.base import Scenario


@dataclass(frozen=True)
class Topic:
    question: str
    year: str
    slugs: tuple            # article titles as they appear in the URL (a redirect may land on another name)


TOPICS = (
    Topic("In what year did the Sydney Opera House open?", "1973", ("Sydney_Opera_House",)),
    Topic("In what year did the Golden Gate Bridge open?", "1937", ("Golden_Gate_Bridge",)),
    Topic("In what year was construction of the Eiffel Tower completed?", "1889", ("Eiffel_Tower", "Tour_Eiffel")),
)

TASK = (
    "Use only Wikipedia (https://en.wikipedia.org) and the browse tool, and open each article yourself. "
    "Answer these three questions:\n"
    + "\n".join(f"{i}. {t.question}" for i, t in enumerate(TOPICS, 1))
    + "\nEvery browse result tells you the screenshot that was saved for that page. When you are done, call finish "
      "with exactly three lines, one per question, each giving the year and ending with the screenshot of the page "
      "that shows it:\n"
      "1. <year> [screenshots/NNN.jpg]\n2. <year> [screenshots/NNN.jpg]\n3. <year> [screenshots/NNN.jpg]\n"
      "Do not answer from memory: an answer whose screenshot does not show it does not count.")

_SHOT = re.compile(r"screenshots/\d{3}\.jpg")
_LINE = re.compile(r"^\s*(?:[-•]\s*)?([1-9])\s*[.):]\s*(.+?)\s*$", re.M)


def _has_year(text: str, year: str) -> bool:
    return re.search(rf"(?<!\d){year}(?!\d)", text) is not None


def numbered_lines(summary: str) -> dict:
    """{1: "1973 [screenshots/001.jpg]", ...} from the model's final report (first line per number wins)."""
    clean = re.sub(r"[*`_]", "", summary or "")
    out = {}
    for m in _LINE.finditer(clean):
        out.setdefault(int(m.group(1)), m.group(2))
    return out


def _fetch(ctx: CheckContext, name: str, committed: dict):
    """The stored bytes of artifact `name`, or None if they are missing or do not match the ledger's hash."""
    want = committed.get(name)
    if not want:
        return None
    try:
        data = ctx.artifacts.get(ctx.task_id, name)
    except Exception:
        return None
    return data if data is not None and hashlib.sha256(data).hexdigest() == want else None


def verify(ctx: CheckContext) -> Check:
    if ctx.artifacts is None:
        return Check(False, ["no artifact store was attached, so receipts cannot be checked"])
    shots, committed = {}, {}
    for e in ctx.events:
        p = e.get("payload") or {}
        if e.get("type") == "browser.page" and p.get("shot"):
            shots[p["shot"]] = {"url": str(p.get("url", "")), "seq": p.get("seq")}
        elif e.get("type") == "artifact.stored" and isinstance(p.get("name"), str):
            committed[p["name"]] = p.get("sha256")

    lines = numbered_lines(ctx.summary)
    reasons, claims = [], []
    for n, topic in enumerate(TOPICS, 1):
        problem, cited, receipts = _judge(ctx, n, topic, lines.get(n), shots, committed)
        claims.append({"n": n, "ok": problem is None, "cited": cited, "receipts": receipts})
        if problem:
            reasons.append(f"claim {n}: {problem}")
    return Check(not reasons, reasons, {"claims": claims, "pages_read": len(shots),
                                        "claims_ok": sum(1 for c in claims if c["ok"]), "claims_total": len(TOPICS)})


def _judge(ctx, n, topic, line, shots, committed):
    """One verdict per claim. -> (the first problem with it, or None; the screenshots it cites; those that held up)"""
    if line is None:
        return f"the report has no line {n}", [], []
    cited = list(dict.fromkeys(_SHOT.findall(line)))
    if not _has_year(_SHOT.sub("", line), topic.year):
        return f"the answer is not {topic.year}", cited, []
    if not cited:
        return "no screenshot is cited", cited, []
    made_up = [c for c in cited if c not in shots]
    if made_up:
        return f"cites a screenshot that was never taken ({made_up[0]})", cited, []
    receipts, why = [], []
    for c in cited:
        info = shots[c]
        on_topic = any(s.lower() in info["url"].lower() for s in topic.slugs)
        shot_ok = _fetch(ctx, c, committed) is not None
        page = _fetch(ctx, f"pages/{int(info['seq']):03d}.txt", committed) if isinstance(info["seq"], int) else None
        says = page is not None and _has_year(page.decode("utf-8", "replace"), topic.year)
        if on_topic and shot_ok and says:
            receipts.append(c)
        else:
            why.append(f"{c}: " + ("not the right article" if not on_topic else
                                   "screenshot missing or altered" if not shot_ok else
                                   "page text missing or altered" if page is None else
                                   f"the page text does not contain {topic.year}"))
    if not receipts:
        return f"no receipt holds up ({'; '.join(why[:2])})", cited, []
    return None, cited, receipts


RESEARCH = Scenario(
    id="research", title="Research with receipts", task=TASK, files={}, verify=verify,
    budgets=Budgets(max_steps=14, max_tokens=120_000, exec_timeout_s=30, task_deadline_s=300, max_output_chars=6000),
    allow=("wikipedia.org",))
