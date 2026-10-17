import os
import random
import sys
import time
from collections import Counter

from openai import (APIConnectionError, APITimeoutError, BadRequestError,
                    OpenAI, RateLimitError)

from minilocker.llm import toolcalls


BAD_TOOL_CALL_RETRIES = 3
TOOL_MODES = ("native", "json")
RETRY_NUDGE = {"role": "user", "content": "Your last tool call had invalid JSON arguments and was "
                                          "rejected. Call the tool again with valid JSON arguments."}


def _failed_generation(err):
    """What the model wrote, when the provider rejected it as a malformed tool call (Groq: 400
    `tool_use_failed` + `failed_generation`). The openai SDK hands over the inner `error` object as
    `.body`; look one level down as well in case a provider does not unwrap it."""
    body = getattr(err, "body", None)
    for d in (body, body.get("error") if isinstance(body, dict) else None):
        if isinstance(d, dict) and isinstance(d.get("failed_generation"), str):
            return d["failed_generation"]
    return None


class LLMClient:
    """OpenAI-compatible client. Prep: Groq. Nov 3: Vultr Serverless Inference.
    Only LLM_BASE_URL / LLM_MODEL / LLM_API_KEY change.

    Models differ in how faithfully they follow the tool-calling contract, so `chat` tolerates what it safely
    can (see `toolcalls`): near-miss arguments are repaired, a call written as text is recovered, and a call the
    provider rejected is recovered from `failed_generation`. A recovered reply carries `.salvaged`, which the
    agent loop writes to the ledger. `LLM_TOOL_MODE=json` is for a model with no tool calling at all: the tools
    are described in the prompt and the model answers with one JSON object per step.

    `stats` counts what happened, per client, for the bake-off: native_ok, repaired, salvaged (and
    salvaged:<format>), failed_generation, unparseable, json_unparseable, retries."""

    def __init__(self, base_url=None, model=None, api_key=None, max_retries=6, tool_mode=None):
        self.model = model or os.environ["LLM_MODEL"]
        self.max_retries = max_retries
        mode = (tool_mode or os.environ.get("LLM_TOOL_MODE") or "native").strip().lower()
        if mode not in TOOL_MODES:
            raise ValueError(f"LLM_TOOL_MODE must be one of {', '.join(TOOL_MODES)} (got {mode!r})")
        self.tool_mode = mode
        self.client = OpenAI(
            base_url=base_url or os.environ["LLM_BASE_URL"],
            api_key=api_key or os.environ["LLM_API_KEY"],
            timeout=60,
            max_retries=0,  # we do our own retries so we can honor retry-after
        )
        self.usage = {"prompt": 0, "completion": 0, "calls": 0}
        self.stats = Counter()

    def chat(self, messages, tools=None):
        json_mode = bool(tools) and self.tool_mode == "json"
        if json_mode:
            base = toolcalls.to_json_protocol(messages, tools)
            kwargs = {"model": self.model, "messages": base}
        else:
            base = messages
            kwargs = {"model": self.model, "messages": messages}
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
        bad_calls = 0
        for attempt in range(self.max_retries + 1):
            try:
                r = self.client.chat.completions.create(**kwargs)
            except RateLimitError as e:
                wait = None
                try:
                    wait = float(e.response.headers.get("retry-after"))
                except (TypeError, ValueError, AttributeError):
                    pass
                self._sleep_or_raise(attempt, e, wait)
                continue
            except (APIConnectionError, APITimeoutError) as e:
                self._sleep_or_raise(attempt, e, None)
                continue
            except BadRequestError as e:
                # Some models (seen: gpt-oss on Groq) occasionally emit a malformed tool call and the provider
                # rejects it with 400 tool_use_failed. It usually says what the model wrote: if that is a clear
                # call, use it. Otherwise sampling is random, so retry with a nudge instead of crashing the
                # task. Any other 400 is a real bug.
                got = self._rescue(e, tools)
                if got is not None:
                    return got
                bad_calls += 1
                if "tool_use_failed" not in str(e) or bad_calls > BAD_TOOL_CALL_RETRIES:
                    raise
                print(f"[llm] malformed tool call, retry {bad_calls}/{BAD_TOOL_CALL_RETRIES}", file=sys.stderr)
                self.stats["retries"] += 1
                kwargs = {**kwargs, "messages": self._nudged(base, json_mode)}   # nudge on the retry only
                continue

            if r.usage:
                self.usage["prompt"] += r.usage.prompt_tokens
                self.usage["completion"] += r.usage.completion_tokens
            self.usage["calls"] += 1
            msg, usable = self._accept(r.choices[0].message, tools)
            if usable:
                return msg
            bad_calls += 1
            if bad_calls > BAD_TOOL_CALL_RETRIES:
                return msg          # out of tries: the loop decides what an unusable reply means
            print(f"[llm] unusable tool call, retry {bad_calls}/{BAD_TOOL_CALL_RETRIES}", file=sys.stderr)
            self.stats["retries"] += 1
            kwargs = {**kwargs, "messages": self._nudged(base, json_mode)}
        raise RuntimeError("the model did not give a usable reply within the retry limit")

    # -- tolerant handling of the reply ----------------------------------------------------------

    def _accept(self, msg, tools):
        """-> (message, usable). An unusable reply is worth another try; if the tries run out it is returned
        as is (a native call with broken arguments) or as an empty reply (JSON mode)."""
        if not tools:
            return msg, True
        content = getattr(msg, "content", None)
        if getattr(msg, "tool_calls", None):
            fixed, status = toolcalls.normalize_native_calls(msg, tools)
            if status == "unparseable":
                self.stats["unparseable"] += 1
                return msg, False
            self.stats["native_ok" if status == "ok" else "repaired"] += 1
            return fixed, True
        got = toolcalls.salvage(content, tools)
        if got:
            return self._salvaged(got, "content"), True
        if self.tool_mode == "json" and toolcalls.looks_like_json_call(content):
            self.stats["json_unparseable"] += 1
            return toolcalls.make_message(None, []), False
        return msg, True

    def _rescue(self, err, tools):
        failed = _failed_generation(err)
        if not failed or not tools or "tool_use_failed" not in str(err):
            return None
        got = toolcalls.salvage(failed, tools, strict=False)   # the provider already called it an attempted call
        if not got:
            return None
        self.stats["failed_generation"] += 1
        print(f"[llm] recovered {len(got.calls)} call(s) from a rejected generation ({got.how})", file=sys.stderr)
        return self._salvaged(got, "failed_generation")

    def _salvaged(self, got, source):
        self.stats["salvaged"] += 1
        self.stats[f"salvaged:{got.how}"] += 1
        return toolcalls.make_message(got.content, got.calls,
                                      {"how": got.how, "calls": len(got.calls), "source": source})

    @staticmethod
    def _nudged(base, json_mode):
        """The history plus the retry nudge. A JSON-mode history may already end on a user message, and some
        providers insist on alternating roles, so there the nudge joins it."""
        if json_mode and base and base[-1].get("role") == "user":
            return [*base[:-1], {**base[-1], "content": f"{base[-1]['content']}\n\n{RETRY_NUDGE['content']}"}]
        return [*base, RETRY_NUDGE]

    def _sleep_or_raise(self, attempt, err, wait):
        if attempt >= self.max_retries:
            raise err
        wait = min(wait if wait is not None else 2 ** attempt, 60)
        wait += random.uniform(0, 0.5)
        print(f"[llm] {type(err).__name__}, retrying in {wait:.1f}s", file=sys.stderr)
        time.sleep(wait)

    @property
    def total_tokens(self):
        return self.usage["prompt"] + self.usage["completion"]
