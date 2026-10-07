"""LLMClient behaviour against a fake provider. No network, no Docker."""
from types import SimpleNamespace as NS

import httpx
import pytest
from openai import BadRequestError

from minilocker.llm.client import RETRY_NUDGE, LLMClient


def bad_request(code="tool_use_failed"):
    resp = httpx.Response(400, request=httpx.Request("POST", "http://x"))
    return BadRequestError(f"Error code: 400 - {{'error': {{'code': '{code}'}}}}",
                           response=resp, body={"code": code})


def client_with(errors):
    """Fails with each error in order, then answers 'MSG'. Records every call's messages."""
    c = LLMClient(base_url="http://x", model="m", api_key="k")
    calls, pending = [], list(errors)

    def create(**kw):
        calls.append(kw["messages"])
        if pending:
            raise pending.pop(0)
        return NS(usage=None, choices=[NS(message="MSG")])

    c.client = NS(chat=NS(completions=NS(create=create)))
    return c, calls


def test_malformed_tool_call_is_retried_with_a_nudge():
    c, calls = client_with([bad_request()])
    msgs = [{"role": "user", "content": "hi"}]
    assert c.chat(msgs, tools=[{}]) == "MSG"
    assert len(calls) == 2
    assert RETRY_NUDGE not in calls[0] and calls[1][-1] == RETRY_NUDGE
    assert msgs == [{"role": "user", "content": "hi"}]   # caller's history is not polluted


def test_gives_up_after_the_retry_limit():
    c, calls = client_with([bad_request() for _ in range(10)])
    with pytest.raises(BadRequestError):
        c.chat([{"role": "user", "content": "hi"}], tools=[{}])
    assert len(calls) == 4   # first try + 3 retries


def test_other_bad_requests_are_not_retried():
    c, calls = client_with([bad_request("context_length_exceeded")])
    with pytest.raises(BadRequestError):
        c.chat([{"role": "user", "content": "hi"}])
    assert len(calls) == 1
