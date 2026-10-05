import os
import random
import sys
import time

from openai import (APIConnectionError, APITimeoutError, OpenAI,
                    RateLimitError)


class LLMClient:
    """OpenAI-compatible client. Prep: Groq. Nov 3: Vultr Serverless Inference.
    Only LLM_BASE_URL / LLM_MODEL / LLM_API_KEY change."""

    def __init__(self, base_url=None, model=None, api_key=None, max_retries=6):
        self.model = model or os.environ["LLM_MODEL"]
        self.max_retries = max_retries
        self.client = OpenAI(
            base_url=base_url or os.environ["LLM_BASE_URL"],
            api_key=api_key or os.environ["LLM_API_KEY"],
            timeout=60,
            max_retries=0,  # we do our own retries so we can honor retry-after
        )
        self.usage = {"prompt": 0, "completion": 0, "calls": 0}

    def chat(self, messages, tools=None):
        kwargs = {"model": self.model, "messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        for attempt in range(self.max_retries + 1):
            try:
                r = self.client.chat.completions.create(**kwargs)
                if r.usage:
                    self.usage["prompt"] += r.usage.prompt_tokens
                    self.usage["completion"] += r.usage.completion_tokens
                self.usage["calls"] += 1
                return r.choices[0].message
            except RateLimitError as e:
                wait = None
                try:
                    wait = float(e.response.headers.get("retry-after"))
                except (TypeError, ValueError, AttributeError):
                    pass
                self._sleep_or_raise(attempt, e, wait)
            except (APIConnectionError, APITimeoutError) as e:
                self._sleep_or_raise(attempt, e, None)

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
