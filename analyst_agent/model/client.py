"""ModelClient: the one interface the harness uses to call Claude.

Backends:
  HttpBackend  - stdlib urllib, streams /v1/messages from the gateway. No packages needed.
  SdkBackend   - the official `anthropic` SDK, when installed.
  MockBackend  - scripted replies for tests and offline demos.

Every backend takes a plain JSON request body and returns the plain message
dict, so the assistant content can be appended back to the history unchanged
(thinking blocks included).
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import Settings
from .sse import MessageAccumulator, StreamError, iter_sse


class ModelError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class RefusalError(ModelError):
    def __init__(self, category: str | None, explanation: str | None):
        super().__init__(f"model declined the request (category={category}): {explanation}")
        self.category = category
        self.explanation = explanation


@dataclass
class ModelReply:
    message: dict

    @property
    def content(self) -> list[dict]:
        return self.message.get("content", [])

    @property
    def stop_reason(self) -> str | None:
        return self.message.get("stop_reason")

    @property
    def usage(self) -> dict:
        return self.message.get("usage", {})

    def text(self) -> str:
        return "".join(b.get("text", "") for b in self.content if b.get("type") == "text")

    def tool_uses(self) -> list[dict]:
        return [b for b in self.content if b.get("type") == "tool_use"]

    def json(self) -> Any:
        return json.loads(self.text())


# --------------------------------------------------------------------------- backends


class HttpBackend:
    """Talks to the gateway's native Messages API route with urllib only."""

    def __init__(self, settings: Settings):
        g = settings["gateway"]
        self.url = g["base_url"].rstrip("/") + "/v1/messages"
        self.api_version = g["api_version"]
        self.auth_style = g["auth_style"]
        self.token = settings.gateway_token()
        self.timeout = g["timeout_s"]
        self.max_retries = g["max_retries"]
        self.extra_headers = dict(g.get("extra_headers") or {})
        self.last_headers: dict[str, str] = {}
        # Timing of the last stream, used by gateway-check to spot buffering.
        self.last_stream: dict[str, float | int | None] = {}

    def _headers(self, betas: list[str]) -> dict[str, str]:
        h = {
            "content-type": "application/json",
            "accept": "text/event-stream",
            "anthropic-version": self.api_version,
        }
        if self.token:
            if self.auth_style == "bearer":
                h["authorization"] = f"Bearer {self.token}"
            else:
                h["x-api-key"] = self.token
        if betas:
            h["anthropic-beta"] = ",".join(betas)
        h.update(self.extra_headers)
        return h

    def send(self, body: dict, betas: list[str]) -> dict:
        payload = json.dumps({**body, "stream": True}).encode("utf-8")
        attempt = 0
        while True:
            req = urllib.request.Request(self.url, data=payload, headers=self._headers(betas), method="POST")
            try:
                start = time.monotonic()
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    self.last_headers = {k.lower(): v for k, v in resp.headers.items()}
                    acc = MessageAccumulator()
                    text_events, first_text = 0, None
                    for event, data in iter_sse(resp):
                        if '"text_delta"' in data:
                            text_events += 1
                            if first_text is None:
                                first_text = time.monotonic()
                        acc.feed(event, data)
                    self.last_stream = _stream_stats(start, text_events, first_text)
                    return acc.result()
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:2000]
                should_retry = e.headers.get("x-should-retry")
                retryable = e.code in (408, 409, 429) or e.code >= 500
                if should_retry is not None:
                    retryable = should_retry.lower() == "true"
                err = ModelError(f"HTTP {e.code} from gateway: {detail}", status=e.code, retryable=retryable)
                wait = _retry_after(e.headers.get("retry-after"))
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                err = ModelError(f"cannot reach gateway at {self.url}: {e}", retryable=True)
                wait = None
            except StreamError as e:
                err = ModelError(f"stream error: {e}", retryable="overloaded" in str(e))
                wait = None
            if not err.retryable or attempt >= self.max_retries:
                raise err
            attempt += 1
            time.sleep(wait if wait is not None else min(60.0, 2**attempt + random.random()))


def _stream_stats(start: float, text_events: int, first_text: float | None) -> dict:
    return {
        "text_events": text_events,
        "seconds_to_first_text": round(first_text - start, 1) if first_text is not None else None,
        "seconds_total": round(time.monotonic() - start, 1),
    }


def _retry_after(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


class SdkBackend:
    """Uses the official SDK. Fields newer than the installed SDK go through extra_body."""

    _KWARGS = ("model", "max_tokens", "messages", "system", "tools", "tool_choice", "thinking", "stop_sequences", "metadata")

    def __init__(self, settings: Settings):
        import anthropic  # optional dependency

        g = settings["gateway"]
        token = settings.gateway_token()
        auth = {"auth_token": token} if g["auth_style"] == "bearer" else {"api_key": token}
        self.client = anthropic.Anthropic(
            base_url=g["base_url"],
            timeout=g["timeout_s"],
            max_retries=g["max_retries"],
            default_headers={"anthropic-version": g["api_version"], **(g.get("extra_headers") or {})},
            **auth,
        )
        self._anthropic = anthropic
        self.last_headers: dict[str, str] = {}
        self.last_stream: dict[str, float | int | None] = {}

    def send(self, body: dict, betas: list[str]) -> dict:
        kwargs = {k: v for k, v in body.items() if k in self._KWARGS}
        extra = {k: v for k, v in body.items() if k not in self._KWARGS}
        headers = {"anthropic-beta": ",".join(betas)} if betas else None
        try:
            start = time.monotonic()
            with self.client.messages.stream(**kwargs, extra_body=extra or None, extra_headers=headers) as stream:
                text_events, first_text = 0, None
                for _ in stream.text_stream:
                    text_events += 1
                    if first_text is None:
                        first_text = time.monotonic()
                msg = stream.get_final_message()
            self.last_stream = _stream_stats(start, text_events, first_text)
        except self._anthropic.APIStatusError as e:
            raise ModelError(f"HTTP {e.status_code}: {e.message}", status=e.status_code) from e
        except self._anthropic.APIConnectionError as e:
            raise ModelError(f"cannot reach gateway: {e}", retryable=True) from e
        return msg.to_dict()


class MockBackend:
    """Returns scripted replies. Each script item is a message dict or a callable(body) -> dict."""

    def __init__(self, script: list[dict | Callable[[dict], dict]] | None = None):
        self.script = list(script or [])
        self.requests: list[dict] = []
        self.last_headers: dict[str, str] = {}
        self.last_stream: dict = {}

    def push(self, *items: dict | Callable[[dict], dict]) -> None:
        self.script.extend(items)

    def send(self, body: dict, betas: list[str]) -> dict:
        self.requests.append({"body": json.loads(json.dumps(body)), "betas": list(betas)})
        if not self.script:
            raise ModelError("MockBackend: no scripted reply left")
        item = self.script.pop(0)
        reply = item(body) if callable(item) else item
        reply = json.loads(json.dumps(reply))
        # A scripted reply may carry "_stream" stats to simulate stream timing.
        self.last_stream = reply.pop("_stream", {})
        reply.setdefault("role", "assistant")
        reply.setdefault("stop_reason", "end_turn")
        reply.setdefault("usage", {"input_tokens": 0, "output_tokens": 0})
        return reply


def mock_text(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}


def mock_tool(name: str, tool_input: dict, tool_id: str | None = None, text: str = "", **extra) -> dict:
    content = [{"type": "text", "text": text}] if text else []
    content.append({"type": "tool_use", "id": tool_id or f"toolu_{random.randrange(16**12):012x}", "name": name, "input": tool_input, **extra})
    return {"content": content, "stop_reason": "tool_use"}


# --------------------------------------------------------------------------- client


@dataclass
class UsageMeter:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    by_model: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, model: str, usage: dict) -> None:
        self.calls += 1
        i, o = usage.get("input_tokens", 0) or 0, usage.get("output_tokens", 0) or 0
        c = usage.get("cache_read_input_tokens", 0) or 0
        self.input_tokens += i
        self.output_tokens += o
        self.cache_read_tokens += c
        m = self.by_model.setdefault(model, {"calls": 0, "input": 0, "output": 0, "cache_read": 0})
        m["calls"] += 1
        m["input"] += i
        m["output"] += o
        m["cache_read"] += c


class ModelClient:
    """Builds requests per role (planner, executor, verifier, helper) and sends them."""

    def __init__(self, settings: Settings, backend: Any | None = None):
        self.settings = settings
        self.backend = backend or make_backend(settings)
        self.usage = UsageMeter()

    def role(self, name: str) -> dict:
        return self.settings["models"][name]

    def create(
        self,
        role: str,
        messages: list[dict],
        system: str | list[dict] | None = None,
        tools: list[dict] | None = None,
        output_schema: dict | None = None,
        extra_betas: list[str] | None = None,
        **extra: Any,
    ) -> ModelReply:
        cfg = self.role(role)
        g = self.settings["gateway"]
        body: dict[str, Any] = {
            "model": cfg["model"],
            "max_tokens": cfg.get("max_tokens", 16000),
            "messages": messages,
            # Thinking is left at the model default (adaptive). Depth is set by effort.
            "output_config": {"effort": cfg.get("effort", "medium")},
            # Automatic prompt caching of the stable prefix (system + tools + playbook).
            "cache_control": {"type": "ephemeral"},
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools
        if output_schema:
            body["output_config"]["format"] = {"type": "json_schema", "schema": output_schema}
        betas = list(extra_betas or [])
        if g.get("fallbacks"):
            body["fallbacks"] = g["fallbacks"]
            betas.append(g["fallback_beta"])
        body.update(extra)

        message = self.backend.send(body, betas)
        self.usage.add(cfg["model"], message.get("usage", {}))
        reply = ModelReply(message)
        if reply.stop_reason == "refusal":
            details = message.get("stop_details") or {}
            raise RefusalError(details.get("category"), details.get("explanation"))
        return reply


def make_backend(settings: Settings):
    choice = settings["gateway"]["backend"]
    if choice == "mock":
        return MockBackend()
    if choice == "http":
        return HttpBackend(settings)
    if choice == "sdk":
        return SdkBackend(settings)
    try:
        import anthropic  # noqa: F401

        return SdkBackend(settings)
    except ImportError:
        return HttpBackend(settings)
