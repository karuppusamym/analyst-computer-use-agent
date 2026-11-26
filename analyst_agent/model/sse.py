"""Accumulate a Messages API server-sent-event stream into one message dict.

Written without the SDK so the harness works where `anthropic` cannot be
installed. Unknown block and delta types are kept generically, so fields the
gateway passes through (thinking signatures, fallback blocks, citations)
survive and can be sent back unchanged - the history must stay append-only.
"""

from __future__ import annotations

import json
from typing import Iterable, Iterator


class StreamError(RuntimeError):
    pass


def iter_sse(lines: Iterable[bytes]) -> Iterator[tuple[str, str]]:
    """Yield (event, data) pairs from raw SSE lines."""
    event, data = "", []
    for raw in lines:
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            if data:
                yield event, "\n".join(data)
            event, data = "", []
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "event":
            event = value
        elif name == "data":
            data.append(value)
    if data:
        yield event, "\n".join(data)


class MessageAccumulator:
    def __init__(self) -> None:
        self.message: dict | None = None
        self.blocks: dict[int, dict] = {}
        self._json: dict[int, str] = {}

    def feed(self, event: str, data: str) -> None:
        payload = json.loads(data)
        kind = payload.get("type", event)
        if kind == "message_start":
            self.message = payload["message"]
            self.message.setdefault("content", [])
        elif kind == "content_block_start":
            idx = payload["index"]
            block = dict(payload["content_block"])
            if "input" in block and block.get("type", "").endswith("tool_use"):
                # Input arrives as input_json_delta fragments.
                self._json[idx] = ""
                block["input"] = {}
            self.blocks[idx] = block
        elif kind == "content_block_delta":
            idx = payload["index"]
            block = self.blocks.setdefault(idx, {})
            delta = payload.get("delta", {})
            for key, value in delta.items():
                if key == "type":
                    continue
                if key == "partial_json":
                    self._json[idx] = self._json.get(idx, "") + value
                elif isinstance(value, str):
                    block[key] = block.get(key, "") + value
                elif isinstance(value, list):
                    block.setdefault(key, []).extend(value)
                elif key == "citation":
                    block.setdefault("citations", []).append(value)
                else:
                    block[key] = value
        elif kind == "content_block_stop":
            idx = payload["index"]
            if idx in self._json:
                raw = self._json.pop(idx)
                try:
                    self.blocks[idx]["input"] = json.loads(raw) if raw.strip() else {}
                except json.JSONDecodeError:
                    # Truncated or invalid input: keep the text so the caller
                    # can answer it with an is_error tool_result.
                    self.blocks[idx]["input"] = {"INVALID_JSON": raw}
        elif kind == "message_delta":
            if self.message is None:
                raise StreamError("message_delta before message_start")
            for key, value in payload.get("delta", {}).items():
                self.message[key] = value
            usage = payload.get("usage") or {}
            self.message.setdefault("usage", {}).update({k: v for k, v in usage.items() if v is not None})
            # Keep other top-level fields (beta-only ones such as diagnostics).
            for key, value in payload.items():
                if key not in ("type", "delta", "usage"):
                    self.message[key] = value
        elif kind == "error":
            err = payload.get("error", {})
            raise StreamError(f"{err.get('type', 'error')}: {err.get('message', data)}")
        # ping and message_stop need no handling.

    def result(self) -> dict:
        if self.message is None:
            raise StreamError("stream ended without message_start")
        self.message["content"] = [self.blocks[i] for i in sorted(self.blocks)]
        return self.message
