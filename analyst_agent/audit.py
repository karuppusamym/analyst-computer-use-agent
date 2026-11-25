"""Append-only audit store: every step, tool call, screenshot, approval and output.

One folder per task session: events.jsonl plus a screenshots/ folder.
Values under keys that look like secrets are masked before they are written.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_SECRET_KEYS = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|credential)", re.I)


def _mask(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if _SECRET_KEYS.search(str(k)) else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    return obj


class AuditLog:
    def __init__(self, root: str | Path, session_id: str | None = None, user: str = "unknown"):
        self.session_id = session_id or time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.dir = Path(root) / self.session_id
        (self.dir / "screenshots").mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"
        self.user = user
        self._seq = 0
        self._lock = threading.Lock()

    def event(self, kind: str, /, **data: Any) -> dict:
        with self._lock:
            self._seq += 1
            record = {"seq": self._seq, "ts": time.time(), "session": self.session_id, "user": self.user, "kind": kind, **_mask({k: v for k, v in data.items() if k != "kind"}), **({"detail_kind": data["kind"]} if "kind" in data else {})}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
            return record

    def save_image(self, png: bytes, label: str = "screen") -> Path:
        with self._lock:
            name = f"{self._seq:05d}-{re.sub(r'[^a-z0-9_-]', '', label.lower())[:30]}-{uuid.uuid4().hex[:4]}.png"
        p = self.dir / "screenshots" / name
        p.write_bytes(png)
        return p

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
