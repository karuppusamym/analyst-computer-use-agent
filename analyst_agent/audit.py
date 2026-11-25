"""Append-only audit store: every step, tool call, screenshot, approval and output.

One folder per task session: events.jsonl plus a screenshots/ folder.
Values under keys that look like secrets are masked before they are written,
and vault secret values are replaced with [REDACTED:name] (see Redactor).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_SECRET_KEYS = re.compile(r"(^pass$|^pwd$|password|passwd|passphrase|secret|token|api[_-]?key|authorization|credential)", re.I)


def _mask(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if _SECRET_KEYS.search(str(k)) else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    return obj


class Redactor:
    """Replaces known secret values (and their URL/HTML-escaped forms) with [REDACTED:name].

    The vault registers a value here before any tool uses it, so everything
    recorded afterwards (audit events, tool results, reports, checkpoints) is
    cleaned. Images cannot be redacted; see the README.
    """

    def __init__(self):
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()

    def add(self, name: str, value: str) -> None:
        if not value:
            return
        from html import escape
        from urllib.parse import quote, quote_plus

        with self._lock:
            for form in {value, quote(value, safe=""), quote_plus(value), escape(value), json.dumps(value)[1:-1]}:
                if form:
                    self._values[form] = name

    def __bool__(self) -> bool:
        return bool(self._values)

    def text(self, s: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            if value in s:
                s = s.replace(value, f"[REDACTED:{self._values[value]}]")
        return s

    def apply(self, obj: Any) -> Any:
        if not self._values:
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.apply(k) if isinstance(k, str) else k: self.apply(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.apply(x) for x in obj)
        return obj


_FILE_LOCKS: dict[str, threading.Lock] = {}
_FILE_LOCKS_GUARD = threading.Lock()


def file_lock(path: str | Path) -> threading.Lock:
    """One lock per events.jsonl in this process, shared by the run's AuditLog and the portal,
    so two writers (e.g. a human takeover and the agent) never interleave or reuse a seq."""
    key = str(Path(path).resolve()).lower()
    with _FILE_LOCKS_GUARD:
        return _FILE_LOCKS.setdefault(key, threading.Lock())


def _scan_last_seq(path: Path) -> int:
    if not path.exists():
        return 0
    last = 0
    with path.open("rb") as fh:
        for line in fh:
            try:
                last = max(last, int(json.loads(line).get("seq", 0)))
            except (ValueError, TypeError, AttributeError):
                continue
    return last


def append_event(session_dir: str | Path, kind: str, user: str = "portal", **data: Any) -> dict | None:
    """Append one event to a session's events.jsonl from outside its run (portal, takeover).
    Secret-looking keys are masked like AuditLog.event; the seq continues the file's sequence."""
    d = Path(session_dir)
    if not d.is_dir():
        return None
    path = d / "events.jsonl"
    with file_lock(path):
        rec = {"seq": _scan_last_seq(path) + 1, "ts": time.time(), "session": d.name, "user": user, "kind": kind, **_mask(data)}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return rec


def redact(obj: Any, audit: Any) -> Any:
    """Apply the audit log's redactor if it has one (test doubles may not)."""
    r = getattr(audit, "redactor", None)
    return r.apply(obj) if r else obj


class AuditLog:
    def __init__(self, root: str | Path, session_id: str | None = None, user: str = "unknown"):
        self.session_id = session_id or time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.dir = Path(root) / self.session_id
        (self.dir / "screenshots").mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"
        self.user = user
        self._seq = self._last_seq()  # a resumed session continues its sequence; it never restarts at 1
        self._lock = file_lock(self.path)
        self._size = self.path.stat().st_size if self.path.exists() else 0
        self.redactor = Redactor()

    def _last_seq(self) -> int:
        return _scan_last_seq(self.path)

    def event(self, kind: str, /, **data: Any) -> dict:
        with self._lock:
            size = self.path.stat().st_size if self.path.exists() else 0
            if size != self._size:  # someone else (the portal) appended: continue after their seq
                self._seq = max(self._seq, self._last_seq())
            self._seq += 1
            record = {"seq": self._seq, "ts": time.time(), "session": self.session_id, "user": self.user, "kind": kind, **_mask({k: v for k, v in data.items() if k != "kind"}), **({"detail_kind": data["kind"]} if "kind" in data else {})}
            record = self.redactor.apply(record)
            line = json.dumps(record, default=str)
            if self.redactor:
                line = self.redactor.text(line)  # values hidden inside objects rendered by default=str
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
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
