"""Durable state for pending approvals and clarifying questions.

One JSON file per request under workspace/portal_state/ (setting
portal.state_dir), written atomically (temp file, fsync, os.replace). A request
is written as "pending" before anyone can see it, and closed (decision, who,
when) before the waiting run thread is released, so a decision is never lost.

Each PortalApp has its own instance id. A pending record from another instance
belongs to a run thread that no longer exists (the portal was restarted or
crashed): the new portal closes it as declined ("orphaned").
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

ORPHAN_BY = "portal-restart"
ORPHAN_NOTE = "orphaned — run was interrupted (the portal restarted before a decision); declined, never auto-approved"
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=1, default=str, ensure_ascii=False))
        f.flush()
        os.fsync(f.fileno())
    for attempt in range(20):
        try:
            os.replace(tmp, path)  # atomic on the same volume
            return
        except PermissionError:  # Windows: a reader has the target open for a moment
            if attempt == 19:
                tmp.unlink(missing_ok=True)
                raise
            time.sleep(0.01 * (attempt + 1))


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class PendingStore:
    """portal_state/<kind>-<id>.json, one file per approval request or question set."""

    def __init__(self, root: Path, keep_closed: int = 500):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.instance = secrets.token_hex(8)
        self.keep_closed = keep_closed
        self._lock = threading.Lock()

    def _path(self, kind: str, rid: str) -> Path:
        return self.root / f"{_SAFE.sub('_', kind)}-{_SAFE.sub('_', rid)}.json"

    def open(self, kind: str, rid: str, record: dict) -> dict:
        rec = {**record, "kind": kind, "id": rid, "status": "pending", "instance": self.instance, "pid": os.getpid()}
        with self._lock:
            atomic_write_json(self._path(kind, rid), rec)
        return rec

    def get(self, kind: str, rid: str) -> dict | None:
        rec = read_json(self._path(kind, rid))
        return rec if isinstance(rec, dict) else None

    def put(self, kind: str, rid: str, record: dict, status: str) -> dict:
        """Write a record with an explicit status (e.g. "held" for a takeover left over by an
        earlier portal). Only "pending" records are ever treated as orphans."""
        rec = {**record, "kind": kind, "id": rid, "status": status, "instance": self.instance, "pid": os.getpid()}
        with self._lock:
            atomic_write_json(self._path(kind, rid), rec)
        return rec

    def adopt(self, kind: str, rid: str, **extra: Any) -> dict | None:
        """Take over a pending record from a dead portal instance (it stays pending, now ours)."""
        p = self._path(kind, rid)
        with self._lock:
            rec = read_json(p)
            if not isinstance(rec, dict) or rec.get("status") != "pending":
                return None
            rec.update(extra, previous_instance=rec.get("instance"), instance=self.instance, pid=os.getpid())
            atomic_write_json(p, rec)
        return rec

    def close(self, kind: str, rid: str, outcome: str, by: str, note: str = "", **extra: Any) -> bool:
        """Mark a record decided. False if it was already closed (e.g. by another portal instance)."""
        p = self._path(kind, rid)
        with self._lock:
            rec = read_json(p) or {"kind": kind, "id": rid}
            if rec.get("status") == "closed":
                return False
            rec.update(extra, status="closed", outcome=outcome, by=by, note=note, decided_at=time.time(), closed_by_instance=self.instance)
            atomic_write_json(p, rec)
        return True

    def records(self, kind: str | None = None) -> list[dict]:
        out = []
        for p in self.root.glob("*.json"):
            rec = read_json(p)
            if isinstance(rec, dict) and rec.get("id") and (kind is None or rec.get("kind") == kind):
                out.append(rec)
        return sorted(out, key=lambda r: r.get("created_at") or 0)

    def orphans(self) -> list[dict]:
        """Pending records whose run thread belonged to another (dead) portal instance."""
        return [r for r in self.records() if r.get("status") == "pending" and r.get("instance") != self.instance]

    def prune(self) -> int:
        closed = sorted((r for r in self.records() if r.get("status") == "closed"), key=lambda r: r.get("decided_at") or 0)
        drop = closed[: max(0, len(closed) - self.keep_closed)]
        for r in drop:
            self._path(r["kind"], r["id"]).unlink(missing_ok=True)
        return len(drop)
