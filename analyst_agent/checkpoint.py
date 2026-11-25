"""Checkpoints: after each verified step, save task state so a failure resumes
from the last good step instead of starting over."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class CheckpointStore:
    def __init__(self, session_dir: str | Path):
        self.path = Path(session_dir) / "checkpoint.json"

    def save(self, state: dict[str, Any]) -> None:
        state = {**state, "saved_at": time.time()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        tmp.replace(self.path)  # atomic on the same volume

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text(encoding="utf-8"))
