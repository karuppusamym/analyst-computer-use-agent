"""Shared test helpers: temp workspace settings and a mock model client."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from analyst_agent.config import load_settings
from analyst_agent.model import MockBackend, ModelClient

ROOT = Path(__file__).resolve().parent.parent


class TempWorkspace:
    """A temp project root with copies of samples and playbooks; settings point into it."""

    def __init__(self, extra: dict | None = None):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        shutil.copytree(ROOT / "samples", self.root / "samples")
        shutil.copytree(ROOT / "playbooks", self.root / "playbooks")
        overrides = {
            "workspace": {"root": str(self.root / "workspace"), "input_dirs": [str(self.root / "samples")], "output_dir": str(self.root / "workspace" / "output")},
            "audit": {"dir": str(self.root / "workspace" / "audit")},
            "connectors": {"databases": {"warehouse": str(self.root / "samples" / "warehouse.sqlite")}},
            "gateway": {"backend": "mock", "fallbacks": None},
            "tiers": {"browser": {"enabled": False}},
        }
        if extra:
            from analyst_agent.config import _deep_merge

            overrides = _deep_merge(overrides, extra)
        self.settings = load_settings(overrides=overrides)
        self.settings.base_dir = self.root

    def client(self, script=None) -> tuple[ModelClient, MockBackend]:
        backend = MockBackend(script)
        return ModelClient(self.settings, backend=backend), backend

    def cleanup(self):
        self._tmp.cleanup()
