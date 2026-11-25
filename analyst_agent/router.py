"""Tool-tier router: always picks the most reliable tier that can do the step.

Order: 1 connector > 2 code > 3 browser (DOM) > 4 desktop UI Automation > 5 desktop pixels.
Tiers whose packages or settings are missing report unavailable and are skipped.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass

from .config import Settings
from .playbook import TIERS
from .tools.base import Tier

_TIER_CLASSES = {
    "connector": ("analyst_agent.tools.connectors", "ConnectorTier"),
    "code": ("analyst_agent.tools.code", "CodeTier"),
    "browser": ("analyst_agent.tools.browser", "BrowserTier"),
    "desktop_uia": ("analyst_agent.tools.desktop_uia", "UiaTier"),
    "desktop_pixels": ("analyst_agent.tools.computer", "ComputerTier"),
}

# Where a step may fall back when its tier is unavailable: only toward tiers
# that can do the same kind of work.
_FALLBACK = {
    "connector": ["code"],
    "code": [],
    "browser": ["desktop_pixels"],
    "desktop_uia": ["desktop_pixels"],
    "desktop_pixels": [],
}


@dataclass
class Route:
    tier: Tier
    requested: str
    note: str = ""


class RouteError(RuntimeError):
    pass


class Router:
    def __init__(self, settings: Settings, tiers: dict[str, Tier] | None = None):
        self.settings = settings
        self._tiers: dict[str, Tier] = dict(tiers or {})
        self._errors: dict[str, str] = {}

    def tier(self, name: str) -> Tier | None:
        if name in self._tiers:
            return self._tiers[name]
        if name in self._errors:
            return None
        module, cls = _TIER_CLASSES[name]
        try:
            self._tiers[name] = getattr(importlib.import_module(module), cls)(self.settings)
        except Exception as e:  # missing optional package or module
            self._errors[name] = f"{type(e).__name__}: {e}"
            return None
        return self._tiers[name]

    def status(self) -> dict[str, tuple[bool, str]]:
        out = {}
        for name in TIERS:
            t = self.tier(name)
            out[name] = t.available() if t else (False, self._errors.get(name, "not loaded"))
        return out

    def available_names(self) -> list[str]:
        return [n for n, (ok, _) in self.status().items() if ok]

    def route(self, requested: str) -> Route:
        if requested not in TIERS:
            raise RouteError(f"unknown tier {requested}")
        for name in [requested] + _FALLBACK[requested]:
            t = self.tier(name)
            if t and t.available()[0]:
                note = "" if name == requested else f"{requested} unavailable ({self.status()[requested][1]}); using {name}"
                return Route(t, requested, note)
        raise RouteError(f"no available tier for '{requested}': {self.status()[requested][1]}")

    def close(self) -> None:
        for t in self._tiers.values():
            try:
                t.close()
            except Exception:
                pass
