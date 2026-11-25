"""Playbooks: versioned, parameterised workflows the agent follows.

Stored as plain-text JSON (YAML too when pyyaml is installed) in a
version-controlled registry folder. A playbook is steps + parameters + checks,
never a list of click positions.
"""

from __future__ import annotations

import json
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TIERS = ("connector", "code", "browser", "desktop_uia", "desktop_pixels")


class PlaybookError(ValueError):
    pass


@dataclass
class Step:
    id: str
    intent: str
    tier: str
    instructions: str = ""
    script: dict | None = None  # {"kind": "python", "code": "..."} for scripted replay
    target: dict = field(default_factory=dict)
    checks: list[dict] = field(default_factory=list)
    approval: str = "none"  # "required" -> human approves before it runs
    action_class: str | None = None  # send / submit / delete / upload_external / ...
    mode: str = "guided"  # "scripted" when script is set and proven
    no_check_reason: str = ""  # reviewed exception to "no check, no step" (e.g. an intermediate UI action)
    approval_amount: str | None = None  # e.g. "{amount}": carried on this step's approval requests for reviewer amount limits

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {}, "")}


@dataclass
class Playbook:
    name: str
    version: int
    owner: str
    workflow: str
    description: str
    steps: list[Step]
    parameters: dict[str, dict] = field(default_factory=dict)
    permissions: dict = field(default_factory=dict)
    final_checks: list[dict] = field(default_factory=list)
    backup_owner: str = ""
    approver: str = ""
    source_path: str = ""
    status: str = "active"  # "draft" playbooks (teach mode) are never matched or run until promoted
    provenance: dict = field(default_factory=dict)

    def invalid_params(self, params: dict[str, Any]) -> dict[str, str]:
        """Check given values against each parameter's declared `format` / `enum` / `pattern` / `type`.

        Returns {name: reason} for every value that does not fit. Values are text
        substituted into SQL, code, file names and UI fields, so a value that does
        not match its declared shape must never reach a step.
        """
        bad: dict[str, str] = {}
        for k, spec in self.parameters.items():
            if k not in params:
                continue
            reason = param_problem(params[k], spec)
            if reason:
                bad[k] = reason
        return bad

    def bind(self, params: dict[str, Any]) -> "Playbook":
        """Return a copy with {placeholders} filled in. Missing required params raise."""
        missing = [k for k, spec in self.parameters.items() if spec.get("required", True) and k not in params and "default" not in spec]
        if missing:
            raise PlaybookError(f"missing parameters: {', '.join(missing)}")
        values = {k: spec.get("default") for k, spec in self.parameters.items() if "default" in spec}
        values.update(params)
        data = _fill(self.to_dict(), values)
        return playbook_from_dict(data, self.source_path)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "owner": self.owner,
            "backup_owner": self.backup_owner,
            "approver": self.approver,
            "workflow": self.workflow,
            "description": self.description,
            "parameters": self.parameters,
            "permissions": self.permissions,
            "steps": [s.to_dict() for s in self.steps],
            "final_checks": self.final_checks,
            **({"status": self.status} if self.status != "active" else {}),
            **({"provenance": self.provenance} if self.provenance else {}),
        }


_FORMATS: dict[str, tuple[str, str]] = {
    "date": (r"\d{4}-\d{2}-\d{2}", "a date as YYYY-MM-DD"),
    "month": (r"\d{4}-(0[1-9]|1[0-2])", "a month as YYYY-MM"),
    "week": (r"([1-9]|[1-4]\d|5[0-3])", "an ISO week number from 1 to 53"),
    "number": (r"-?\d+(\.\d+)?", "a number"),
    "email": (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "an email address"),
    "identifier": (r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", "letters, digits, '_', '.' or '-' only"),
    "url": (r"https?://[^\s'\"<>]+", "an http(s) URL"),
}


def param_problem(value: Any, spec: dict) -> str:
    """Why `value` does not fit the parameter spec, or "" when it does."""
    text = str(value).strip()
    if "enum" in spec:
        allowed = [str(x) for x in spec["enum"]]
        if text not in allowed and text.lower() not in [a.lower() for a in allowed]:
            return f"must be one of {', '.join(allowed)}"
    fmt = spec.get("format") or ("number" if spec.get("type") == "number" else "")
    if fmt:
        if fmt not in _FORMATS:
            return f"unknown format '{fmt}' in the playbook"
        rx, what = _FORMATS[fmt]
        if not re.fullmatch(rx, text):
            return f"must be {what}"
        if fmt == "date":
            import datetime as _dt

            try:
                _dt.date.fromisoformat(text)
            except ValueError:
                return "is not a real calendar date"
    if spec.get("pattern") and not re.fullmatch(spec["pattern"], text):
        return f"does not match the required pattern {spec['pattern']}"
    return ""


class _Keep(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _fill(obj: Any, values: dict) -> Any:
    if isinstance(obj, str):
        # Only replace {name} tokens that are known parameters; leave code braces alone.
        def sub(m: re.Match) -> str:
            key = m.group(1)
            return str(values[key]) if key in values else m.group(0)

        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, obj)
    if isinstance(obj, list):
        return [_fill(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    return obj


def playbook_from_dict(data: dict, source_path: str = "") -> Playbook:
    for key in ("name", "steps"):
        if key not in data:
            raise PlaybookError(f"playbook is missing '{key}'")
    steps = []
    seen = set()
    for raw in data["steps"]:
        tier = raw.get("tier", "code")
        if tier not in TIERS:
            raise PlaybookError(f"step {raw.get('id')}: unknown tier '{tier}' (use one of {TIERS})")
        if raw["id"] in seen:
            raise PlaybookError(f"duplicate step id {raw['id']}")
        seen.add(raw["id"])
        checks = raw.get("checks", raw.get("check", []))
        if isinstance(checks, dict):
            checks = [checks]
        if not checks and raw.get("approval") != "required" and not raw.get("no_check_reason"):
            raise PlaybookError(f"step {raw['id']} has no success check (rule: no check, no step; or give a reviewed no_check_reason)")
        steps.append(
            Step(
                id=raw["id"],
                intent=raw.get("intent", raw["id"]),
                tier=tier,
                instructions=raw.get("instructions", ""),
                script=raw.get("script"),
                target=raw.get("target", {}),
                checks=checks,
                approval=raw.get("approval", "none"),
                action_class=raw.get("action_class"),
                mode=raw.get("mode", "scripted" if raw.get("script") else "guided"),
                no_check_reason=raw.get("no_check_reason", ""),
                approval_amount=None if raw.get("approval_amount") in (None, "") else str(raw["approval_amount"]),
            )
        )
    return Playbook(
        name=data["name"],
        version=int(data.get("version", 1)),
        owner=data.get("owner", ""),
        backup_owner=data.get("backup_owner", ""),
        approver=data.get("approver", ""),
        workflow=data.get("workflow", data["name"]),
        description=data.get("description", ""),
        parameters=data.get("parameters", {}),
        permissions=data.get("permissions", {}),
        steps=steps,
        final_checks=data.get("final_checks", []),
        source_path=source_path,
        status=data.get("status", "active"),
        provenance=data.get("provenance", {}),
    )


def load_playbook(path: str | Path) -> Playbook:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional
        except ImportError as e:
            raise PlaybookError("pyyaml is not installed; save the playbook as .json instead") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return playbook_from_dict(data, str(p))


class PlaybookRegistry:
    """A folder of playbooks. Matching by workflow name or keywords in the request.

    Drafts (the drafts/ subfolder, or any file with "status": "draft") are skipped
    by all/get/match unless include_drafts=True; list them with drafts().
    """

    def __init__(self, folder: str | Path, include_drafts: bool = False):
        self.folder = Path(folder)
        self.include_drafts = include_drafts

    @property
    def drafts_folder(self) -> Path:
        return self.folder / "drafts"

    def all(self) -> list[Playbook]:
        if not self.folder.exists():
            return []
        out = []
        for p in sorted(self.folder.iterdir()):
            if p.suffix in (".json", ".yaml", ".yml"):
                pb = load_playbook(p)
                if pb.status != "draft" or self.include_drafts:
                    out.append(pb)
        return out + (self.drafts() if self.include_drafts else [])

    def drafts(self) -> list[Playbook]:
        if not self.drafts_folder.exists():
            return []
        return [load_playbook(p) for p in sorted(self.drafts_folder.iterdir()) if p.suffix in (".json", ".yaml", ".yml")]

    def get(self, name: str) -> Playbook:
        for pb in self.all():
            if pb.name == name or pb.workflow == name:
                return pb
        hint = " (a draft with that name exists; promote it first: teach promote)" if (self.drafts_folder / f"{name}.json").exists() else ""
        raise PlaybookError(f"no playbook named {name} in {self.folder}{hint}")

    def match(self, request: str) -> Playbook | None:
        words = set(re.findall(r"[a-z0-9]+", request.lower()))
        best, score = None, 0
        for pb in self.all():
            keys = set(re.findall(r"[a-z0-9]+", f"{pb.name} {pb.workflow} {pb.description}".lower())) - _STOP
            s = len(words & keys)
            if s > score:
                best, score = pb, s
        return best if score >= 2 else None


_STOP = set(string.ascii_lowercase) | {"the", "and", "a", "to", "of", "in", "for", "from", "with", "on", "by", "into"}
