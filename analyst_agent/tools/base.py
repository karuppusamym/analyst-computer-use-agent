"""Tool and tier interfaces shared by all five tiers."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..audit import AuditLog
from ..config import Settings
from ..policy import Approver, PolicyEngine


@dataclass
class ToolOutput:
    text: str = ""
    images: list[bytes] = field(default_factory=list)  # PNG bytes
    is_error: bool = False
    files: list[str] = field(default_factory=list)  # files written, for the report

    def content_blocks(self) -> list[dict]:
        blocks: list[dict] = []
        if self.text:
            blocks.append({"type": "text", "text": self.text})
        for png in self.images:
            blocks.append({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(png).decode()}})
        return blocks or [{"type": "text", "text": "OK"}]


@dataclass
class ToolContext:
    settings: Settings
    policy: PolicyEngine
    audit: AuditLog
    approver: Approver
    step_id: str = ""
    workdir: Path = Path(".")
    params: dict = field(default_factory=dict)


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    fn: Callable[[dict, ToolContext], ToolOutput]
    tier: str = ""

    def definition(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}

    def run(self, tool_input: dict, ctx: ToolContext) -> ToolOutput:
        missing = [k for k in self.input_schema.get("required", []) if k not in tool_input]
        if "INVALID_JSON" in tool_input:
            return ToolOutput("Error: the tool input was not valid JSON. Send the call again.", is_error=True)
        if missing:
            return ToolOutput(f"Error: missing required fields {missing}", is_error=True)
        return self.fn(tool_input, ctx)


def schema(properties: dict[str, Any], required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or list(properties), "additionalProperties": False}


class Tier:
    """A group of tools. `available()` says whether its packages and settings allow it."""

    name = "base"
    rank = 0  # 1 = most reliable (connectors) ... 5 = least (pixels)

    def __init__(self, settings: Settings):
        self.settings = settings

    def available(self) -> tuple[bool, str]:
        return True, "ok"

    def tools(self) -> list[Tool]:
        return []

    def api_tools(self) -> list[dict]:
        return [t.definition() for t in self.tools()]

    def handles(self, block: dict) -> bool:
        return any(t.name == block.get("name") for t in self.tools()) and "toolset_name" not in block

    def execute(self, block: dict, ctx: ToolContext) -> ToolOutput:
        for t in self.tools():
            if t.name == block["name"]:
                return t.run(block.get("input") or {}, ctx)
        return ToolOutput(f"Error: unknown tool {block['name']}", is_error=True)

    def close(self) -> None:
        pass
