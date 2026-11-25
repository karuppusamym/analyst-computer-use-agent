"""Tier 4 - Windows desktop through the UI Automation tree (pywinauto, optional).

Targets controls by automation id or name, not coordinates, so playbooks
survive window moves and resolution changes. Disabled by default; enable it
in settings only inside an agent workspace.
"""

from __future__ import annotations

import os
import re

from ..policy import ApprovalRequest, PolicyViolation, wrap_untrusted
from .base import Tier, Tool, ToolContext, ToolOutput, schema

RISKY = re.compile(r"\b(submit|send|pay|delete|remove|confirm|place order|purchase|transfer|sign)\b", re.I)


class UiaTier(Tier):
    name = "desktop_uia"
    rank = 4

    def available(self) -> tuple[bool, str]:
        if os.name != "nt":
            return False, "UI Automation needs Windows"
        try:
            import pywinauto  # noqa: F401
        except ImportError:
            return False, "pywinauto not installed"
        if not self.settings["tiers"]["desktop_uia"].get("enabled", False):
            return False, "desktop_uia tier disabled in settings"
        return True, "ok"

    # ---------------------------------------------------------------- helpers
    def _desktop(self):
        from pywinauto import Desktop

        return Desktop(backend="uia")

    @staticmethod
    def _proc_name(win) -> str:
        try:
            import psutil  # optional

            return psutil.Process(win.process_id()).name()
        except Exception:
            try:
                from pywinauto.application import Application

                app = Application(backend="uia").connect(process=win.process_id())
                return os.path.basename(app.process and str(app.process) or "")  # best effort
            except Exception:
                return f"pid-{win.process_id()}"

    def _window(self, title: str, ctx: ToolContext):
        matches = [w for w in self._desktop().windows() if title.lower() in (w.window_text() or "").lower()]
        if not matches:
            raise ValueError(f"no window with '{title}' in its title")
        win = matches[0]
        ctx.policy.check_app(self._proc_name(win))
        return win

    def _control(self, win, inp: dict):
        crit = {}
        if inp.get("automation_id"):
            crit["auto_id"] = inp["automation_id"]
        if inp.get("name"):
            crit["title"] = inp["name"]
        if not crit:
            raise ValueError("give automation_id or name")
        ctl = win.child_window(**crit)
        if not ctl.exists(timeout=3):
            raise ValueError(f"control {crit} not found; read uia_tree again")
        return ctl.wrapper_object()

    # ---------------------------------------------------------------- tools
    def _list(self, inp: dict, ctx: ToolContext) -> ToolOutput:
        lines = []
        for w in self._desktop().windows():
            title = w.window_text()
            if title:
                lines.append(f"{title!r}\tprocess={self._proc_name(w)}\thandle={w.handle}")
        ctx.audit.event("uia_action", step=ctx.step_id, action="list_windows", count=len(lines))
        return ToolOutput(wrap_untrusted("desktop", "\n".join(lines[:200])))

    def _tree(self, inp: dict, ctx: ToolContext) -> ToolOutput:
        win = self._window(inp["window"], ctx)
        depth = int(inp.get("depth", 3))
        lines: list[str] = []

        def walk(el, level):
            if len(lines) >= 400 or level > depth:
                return
            info = el.element_info
            value = ""
            try:
                if info.control_type in ("Edit", "Text"):
                    value = (el.window_text() or "")[:80]
            except Exception:
                pass
            lines.append(f"{'  ' * level}{info.control_type} name={info.name!r} automation_id={info.automation_id!r} enabled={info.enabled}" + (f" value={value!r}" if value else ""))
            for ch in el.children():
                walk(ch, level + 1)

        walk(win, 0)
        ctx.audit.event("uia_action", step=ctx.step_id, action="tree", window=inp["window"], lines=len(lines))
        return ToolOutput(wrap_untrusted(f"window:{inp['window']}", "\n".join(lines)))

    def _invoke(self, inp: dict, ctx: ToolContext) -> ToolOutput:
        win = self._window(inp["window"], ctx)
        ctl = self._control(win, inp)
        label = ctl.element_info.name or inp.get("name") or ""
        if RISKY.search(label):
            d = ctx.approver.request(ApprovalRequest(step_id=ctx.step_id, action_class="submit", summary=f"Desktop app wants to press '{label}' in '{inp['window']}'"))
            ctx.audit.event("approval", step=ctx.step_id, action_class="submit", label=label, approved=d.approved, by=d.by)
            if not d.approved:
                return ToolOutput(f"Error: '{label}' needs human approval and was not approved.", is_error=True)
            ctx.audit.event("outbound_action", step=ctx.step_id, tier="desktop_uia", label=label, approved=True, by=d.by)
        try:
            ctl.invoke()
        except Exception:
            ctl.click_input()
        ctx.audit.event("uia_action", step=ctx.step_id, action="invoke", window=inp["window"], control=label)
        return ToolOutput(f"invoked {label!r}. Read uia_tree to confirm the change.")

    def _set_text(self, inp: dict, ctx: ToolContext) -> ToolOutput:
        win = self._window(inp["window"], ctx)
        ctl = self._control(win, inp)
        ctl.set_edit_text(inp["text"])
        ctx.audit.event("uia_action", step=ctx.step_id, action="set_text", window=inp["window"], control=ctl.element_info.name, chars=len(inp["text"]))
        return ToolOutput("text set")

    def _get_text(self, inp: dict, ctx: ToolContext) -> ToolOutput:
        win = self._window(inp["window"], ctx)
        ctl = self._control(win, inp)
        text = ctl.window_text()
        try:
            text = ctl.get_value() or text
        except Exception:
            pass
        ctx.audit.event("uia_action", step=ctx.step_id, action="get_text", window=inp["window"], control=ctl.element_info.name)
        return ToolOutput(wrap_untrusted(f"window:{inp['window']}", str(text)))

    def tools(self) -> list[Tool]:
        s = {"type": "string"}
        target = {"window": {"type": "string", "description": "part of the window title"}, "automation_id": s, "name": s}
        return [
            Tool("uia_list_windows", "List top-level windows with their process.", schema({}), self._list, self.name),
            Tool("uia_tree", "Show a window's UI Automation tree (controls, names, automation ids).", schema({"window": s, "depth": {"type": "integer"}}, ["window"]), self._tree, self.name),
            Tool("uia_invoke", "Press/invoke a control by automation_id or name.", schema(target, ["window"]), self._invoke, self.name),
            Tool("uia_set_text", "Set the text of an edit control.", schema({**target, "text": s}, ["window", "text"]), self._set_text, self.name),
            Tool("uia_get_text", "Read a control's text or value.", schema(target, ["window"]), self._get_text, self.name),
        ]

    def handles(self, block: dict) -> bool:
        return block.get("name", "").startswith("uia_") and "toolset_name" not in block

    def execute(self, block: dict, ctx: ToolContext) -> ToolOutput:
        try:
            return super().execute(block, ctx)
        except (PolicyViolation, ValueError) as e:
            return ToolOutput(f"Error: {e}", is_error=True)
        except Exception as e:
            ctx.audit.event("uia_error", step=ctx.step_id, tool=block.get("name"), error=str(e)[:500])
            return ToolOutput(f"Error: {type(e).__name__}: {str(e)[:500]}", is_error=True)
