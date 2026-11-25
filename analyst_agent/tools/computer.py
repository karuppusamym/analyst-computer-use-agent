"""Tier 5 - desktop pixels: the Claude computer_toolset_20260801.

Last resort, for apps with no API and no accessibility tree. Runs on
Windows with ctypes only (see screen_win.py).

Safety, because there may be no VM: before every input action the
foreground window must be on the allowlist (app exe via the policy, or a
window-title pattern from settings). Anything else is refused and no input is
sent. `dry_run` logs actions without sending them.
"""

from __future__ import annotations

import fnmatch
import math
import sys
import time

from ..policy import PolicyViolation
from ..vault import has_placeholder, resolve_secrets
from . import screen_win as sw
from .base import Tier, ToolContext, ToolOutput

MEMBERS = (
    "screenshot", "zoom", "left_click", "right_click", "middle_click", "double_click", "triple_click",
    "left_click_drag", "mouse_move", "left_mouse_down", "left_mouse_up", "cursor_position",
    "scroll", "type", "key", "hold_key", "wait",
)
READ_ONLY = {"screenshot", "zoom", "cursor_position", "wait"}
MAX_TOKENS_IMG = 4784
PATCH = 28


def fits(w: int, h: int, max_long_edge: int) -> bool:
    return max(w, h) <= max_long_edge and math.ceil(w / PATCH) * math.ceil(h / PATCH) <= MAX_TOKENS_IMG


def scale_factor(w: int, h: int, max_long_edge: int = 2576) -> float:
    """Largest s <= 1 so the scaled screenshot fits the model's image limits."""
    s = min(1.0, max_long_edge / max(w, h), math.sqrt(MAX_TOKENS_IMG * PATCH * PATCH / (w * h)))
    while s > 0.05 and not fits(round(w * s), round(h * s), max_long_edge):
        s -= 0.002
    return s


def to_screen(coord, s: float, size: tuple[int, int]) -> tuple[int, int]:
    """Model coordinates (scaled space) -> physical screen pixels, clamped."""
    x, y = int(round(coord[0] / s)), int(round(coord[1] / s))
    return max(0, min(size[0] - 1, x)), max(0, min(size[1] - 1, y))


class ComputerTier(Tier):
    name = "desktop_pixels"
    rank = 5

    def __init__(self, settings):
        super().__init__(settings)
        self.cfg = settings["tiers"]["desktop_pixels"]
        self._held_mouse = False

    # ---- tier interface
    def available(self) -> tuple[bool, str]:
        if not self.cfg.get("enabled"):
            return False, "desktop_pixels tier is disabled in settings"
        if sys.platform != "win32":
            return False, "desktop_pixels tier needs Windows (ctypes backend)"
        return True, "ok"

    def api_tools(self) -> list[dict]:
        return [{"type": "computer_toolset_20260801"}]

    def tools(self):
        return []

    def handles(self, block: dict) -> bool:
        return block.get("toolset_name") == "computer"

    # ---- geometry
    def geometry(self) -> tuple[tuple[int, int], float]:
        size = sw.screen_size()
        return size, scale_factor(size[0], size[1], int(self.cfg.get("max_long_edge", 2576)))

    def screenshot_png(self) -> bytes:
        (w, h), s = self.geometry()
        png, _, _ = sw.capture(out_size=(round(w * s), round(h * s)))
        return png

    # ---- safety
    def _guard(self, ctx: ToolContext) -> tuple[bool, str, tuple[str, str]]:
        title, exe = sw.foreground_window()
        titles = self.cfg.get("allowed_window_titles", []) or []
        if any(fnmatch.fnmatch(title.lower(), pat.lower()) for pat in titles):
            return True, "", (title, exe)
        try:
            if exe:
                ctx.policy.check_app(exe)
                return True, "", (title, exe)
        except PolicyViolation:
            pass
        return False, f"Error: refused - foreground window '{title}' ({exe or 'unknown exe'}) is not on the allowlist", (title, exe)

    # ---- execution
    def execute(self, block: dict, ctx: ToolContext) -> ToolOutput:
        member = block.get("name", "")
        inp = block.get("input") or {}
        if member not in MEMBERS:
            return ToolOutput(f"Error: unknown computer action {member}", is_error=True)
        try:
            size, s = self.geometry()
            foreground = ("", "")
            if member not in READ_ONLY:
                ok, msg, foreground = self._guard(ctx)
                if not ok:
                    ctx.audit.event("computer_action_refused", member=member, input=inp, foreground=foreground, step=ctx.step_id)
                    return ToolOutput(msg, is_error=True)
            ctx.audit.event("computer_action", member=member, input=inp, foreground=foreground, step=ctx.step_id, dry_run=bool(self.cfg.get("dry_run")))
            if self.cfg.get("dry_run") and member not in READ_ONLY:
                return ToolOutput("OK (dry run - not executed)")
            return self._run(member, inp, ctx, size, s)
        except (OSError, ValueError) as e:
            return ToolOutput(f"Error: {e}", is_error=True)

    def _run(self, member: str, inp: dict, ctx: ToolContext, size, s: float) -> ToolOutput:
        pt = (lambda c: to_screen(c, s, size)) if s else None
        mods = sw.parse_modifiers(inp.get("text")) if member.endswith("click") or member in ("scroll", "left_click_drag") else []

        if member == "screenshot":
            png, w, h = sw.capture(out_size=(round(size[0] * s), round(size[1] * s)))
            ctx.audit.save_image(png, f"{ctx.step_id}-screenshot")
            return ToolOutput(images=[png])
        if member == "zoom":
            r = inp.get("region")
            if not r or len(r) != 4:
                return ToolOutput("Error: zoom needs region [x0, y0, x1, y1]", is_error=True)
            x0, y0 = to_screen(r[:2], s, size)
            x1, y1 = to_screen(r[2:], s, size)
            x1, y1 = max(x1, x0 + 1), max(y1, y0 + 1)
            rw, rh = x1 - x0, y1 - y0
            zs = scale_factor(rw, rh, int(self.cfg.get("max_long_edge", 2576)))
            png, _, _ = sw.capture((x0, y0, x1, y1), (max(1, round(rw * zs)), max(1, round(rh * zs))))
            ctx.audit.save_image(png, f"{ctx.step_id}-zoom")
            return ToolOutput(images=[png])
        if member == "cursor_position":
            x, y = sw.cursor_pos()
            return ToolOutput(f"X={round(x * s)}, Y={round(y * s)}")
        if member == "wait":
            time.sleep(max(0.0, min(300.0, float(inp.get("duration", 1)))))
            return ToolOutput("OK")

        coord = pt(inp["coordinate"]) if inp.get("coordinate") else (None, None)
        if member in ("left_click", "right_click", "middle_click", "double_click", "triple_click"):
            button = {"right_click": "right", "middle_click": "middle"}.get(member, "left")
            count = {"double_click": 2, "triple_click": 3}.get(member, 1)
            sw.click(coord[0], coord[1], button, count, mods)
        elif member == "left_click_drag":
            if not inp.get("start_coordinate") or not inp.get("coordinate"):
                return ToolOutput("Error: left_click_drag needs start_coordinate and coordinate", is_error=True)
            sw.drag(pt(inp["start_coordinate"]), coord, mods)
        elif member == "mouse_move":
            if coord[0] is None:
                return ToolOutput("Error: mouse_move needs coordinate", is_error=True)
            sw.move(*coord)
        elif member == "left_mouse_down":
            sw.mouse_button("left", down=True)
        elif member == "left_mouse_up":
            sw.mouse_button("left", down=False)
        elif member == "scroll":
            sw.scroll(coord[0], coord[1], inp.get("scroll_direction", "down"), int(inp.get("scroll_amount", 3)), mods)
        elif member == "type":
            text = inp.get("text", "")
            if has_placeholder(text):
                # The guard already checked the foreground window against the policy; the
                # secret must also allow this exe or title. Re-read it right before typing.
                ok, msg, (title, exe) = self._guard(ctx)
                if not ok:
                    return ToolOutput(msg, is_error=True)
                text = resolve_secrets(text, ctx, tool="computer.type", app=exe, window=title)
            sw.type_text(text)
        elif member == "key":
            sw.key_combo(inp["text"], int(inp.get("repeat", 1)))
        elif member == "hold_key":
            sw.hold(inp["text"], float(inp.get("duration", 1)))
        time.sleep(0.15)  # let the UI react before the next look
        return ToolOutput("OK")
