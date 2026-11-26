"""Portal side of human takeover: pause a running session, stream the screen, relay input.

Who may take over (needs the session to be visible to them and its run alive in this portal):
- admins, any session;
- reviewers, any session they can see;
- the session owner when they are an analyst, if `portal.takeover.owner_analysts` (default true).
Only the person holding the takeover can send input. They or an admin can hand back.

A hold with no live run behind it is "stale": its PAUSE file was left by an earlier portal
process (restart or crash) or the run ended while it was held. The portal records such holds
at start-up (portal_state/takeover-<session>.json, takeover_orphaned in the audit logs) and
shows them as held by X (from before restart). No input or screen is served for them; the
holder or an admin releases the hold (takeover_released), also as part of Resume.

Every input is a ComputerTier action: the same foreground-window allowlist guard and
dry_run as the agent. It is audited in the session's events.jsonl as human_action /
human_action_refused with actor="human:<user>". The screen is captured on demand, at
the agent's model scale reduced to `frame_max_width`, and is never saved to disk.
"""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..audit import append_event
from ..config import Settings
from ..policy import PolicyEngine, UnattendedApprover
from ..takeover import PAUSE_FILE as PAUSE_FILE_NAME, clear_pause, pause_info, write_pause
from ..tools import screen_win as sw
from ..tools.base import ToolContext
from ..vault import has_placeholder
from .auth import Identity

CLICKS = {"click": "left_click", "double_click": "double_click", "right_click": "right_click"}
ACTIONS = set(CLICKS) | {"type", "key", "scroll", "move", "drag"}
FORBIDDEN_KEYS = re.compile(r"(^|\+)\s*(win|super|meta|cmd|lwin|rwin)\s*(\+|$)", re.I)
# Chords that switch to another window or open a system screen: the window allowlist guard checks the
# window in front before the input, so these would hand the keyboard to a window nobody checked.
FORBIDDEN_CHORDS = ("alt+tab", "alt+shift+tab", "alt+escape", "ctrl+escape", "ctrl+shift+escape", "ctrl+alt+delete")
MAX_CHORD_KEYS = 4


def chord_key(combo: str) -> frozenset[int]:
    """The set of virtual keys of a combination, so 'Ctrl+C', 'control+c' and 'c+ctrl' compare equal."""
    return frozenset(sw.parse_combo(combo))


class TakeoverError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def scale_point(x: float, y: float, from_size: tuple[int, int], to_size: tuple[int, int]) -> tuple[int, int]:
    """A point in an image of from_size -> the same spot in to_size, clamped inside it."""
    fw, fh = max(1, from_size[0]), max(1, from_size[1])
    tx = int(round(float(x) * to_size[0] / fw))
    ty = int(round(float(y) * to_size[1] / fh))
    return max(0, min(to_size[0] - 1, tx)), max(0, min(to_size[1] - 1, ty))


def frame_size(model_size: tuple[int, int], max_width: int) -> tuple[int, int]:
    w, h = model_size
    f = min(1.0, max(64, int(max_width)) / max(1, w))
    return max(1, round(w * f)), max(1, round(h * f))


class HumanAudit:
    """Stands in for ctx.audit while a human drives the desktop: the tier's computer_action /
    computer_action_refused events go to the session log as human_action / human_action_refused."""

    redactor = None
    KINDS = {"computer_action": "human_action", "computer_action_refused": "human_action_refused"}

    def __init__(self, session_dir: Path, user: str, on_refused: Callable[..., None] | None = None):
        self.dir = Path(session_dir)
        self.user = user
        self.on_refused = on_refused or (lambda **k: None)

    def event(self, kind: str, /, **data: Any) -> dict:
        kind = self.KINDS.get(kind, kind)
        rec = append_event(self.dir, kind, self.user, actor=f"human:{self.user}", **data) or {}
        if kind == "human_action_refused":
            self.on_refused(session=self.dir.name, actor=f"human:{self.user}", member=data.get("member"), foreground=data.get("foreground"), reason=data.get("reason"))
        return rec

    def save_image(self, png: bytes, label: str = "screen") -> Path:  # not used for frames; kept for the tier interface
        p = self.dir / "screenshots" / f"human-{re.sub(r'[^a-z0-9_-]', '', label.lower())[:30]}.png"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(png)
        return p


class TakeoverManager:
    def __init__(self, settings: Settings, runs, audit, tier_factory: Callable[[Settings], Any] | None = None, capture: Callable[[tuple[int, int]], bytes] | None = None,
                 store=None, instance: str = ""):
        self.settings = settings
        self.store = store  # PendingStore: records holds left over from an earlier portal
        self.instance = instance
        self.cfg = dict(settings.data.get("portal", {}).get("takeover", {}) or {})
        self.runs = runs
        self.audit = audit
        self._tier_factory = tier_factory
        self._capture = capture or (lambda size: sw.capture(out_size=size)[0])
        self._tier = None
        self._lock = threading.Lock()

    # ---- configuration
    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def tier(self):
        if self._tier is None:
            if self._tier_factory:
                self._tier = self._tier_factory(self.settings)
            else:
                from ..tools.computer import ComputerTier

                self._tier = ComputerTier(self.settings)
        return self._tier

    def desktop(self) -> tuple[bool, str]:
        """Can the portal show the screen and send input? (The pause itself always works.)"""
        ok, why = self.tier().available()
        return ok, ("ok" if ok else f"remote control is unavailable: {why}")

    def sizes(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """(model_size, frame_size): the agent's screenshot space and the streamed frame's."""
        (w, h), s = self.tier().geometry()
        model = (round(w * s), round(h * s))
        return model, frame_size(model, int(self.cfg.get("frame_max_width", 1280)))

    # ---- state
    def session_dir(self, sid: str) -> Path:
        return self.settings.audit_dir / sid

    def active(self, sid: str) -> dict | None:
        return pause_info(self.session_dir(sid))

    def may_take_over(self, ident: Identity, sid: str) -> tuple[bool, str]:
        """Role rule only; the caller has already checked the session is visible to ident."""
        if not self.enabled:
            return False, "human takeover is turned off (portal.takeover.enabled)"
        if ident.can("reviewer"):
            return True, ""
        if self.runs.owner(sid) == ident.name and self.cfg.get("owner_analysts", True):
            return True, ""
        return False, "only reviewers, admins and the session owner can take over"

    def controls(self, ident: Identity, sid: str) -> bool:
        info = self.active(sid)
        return bool(info) and info.get("by") == ident.name

    def stale(self, sid: str) -> dict | None:
        """The PAUSE info of a hold with no live run in this portal (else None), plus from_restart."""
        info = self.active(sid)
        if info is None:
            return None
        run = self.runs.runs.get(sid)
        if run is not None and run.alive:
            return None
        return {**info, "from_restart": info.get("portal_instance") != self.instance}

    def may_release(self, ident: Identity, sid: str) -> bool:
        info = self.active(sid)
        return info is not None and ((bool(info.get("by")) and info.get("by") == ident.name) or ident.can("admin"))

    def detect_stale(self) -> list[str]:
        """At portal start: every PAUSE file belongs to a run thread that no longer exists.
        Record who held it (once per hold) and audit it as takeover_orphaned."""
        root = self.settings.audit_dir
        found: list[str] = []
        if not root.exists():
            return found
        for d in sorted(root.iterdir()):
            if not d.is_dir() or not (d / PAUSE_FILE_NAME).exists():
                continue
            sid = d.name
            run = self.runs.runs.get(sid)
            if run is not None and run.alive:
                continue
            info = pause_info(d) or {}
            found.append(sid)
            if self.store is not None:
                rec = self.store.get("takeover", sid)
                if rec and rec.get("status") == "held" and rec.get("at") == info.get("at"):
                    continue  # recorded by an earlier start already
                try:
                    self.store.put("takeover", sid, {"session_id": sid, "by": info.get("by"), "role": info.get("role"), "at": info.get("at"), "hand_made": not info.get("by"),
                                                     "portal_instance": info.get("portal_instance"), "detected_at": time.time()}, "held")
                except OSError:
                    pass  # the PAUSE file itself still holds the session; only the record is missing
            data = dict(held_by=info.get("by"), held_since=info.get("at"), role=info.get("role"), hand_made=not info.get("by"), note="the run thread is gone (the portal restarted); the hold stays until the holder or an admin releases it")
            append_event(d, "takeover_orphaned", "portal", by="portal-restart", **data)
            self.audit.event("takeover_orphaned", session=sid, by="portal-restart", **data)
        return found

    def release(self, ident: Identity, sid: str, reason: str = "released") -> dict:
        """End a stale hold (no live run). Only the holder or an admin. Audited as takeover_released."""
        with self._lock:
            info = self.stale(sid)
            if info is None:
                if self.active(sid) is None:
                    raise TakeoverError("this session is not taken over")
                raise TakeoverError("the run is still alive; hand back instead")
            if not self.may_release(ident, sid):
                who = info.get("by")
                raise TakeoverError(f"only {who} (who holds it) or an admin can release this hold" if who else "only an admin can release a hand-made PAUSE file", 403)
            data = dict(by=ident.name, role=ident.role, held_by=info.get("by"), held_since=info.get("at"), from_restart=info["from_restart"], reason=reason)
            append_event(self.session_dir(sid), "takeover_released", ident.name, actor=f"human:{ident.name}", **data)
            clear_pause(self.session_dir(sid))
        if self.store is not None and (self.store.get("takeover", sid) or {}).get("status") == "held":
            try:
                self.store.close("takeover", sid, "released", ident.name, reason)
            except OSError:
                pass
        self.audit.event("takeover_released", session=sid, **data)
        return info

    def _live_hold(self, sid: str) -> None:
        info = self.stale(sid)
        if info is not None:
            when = " from before the portal restarted" if info["from_restart"] else ""
            raise TakeoverError(f"this hold is{when} and the run is no longer running here, so there is no screen or input; release the hold (and resume)", 409)

    # ---- start / end
    def start(self, ident: Identity, sid: str) -> dict:
        ok, why = self.may_take_over(ident, sid)
        if not ok:
            raise TakeoverError(why, 403)
        with self._lock:
            run = self.runs.runs.get(sid)
            if not run or not run.alive:
                raise TakeoverError("this session is not running in this portal, so there is no agent to pause")
            d = self.session_dir(sid)
            if (d / "STOP").exists():
                raise TakeoverError("the kill switch was pressed for this session")
            cur = self.active(sid)
            if cur is not None:
                raise TakeoverError(f"{cur.get('by') or 'someone'} has already taken over this session")
            d.mkdir(parents=True, exist_ok=True)
            info = write_pause(d, ident.name, role=ident.role, portal_instance=self.instance)
        append_event(d, "takeover_started", ident.name, by=ident.name, role=ident.role, actor=f"human:{ident.name}", dry_run=bool(self.settings["tiers"]["desktop_pixels"].get("dry_run")))
        self.audit.event("takeover_started", session=sid, by=ident.name, role=ident.role)
        return info

    def end(self, ident: Identity, sid: str) -> None:
        if self.stale(sid) is not None:
            self.release(ident, sid, "hand back")  # no run waits for a hand-back: release the hold
            return
        with self._lock:
            cur = self.active(sid)
            if cur is None:
                raise TakeoverError("this session is not taken over")
            if cur.get("by") != ident.name and not ident.can("admin"):
                raise TakeoverError("only the person who took over (or an admin) can hand back", 403)
            # Log first: the run thread reads these events as soon as PAUSE is gone.
            append_event(self.session_dir(sid), "takeover_ended", ident.name, by=ident.name, held_by=cur.get("by"), actor=f"human:{ident.name}")
            clear_pause(self.session_dir(sid))
        self.audit.event("takeover_ended", session=sid, by=ident.name, held_by=cur.get("by"))

    # ---- screen and input
    def frame(self, ident: Identity, sid: str) -> bytes:
        if not (self.controls(ident, sid) or (ident.can("admin") and self.active(sid) is not None)):
            raise TakeoverError("the screen is streamed only to the person holding the takeover (and admins)", 403)
        self._live_hold(sid)
        ok, why = self.desktop()
        if not ok:
            raise TakeoverError(why, 503)
        _, fsize = self.sizes()
        return self._capture(fsize)

    def _refuse(self, hud: HumanAudit, member: str, inp: dict, reason: str) -> tuple[bool, str]:
        hud.event("human_action_refused", member=member, input=inp, reason=reason, step="takeover")
        return False, f"refused: {reason}"

    def human_input(self, ident: Identity, sid: str, form: dict[str, str]) -> tuple[bool, str]:
        """One input from the person holding the takeover. Returns (sent_ok, message)."""
        if not self.controls(ident, sid):
            raise TakeoverError("take over this session first; only the person holding it can send input", 403)
        self._live_hold(sid)
        ok, why = self.desktop()
        if not ok:
            raise TakeoverError(why, 503)
        action = form.get("action", "")
        if action not in ACTIONS:
            raise TakeoverError(f"unknown action {action!r}", 400)
        hud = HumanAudit(self.session_dir(sid), ident.name, on_refused=lambda **k: self.audit.event("human_action_refused", **k))
        inp: dict[str, Any] = {}
        member = CLICKS.get(action, {"move": "mouse_move", "drag": "left_click_drag"}.get(action, action))
        if action in CLICKS or action in ("scroll", "move", "drag"):
            try:
                x, y = float(form.get("x", "")), float(form.get("y", ""))
            except ValueError:
                raise TakeoverError("x and y must be numbers", 400) from None
            model, fsize = self.sizes()
            inp["coordinate"] = list(scale_point(x, y, fsize, model))
        if action == "drag":
            # Mouse down at (x, y), move, mouse up at (x2, y2): one action, one guard check, one audit event.
            try:
                x2, y2 = float(form.get("x2", "")), float(form.get("y2", ""))
            except ValueError:
                raise TakeoverError("a drag needs x, y (start) and x2, y2 (end) as numbers", 400) from None
            inp["start_coordinate"] = inp.pop("coordinate")
            inp["coordinate"] = list(scale_point(x2, y2, fsize, model))
        if action == "scroll":
            direction = form.get("direction", "down")
            if direction not in ("up", "down", "left", "right"):
                raise TakeoverError("direction must be up, down, left or right", 400)
            inp["scroll_direction"] = direction
            inp["scroll_amount"] = max(1, min(10, int(form.get("amount", "3") or 3)))
        if action == "type":
            text = form.get("text", "")
            if not text:
                raise TakeoverError("nothing to type", 400)
            if len(text) > int(self.cfg.get("max_text", 2000)):
                raise TakeoverError("text is too long", 400)
            if has_placeholder(text):
                return self._refuse(hud, member, {"text_length": len(text)}, "vault placeholders cannot be typed by a person; the agent resolves secrets itself")
            inp["text"] = text
        if action == "key":
            combo = form.get("text", "").strip()
            if FORBIDDEN_KEYS.search(combo):
                return self._refuse(hud, member, {"text": combo}, "Windows-key combinations are not allowed during a takeover")
            try:
                keys = chord_key(combo)
                denied = {chord_key(c): c for c in (*FORBIDDEN_CHORDS, *(self.cfg.get("forbidden_keys") or []))}
            except ValueError as e:
                raise TakeoverError(str(e), 400) from None
            if len(keys) > MAX_CHORD_KEYS:
                raise TakeoverError(f"at most {MAX_CHORD_KEYS} keys at once", 400)
            if keys in denied:
                return self._refuse(hud, member, {"text": combo}, f"{denied[keys]} switches windows or opens a system screen, so it is not allowed during a takeover")
            inp["text"] = combo
            inp["repeat"] = max(1, min(20, int(form.get("repeat", "1") or 1)))
        if (action in CLICKS or action == "drag") and form.get("modifiers"):
            inp["text"] = form["modifiers"]  # e.g. "shift" or "ctrl+shift", as for the agent
        perms = None
        pb_name = self.runs.playbook_of(sid) if hasattr(self.runs, "playbook_of") else None
        if pb_name:
            pb = next((p for p in self.runs.runnable_playbooks() if p.name == pb_name), None)
            perms = pb.permissions if pb else None
        ctx = ToolContext(self.settings, PolicyEngine(self.settings, perms), hud, UnattendedApprover(), step_id="takeover", workdir=self.session_dir(sid) / "scratch")
        out = self.tier().execute({"type": "tool_use", "id": "human", "name": member, "toolset_name": "computer", "input": inp}, ctx)
        return (not out.is_error), (out.text or "OK")
