"""Human takeover: a resumable pause of one session's agent.

A PAUSE file in the session's audit folder (written by the portal, or by hand)
tells the orchestrator and the executor to stop before their next action and wait
until the file is removed ("hand back"). Unlike STOP, the run continues afterwards.

While paused, a person may drive the desktop through the portal. Every one of their
inputs goes through the same window allowlist guard as the agent and is written to
the session's audit log as `human_action` / `human_action_refused` with
actor="human:<user>". On hand-back the orchestrator turns those events into a short
note for the executor and makes it take a fresh screenshot before acting again.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

PAUSE_FILE = "PAUSE"
HUMAN_KINDS = ("human_action", "human_action_refused")


def pause_info(session_dir: str | Path) -> dict | None:
    """The PAUSE file's content ({"by", "at", ...}), {} for a hand-made file, None when not paused."""
    p = Path(session_dir) / PAUSE_FILE
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8") or "{}")
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_pause(session_dir: str | Path, by: str, **extra) -> dict:
    d = Path(session_dir)
    info = {"by": by, "at": time.time(), **extra}
    tmp = d / f".{PAUSE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(info), encoding="utf-8")
    os.replace(tmp, d / PAUSE_FILE)
    return info


def clear_pause(session_dir: str | Path) -> bool:
    try:
        (Path(session_dir) / PAUSE_FILE).unlink()
        return True
    except FileNotFoundError:
        return False


def _describe(e: dict) -> str:
    member = e.get("member", "?")
    inp = e.get("input") or {}
    if member == "type":
        what = f"typed {len(str(inp.get('text', '')))} characters"
    elif member == "key":
        what = f"pressed {inp.get('text', '')}"
    elif member == "left_click_drag":
        what = f"dragged from {inp.get('start_coordinate')} to {inp.get('coordinate')}"
    elif member == "scroll":
        what = f"scrolled {inp.get('scroll_direction', 'down')} at {inp.get('coordinate')}"
    else:
        what = f"{member} at {inp.get('coordinate')}"
    fg = e.get("foreground") or ["", ""]
    title = fg[0] if isinstance(fg, (list, tuple)) and fg else ""
    if e.get("kind") == "human_action_refused":
        return f"REFUSED {what} (window '{title}' is not on the allowlist)"
    return what + (f" in '{title}'" if title else "") + (" [dry run, not sent]" if e.get("dry_run") else "")


def human_note(events: list[dict], who: str = "") -> str:
    """The note the executor gets after a hand-back."""
    actions = [e for e in events if e.get("kind") in HUMAN_KINDS]
    names = sorted({str(e.get("actor", "")).removeprefix("human:") for e in actions if e.get("actor")} | ({who} if who else set()))
    by = ", ".join(n for n in names if n) or "a person"
    lines = [f"A human ({by}) took over this session while you were paused and has now handed it back."]
    if actions:
        shown = actions[-30:]
        lines.append(f"They did {len(actions)} desktop action(s)" + (f" (last {len(shown)} shown)" if len(shown) < len(actions) else "") + ":")
        lines += [f"- {_describe(e)}" for e in shown]
    else:
        lines.append("They did no desktop actions through the portal (they may have changed files or other state).")
    lines.append("The screen may have changed. Take a fresh screenshot before your next action, check what the human already did, and do not repeat it.")
    return "\n".join(lines)
