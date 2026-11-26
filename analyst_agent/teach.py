"""Teach mode: turn demonstrated work into DRAFT playbooks a person reviews and promotes.

  teach from-session <session> --name N   learn from a finished session's audit log
  teach record --name N --url URL         record a person's browser actions (Playwright, optional)
  teach drafts                            list drafts
  teach promote N [--reviewer X]          validate a draft and move it into playbooks/

Drafts live in playbooks/drafts/ with "status": "draft". PlaybookRegistry never
matches or runs them until they are promoted. Recorded password fields are stored
only as a {{secret:<field>}} placeholder; the value never reaches Python.
The recorder follows every tab of the browser context (popups included): steps
carry the tab through `expect_popup` on the click that opened it,
`browser_switch_tab` and `browser_close_tab` steps. Tabs are matched at replay
by a stable URL (`url_contains`: host + path, volatile query values dropped),
with the open-order index only as a fallback. Downloads become browser_download
steps; file uploads become browser_upload steps with a `{<field>_path}`
parameter, or a `{<field>_paths}` list parameter for several files (only file
names are seen, never the content). Actions inside iframes carry the frame
chain (name, iframe CSS, URL) and replay inside that frame.
"""

from __future__ import annotations

import copy
import getpass
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urldefrag, urljoin, urlparse

from .config import Settings
from .playbook import TIERS, PlaybookError, PlaybookRegistry, playbook_from_dict
from .policy import PolicyEngine, PolicyViolation
from .tools.browser import stable_url


class TeachError(RuntimeError):
    pass


class TeachUnavailable(TeachError):
    """An optional dependency (Playwright + Chromium) is missing."""


NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}")
NO_CHECK_INTERMEDIATE = "intermediate recorded action; the outcome is checked by a later step"

# Tool calls that only read or look; they are not replayed.
READ_ONLY_TOOLS = {
    "browser_snapshot", "browser_screenshot", "list_files", "read_file",
    "uia_list_windows", "uia_tree", "uia_get_text",
    "screenshot", "zoom", "cursor_position", "wait",
}
CONNECTOR_ACTIONS = {"copy_file", "sql_query", "draft_email"}
BROWSER_REF_TOOLS = {"browser_click", "browser_fill", "browser_select", "browser_download", "browser_upload"}
UIA_ACTIONS = {"uia_invoke", "uia_set_text"}
_NO_PARAM_KEYS = {"id", "tier", "kind", "tool", "type", "mode", "approval", "action_class", "role"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME", "unknown")


def _check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name or ""):
        raise TeachError(f"invalid playbook name {name!r}: use letters, digits, '-', '_' or '.'")
    return name


def _slug(text: str, fallback: str = "field") -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")[:40]
    return s or fallback


# --------------------------------------------------------------------------- parameters


def _value_regex(value: str) -> re.Pattern:
    # Digits only need to be apart from other digits ("wk47" -> "wk{week}"); letters from letters and digits.
    left = r"(?<!\d)" if value[0].isdigit() else r"(?<![A-Za-z0-9])" if value[0].isalpha() else ""
    right = r"(?!\d)(?!-\d)" if value[-1].isdigit() else r"(?![A-Za-z0-9])" if value[-1].isalpha() else ""
    return re.compile(left + re.escape(value) + right)


def _walk_strings(obj: Any, key: str = ""):
    if isinstance(obj, str):
        if key not in _NO_PARAM_KEYS:
            yield obj
    elif isinstance(obj, list):
        for x in obj:
            yield from _walk_strings(x, key)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, k)


def parameterize(obj: Any, values: dict[str, str], key: str = "") -> Any:
    """Replace literal parameter values with {name} placeholders (longest value first)."""
    if isinstance(obj, str):
        if key in _NO_PARAM_KEYS:
            return obj
        for name, value in sorted(values.items(), key=lambda kv: -len(kv[1])):
            obj = _value_regex(value).sub("{" + name + "}", obj)
        return obj
    if isinstance(obj, list):
        return [parameterize(x, values, key) for x in obj]
    if isinstance(obj, dict):
        return {k: parameterize(v, values, k) for k, v in obj.items()}
    return obj


_REQUEST_PATTERNS = [
    ("date", re.compile(r"\b\d{4}-\d{2}-\d{2}\b")),
    ("period", re.compile(r"\b\d{4}-(?:0[1-9]|1[0-2])\b(?!-\d)")),
    ("quarter", re.compile(r"\b(?:Q[1-4][ -]?\d{4}|\d{4}[ -]?Q[1-4])\b", re.I)),
    ("recipient", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")),
    ("week", re.compile(r"(?<=\bweek )\d{1,2}\b", re.I)),
]


def infer_parameters(request: str, known: dict[str, Any], defaults: dict[str, Any], strings: list[str]) -> tuple[dict[str, str], dict[str, dict]]:
    """Pick the values worth turning into parameters.

    known: explicit run parameters (always kept if they appear in the steps).
    defaults: source-playbook defaults (kept, as defaults, if they appear).
    request tokens (dates, periods, quarters, emails, week numbers) are kept when
    they repeat in the steps.
    Returns ({name: literal value}, {name: parameter spec}).
    """
    blob = "\n".join(strings)

    def appears(v: str) -> bool:
        return bool(v) and bool(_value_regex(v).search(blob))

    values: dict[str, str] = {}
    specs: dict[str, dict] = {}
    taken: set[str] = set()

    def add(name: str, value: str, spec: dict) -> None:
        if value in taken or name in values:
            return
        if len(value) < 2 or (value.isdigit() and len(value) < 2):
            return
        if not appears(value):
            return
        values[name] = value
        specs[name] = spec
        taken.add(value)

    for k, v in known.items():
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            add(k, str(v), {"type": "string", "required": True, "example": str(v)})
    for k, v in defaults.items():
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            add(k, str(v), {"type": "string", "default": str(v)})
    for base, pat in _REQUEST_PATTERNS:
        for m in pat.finditer(request or ""):
            v = m.group(0)
            if v in taken:
                continue
            name, n = base, 2
            while name in values:
                name, n = f"{base}_{n}", n + 1
            add(name, v, {"type": "string", "required": True, "example": v, "description": f"inferred from the request ('{v}')"})
    return values, specs


# --------------------------------------------------------------------------- from-session


_SNAP_LINE = re.compile(r"\[(e\d+)\] ([a-z0-9]+)(?:/([\w-]+))? (['\"])(.*?)\4")


def _parse_snapshot(text: str) -> dict[str, dict]:
    out = {}
    for m in _SNAP_LINE.finditer(text or ""):
        out[m.group(1)] = {"tag": m.group(2), "type": (m.group(3) or "").lower(), "name": m.group(5)}
    return out


def _role_for(tag: str, typ: str) -> str:
    if typ in ("button", "link", "checkbox", "radio", "combobox", "textbox", "tab", "menuitem"):
        return typ
    if tag == "a":
        return "link"
    if tag == "button" or (tag == "input" and typ in ("submit", "button", "reset", "image")):
        return "button"
    if tag == "select":
        return "combobox"
    if tag == "textarea" or (tag == "input" and typ in ("", "text", "email", "search", "tel", "url")):
        return "textbox"
    return ""


def _targets_from_snapshot(el: dict) -> list[dict]:
    targets = []
    role = _role_for(el["tag"], el["type"])
    if role and el["name"]:
        targets.append({"role": role, "name": el["name"]})
    if el["tag"] in ("input", "select", "textarea") and el["name"]:
        targets.append({"label": el["name"]})
    if el["name"]:
        targets.append({"text": el["name"]})
    return targets


def _load_events(settings: Settings, session_id: str) -> list[dict]:
    path = settings.audit_dir / session_id / "events.jsonl"
    if not path.exists():
        raise TeachError(f"no audit log for session {session_id} at {path}")
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _convert_action(call: dict, snapshot: dict[str, dict]) -> dict | None:
    """One successful tool call -> {"tier", "script", "intent"}; None if it can't be replayed without the model."""
    name, inp = call.get("tool") or "", dict(call.get("input") or {})
    if name == "run_python" and inp.get("code"):
        return {"tier": "code", "script": {"kind": "python", "code": inp["code"]}, "intent": "Run the recorded Python step"}
    if name in CONNECTOR_ACTIONS:
        return {"tier": "connector", "script": {"kind": "tool", "tool": name, "input": inp}, "intent": f"Run {name}"}
    if name in UIA_ACTIONS:
        what = inp.get("name") or inp.get("automation_id") or "control"
        return {"tier": "desktop_uia", "script": {"kind": "tool", "tool": name, "input": inp}, "intent": f"{'Press' if name == 'uia_invoke' else 'Set text of'} '{what}' in '{inp.get('window', '')}'"}
    if name == "browser_goto" and inp.get("url"):
        return {"tier": "browser", "script": {"kind": "tool", "tool": "browser_goto", "input": {"url": inp["url"]}}, "intent": f"Open {inp['url']}"}
    if name in ("browser_switch_tab", "browser_close_tab") and (inp.get("tab") is not None or inp.get("url_contains")):
        keep = {k: inp[k] for k in ("url_contains", "tab", "new_tab", "wait_s") if k in inp}
        verb = "Switch to" if name == "browser_switch_tab" else "Close"
        return {"tier": "browser", "script": {"kind": "tool", "tool": name, "input": keep}, "intent": f"{verb} tab {inp.get('url_contains') or inp.get('tab')}"}
    if name in BROWSER_REF_TOOLS:
        el = snapshot.get(inp.get("ref", ""))
        if not el or not el["name"]:
            return None
        new = {"targets": _targets_from_snapshot(el)}
        if name == "browser_fill":
            new["text"] = "{{secret:" + _slug(el["name"]) + "}}" if el["type"] == "password" or "password" in el["name"].lower() else inp.get("text", "")
        if name == "browser_select":
            new["value"] = inp.get("value", "")
        if name == "browser_upload":
            if inp.get("paths"):
                new["paths"] = inp["paths"]
            else:
                new["path"] = inp.get("path", "")
        if name == "browser_click" and inp.get("expect_popup"):
            new["expect_popup"] = True
        verb = {"browser_click": "Click", "browser_fill": "Fill", "browser_select": "Select in", "browser_download": "Download via", "browser_upload": "Upload a file into"}[name]
        return {"tier": "browser", "script": {"kind": "tool", "tool": name, "input": new}, "intent": f"{verb} '{el['name']}'"}
    return None


def _hint(call: dict, foreground: str = "") -> str:
    name, inp = call.get("tool"), call.get("input") or {}
    where = f" in window '{foreground}'" if foreground else ""
    if "coordinate" in inp:
        return f"{name} at {inp['coordinate']}{where}"
    if "text" in inp and name not in ("browser_fill",):
        return f"{name} {json.dumps(inp.get('text'))[:80]}{where}"
    return f"{name} {json.dumps(inp)[:160]}{where}"


def draft_from_session(settings: Settings, session_id: str, name: str, playbooks_dir: str | Path, created_by: str | None = None, force: bool = False) -> tuple[Path, dict]:
    """Build a draft playbook from the verified steps of a finished session."""
    _check_name(name)
    events = _load_events(settings, session_id)
    started = next((e for e in events if e["kind"] == "task_started"), None)
    finished = next((e for e in reversed(events) if e["kind"] == "task_finished"), None)
    if started is None:
        raise TeachError(f"session {session_id} has no task_started event")
    if finished is None:
        raise TeachError(f"session {session_id} has not finished; teach from a finished session")

    step_defs: dict[str, dict] = {}
    order: list[str] = []
    final_checks: list[dict] = []
    verdicts: dict[str, int] = {}  # step -> verdicts seen so far
    passed_attempt: dict[str, int] = {}
    scripted: set[tuple[str, int]] = set()
    calls: dict[tuple[str, int], list[dict]] = {}
    foreground: dict[tuple[str, int], list[str]] = {}
    snapshots: dict[tuple[str, int], list[tuple[int, dict]]] = {}
    rejected: dict[str, str] = {}

    for e in events:
        k = e["kind"]
        if k in ("plan", "replanned"):
            for st in e.get("steps") or []:
                step_defs[st["id"]] = st
                if st["id"] not in order:
                    order.append(st["id"])
            if k == "plan" and e.get("final_checks"):
                final_checks = e["final_checks"]
            continue
        sid = e.get("step")
        if not sid:
            continue
        attempt = verdicts.get(sid, 0) + 1
        if k == "scripted_step":
            scripted.add((sid, attempt))
        elif k == "tool_call":
            calls.setdefault((sid, attempt), []).append(e)
            if e.get("tool") == "browser_snapshot" and not e.get("is_error"):
                snapshots.setdefault((sid, attempt), []).append((len(calls[(sid, attempt)]), _parse_snapshot(e.get("output", ""))))
        elif k == "computer_action":
            title = (e.get("foreground") or ["", ""])[0]
            foreground.setdefault((sid, attempt), []).append(title)
        elif k == "step_verdict":
            verdicts[sid] = attempt
            if e.get("passed"):
                passed_attempt[sid] = attempt
        elif k == "step_rejected":
            rejected[sid] = "approval was declined"
        elif k == "step_blocked":
            rejected[sid] = "blocked: " + str(e.get("reason", ""))[:200]

    source_pb = None
    if started.get("playbook"):
        try:
            source_pb = PlaybookRegistry(playbooks_dir).get(started["playbook"])
        except (PlaybookError, OSError, ValueError):
            source_pb = None

    steps: list[dict] = []
    skipped: list[dict] = []
    hosts: set[str] = set()
    apps: set[str] = set()
    for sid in order:
        base = copy.deepcopy(step_defs[sid])
        if sid not in passed_attempt:
            skipped.append({"id": sid, "reason": rejected.get(sid, "not verified in this session")})
            continue
        att = passed_attempt[sid]
        keep = {k: base[k] for k in ("id", "intent", "tier", "instructions", "target", "checks", "approval", "action_class", "no_check_reason") if base.get(k) not in (None, "", [], {})}
        if (sid, att) in scripted and base.get("script"):
            keep["script"] = base["script"]
            keep["learned_from"] = "scripted replay"
            steps.append(keep)
            continue
        bucket = [c for c in calls.get((sid, att), []) if not c.get("is_error")]
        snaps = snapshots.get((sid, att), [])
        actions, converted, ok = [], [], True
        for idx, c in enumerate(calls.get((sid, att), []), start=1):
            if c.get("is_error") or (c.get("tool") or "") in READ_ONLY_TOOLS:
                continue
            actions.append(c)
            snap = {}
            for pos, sn in snaps:
                if pos < idx:
                    snap = sn
            conv = _convert_action(c, snap)
            if conv is None:
                ok = False
            else:
                converted.append(conv)
            if c.get("tool") == "browser_goto":
                hosts.add((urlparse(c["input"].get("url", "")).hostname or "").lower())
        for t in foreground.get((sid, att), []):
            apps.add(t)
        if actions and ok:
            keep["learned_from"] = "guided run (tool calls)"
            if len(converted) == 1:
                keep.update(tier=converted[0]["tier"], script=converted[0]["script"])
                steps.append(keep)
                continue
            for n, conv in enumerate(converted, start=1):
                sub = {"id": f"{sid}-{n}", "intent": conv["intent"] if n < len(converted) else keep.get("intent", conv["intent"]), "tier": conv["tier"], "script": conv["script"], "learned_from": f"guided run of {sid}, action {n}/{len(converted)}"}
                if n == 1 and keep.get("approval") == "required":
                    sub["approval"] = "required"
                    if keep.get("action_class"):
                        sub["action_class"] = keep["action_class"]
                if n == len(converted):
                    if keep.get("checks"):
                        sub["checks"] = keep["checks"]
                    elif keep.get("no_check_reason"):
                        sub["no_check_reason"] = keep["no_check_reason"]
                else:
                    sub["no_check_reason"] = NO_CHECK_INTERMEDIATE
                steps.append(sub)
            continue
        # Not fully replayable (pixel actions, unknown refs, or read-only work): guided, with hints.
        fg = foreground.get((sid, att), [])
        hints = [_hint(c, fg[i] if i < len(fg) else "") for i, c in enumerate(actions or bucket)]
        keep.pop("script", None)
        keep["learned_from"] = "guided run (needs the model to replay)"
        if hints:
            keep["recorded_actions"] = hints
            keep["instructions"] = (keep.get("instructions", "") + "\nIn the taught session these actions worked (hints, not coordinates to trust): " + "; ".join(hints))[:4000].strip()
        steps.append(keep)

    if not steps:
        raise TeachError(f"session {session_id} has no verified steps to learn from")

    known = dict(started.get("params") or {})
    defaults = {k: spec["default"] for k, spec in (source_pb.parameters if source_pb else {}).items() if "default" in spec}
    request = started.get("request", "")
    strings = list(_walk_strings(steps)) + list(_walk_strings(final_checks))
    values, specs = infer_parameters(request, known, defaults, strings)
    if source_pb:
        for k, spec in source_pb.parameters.items():
            if k in specs:
                specs[k] = {**spec, **({"example": specs[k]["example"]} if "example" in specs[k] else {})}
    steps = parameterize(steps, values)
    final_checks = parameterize(final_checks, values)

    who = created_by or _user()
    permissions = copy.deepcopy(source_pb.permissions) if source_pb else {"data_class": "internal"}
    hosts.discard("")
    if hosts and not source_pb:
        permissions["hosts"] = sorted(hosts)
    data = {
        "name": name,
        "version": 0,
        "status": "draft",
        "owner": (source_pb.owner if source_pb and source_pb.owner else who),
        "backup_owner": source_pb.backup_owner if source_pb else "",
        "approver": source_pb.approver if source_pb else "",
        "workflow": source_pb.workflow if source_pb else request,
        "description": f"DRAFT learned from session {session_id}: {request}"[:500],
        "permissions": permissions,
        "parameters": specs,
        "steps": steps,
        "final_checks": final_checks,
        "provenance": {
            "method": "from-session",
            "source_session": session_id,
            "source_playbook": started.get("playbook"),
            "source_status": finished.get("status"),
            "request": request,
            "created_at": _now_iso(),
            "created_by": who,
            "inferred_parameters": values,
            "skipped_steps": skipped,
            **({"windows_seen": sorted(a for a in apps if a)} if apps else {}),
        },
    }
    return write_draft(playbooks_dir, data, force=force), data


def write_draft(playbooks_dir: str | Path, data: dict, force: bool = False) -> Path:
    folder = Path(playbooks_dir) / "drafts"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{_check_name(data['name'])}.json"
    if path.exists() and not force:
        raise TeachError(f"draft {path} already exists (use --force to overwrite)")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


# --------------------------------------------------------------------------- recorder

RECORDER_JS = r"""
(() => {
  // Guard per document, not per window: a window.open popup keeps its initial about:blank
  // Window object for the same-origin page it loads, but the document (and its listeners) is new.
  if (document.__agentTeachInstalled) return;
  document.__agentTeachInstalled = true;
  // CSS of each iframe element from the top page down to this frame ('' where cross-origin hides it).
  const frameCss = () => {
    const out = [];
    try {
      let w = window;
      while (w !== w.top && out.length < 6) { const fe = w.frameElement; out.unshift(fe ? cssOf(fe) : ''); w = w.parent; }
    } catch (e) { return []; }
    return out;
  };
  const send = (ev) => { try { ev.t = Date.now(); if (window !== window.top) ev.frame_css = frameCss(); window.__agentTeachRecord(ev); } catch (e) {} };
  const txt = (s) => (s || '').replace(/\s+/g, ' ').trim().slice(0, 120);
  const typeOf = (el) => (el.getAttribute && (el.getAttribute('type') || '') || '').toLowerCase();
  const isSecret = (el) => typeOf(el) === 'password' || /password|passcode|pin|secret/i.test(el.getAttribute('autocomplete') || '');
  const implicitRole = (el) => {
    const tag = el.tagName.toLowerCase(), type = typeOf(el);
    if (el.getAttribute('role')) return el.getAttribute('role');
    if (tag === 'a' && el.hasAttribute('href')) return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'input') {
      if (['submit', 'button', 'reset', 'image'].includes(type)) return 'button';
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      if (type === 'number') return 'spinbutton';
      if (type === 'search') return 'searchbox';
      if (['', 'text', 'email', 'tel', 'url'].includes(type)) return 'textbox';
      return '';
    }
    if (tag === 'textarea') return 'textbox';
    if (tag === 'select') return (el.multiple || el.size > 1) ? 'listbox' : 'combobox';
    return '';
  };
  const labelOf = (el) => {
    if (el.labels && el.labels.length) return txt(el.labels[0].innerText);
    const by = el.getAttribute('aria-labelledby');
    if (by) { const l = document.getElementById(by.split(' ')[0]); if (l) return txt(l.innerText); }
    return '';
  };
  const nameOf = (el) => {
    const isField = ['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName);
    const own = isField ? (['submit', 'button', 'reset'].includes(typeOf(el)) ? txt(el.value) : '') : txt(el.innerText);
    return txt(el.getAttribute('aria-label')) || labelOf(el) || own || txt(el.getAttribute('alt')) || txt(el.getAttribute('title')) || txt(el.getAttribute('placeholder'));
  };
  const cssOf = (el) => {
    const doc = el.ownerDocument || document;  // an iframe element lives in its parent's document
    if (el.id && doc.querySelectorAll('#' + CSS.escape(el.id)).length === 1) return '#' + CSS.escape(el.id);
    const nm = el.getAttribute('name');
    if (nm) {
      const s = el.tagName.toLowerCase() + '[name="' + nm.replace(/"/g, '\\"') + '"]';
      if (doc.querySelectorAll(s).length === 1) return s;
    }
    const parts = [];
    let e = el;
    while (e && e.nodeType === 1 && e !== doc.body && parts.length < 6) {
      if (e.id) { parts.unshift('#' + CSS.escape(e.id)); break; }
      let s = e.tagName.toLowerCase();
      const sib = e.parentElement ? Array.from(e.parentElement.children).filter(x => x.tagName === e.tagName) : [];
      if (sib.length > 1) s += ':nth-of-type(' + (sib.indexOf(e) + 1) + ')';
      parts.unshift(s);
      e = e.parentElement;
    }
    return parts.join(' > ');
  };
  const describe = (el) => {
    const role = implicitRole(el), name = nameOf(el), label = labelOf(el);
    const targets = [];
    if (role && name) targets.push({role, name});
    if (label) targets.push({label});
    const tid = el.getAttribute('data-testid');
    if (tid) targets.push({testid: tid});
    for (const a of ['data-test-id', 'data-test', 'data-qa']) {
      const v = el.getAttribute(a);
      if (v) targets.push({css: '[' + a + '="' + v.replace(/"/g, '\\"') + '"]'});
    }
    targets.push({css: cssOf(el)});
    return {tag: el.tagName.toLowerCase(), role, name, label, input_type: typeOf(el),
            field: el.getAttribute('name') || el.id || label || name || '', secret: isSecret(el), targets};
  };
  const isText = (el) => el && (el.tagName === 'TEXTAREA' || (el.tagName === 'INPUT' &&
      !['checkbox', 'radio', 'submit', 'button', 'reset', 'image', 'file', 'hidden', 'range', 'color'].includes(typeOf(el))));
  const lastSent = new WeakMap();
  const dirty = new Set();
  const flush = (el) => {
    if (!dirty.has(el)) return;
    dirty.delete(el);
    const d = describe(el);
    if (d.secret) { send(Object.assign({type: 'fill', masked: true}, d)); return; }  // never the value
    if (lastSent.get(el) === el.value) return;
    lastSent.set(el, el.value);
    send(Object.assign({type: 'fill', value: el.value}, d));
  };
  const flushAll = () => Array.from(dirty).forEach(flush);
  window.__agentTeachFlush = flushAll;
  document.addEventListener('input', (e) => { if (isText(e.target)) dirty.add(e.target); }, true);
  document.addEventListener('change', (e) => {
    const el = e.target;
    if (!isText(el)) flushAll();  // a field typed into before this select/upload comes first
    if (el.tagName === 'INPUT' && typeOf(el) === 'file') {  // file names only, never the content
      send(Object.assign({type: 'upload', files: Array.from(el.files || []).map(f => f.name).slice(0, 20)}, describe(el)));
      return;
    }
    if (el.tagName === 'SELECT') {
      const opt = el.options[el.selectedIndex];
      send(Object.assign({type: 'select', value: el.value, option: opt ? txt(opt.text) : ''}, describe(el)));
    } else if (isText(el)) { dirty.add(el); flush(el); }
  }, true);
  document.addEventListener('focusout', (e) => { if (isText(e.target)) flush(e.target); }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Enter') flushAll(); }, true);
  const CLICKABLE = 'a, button, input, select, textarea, label, summary, [role=button], [role=link], [role=menuitem], [role=tab], [role=checkbox], [role=option], [onclick]';
  document.addEventListener('click', (e) => {
    flushAll();
    const el = (e.target.closest && e.target.closest(CLICKABLE)) || e.target;
    if (!el || !el.tagName) return;
    if (isText(el) || el.tagName === 'SELECT' || el.tagName === 'OPTION') return;  // focus clicks; fills/selects cover them
    const fileInput = (el.tagName === 'INPUT' && typeOf(el) === 'file') || (el.tagName === 'LABEL' && el.control && typeOf(el.control) === 'file');
    if (fileInput) return;  // opens the file chooser; the upload event covers it
    const a = el.closest('a');
    send(Object.assign({type: 'click', href: a && a.href ? a.href : ''}, describe(el)));
  }, true);
  document.addEventListener('submit', (e) => {
    flushAll();
    const f = e.target;
    const b = e.submitter || f.querySelector('button[type=submit], input[type=submit], button:not([type])');
    send(Object.assign({type: 'submit'}, b ? describe(b) : {targets: []}));
  }, true);
  window.addEventListener('pagehide', flushAll, true);
})();
"""

_EVENT_KEYS = {"type", "t", "tag", "role", "name", "label", "input_type", "field", "secret", "masked", "targets", "value", "option", "href", "url", "filename", "title", "reason", "tab", "opener", "files", "frame"}
PAGE_EVENT_TYPES = ("click", "fill", "select", "submit", "upload")  # what the page script may report


def clean_event(ev: Any) -> dict | None:
    """Whitelist an event from the page. Secret fields never keep a value (defence in depth)."""
    if not isinstance(ev, dict) or ev.get("type") not in (*PAGE_EVENT_TYPES, "navigate", "download", "blocked", "popup", "close"):
        return None
    out = {k: v for k, v in ev.items() if k in _EVENT_KEYS}
    if out.get("secret") or out.get("masked") or out.get("input_type") == "password":
        out.pop("value", None)
        out["masked"] = True
    targets = []
    for t in out.get("targets") or []:
        if isinstance(t, dict):
            t = {k: str(v)[:300] for k, v in t.items() if k in ("role", "name", "label", "testid", "text", "css") and v}
            if t:
                targets.append(t)
    out["targets"] = targets
    for k in ("tab", "opener"):
        if k in out:
            try:
                out[k] = int(out[k])
            except (TypeError, ValueError):
                out.pop(k)
    if "frame" in out:  # iframe chain, outermost first: [{name, css, url_contains}]
        chain = out["frame"] if isinstance(out["frame"], list) else []
        levels = [{k: str(v)[:300] for k, v in lv.items() if k in ("name", "css", "url_contains") and v} if isinstance(lv, dict) else {} for lv in chain[:6]]
        if levels:
            out["frame"] = levels
        else:
            out.pop("frame")
    if "files" in out:  # base names only; a browser never reveals the local path
        out["files"] = [re.split(r"[\\/]", str(f))[-1][:200] for f in (out["files"] if isinstance(out["files"], list) else [])][:20]
    if out["type"] == "upload":
        out.pop("value", None)
    out["t"] = float(out.get("t") or time.time() * 1000)
    return out


def _norm_url(u: str) -> str:
    return urldefrag(u or "")[0].rstrip("/")


def _describe(ev: dict) -> str:
    return ev.get("name") or ev.get("label") or ev.get("field") or (ev["targets"][0].get("css") if ev.get("targets") else "element")


def _trailing_closes(evs: list[dict]) -> set[int]:
    """Indexes of the close events at the very end that close every remaining tab
    (the person closed the browser to finish recording); they are not steps."""
    open_tabs = {0}
    for e in evs:
        if e["type"] == "popup":
            open_tabs.add(e.get("tab", 0))
        elif e["type"] == "close":
            open_tabs.discard(e.get("tab", 0))
    if open_tabs:
        return set()
    out = set()
    for i in range(len(evs) - 1, -1, -1):
        if evs[i]["type"] != "close":
            break
        out.add(i)
    return out


def events_to_steps(events: list[dict], start_url: str, cause_window_ms: float = 5000) -> tuple[list[dict], dict[str, dict], list[str]]:
    """Recorded events -> (steps, parameters, warnings). Steps replay with the browser tier tools.

    Events carry `tab` (open order, 0 = first page). A popup marks the click that opened it with
    `expect_popup` (the replay then continues in the new tab); an action on another tab first
    gets a browser_switch_tab step, and a closed tab a browser_close_tab step. Tab steps name the
    tab by a stable URL (`url_contains`) and keep the index only as a fallback. Element actions
    inside an iframe keep the recorded `frame` chain.
    """
    evs = sorted((e for e in (clean_event(x) for x in events) if e), key=lambda e: e["t"])
    skip = _trailing_closes(evs)
    actions: list[dict] = [{"tool": "browser_goto", "input": {"url": start_url}, "intent": f"Open {start_url}", "t": 0.0, "tab": 0}]
    warnings: list[str] = []
    params: dict[str, dict] = {}
    current: dict[int, str] = {0: _norm_url(start_url)}  # last URL per tab
    last_cause: dict[int, dict] = {}  # per tab: the click/submit that may explain the next navigation
    first_load: set[int] = set()  # popups whose first navigation is their own opening
    loaded: set[int] = {0}  # tabs whose first page load has been seen
    open_tabs: set[int] = {0}
    pending: dict[int, list[tuple[dict, str]]] = {}  # tab -> (input, key) waiting for the tab's first URL
    state = {"cur": 0}  # the tab the replay is on (None after it was closed)

    def tab_input(tab: int, key: str = "url_contains", **extra) -> dict:
        inp: dict = {}
        u = stable_url(current.get(tab, ""))
        if u:
            inp[key] = u
        elif key == "url_contains":
            pending.setdefault(tab, []).append((inp, key))
        if key == "url_contains":
            inp["tab"] = tab
        inp.update(extra)
        return inp

    def learned_url(tab: int, url: str) -> None:
        current[tab] = _norm_url(url)
        u = stable_url(url)
        for inp, key in pending.pop(tab, []) if u else []:
            inp[key] = u

    def on_tab(tab: int, t: float) -> None:
        if tab != state["cur"]:
            actions.append({"tool": "browser_switch_tab", "input": tab_input(tab), "intent": f"Switch to tab {tab} ({current.get(tab, 'new tab')})", "t": t, "tab": tab})
            state["cur"] = tab

    def same_target(prev: dict, ev: dict) -> bool:
        return prev["input"].get("targets") == ev["targets"] and prev["input"].get("frame") == ev.get("frame")

    for i, ev in enumerate(evs):
        kind = ev["type"]
        tab = ev.get("tab", 0)
        if kind == "close":
            if i in skip or tab not in open_tabs:
                continue
            open_tabs.discard(tab)
            if not open_tabs:
                continue  # the last tab closing ends the recording
            actions.append({"tool": "browser_close_tab", "input": tab_input(tab), "intent": f"Close tab {tab} ({current.get(tab, 'popup')})", "t": ev["t"], "tab": tab})
            if state["cur"] == tab:
                state["cur"] = None
            continue
        if kind == "popup":
            opener = ev.get("opener")
            url = ev.get("url", "")
            open_tabs.add(tab)
            if url and not url.startswith("about:"):
                learned_url(tab, url)
                loaded.add(tab)
            elif tab not in loaded:
                first_load.add(tab)
            cause = None
            for a in reversed(actions):
                if a["tool"] in ("browser_click", "browser_download") and a.get("tab") == opener and ev["t"] - a["t"] <= cause_window_ms and not a.get("opened"):
                    cause = a
                    break
            if cause is not None and cause["tool"] == "browser_click":
                cause["input"]["expect_popup"] = True
                cause["input"].update(tab_input(tab, "popup_url_contains"))
                if "popup_url_contains" not in cause["input"]:
                    pending.setdefault(tab, []).append((cause["input"], "popup_url_contains"))
                cause["opened"] = tab
                state["cur"] = tab
            else:
                why = "a page script" if opener is not None else "the browser"
                actions.append({"tool": "browser_switch_tab", "input": tab_input(tab, new_tab=True, wait_s=10), "intent": f"Wait for the new tab {tab} opened by {why} and switch to it", "t": ev["t"], "tab": tab})
                state["cur"] = tab
            continue
        if kind == "navigate":
            url = ev.get("url", "")
            if tab in first_load or tab not in loaded:
                # A popup's own opening (its navigation can be reported just before the popup itself).
                first_load.discard(tab)
                loaded.add(tab)
                learned_url(tab, url)
                continue
            if _norm_url(url) == current.get(tab):
                continue
            caused = False
            lc = last_cause.get(tab)
            if lc and ev["t"] - lc["t"] <= cause_window_ms and not lc.get("used"):
                href = lc.get("href", "")
                caused = not href or _norm_url(href) == _norm_url(url) or lc.get("kind") == "submit"
                if caused:
                    lc["used"] = True
            if not caused:
                on_tab(tab, ev["t"])
                actions.append({"tool": "browser_goto", "input": {"url": url}, "intent": f"Open {url}", "t": ev["t"], "tab": tab})
            learned_url(tab, url)
            continue
        if kind == "blocked":
            warnings.append(f"{'a frame on ' if ev.get('reason') == 'frame' else 'navigation to '}{ev.get('url')} was blocked (host not on the allowlist); not recorded")
            continue
        if kind == "download":
            for a in reversed(actions):
                if a["tool"] == "browser_click" and a.get("tab") == tab and not a["input"].get("expect_popup"):
                    a["tool"] = "browser_download"
                    a["intent"] = f"Download via '{a.get('label_text', 'link')}'"
                    a["filename"] = ev.get("filename", "")
                    break
            else:
                warnings.append(f"download {ev.get('filename')} had no recorded click in its tab (a link that downloads into a new tab is not replayable yet)")
            continue
        if not ev["targets"]:
            if kind == "submit":
                warnings.append("a form was submitted without a submit button; replay may need a manual step")
            continue
        label = _describe(ev)
        on_tab(tab, ev["t"])
        prev = actions[-1]
        where = {"frame": ev["frame"]} if ev.get("frame") else {}
        inside = " (in a frame)" if where else ""
        if kind == "click":
            if prev["tool"] == "browser_click" and same_target(prev, ev) and ev["t"] - prev["t"] < 400:
                continue  # double click
            actions.append({"tool": "browser_click", "input": {"targets": ev["targets"], **where}, "intent": f"Click {ev.get('role') or ev.get('tag')} '{label}'{inside}", "label_text": label, "t": ev["t"], "tab": tab})
            last_cause[tab] = {"t": ev["t"], "href": ev.get("href", ""), "kind": "click"}
        elif kind == "submit":
            if prev["tool"] in ("browser_click", "browser_download") and ev["t"] - prev["t"] <= 1500:
                continue  # the click already submitted it
            actions.append({"tool": "browser_click", "input": {"targets": ev["targets"], **where}, "intent": f"Submit the form ('{label}'){inside}", "label_text": label, "t": ev["t"], "tab": tab})
            last_cause[tab] = {"t": ev["t"], "href": "", "kind": "submit"}
        elif kind == "fill":
            if ev.get("masked"):
                text = "{{secret:" + _slug(ev.get("field") or label, "password") + "}}"
            else:
                pname = _slug(ev.get("field") or label)
                text = "{" + pname + "}"
                params[pname] = {"type": "string", "default": ev.get("value", ""), "description": f"recorded value typed into '{label}'"}
            if prev["tool"] == "browser_fill" and same_target(prev, ev):
                prev["input"]["text"] = text
                continue
            actions.append({"tool": "browser_fill", "input": {"targets": ev["targets"], **where, "text": text}, "intent": f"Fill '{label}'{inside}" + (" (secret from the credential vault)" if ev.get("masked") else ""), "t": ev["t"], "tab": tab})
        elif kind == "upload":
            files = ev.get("files") or []
            if not files:
                continue  # the person cleared the file input
            base = _slug(ev.get("field") or label, "file")
            if len(files) > 1:
                pname = base + "_paths"
                params[pname] = {"type": "list", "required": True, "description": f"local paths of the {len(files)} files to upload into '{label}' (recorded file names: {', '.join(files)}); a list, or one string of paths separated by ';' (Windows) or newlines"}
                inp = {"targets": ev["targets"], **where, "paths": "{" + pname + "}"}
            else:
                pname = base + "_path"
                params[pname] = {"type": "string", "required": True, "description": f"local path of the file to upload into '{label}' (recorded file name: {files[0]})"}
                inp = {"targets": ev["targets"], **where, "path": "{" + pname + "}"}
            intent = f"Upload {len(files)} file{'s' if len(files) > 1 else ''} into '{label}'{inside} (needs approval at replay)"
            if prev["tool"] == "browser_upload" and same_target(prev, ev):
                if prev.get("param") != pname:
                    params.pop(prev.get("param"), None)  # the later choice replaces the earlier one
                prev.update(input=inp, intent=intent, param=pname)
                continue
            actions.append({"tool": "browser_upload", "input": inp, "intent": intent, "param": pname, "t": ev["t"], "tab": tab})
        elif kind == "select":
            if prev["tool"] == "browser_select" and same_target(prev, ev):
                prev["input"]["value"] = ev.get("value", "")
                continue
            actions.append({"tool": "browser_select", "input": {"targets": ev["targets"], **where, "value": ev.get("value", "")}, "intent": f"Select '{ev.get('option') or ev.get('value')}' in '{label}'{inside}", "t": ev["t"], "tab": tab})

    steps = []
    for n, a in enumerate(actions, start=1):
        st = {"id": f"step-{n:02d}", "intent": a["intent"], "tier": "browser", "script": {"kind": "tool", "tool": a["tool"], "input": a["input"]}, "learned_from": "recorder"}
        if a["tool"] == "browser_click" and a["input"].get("expect_popup"):
            st["intent"] += f" (opens tab {a['opened']})"
        if a["tool"] == "browser_download" and a.get("filename"):
            fname = re.sub(r"[^\w.\-]", "_", a["filename"])
            st["checks"] = [{"type": "file_exists", "path": f"output/downloads/{fname}"}]
        steps.append(st)
    if not any("checks" in s for s in steps[-1:]):
        where = current.get(state["cur"]) or start_url
        steps[-1]["checks"] = [{"type": "model", "criteria": f"The browser finished at {where} and the page shows the expected result of: {steps[-1]['intent']}"}]
    for st in steps[:-1]:
        if "checks" not in st:
            st["no_check_reason"] = NO_CHECK_INTERMEDIATE
    return steps, params, warnings


def recording_to_draft(name: str, start_url: str, events: list[dict], created_by: str | None = None) -> dict:
    steps, params, warnings = events_to_steps(events, start_url)
    hosts = {(urlparse(start_url).hostname or "").lower()}
    for s in steps:
        if s["script"]["tool"] == "browser_goto":
            hosts.add((urlparse(s["script"]["input"]["url"]).hostname or "").lower())
    blocked = {_norm_url(e.get("url", "")) for e in events if isinstance(e, dict) and e.get("type") == "blocked"}
    for e in events:  # pages reached by clicks or opened as popups in any tab
        if isinstance(e, dict) and e.get("type") in ("navigate", "popup") and str(e.get("url", "")).startswith(("http:", "https:")) and _norm_url(e["url"]) not in blocked:
            hosts.add((urlparse(e["url"]).hostname or "").lower())
    for s in steps:  # iframes acted in
        for lv in s["script"]["input"].get("frame") or []:
            if lv.get("url_contains"):
                hosts.add((urlparse("http://" + lv["url_contains"]).hostname or "").lower())
    hosts.discard("")
    who = created_by or _user()
    return {
        "name": _check_name(name),
        "version": 0,
        "status": "draft",
        "owner": who,
        "workflow": name.replace("-", " ").replace("_", " "),
        "description": f"DRAFT recorded in the browser from {start_url}",
        "permissions": {"data_class": "internal", "hosts": sorted(hosts)},
        "parameters": params,
        "steps": steps,
        "final_checks": [],
        "provenance": {
            "method": "record",
            "start_url": start_url,
            "created_at": _now_iso(),
            "created_by": who,
            "events": len(events),
            "tabs": 1 + max([int(e["tab"]) for e in events if isinstance(e, dict) and isinstance(e.get("tab"), int)] or [0]),
            "warnings": warnings,
            "secrets": sorted({m for s in steps for m in re.findall(r"\{\{secret:([^}]+)\}\}", json.dumps(s))}),
        },
    }


def playwright_status() -> tuple[bool, str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "playwright is not installed (pip install playwright; python -m playwright install chromium)"
    try:
        with sync_playwright() as p:
            path = Path(p.chromium.executable_path)
        return (True, "ok") if path.exists() else (False, "chromium is not installed (python -m playwright install chromium)")
    except Exception as e:  # pragma: no cover - environment specific
        return False, f"playwright unusable: {e}"


def record_browser(settings: Settings, start_url: str, headless: bool = False, driver: Callable[[Any], None] | None = None, on_event: Callable[[dict], None] | None = None) -> list[dict]:
    """Open a browser on an allowlisted start URL and capture the person's actions.

    Ends when the browser window is closed, on Ctrl+C, or (tests) when `driver(page)` returns.
    """
    ok, why = playwright_status()
    if not ok:
        raise TeachUnavailable(why)
    policy = PolicyEngine(settings)
    try:
        policy.check_url(start_url)
    except PolicyViolation as e:
        raise TeachError(f"start URL refused: {e} (add the host to policy.allowed_hosts)") from e
    from playwright.sync_api import Error as PWError
    from playwright.sync_api import sync_playwright

    events: list[dict] = []
    state = {"closed": False, "back": [], "finishing": False, "auto_closed": set(), "blocked_frames": set()}  # back: (page, url) left the allowlist
    pages: list = []  # every page in open order; index = tab

    def push(ev: dict) -> None:
        ev = clean_event(ev)
        if ev:
            events.append(ev)
            if on_event:
                on_event(ev)

    def tab_of(pg) -> int:
        if pg not in pages:
            attach(pg)
        return pages.index(pg)

    def frame_chain(frame, css: Any) -> list[dict] | None:
        """[{name, css, url_contains}] from the top page down to `frame`; None if a frame is off the allowlist."""
        levels, f = [], frame
        while f is not None and f.parent_frame is not None:
            url = f.url
            if url.startswith(("http:", "https:")):
                try:
                    policy.check_url(url)
                except PolicyViolation:
                    if url not in state["blocked_frames"]:
                        state["blocked_frames"].add(url)
                        push({"type": "blocked", "url": url, "reason": "frame", "tab": tab_of(frame.page)})
                    return None
            levels.insert(0, {"name": f.name, "url_contains": stable_url(url)})
            f = f.parent_frame
        if isinstance(css, list) and len(css) == len(levels):
            for lv, c in zip(levels, css):
                if c:
                    lv["css"] = str(c)
        return [{k: v for k, v in lv.items() if v} for lv in levels]

    def from_page(source, ev) -> None:
        # Only element events come from page script; the tab and frame chain are taken from the real source.
        if not (isinstance(ev, dict) and ev.get("type") in PAGE_EVENT_TYPES):
            return
        out = {k: v for k, v in ev.items() if k not in ("tab", "opener", "frame", "frame_css")}
        frame = source.get("frame")
        if frame is not None and frame.parent_frame is not None:
            chain = frame_chain(frame, ev.get("frame_css"))
            if chain is None:
                return  # inside a frame on a host off the allowlist: not recorded
            out["frame"] = chain
        push({**out, "tab": tab_of(source["page"])})

    def attach(pg) -> None:
        if pg in pages:
            return
        pages.append(pg)
        idx = len(pages) - 1

        def on_nav(frame) -> None:
            if frame != pg.main_frame or frame.url.startswith(("about:", "data:", "chrome-error:")):
                return
            try:
                policy.check_url(frame.url)
            except PolicyViolation:
                push({"type": "blocked", "url": frame.url, "tab": idx})
                state["back"].append((pg, idx, frame.url))
                return
            push({"type": "navigate", "url": frame.url, "tab": idx})

        def on_popup(child) -> None:
            child_idx = tab_of(child)
            push({"type": "popup", "url": child.url, "tab": child_idx, "opener": idx})

        def on_close(_pg) -> None:
            if not state["finishing"] and idx not in state["auto_closed"]:
                push({"type": "close", "tab": idx})

        def ensure_recorder(_pg=None) -> None:
            # A window.open popup can load its first real document before the context's init
            # script reaches it (only its about:blank gets it), so install it again on each load.
            # The script's per-document guard makes this a no-op where it is already running.
            for fr in list(pg.frames):
                try:
                    fr.evaluate("() => {" + RECORDER_JS + "}")
                except Exception:
                    pass

        pg.on("framenavigated", on_nav)
        pg.on("popup", on_popup)
        pg.on("close", on_close)
        pg.on("domcontentloaded", ensure_recorder)
        pg.on("download", lambda d: push({"type": "download", "filename": d.suggested_filename, "tab": idx}))

    def live_page():
        return next((pg for pg in pages if not pg.is_closed()), None)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(accept_downloads=True)
        context.expose_binding("__agentTeachRecord", from_page)
        context.add_init_script(RECORDER_JS)
        context.on("page", attach)
        page = context.new_page()
        attach(page)
        browser.on("disconnected", lambda _b: state.update(closed=True))

        def settle() -> None:
            while state["back"]:
                pg, idx, _url = state["back"].pop(0)
                try:
                    if idx == 0:
                        pg.go_back()
                    elif not pg.is_closed():
                        state["auto_closed"].add(idx)
                        pg.close()  # a popup off the allowlist has nothing to go back to
                except PWError:
                    pass

        try:
            page.goto(start_url, wait_until="domcontentloaded")
            if driver is not None:
                driver(page)
                settle()
            else:
                while not state["closed"]:
                    pg = live_page()
                    if pg is None:
                        break
                    try:
                        pg.wait_for_timeout(250)
                        settle()
                    except PWError:
                        if live_page() is None:
                            break
        except KeyboardInterrupt:
            pass
        finally:
            if not state["closed"]:
                for pg in pages:
                    try:
                        if not pg.is_closed():
                            for fr in pg.frames:
                                fr.evaluate("() => window.__agentTeachFlush && window.__agentTeachFlush()")
                    except Exception:
                        pass
                for pg in pages:
                    try:
                        if not pg.is_closed():
                            pg.evaluate("() => window.__agentTeachFlush && window.__agentTeachFlush()")
                    except Exception:
                        pass
                try:
                    pg = live_page()
                    if pg is not None:
                        pg.wait_for_timeout(100)
                except Exception:
                    pass
            state["finishing"] = True  # closing the context is not a recorded tab close
            for closer in (context.close, browser.close):
                try:
                    closer()
                except Exception:
                    pass
    return events


def record_draft(settings: Settings, name: str, start_url: str, playbooks_dir: str | Path, headless: bool = False, driver=None, force: bool = False, created_by: str | None = None, on_event=None) -> tuple[Path, dict]:
    _check_name(name)
    if (Path(playbooks_dir) / "drafts" / f"{name}.json").exists() and not force:
        raise TeachError(f"draft {name} already exists (use --force to overwrite)")
    events = record_browser(settings, start_url, headless=headless, driver=driver, on_event=on_event)
    data = recording_to_draft(name, start_url, events, created_by=created_by)
    return write_draft(playbooks_dir, data, force=True), data


# --------------------------------------------------------------------------- promote


_PLACEHOLDER = re.compile(r"(?<!\{)\{([A-Za-z_][A-Za-z0-9_]*)\}(?!\})")


def validate_draft(data: dict) -> list[str]:
    """Problems that block promotion. Empty list = ready."""
    problems: list[str] = []
    if not isinstance(data, dict):
        return ["playbook is not a JSON object"]
    for key in ("name", "steps", "owner"):
        if not data.get(key):
            problems.append(f"missing '{key}'")
    if data.get("name") and not NAME_RE.fullmatch(str(data["name"])):
        problems.append(f"invalid name {data['name']!r}")
    params = data.get("parameters", {})
    if not isinstance(params, dict) or not all(isinstance(v, dict) for v in params.values()):
        problems.append("'parameters' must map names to specs")
        params = {}
    steps = data.get("steps") if isinstance(data.get("steps"), list) else []
    for i, st in enumerate(steps):
        sid = st.get("id") if isinstance(st, dict) else None
        label = f"step {sid or i + 1}"
        if not isinstance(st, dict) or not sid:
            problems.append(f"{label}: needs an id")
            continue
        if st.get("tier") not in TIERS:
            problems.append(f"{label}: needs a tier, one of {', '.join(TIERS)}")
        if not st.get("checks") and not st.get("check") and not str(st.get("no_check_reason", "")).strip():
            problems.append(f"{label}: needs a check or an explicit no_check_reason")
        script = st.get("script")
        if script is not None:
            if not isinstance(script, dict) or script.get("kind", "python") not in ("python", "tool"):
                problems.append(f"{label}: script kind must be 'python' or 'tool'")
            elif script.get("kind", "python") == "python" and not script.get("code"):
                problems.append(f"{label}: python script has no code")
            elif script.get("kind") == "tool" and not script.get("tool"):
                problems.append(f"{label}: tool script names no tool")
        scan = {k: v for k, v in st.items() if k != "script"}
        if isinstance(script, dict) and script.get("kind") == "tool":
            scan["script_input"] = script.get("input", {})
        for s in _walk_strings(scan):
            for m in _PLACEHOLDER.finditer(s):
                if m.group(1) not in params:
                    problems.append(f"{label}: uses {{{m.group(1)}}} but no such parameter is declared")
    for s in _walk_strings(data.get("final_checks", [])):
        for m in _PLACEHOLDER.finditer(s):
            if m.group(1) not in params:
                problems.append(f"final_checks: uses {{{m.group(1)}}} but no such parameter is declared")
    if not problems:
        try:
            playbook_from_dict(data)
        except (PlaybookError, KeyError, TypeError, ValueError) as e:
            problems.append(f"schema: {e}")
    return list(dict.fromkeys(problems))


def promote(playbooks_dir: str | Path, name: str, reviewer: str | None = None) -> tuple[Path, dict]:
    folder = Path(playbooks_dir)
    src = folder / "drafts" / f"{_check_name(name)}.json"
    if not src.exists():
        raise TeachError(f"no draft named {name} in {src.parent}")
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise TeachError(f"draft {src} is not valid JSON: {e}") from e
    problems = validate_draft(data)
    if problems:
        raise TeachError("draft is not ready to promote:\n  - " + "\n  - ".join(problems))
    existing = next((pb for pb in PlaybookRegistry(folder).all() if pb.name == data["name"]), None)
    previous = existing.version if existing else 0
    data["version"] = max(int(data.get("version", 0) or 0), previous) + 1
    data.pop("status", None)
    prov = dict(data.get("provenance") or {})
    prov.update(promoted_at=_now_iso(), reviewer=reviewer or _user(), promoted_from=str(src.relative_to(folder)).replace("\\", "/"), previous_version=previous or None)
    data["provenance"] = prov
    target = Path(existing.source_path) if existing else folder / f"{data['name']}.json"
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    src.unlink()
    return target, data


def list_drafts(playbooks_dir: str | Path) -> list[tuple[Path, dict | None, list[str]]]:
    folder = Path(playbooks_dir) / "drafts"
    out = []
    if not folder.exists():
        return out
    for p in sorted(folder.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append((p, data, validate_draft(data)))
        except json.JSONDecodeError as e:
            out.append((p, None, [f"invalid JSON: {e}"]))
    return out


# --------------------------------------------------------------------------- CLI


def add_cli(sub) -> None:
    t = sub.add_parser("teach", help="teach mode: draft playbooks from a session or a browser recording")
    ts = t.add_subparsers(dest="teach_cmd", required=True)
    fs = ts.add_parser("from-session", help="draft a playbook from a finished session's audit log")
    fs.add_argument("session")
    fs.add_argument("--name", required=True)
    fs.add_argument("--by", help="created_by (default: current user)")
    fs.add_argument("--force", action="store_true", help="overwrite an existing draft")
    rc = ts.add_parser("record", help="record browser actions into a draft playbook (needs playwright)")
    rc.add_argument("--name", required=True)
    rc.add_argument("--url", required=True, help="start URL; its host must be in policy.allowed_hosts")
    rc.add_argument("--headless", action="store_true", help="run without a window (automation/tests only)")
    rc.add_argument("--force", action="store_true")
    pr = ts.add_parser("promote", help="validate a draft and move it into playbooks/")
    pr.add_argument("name")
    pr.add_argument("--reviewer")
    ts.add_parser("drafts", help="list draft playbooks")


def cli(args, settings: Settings, root: Path) -> int:
    playbooks = root / "playbooks"
    try:
        if args.teach_cmd == "from-session":
            path, data = draft_from_session(settings, args.session, args.name, playbooks, created_by=args.by, force=args.force)
            print(f"draft written: {path}")
            print(f"  steps: {len(data['steps'])}  parameters: {list(data['parameters'])}  skipped: {[s['id'] for s in data['provenance']['skipped_steps']]}")
            _print_problems(validate_draft(data))
            return 0
        if args.teach_cmd == "record":
            print(f"recording from {args.url}. Work in the browser window; close it (or press Ctrl+C here) to finish.")
            path, data = record_draft(settings, args.name, args.url, playbooks, headless=args.headless, force=args.force, on_event=lambda ev: print(f"  recorded {ev['type']}: {_describe(ev) if ev.get('targets') else ev.get('url') or ev.get('filename') or ''}"))
            print(f"draft written: {path}  ({len(data['steps'])} steps)")
            for w in data["provenance"]["warnings"]:
                print(f"  warning: {w}")
            _print_problems(validate_draft(data))
            return 0
        if args.teach_cmd == "promote":
            path, data = promote(playbooks, args.name, reviewer=args.reviewer)
            print(f"promoted {data['name']} v{data['version']} -> {path} (reviewer: {data['provenance']['reviewer']})")
            return 0
        if args.teach_cmd == "drafts":
            drafts = list_drafts(playbooks)
            if not drafts:
                print("no drafts")
            for p, data, problems in drafts:
                if data is None:
                    print(f"{p.name:<32} INVALID  {problems[0]}")
                    continue
                prov = data.get("provenance", {})
                state = "ready" if not problems else f"{len(problems)} problem(s)"
                print(f"{data.get('name', p.stem):<32} steps={len(data.get('steps', []))}  {prov.get('method', '?')} by {prov.get('created_by', '?')} at {prov.get('created_at', '?')}  [{state}]")
                for pr_ in problems:
                    print(f"    - {pr_}")
            return 0
    except TeachUnavailable as e:
        print(f"teach record is unavailable: {e}")
        return 2
    except TeachError as e:
        print(f"error: {e}")
        return 1
    return 2


def _print_problems(problems: list[str]) -> None:
    if problems:
        print("  before promoting, fix:")
        for p in problems:
            print(f"    - {p}")
    else:
        print("  review it, then: python -m analyst_agent teach promote <name> --reviewer <you>")
