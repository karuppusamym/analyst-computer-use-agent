"""Background runs started from the portal, and read-only views of session folders."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..audit import append_event
from ..config import Settings
from ..takeover import PAUSE_FILE, pause_info
from ..playbook import Playbook, PlaybookError, PlaybookRegistry
from .approvals import ApprovalInbox, QuestionBox, WebApprover
from .state import atomic_write_json, read_json

META_FILE = "portal_meta.json"
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")


def valid_session_id(sid: str) -> bool:
    return bool(SESSION_ID_RE.match(sid or "")) and ".." not in sid


def new_session_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def safe_child(root: Path, rel: str) -> Path | None:
    """root/rel resolved, or None if it escapes root (path traversal, absolute paths, drive letters)."""
    if not rel or "\x00" in rel:
        return None
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or any(part == ".." for part in rel.split("/")):
        return None
    root = root.resolve()
    p = (root / rel).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        return None
    return p


def request_stop(audit_dir: Path, session_id: str) -> bool:
    """Kill switch: the same STOP file the `stop` command writes."""
    if not valid_session_id(session_id):
        return False
    d = audit_dir / session_id
    if not d.exists():
        return False
    (d / "STOP").write_text("stop requested\n")
    return True


def read_meta(session_dir: Path) -> dict:
    """portal_meta.json: who started the run in the portal (absent for CLI and scheduled runs)."""
    m = read_json(session_dir / META_FILE)
    return m if isinstance(m, dict) else {}


def write_meta(session_dir: Path, meta: dict) -> None:
    atomic_write_json(session_dir / META_FILE, meta)


def append_session_event(session_dir: Path, kind: str, user: str = "portal", **data: Any) -> None:
    """Append one event to a session's audit log from outside its run (e.g. an orphaned request)."""
    append_event(session_dir, kind, user, **data)


def read_events(session_dir: Path, limit: int | None = None) -> list[dict]:
    p = session_dir / "events.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out[-limit:] if limit else out


def summarize_events(events: list[dict]) -> dict[str, Any]:
    """Rebuild request, step statuses and final status from an audit log."""
    info: dict[str, Any] = {"request": "", "user": "", "playbook": None, "params": {}, "started": None, "status": "", "report": "", "steps": [], "approvals": [], "orphaned": []}
    steps: dict[str, dict] = {}

    def add_steps(lst):
        for st in lst or []:
            if isinstance(st, dict) and st.get("id") and st["id"] not in steps:
                steps[st["id"]] = {"id": st["id"], "intent": st.get("intent", ""), "tier": st.get("tier", ""), "status": "pending", "attempts": 0, "note": ""}

    for e in events:
        k = e.get("kind")
        if k == "task_started":
            info.update(request=e.get("request", ""), user=e.get("user", ""), playbook=e.get("playbook"), params=e.get("params") or {}, started=e.get("ts"))
            info["status"] = "running"
        elif k in ("plan", "replanned"):
            add_steps(e.get("steps"))
        elif k == "step_started" and e.get("step") in steps:
            steps[e["step"]]["status"] = "running"
        elif k == "step_verdict" and e.get("step") in steps:
            s = steps[e["step"]]
            s["attempts"] = e.get("attempt", s["attempts"])
            s["status"] = "verified" if e.get("passed") else "failed"
            if not e.get("passed"):
                s["note"] = str(e.get("problems") or "")[:300]
        elif k == "step_rejected" and e.get("step") in steps:
            steps[e["step"]]["status"] = "rejected"
        elif k == "step_blocked" and e.get("step") in steps:
            steps[e["step"]].update(status="blocked", note=str(e.get("reason", ""))[:300])
        elif k == "resumed":
            for sid in e.get("verified_steps", []):
                if sid in steps:
                    steps[sid]["status"] = "verified"
        elif k == "approval_decided":
            info["approvals"].append({"step": e.get("step"), "approved": e.get("approved"), "by": e.get("by"), "note": e.get("note", ""), "ts": e.get("ts")})
        elif k == "approval_parked_decided" and not e.get("approved"):
            # A plan approval carried over a restart and then declined (or timed out): no run logs it.
            info["approvals"].append({"step": e.get("step"), "approved": False, "by": e.get("by"), "note": e.get("note", ""), "ts": e.get("ts")})
        elif k in ("approval_orphaned", "question_orphaned"):
            if k == "approval_orphaned":
                what = f"approval for step {e.get('step')}: {e.get('summary', '')}"
                info["approvals"].append({"step": e.get("step"), "approved": False, "by": e.get("by"), "note": e.get("note", ""), "ts": e.get("ts")})
            else:
                what = "clarifying questions: " + "; ".join(map(str, e.get("questions") or []))
            info["orphaned"].append({"kind": k, "what": what, "note": e.get("note", ""), "ts": e.get("ts")})
        elif k == "needs_input":
            info["status"] = "needs_input"
        elif k == "task_failed":
            info["status"] = "failed"
        elif k == "task_finished":
            info["status"] = e.get("status", "finished")
            info["report"] = e.get("report", "")
    info["steps"] = list(steps.values())
    return info


class _FixedRegistry(PlaybookRegistry):
    """PlaybookRegistry.match over an already-loaded list (approved playbooks only)."""

    def __init__(self, playbooks: list[Playbook]):
        self._playbooks = playbooks

    def all(self) -> list[Playbook]:
        return list(self._playbooks)


@dataclass
class Run:
    session_id: str
    request: str
    user: str
    playbook: str | None
    params: dict
    started_at: float = field(default_factory=time.time)
    status: str = "starting"
    message: str = ""
    result: Any = None
    thread: threading.Thread | None = None
    finished_at: float | None = None
    resume: bool = False
    carried_plan: dict | None = None  # a plan approval decided after a portal restart (WebApprover.carried)

    @property
    def alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


class RunManager:
    def __init__(
        self,
        settings: Settings,
        playbooks_dir: Path,
        knowledge_dir: Path | None,
        inbox: ApprovalInbox,
        questions: QuestionBox,
        client_factory: Callable[[Settings], Any] | None = None,
        router_factory: Callable[[Settings], Any] | None = None,
        on_event: Callable[..., None] | None = None,
    ):
        self.settings = settings
        self.playbooks_dir = Path(playbooks_dir)
        self.knowledge_dir = knowledge_dir
        self.inbox = inbox
        self.questions = questions
        self.client_factory = client_factory
        self.router_factory = router_factory
        self.on_event = on_event or (lambda *a, **k: None)
        self.runs: dict[str, Run] = {}
        self._lock = threading.Lock()
        self.instance = ""  # the portal instance id (PortalApp sets it); tells holds from before a restart apart

    @property
    def approval_timeout(self) -> float:
        return float(self.settings["policy"].get("approval_timeout_s", 900))

    @property
    def question_timeout(self) -> float:
        return float(self.settings.data.get("portal", {}).get("question_timeout_s", self.approval_timeout))

    # ---- playbooks that may run (drafts never run)
    def runnable_playbooks(self) -> list[Playbook]:
        from .playbooks import list_playbooks

        return [e.playbook for e in list_playbooks(self.playbooks_dir) if e.playbook and not e.is_draft]

    def resolve_playbook(self, choice: str, request: str) -> Playbook | None:
        runnable = self.runnable_playbooks()
        if choice in ("", "none", None):
            return None
        if choice == "auto":
            # Same matching as the CLI, restricted to non-draft playbooks.
            return _FixedRegistry(runnable).match(request)
        for pb in runnable:
            if pb.name == choice or pb.workflow == choice:
                return pb
        raise PlaybookError(f"no approved playbook named {choice}")

    # ---- start / stop
    def start(self, request: str, playbook_choice: str, params: dict, user: str) -> Run:
        pb = self.resolve_playbook(playbook_choice, request)
        sid = new_session_id()
        run = Run(sid, request, user, pb.name if pb else None, dict(params))
        # Owner first, so the session is never shown to the wrong people, even before its first event.
        write_meta(self.settings.audit_dir / sid, {"owner": user, "started_by": user, "created_at": run.started_at, "source": "portal", "resumes": []})
        with self._lock:
            self.runs[sid] = run
        self._launch(run, pb)
        self.on_event("run_started", session=sid, request=request, playbook=run.playbook, by=user)
        return run

    def _launch(self, run: Run, pb: Playbook | None) -> None:
        t = threading.Thread(target=self._run, args=(run, pb), name=f"portal-run-{run.session_id}", daemon=True)
        run.thread = t
        t.start()

    def owner(self, sid: str) -> str | None:
        """The portal user who started the session; None for CLI / scheduled sessions."""
        if not valid_session_id(sid):
            return None
        owner = read_meta(self.settings.audit_dir / sid).get("owner")
        run = self.runs.get(sid)
        return str(owner) if owner else (run.user if run else None)

    def playbook_of(self, sid: str) -> str | None:
        """The session's playbook name (None for planner-built or unknown sessions)."""
        run = self.runs.get(sid)
        if run and run.playbook:
            return run.playbook
        if not valid_session_id(sid):
            return None
        for e in read_events(self.settings.audit_dir / sid):
            if e.get("kind") == "task_started":
                return e.get("playbook") or None
        return None

    def viewers(self, sid: str) -> list[str]:
        """Users the owner or an admin shared this session with (portal_meta.json "viewers")."""
        if not valid_session_id(sid):
            return []
        v = read_meta(self.settings.audit_dir / sid).get("viewers")
        return [str(x) for x in v] if isinstance(v, list) else []

    def set_viewers(self, sid: str, viewers: list[str]) -> None:
        with self._lock:
            d = self.settings.audit_dir / sid
            meta = read_meta(d)
            if not meta.get("owner"):
                run = self.runs.get(sid)
                if run:
                    meta["owner"] = run.user
            meta["viewers"] = sorted(dict.fromkeys(viewers))
            d.mkdir(parents=True, exist_ok=True)
            write_meta(d, meta)

    # ---- resume (the portal's `run --resume <session>`)
    def hold_from_restart(self, sid: str) -> bool:
        """The session's PAUSE file was written by an earlier portal (or by hand), not by this one."""
        info = pause_info(self.settings.audit_dir / sid) if valid_session_id(sid) else None
        return info is not None and info.get("portal_instance") != self.instance

    def resume_problem(self, sid: str, info: dict | None = None, carried: bool = False, ignore_pause: bool = False) -> str:
        """Why this session cannot be resumed, or "" if it can.

        carried: for a plan approval carried over a restart, which resumes a session that may not
        have a checkpoint yet (it was waiting on the plan) and is still listed as waiting.
        ignore_pause: the caller releases a leftover takeover hold first."""
        d = self.settings.audit_dir / sid
        if not valid_session_id(sid) or not (carried or (d / "checkpoint.json").is_file()):
            return "this session has no checkpoint (no step was verified yet)"
        run = self.runs.get(sid)
        if run and (run.alive or run.status == "starting"):
            return "this session is still running"
        info = info if info is not None else self.session_info(sid, _resume_check=False)
        status = str(info.get("status") or "")
        if status == "success":
            return "this session already finished successfully"
        if status.startswith("waiting") and not carried:
            return "this session is waiting for a decision"
        if (d / "STOP").exists():
            return "the kill switch was pressed for this session, so it is not resumed from the portal"
        if (d / PAUSE_FILE).exists() and not ignore_pause:
            who = (pause_info(d) or {}).get("by") or ""
            when = " from before the portal restarted" if self.hold_from_restart(sid) else ""
            if who:
                return f"{who} holds a takeover of this session{when}; {who} or an admin must release it first (Release hold on the live view)"
            return f"a PAUSE file holds this session{when}; an admin must release it first (Release hold on the live view)"
        if not info.get("request"):
            return "the original request is not in the audit log"
        return ""

    def resume(self, sid: str, by: str, carried_plan: dict | None = None) -> Run:
        """Continue a session from its last checkpoint in a background thread.

        Calls Orchestrator.run(..., session_id=sid, resume=True), as `run --resume` does:
        verified steps are skipped and the plan goes to the approval inbox again, unless
        carried_plan holds a plan approval made after a restart for exactly the same plan.
        """
        with self._lock:
            info = self.session_info(sid, _resume_check=False)
            problem = self.resume_problem(sid, info, carried=carried_plan is not None)
            if problem:
                raise PlaybookError(problem)
            d = self.settings.audit_dir / sid
            cp = read_json(d / "checkpoint.json") or {}
            params = dict(info.get("params") or {})
            for k, v in (cp.get("params") or {}).items():
                if "[REDACTED:" not in str(v):  # never feed a redaction marker back in as a value
                    params.setdefault(k, v)
            pb = None
            if info.get("playbook"):
                pb = next((p for p in self.runnable_playbooks() if p.name == info["playbook"]), None)
                if pb is None:
                    raise PlaybookError(f"the session's playbook {info['playbook']} is no longer an approved playbook")
            meta = read_meta(d)
            owner = meta.get("owner") or info.get("user") or by
            run = Run(sid, info.get("request") or str(cp.get("request", "")), str(owner), pb.name if pb else None, params, resume=True, carried_plan=carried_plan)
            if meta:
                meta.setdefault("resumes", []).append({"by": by, "at": run.started_at, **({"plan_request": carried_plan.get("request_id")} if carried_plan else {})})
                write_meta(d, meta)
            self.runs[sid] = run
            self._launch(run, pb)
        self.on_event("run_resumed", session=sid, by=by, owner=owner, playbook=run.playbook, **({"carried_plan_request": carried_plan.get("request_id")} if carried_plan else {}))
        return run

    def _run_event(self, sid: str):
        def ev(kind: str, **data: Any) -> None:
            append_event(self.settings.audit_dir / sid, kind, "portal", **data)
            self.on_event(kind, session=sid, **data)

        return ev

    def _run(self, run: Run, pb: Playbook | None) -> None:
        from ..orchestrator import Orchestrator

        run.status = "running"
        orch = None
        try:
            kwargs: dict[str, Any] = {}
            if self.client_factory:
                kwargs["client"] = self.client_factory(self.settings)
            if self.router_factory:
                kwargs["router"] = self.router_factory(self.settings)
            orch = Orchestrator(
                self.settings,
                approver=WebApprover(self.inbox, run.session_id, run.user, self.approval_timeout, carried=run.carried_plan, on_event=self._run_event(run.session_id)),
                user=run.user,
                ask=self.questions.asker(run.session_id, run.user, self.question_timeout),
                knowledge_dir=self.knowledge_dir,
                require_plan_approval=True,
                **kwargs,
            )
            result = orch.run(run.request, playbook=pb, params=run.params, session_id=run.session_id, resume=run.resume)
            run.result = result
            run.status = result.status
            run.message = result.message
        except Exception as e:  # noqa: BLE001 - report any crash in the UI
            run.status = "error"
            run.message = f"{type(e).__name__}: {e}"
            run.result = None
            traceback.print_exc()
        finally:
            run.finished_at = time.time()
            if orch is not None:
                try:
                    orch.router.close()
                except Exception:  # noqa: BLE001
                    pass
            self.on_event("run_finished", session=run.session_id, status=run.status)

    def stop(self, session_id: str, by: str) -> bool:
        run = self.runs.get(session_id)
        d = self.settings.audit_dir / session_id
        if run and valid_session_id(session_id):
            d.mkdir(parents=True, exist_ok=True)  # a just-started run may not have created it yet
        ok = request_stop(self.settings.audit_dir, session_id)
        if ok:
            self.inbox.cancel_session(session_id, by, "kill switch pressed; declined")
            self.questions.answer(session_id, None, by)
            self.on_event("kill_switch", session=session_id, by=by)
        return ok

    # ---- listing
    def sessions(self) -> list[dict]:
        """Every session folder on disk plus runs that have not written one yet, newest first."""
        out: dict[str, dict] = {}
        root = self.settings.audit_dir
        if root.exists():
            for d in root.iterdir():
                if d.is_dir() and valid_session_id(d.name) and (d / "events.jsonl").exists():
                    out[d.name] = self.session_info(d.name)
        for sid in list(self.runs):
            if sid not in out:
                out[sid] = self.session_info(sid)
        return sorted(out.values(), key=lambda x: x.get("started") or 0, reverse=True)

    def session_info(self, sid: str, _resume_check: bool = True) -> dict:
        d = self.settings.audit_dir / sid
        info = summarize_events(read_events(d))
        info["id"] = sid
        info["stopped"] = (d / "STOP").exists()
        info["takeover"] = pause_info(d)
        info["owner"] = self.owner(sid)
        run = self.runs.get(sid)
        # A hold with no live run behind it: left over from before a restart, or the run ended meanwhile.
        info["takeover_stale"] = info["takeover"] is not None and not (run and run.alive)
        info["takeover_from_restart"] = info["takeover_stale"] and (info["takeover"] or {}).get("portal_instance") != self.instance
        if run:
            info["request"] = info["request"] or run.request
            info["user"] = info["user"] or run.user
            info["playbook"] = info["playbook"] or run.playbook
            info["started"] = info["started"] or run.started_at
            if run.alive:
                info["status"] = "running"
            elif run.status in ("error",):
                info["status"] = "error"
            info["message"] = run.message
            if run.result is not None:
                info["steps"] = [{"id": r.step.id, "intent": r.step.intent, "tier": r.tier_used or r.step.tier, "status": r.status, "attempts": r.attempts, "note": r.summary[:300]} for r in run.result.records]
                info["questions"] = list(run.result.questions)
                info["report"] = run.result.report_path or info["report"]
        elif info["status"] == "running":
            info["status"] = "interrupted"  # no live thread in this portal and no task_finished event
        if info["takeover"] is not None and info["status"] == "running":
            info["status"] = "paused (human takeover)"
        if self.inbox.pending(sid):
            info["status"] = "waiting for approval"
        if self.questions.get(sid):
            info["status"] = "waiting for answers"
        info["outputs"] = self.outputs(sid)
        if _resume_check:
            info["resume_problem"] = self.resume_problem(sid, info)
            info["resumable"] = not info["resume_problem"]
            # Resumable once a leftover hold is released (the holder or an admin may do both at once).
            info["resumable_after_release"] = bool(info["takeover_stale"]) and not self.resume_problem(sid, info, ignore_pause=True)
        return info

    def outputs(self, sid: str) -> list[dict]:
        """Files produced by the session that the portal may serve (under output/ or the session folder)."""
        s = self.settings
        names: list[str] = []
        run = self.runs.get(sid)
        if run and run.result is not None:
            names += [f for r in run.result.records for f in r.files]
        cp = s.audit_dir / sid / "checkpoint.json"
        if cp.exists():
            try:
                names += list(json.loads(cp.read_text(encoding="utf-8")).get("files", []))
            except ValueError:
                pass
        for e in read_events(s.audit_dir / sid):
            if e.get("kind") == "tool_result" and isinstance(e.get("files"), list):
                names += [str(x) for x in e["files"]]
        out, seen = [], set()
        for name in dict.fromkeys(names):
            p = Path(name)
            cands = [p] if p.is_absolute() else [s.workspace_root / p, s.base_dir / p, s.output_dir / p]
            for c in cands:
                c = c.resolve()
                if not c.is_file() or c in seen:
                    continue
                for kind, root in (("out", s.output_dir), ("session", s.audit_dir / sid)):
                    try:
                        rel = c.relative_to(root.resolve()).as_posix()
                    except ValueError:
                        continue
                    seen.add(c)
                    out.append({"name": name, "kind": kind, "rel": rel, "size": c.stat().st_size})
                    break
                break
        return out

    def screenshots(self, sid: str, limit: int = 4) -> list[str]:
        d = self.settings.audit_dir / sid / "screenshots"
        if not valid_session_id(sid) or not d.exists():
            return []
        shots = sorted((p for p in d.iterdir() if p.suffix.lower() in (".png", ".jpg", ".jpeg")), key=lambda p: (p.stat().st_mtime, p.name))
        return [p.name for p in shots[-limit:]]
