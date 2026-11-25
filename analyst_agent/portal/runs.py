"""Background runs started from the portal, and read-only views of session folders."""

from __future__ import annotations

import json
import re
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..playbook import Playbook, PlaybookError, PlaybookRegistry
from .approvals import ApprovalInbox, QuestionBox, WebApprover

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
    info: dict[str, Any] = {"request": "", "user": "", "playbook": None, "params": {}, "started": None, "status": "", "report": "", "steps": [], "approvals": []}
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
        with self._lock:
            self.runs[sid] = run
        t = threading.Thread(target=self._run, args=(run, pb), name=f"portal-run-{sid}", daemon=True)
        run.thread = t
        t.start()
        self.on_event("run_started", session=sid, request=request, playbook=run.playbook, by=user)
        return run

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
                approver=WebApprover(self.inbox, run.session_id, run.user, self.approval_timeout),
                user=run.user,
                ask=self.questions.asker(run.session_id, run.user, self.question_timeout),
                knowledge_dir=self.knowledge_dir,
                require_plan_approval=True,
                **kwargs,
            )
            result = orch.run(run.request, playbook=pb, params=run.params, session_id=run.session_id)
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

    def session_info(self, sid: str) -> dict:
        d = self.settings.audit_dir / sid
        info = summarize_events(read_events(d))
        info["id"] = sid
        info["stopped"] = (d / "STOP").exists()
        run = self.runs.get(sid)
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
        if self.inbox.pending(sid):
            info["status"] = "waiting for approval"
        if self.questions.get(sid):
            info["status"] = "waiting for answers"
        info["outputs"] = self.outputs(sid)
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
