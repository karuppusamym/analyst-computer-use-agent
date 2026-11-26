"""Task orchestrator: clarify -> plan -> plan approval -> steps (route, run, verify,
checkpoint, recover) -> final verification -> "what I checked" report.

Recovery ladder per step: scripted replay -> guided executor -> retry once with
the error -> re-plan the rest -> stop and ask the human a precise question.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

from .agents import Executor, Plan, Planner, StepRun, Verdict, Verifier
from .audit import AuditLog, redact
from .checks import CheckOutcome
from .checkpoint import CheckpointStore
from .config import Settings
from .model import ModelClient, ModelError
from .playbook import Playbook, Step
from .policy import ApprovalDecision, ApprovalRequest, Approver, ConsoleApprover, PolicyEngine
from .report import write_report
from .router import RouteError, Router
from .takeover import HUMAN_KINDS, PAUSE_FILE, clear_pause, human_note, pause_info
from .tools.base import ToolContext, ToolOutput
from .tools.code import run_python


def plan_fingerprint(request: str, playbook: Playbook | None, plan: Plan, params: dict, preview: str) -> str:
    """sha256 over everything a plan approval is about: the request, the playbook and its version,
    the bound steps, the final checks, the parameters and the preview the reviewer saw. A plan
    approval carried over a portal restart is reused only for a run whose plan has the same value."""
    body = {
        "request": request,
        "playbook": playbook.name if playbook else None,
        "playbook_version": playbook.version if playbook else None,
        "steps": [st.to_dict() for st in plan.steps],
        "final_checks": plan.final_checks,
        "params": params,
        "preview": preview,
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")).hexdigest()


class _StepAmountApprover:
    """Gives in-step tool approvals (browser submit, desktop press, upload) the amount the
    playbook step declared, so a reviewer's amount limit also applies to them."""

    def __init__(self, inner: Approver, amounts: dict[str, str]):
        self.inner = inner
        self.amounts = amounts

    def request(self, req: ApprovalRequest) -> "ApprovalDecision":
        if req.amount is None and self.amounts.get(req.step_id):
            req = replace(req, amount=self.amounts[req.step_id])
        return self.inner.request(req)


@dataclass
class StepRecord:
    step: Step
    status: str = "pending"  # verified | failed | skipped | rejected | blocked
    tier_used: str = ""
    route_note: str = ""
    attempts: int = 0
    summary: str = ""
    verdict: Verdict | None = None
    files: list[str] = field(default_factory=list)


@dataclass
class TaskResult:
    status: str  # success | partial | blocked | failed | needs_input | rejected
    session_id: str
    records: list[StepRecord]
    final: Verdict | None = None
    questions: list[str] = field(default_factory=list)
    report_path: str = ""
    message: str = ""
    usage: dict = field(default_factory=dict)
    approvals: list[dict] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        client: ModelClient | None = None,
        approver: Approver | None = None,
        router: Router | None = None,
        user: str = "analyst",
        ask: Callable[[list[str]], dict[str, str] | None] | None = None,
        knowledge_dir: str | Path | None = None,
        require_plan_approval: bool = True,
    ):
        self.settings = settings
        self.client = client or ModelClient(settings)
        self.approver = approver or ConsoleApprover(user)
        self.router = router or Router(settings)
        self.user = user
        self.ask = ask
        self.knowledge_dir = Path(knowledge_dir) if knowledge_dir else None
        self.require_plan_approval = require_plan_approval
        self.planner = Planner(self.client)
        self.verifier = Verifier(self.client)
        self.pause_poll_s = 0.25
        self._human_note = ""
        self._pause_end = ""
        self._held_s = 0.0  # time spent waiting for human takeovers; added to the task deadline

    # ------------------------------------------------------------------ helpers
    def _knowledge(self) -> str:
        if not self.knowledge_dir or not self.knowledge_dir.exists():
            return ""
        return "\n\n".join(p.read_text(encoding="utf-8")[:6000] for p in sorted(self.knowledge_dir.glob("*.md")))

    def _approve(self, audit: AuditLog, approvals: list, req: ApprovalRequest) -> bool:
        extra = {"amount": req.amount} if req.amount is not None else {}
        if req.fingerprint:
            extra["plan_fingerprint"] = req.fingerprint
        audit.event("approval_requested", step=req.step_id, action_class=req.action_class, summary=req.summary, **extra)
        decision = self.approver.request(req)
        audit.event("approval_decided", step=req.step_id, approved=decision.approved, by=decision.by, note=decision.note)
        approvals.append({"step": req.step_id, "action": req.action_class, "approved": decision.approved, "by": decision.by})
        return decision.approved

    def _stop_requested(self, audit: AuditLog) -> bool:
        return (audit.dir / "STOP").exists() or (self.settings.workspace_root / "STOP").exists()

    # ------------------------------------------------------------------ human takeover (PAUSE file)
    def _wait_if_paused(self, audit: AuditLog, step_id: str = "") -> bool:
        """Block while a human holds this session (PAUSE file). Like STOP, but resumable.

        Returns False when the run must stop instead (kill switch, or no hand-back within
        limits.takeover_timeout_s); self._pause_end says why. A hold older than
        limits.takeover_max_hold_s (0 = no limit) expires: the run removes PAUSE, logs
        takeover_expired and goes on as after a hand-back. The time spent waiting is added to
        the task deadline (self._held_s). On hand-back the human's audited actions become a note
        for the executor's next turn (self._human_note)."""
        if not (audit.dir / PAUSE_FILE).exists():
            return True
        info = pause_info(audit.dir) or {}
        start = audit.event("takeover_paused", step=step_id, by=info.get("by"))
        limits = self.settings["limits"]
        limit = float(limits.get("takeover_timeout_s", 1800))
        max_hold = float(limits.get("takeover_max_hold_s", 0) or 0)
        t0 = time.time()
        try:
            held_since = min(t0, float(info.get("at") or t0))
        except (TypeError, ValueError):
            held_since = t0
        expired = False
        while (audit.dir / PAUSE_FILE).exists():
            if self._stop_requested(audit):
                self._pause_end = "stopped by kill switch"
                audit.event("takeover_wait_ended", step=step_id, reason="kill switch")
                self._held_s += time.time() - t0
                return False
            now = time.time()
            if max_hold > 0 and now - held_since > max_hold:
                cur = pause_info(audit.dir)
                if cur is not None and cur.get("at") == info.get("at"):
                    # Log first: the portal treats the hold as over as soon as PAUSE is gone.
                    audit.event("takeover_expired", step=step_id, by=info.get("by"), held_s=round(now - held_since, 1), max_hold_s=max_hold)
                    clear_pause(audit.dir)
                    expired = True
                    break
                info = cur or {}  # handed back and taken over again in between: time the new hold
                held_since = now
                continue
            if now - t0 > limit:
                self._pause_end = f"stopped: human takeover was not handed back within {int(limit)} s"
                audit.event("takeover_timeout", step=step_id, by=info.get("by"), waited_s=round(now - t0, 1))
                self._held_s += now - t0
                return False
            time.sleep(self.pause_poll_s)
        waited = time.time() - t0
        self._held_s += waited
        after = [e for e in audit.events() if int(e.get("seq", 0) or 0) > int(start.get("seq", 0))]
        actions = [e for e in after if e.get("kind") in HUMAN_KINDS]
        ended_by = None if expired else next((e.get("by") for e in reversed(after) if e.get("kind") == "takeover_ended"), None)
        note = human_note(after, str(info.get("by") or ""))
        if expired:
            note = f"The takeover hold expired after {int(max_hold)} s without a hand-back.\n" + note
        self._human_note = note if not self._human_note else self._human_note + "\n\n" + note
        audit.event("takeover_resumed", step=step_id, by=info.get("by"), handed_back_by=ended_by, expired=expired, human_actions=sum(1 for e in actions if e["kind"] == "human_action"),
                    human_refused=sum(1 for e in actions if e["kind"] == "human_action_refused"), paused_s=round(waited, 1), deadline_extended_s=round(waited, 1), held_total_s=round(self._held_s, 1))
        return True

    def _pause_hook(self, audit: AuditLog, step_id: str) -> tuple[bool, str]:
        """For the executor: (False, reason) to stop, else (True, note-for-the-model or "")."""
        if not self._wait_if_paused(audit, step_id):
            return False, self._pause_end
        note, self._human_note = self._human_note, ""
        if note:
            audit.event("takeover_note_sent", step=step_id, note=note)
        return True, note

    # ------------------------------------------------------------------ main entry
    def run(self, request: str, playbook: Playbook | None = None, params: dict | None = None, session_id: str | None = None, resume: bool = False, guide: Playbook | None = None) -> TaskResult:
        """playbook: follow it exactly (scripted replay). guide: a playbook matched to the request,
        given to the planner as a reference so the plan covers everything the request asks."""
        self._guide = guide
        self._human_note = ""
        self._held_s = 0.0
        s = self.settings
        s.output_dir.mkdir(parents=True, exist_ok=True)
        audit = AuditLog(s.audit_dir, session_id=session_id, user=self.user)
        checkpoints = CheckpointStore(audit.dir)
        deadline = time.time() + s["limits"]["task_timeout_s"]
        approvals: list[dict] = []
        params = dict(params or {})
        audit.event("task_started", request=request, playbook=playbook.name if playbook else None, params=params, tiers={k: v[0] for k, v in self.router.status().items()})

        try:
            plan = self._make_plan(request, playbook, params, audit)
        except ModelError as e:
            audit.event("task_failed", error=str(e))
            return TaskResult("failed", audit.session_id, [], message=f"planning failed: {e}", usage=self._usage())

        if plan.questions:
            answers = self.ask(plan.questions) if self.ask else None
            if not answers:
                audit.event("needs_input", questions=plan.questions)
                return TaskResult("needs_input", audit.session_id, [], questions=plan.questions, message="the agent needs answers before it starts", usage=self._usage())
            params.update(answers)
            plan = self._make_plan(request + "\nAnswers: " + json.dumps(answers), playbook, params, audit)
            if plan.questions:
                return TaskResult("needs_input", audit.session_id, [], questions=plan.questions, usage=self._usage())
        params.update(plan.params)

        policy = PolicyEngine(s, playbook.permissions if playbook else None)
        amounts = {st.id: st.approval_amount for st in plan.steps if st.approval_amount}
        ctx = ToolContext(s, policy, audit, _StepAmountApprover(self.approver, amounts) if amounts else self.approver, workdir=audit.dir / "scratch", params=params)

        if self.require_plan_approval:
            preview = "\n".join(f"{i + 1}. [{st.tier}] {st.intent}" + (("  (needs approval" + (f", amount {st.approval_amount}" if st.approval_amount else "") + ")") if st.approval == "required" or policy.needs_approval(st.action_class) else "") for i, st in enumerate(plan.steps))
            fp = plan_fingerprint(request, playbook, plan, params, preview)
            if not self._approve(audit, approvals, ApprovalRequest("plan", "plan", f"Plan for: {request}", preview, fingerprint=fp)):
                return TaskResult("rejected", audit.session_id, [], message="plan was not approved", usage=self._usage(), approvals=approvals)

        records = [StepRecord(st) for st in plan.steps]
        done_ids: set[str] = set()
        if resume and (cp := checkpoints.load()):
            done_ids = set(cp.get("verified_steps", []))
            for r in records:
                if r.step.id in done_ids:
                    r.status = "verified"
                    r.summary = "restored from checkpoint"
            audit.event("resumed", verified_steps=sorted(done_ids))

        replans = 0
        i = 0
        while i < len(records):
            rec = records[i]
            i += 1
            if rec.status == "verified":
                continue
            if self._stop_requested(audit):
                rec.status = "blocked"
                rec.summary = "stopped by kill switch"
                break
            if not self._wait_if_paused(audit, rec.step.id):
                rec.status = "blocked"
                rec.summary = self._pause_end
                break
            if time.time() > deadline + self._held_s:  # time held by a human takeover does not count
                rec.status = "failed"
                rec.summary = "task time-out reached"
                break
            self._run_step(rec, records, ctx, policy, audit, approvals, deadline)
            if rec.status == "verified":
                done_ids.add(rec.step.id)
                checkpoints.save(redact({"request": request, "verified_steps": sorted(done_ids), "params": params, "files": [f for r in records for f in r.files]}, audit))
                continue
            if rec.status in ("rejected", "skipped"):
                continue  # a declined action is reported, never forced
            # Step failed after retries: re-plan the remaining work once, then stop and ask.
            if replans < s["limits"]["max_replans"] and playbook is None:
                replans += 1
                try:
                    new = self.planner.plan(request, self.router.available_names(), knowledge=self._knowledge(), failure=rec.summary + "\n" + (rec.verdict.failure_text() if rec.verdict else ""), done_steps=sorted(done_ids))
                except ModelError as e:
                    audit.event("replan_failed", error=str(e))
                    break
                audit.event("replanned", steps=[st.to_dict() for st in new.steps])
                records = [r for r in records if r.status == "verified"] + [StepRecord(st) for st in new.steps]
                plan.final_checks = new.final_checks  # final checks must match the new steps
                i = len([r for r in records if r.status == "verified"])
                continue
            rec.status = "blocked"
            break

        final = None
        all_verified = all(r.status == "verified" for r in records)
        if all_verified and plan.final_checks:
            files = [f for r in records for f in r.files]
            try:
                final = self.verifier.verify(f"Final output of: {request}", plan.final_checks, s.workspace_root, files=files)
            except ModelError as e:
                final = Verdict(False, [], f"final verification failed: {e}")
            audit.event("final_verdict", passed=final.passed, outcomes=[o.to_dict() for o in final.outcomes])

        if all_verified and (final is None or final.passed):
            status = "success"
        elif any(r.status == "blocked" for r in records):
            status = "blocked"
        elif any(r.status in ("rejected", "skipped") for r in records) and not any(r.status == "failed" for r in records):
            status = "partial"
        else:
            status = "failed"
        questions = []
        blocked = next((r for r in records if r.status == "blocked"), None)
        if blocked:
            questions = [f"Step '{blocked.step.intent}' could not be completed: {blocked.summary[:500]}. How should I proceed?"]
        result = TaskResult(status, audit.session_id, records, final, questions, usage=self._usage(), approvals=approvals)
        result.report_path = str(write_report(result, request, s, audit))
        audit.event("task_finished", status=status, report=result.report_path, usage=result.usage)
        return result

    def _usage(self) -> dict:
        u = self.client.usage
        return {"calls": u.calls, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens, "cache_read_tokens": u.cache_read_tokens, "by_model": u.by_model}

    def _make_plan(self, request: str, playbook: Playbook | None, params: dict, audit: AuditLog) -> Plan:
        if playbook:
            invalid = playbook.invalid_params(params)
            if invalid:
                # A value that does not fit its declared shape never reaches a step (SQL, code, file names, UI).
                # Drop it and ask for a valid one; the model is not allowed to guess what was meant.
                audit.event("params_invalid", params={k: {"value": str(params[k])[:200], "reason": r} for k, r in invalid.items()})
                for k in invalid:
                    params.pop(k, None)
                return Plan([], [], [f"The value given for '{k}' {r}. Please give a valid value for '{k}'." for k, r in invalid.items()], {}, "playbook")
            missing = [k for k, spec in playbook.parameters.items() if spec.get("required", True) and k not in params and "default" not in spec]
            if missing:
                # Let the planner read parameter values out of the request text.
                try:
                    plan = self.planner.plan(request, self.router.available_names(), playbook=playbook.to_dict(), knowledge=self._knowledge())
                except ModelError as e:
                    # No model to read the request: ask for the values instead of failing.
                    audit.event("planner_unavailable", error=str(e)[:500])
                    audit.event("params_missing", params=missing)
                    return Plan([], [], [f"Please give a value for '{k}'" for k in missing], {}, "playbook")
                params.update({k: v for k, v in plan.params.items() if k in playbook.parameters})
                invalid = playbook.invalid_params(params)
                if invalid:
                    audit.event("params_invalid", source="planner", params={k: {"value": str(params[k])[:200], "reason": r} for k, r in invalid.items()})
                    for k in invalid:
                        params.pop(k, None)
                still = [k for k in missing if k not in params]
                if still:
                    audit.event("params_missing", params=still)
                    return Plan([], [], plan.questions or [f"Please give a value for '{k}'" for k in still], {}, "playbook")
            bound = playbook.bind(params)
            audit.event("plan", source="playbook", playbook=bound.name, version=bound.version, steps=[st.to_dict() for st in bound.steps], final_checks=bound.final_checks)
            return Plan(bound.steps, bound.final_checks, [], {}, "playbook")
        guide = getattr(self, "_guide", None)
        plan = self.planner.plan(request, self.router.available_names(), playbook=guide.to_dict() if guide else None, knowledge=self._knowledge())
        audit.event("plan", source="planner", guide=guide.name if guide else None, questions=plan.questions, steps=[st.to_dict() for st in plan.steps], final_checks=plan.final_checks)
        return plan

    # ------------------------------------------------------------------ one step
    def _run_step(self, rec: StepRecord, records: list[StepRecord], ctx: ToolContext, policy: PolicyEngine, audit: AuditLog, approvals: list, deadline: float) -> None:
        step = rec.step
        ctx.step_id = step.id
        audit.event("step_started", step=step.id, intent=step.intent, tier=step.tier)
        if step.approval == "required" or policy.needs_approval(step.action_class):
            preview = json.dumps(step.script or {"instructions": step.instructions}, indent=1)[:3000]
            if not self._approve(audit, approvals, ApprovalRequest(step.id, step.action_class or "approval", f"Step: {step.intent}", preview, amount=step.approval_amount)):
                rec.status = "rejected"
                last = approvals[-1]
                rec.summary = f"not approved (decided by {last['by']}); nothing was done"
                audit.event("step_rejected", step=step.id)
                return
        try:
            route = self.router.route(step.tier)
        except RouteError as e:
            rec.status = "blocked"
            rec.summary = str(e)
            audit.event("step_blocked", step=step.id, reason=str(e))
            return
        rec.tier_used, rec.route_note = route.tier.name, route.note
        prior = "\n".join(f"- {r.step.id}: {r.summary[:600]} files={r.files}" for r in records if r.status == "verified")
        error = ""
        scripted_failure = ""
        max_attempts = 1 + self.settings["limits"]["max_step_retries"] + (1 if step.script else 0)
        while rec.attempts < max_attempts:
            # A takeover may have started while this step waited for its approval.
            if not self._wait_if_paused(audit, step.id):
                rec.status, rec.summary = "blocked", self._pause_end
                return
            rec.attempts += 1
            if step.script and rec.attempts == 1 and route.requested == route.tier.name:
                run = self._run_script(step, route.tier, ctx)
            else:
                try:
                    run = Executor(self.client).run(step, route.tier, ctx, prior=prior, error=error, deadline=lambda: deadline + self._held_s, stop_flag=lambda: self._stop_requested(audit),
                                                   pause_hook=lambda: self._pause_hook(audit, step.id), paused=lambda: (audit.dir / PAUSE_FILE).exists())
                except ModelError as e:
                    # Keep the real cause from the scripted attempt; the model retry is only a fallback.
                    first = f"{scripted_failure}; " if scripted_failure else ""
                    run = StepRun("failed", f"{first}guided retry unavailable (model call failed: {e})")
            if step.script and rec.attempts == 1 and run.status != "done":
                scripted_failure = f"scripted run failed: {run.summary[:1500]}"
            rec.summary = run.summary
            rec.files = list(dict.fromkeys(rec.files + run.files))
            if run.status == "blocked" and ("kill switch" in run.summary or run.summary.startswith("stopped: human takeover")):
                rec.status = "blocked"
                return
            try:
                if not step.checks and step.no_check_reason:
                    # Reviewed exception (teach-mode drafts): the step passes if it ran without error.
                    verdict = Verdict(run.status == "done", [CheckOutcome("no check (reviewed)", run.status == "done", step.no_check_reason)])
                else:
                    verdict = self.verifier.verify(step.intent, step.checks, self.settings.workspace_root, run.summary, rec.files, run.last_screenshot)
            except ModelError as e:
                verdict = Verdict(False, [], f"verifier call failed: {e}")
            rec.verdict = verdict
            audit.event("step_verdict", step=step.id, attempt=rec.attempts, passed=verdict.passed, outcomes=[o.to_dict() for o in verdict.outcomes], problems=verdict.problems)
            if verdict.passed:
                rec.status = "verified"
                return
            error = f"Executor said: {run.summary[-1500:]}\nFailed checks:\n{verdict.failure_text()}"
        rec.status = "failed"

    def _run_script(self, step: Step, tier, ctx: ToolContext) -> StepRun:
        """Scripted replay of a proven step: no model call; the checks still decide."""
        script = step.script or {}
        kind = script.get("kind", "python")
        ctx.audit.event("scripted_step", step=step.id, kind=kind)
        try:
            if kind == "python":
                out = run_python(script["code"], ctx)
            elif kind == "tool":
                out = tier.execute({"name": script["tool"], "input": script.get("input", {})}, ctx)
            elif kind == "tools":  # a fixed sequence of tool calls on one tier; stops at the first error
                texts, written, failed = [], [], False
                for call in script.get("calls", []):
                    if (ctx.audit.dir / PAUSE_FILE).exists():
                        # A human took over mid-sequence: the screen no longer matches the script.
                        # Fail this attempt; the guided retry waits for the hand-back and gets the note.
                        texts.append("interrupted: a human took over this session during the scripted sequence")
                        failed = True
                        break
                    o = tier.execute({"name": call["tool"], "input": call.get("input", {})}, ctx)
                    texts.append(f"{call['tool']}: {o.text}")
                    written += o.files
                    if o.is_error:
                        failed = True
                        break
                out = ToolOutput("\n".join(texts), is_error=failed, files=written)
            else:
                out = ToolOutput(f"Error: unknown script kind {kind}", is_error=True)
        except Exception as e:  # a policy refusal or tool crash fails the step; it never crashes the task
            ctx.audit.event("scripted_step_error", step=step.id, error=f"{type(e).__name__}: {str(e)[:500]}")
            out = ToolOutput(f"Error: {type(e).__name__}: {str(e)[:1000]}", is_error=True)
        files = list(out.files) + [c["path"] for c in step.checks if c.get("type") == "file_exists"]
        return StepRun("failed" if out.is_error else "done", redact(out.text, ctx.audit), files)
