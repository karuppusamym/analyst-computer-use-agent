"""Task orchestrator: clarify -> plan -> plan approval -> steps (route, run, verify,
checkpoint, recover) -> final verification -> "what I checked" report.

Recovery ladder per step: scripted replay -> guided executor -> retry once with
the error -> re-plan the rest -> stop and ask the human a precise question.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .agents import Executor, Plan, Planner, StepRun, Verdict, Verifier
from .audit import AuditLog
from .checkpoint import CheckpointStore
from .config import Settings
from .model import ModelClient, ModelError
from .playbook import Playbook, Step
from .policy import ApprovalRequest, Approver, ConsoleApprover, PolicyEngine
from .report import write_report
from .router import RouteError, Router
from .tools.base import ToolContext, ToolOutput
from .tools.code import run_python


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

    # ------------------------------------------------------------------ helpers
    def _knowledge(self) -> str:
        if not self.knowledge_dir or not self.knowledge_dir.exists():
            return ""
        return "\n\n".join(p.read_text(encoding="utf-8")[:6000] for p in sorted(self.knowledge_dir.glob("*.md")))

    def _approve(self, audit: AuditLog, approvals: list, req: ApprovalRequest) -> bool:
        audit.event("approval_requested", step=req.step_id, action_class=req.action_class, summary=req.summary)
        decision = self.approver.request(req)
        audit.event("approval_decided", step=req.step_id, approved=decision.approved, by=decision.by, note=decision.note)
        approvals.append({"step": req.step_id, "action": req.action_class, "approved": decision.approved, "by": decision.by})
        return decision.approved

    def _stop_requested(self, audit: AuditLog) -> bool:
        return (audit.dir / "STOP").exists() or (self.settings.workspace_root / "STOP").exists()

    # ------------------------------------------------------------------ main entry
    def run(self, request: str, playbook: Playbook | None = None, params: dict | None = None, session_id: str | None = None, resume: bool = False) -> TaskResult:
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
        ctx = ToolContext(s, policy, audit, self.approver, workdir=audit.dir / "scratch", params=params)

        if self.require_plan_approval:
            preview = "\n".join(f"{i + 1}. [{st.tier}] {st.intent}" + ("  (needs approval)" if st.approval == "required" or policy.needs_approval(st.action_class) else "") for i, st in enumerate(plan.steps))
            if not self._approve(audit, approvals, ApprovalRequest("plan", "plan", f"Plan for: {request}", preview)):
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
            if time.time() > deadline:
                rec.status = "failed"
                rec.summary = "task time-out reached"
                break
            self._run_step(rec, records, ctx, policy, audit, approvals, deadline)
            if rec.status == "verified":
                done_ids.add(rec.step.id)
                checkpoints.save({"request": request, "verified_steps": sorted(done_ids), "params": params, "files": [f for r in records for f in r.files]})
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
            missing = [k for k, spec in playbook.parameters.items() if spec.get("required", True) and k not in params and "default" not in spec]
            if missing:
                # Let the planner read parameter values out of the request text.
                plan = self.planner.plan(request, self.router.available_names(), playbook=playbook.to_dict(), knowledge=self._knowledge())
                params.update({k: v for k, v in plan.params.items() if k in playbook.parameters})
                still = [k for k in missing if k not in params]
                if still:
                    return Plan([], [], plan.questions or [f"Please give a value for '{k}'" for k in still], {}, "playbook")
            bound = playbook.bind(params)
            audit.event("plan", source="playbook", playbook=bound.name, version=bound.version, steps=[st.to_dict() for st in bound.steps])
            return Plan(bound.steps, bound.final_checks, [], {}, "playbook")
        plan = self.planner.plan(request, self.router.available_names(), knowledge=self._knowledge())
        audit.event("plan", source="planner", questions=plan.questions, steps=[st.to_dict() for st in plan.steps])
        return plan

    # ------------------------------------------------------------------ one step
    def _run_step(self, rec: StepRecord, records: list[StepRecord], ctx: ToolContext, policy: PolicyEngine, audit: AuditLog, approvals: list, deadline: float) -> None:
        step = rec.step
        ctx.step_id = step.id
        audit.event("step_started", step=step.id, intent=step.intent, tier=step.tier)
        if step.approval == "required" or policy.needs_approval(step.action_class):
            preview = json.dumps(step.script or {"instructions": step.instructions}, indent=1)[:3000]
            if not self._approve(audit, approvals, ApprovalRequest(step.id, step.action_class or "approval", f"Step: {step.intent}", preview)):
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
        max_attempts = 1 + self.settings["limits"]["max_step_retries"] + (1 if step.script else 0)
        while rec.attempts < max_attempts:
            rec.attempts += 1
            if step.script and rec.attempts == 1 and route.requested == route.tier.name:
                run = self._run_script(step, route.tier, ctx)
            else:
                try:
                    run = Executor(self.client).run(step, route.tier, ctx, prior=prior, error=error, deadline=deadline, stop_flag=lambda: self._stop_requested(audit))
                except ModelError as e:
                    run = StepRun("failed", f"model call failed: {e}")
            rec.summary = run.summary
            rec.files = list(dict.fromkeys(rec.files + run.files))
            if run.status == "blocked" and "kill switch" in run.summary:
                rec.status = "blocked"
                return
            try:
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
        if kind == "python":
            out = run_python(script["code"], ctx)
        elif kind == "tool":
            out = tier.execute({"name": script["tool"], "input": script.get("input", {})}, ctx)
        else:
            out = ToolOutput(f"Error: unknown script kind {kind}", is_error=True)
        files = list(out.files) + [c["path"] for c in step.checks if c.get("type") == "file_exists"]
        return StepRun("failed" if out.is_error else "done", out.text, files)
