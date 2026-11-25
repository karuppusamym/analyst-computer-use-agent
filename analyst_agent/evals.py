"""Evaluation set runner. No change ships unless the eval set passes at the
same or better success rate (design doc, Evaluation and success metrics).

Each task in evals/tasks.json:
  {"id", "workflow", "split": "tune"|"holdout", "request", "playbook"?, "params"?,
   "graders": [check specs], "expect_status": "success", "manual_minutes": 30}
Graders are the same check types as playbook checks, run after the task on
the workspace, independent of what the agent's own verifier said.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .checks import run_deterministic
from .config import Settings
from .orchestrator import Orchestrator, TaskResult
from .playbook import PlaybookRegistry
from .policy import UnattendedApprover

# A rough per-token price table (USD per million tokens) for the cost metric.
PRICES = {
    "claude-fable-5-2": (8.0, 40.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}


@dataclass
class EvalOutcome:
    task_id: str
    split: str
    status: str
    graded_pass: bool
    verified_wrong: bool
    unapproved_outbound: int
    interventions: int
    seconds: float
    cost_usd: float
    grader_details: list[str] = field(default_factory=list)


def _cost(usage: dict) -> float:
    total = 0.0
    for model, u in usage.get("by_model", {}).items():
        # OpenRouter names models like "anthropic/claude-opus-5.5".
        key = model.split("/")[-1].replace(".", "-")
        pin, pout = PRICES.get(key, (0.0, 0.0))
        total += (u["input"] * pin + u["output"] * pout + u.get("cache_read", 0) * pin * 0.1) / 1e6
    return total


def _unapproved_outbound(session_dir: Path) -> int:
    """Outbound actions recorded without a preceding approval in the same step."""
    events_path = session_dir / "events.jsonl"
    if not events_path.exists():
        return 0
    count = 0
    for line in events_path.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        if e["kind"] == "outbound_action" and e.get("approved") is not True:
            count += 1
    return count


def run_evals(
    settings: Settings,
    tasks_path: str | Path,
    playbooks_dir: str | Path,
    make_orchestrator: Callable[[Settings], Orchestrator] | None = None,
    split: str | None = None,
    reset_output: bool = True,
) -> tuple[list[EvalOutcome], dict]:
    tasks = json.loads(Path(tasks_path).read_text(encoding="utf-8"))
    registry = PlaybookRegistry(playbooks_dir)
    outcomes: list[EvalOutcome] = []
    for t in tasks:
        if split and t.get("split", "tune") != split:
            continue
        if reset_output and settings.output_dir.exists():
            shutil.rmtree(settings.output_dir)
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        orch = make_orchestrator(settings) if make_orchestrator else Orchestrator(settings, approver=UnattendedApprover(), require_plan_approval=False)
        pb = registry.get(t["playbook"]) if t.get("playbook") else None
        start = time.time()
        result = None
        try:
            result: TaskResult = orch.run(t["request"], playbook=pb, params=t.get("params"), session_id=f"eval-{t['id']}-{int(start)}")
            status = result.status
            usage = result.usage
            session_dir = settings.audit_dir / result.session_id
        except Exception as e:
            status, usage, session_dir = f"crashed: {e}", {}, settings.audit_dir
        graded, _ = run_deterministic(t.get("graders", []), settings.workspace_root)
        graded_pass = bool(graded) and all(o.passed for o in graded)
        expected = t.get("expect_status", "success")
        ok = graded_pass and status == expected
        outcomes.append(
            EvalOutcome(
                task_id=t["id"],
                split=t.get("split", "tune"),
                status=status,
                graded_pass=ok,
                verified_wrong=status == "success" and not graded_pass,
                unapproved_outbound=_unapproved_outbound(session_dir),
                interventions=len(result.approvals) if result else 0,
                seconds=time.time() - start,
                cost_usd=_cost(usage),
                grader_details=[f"[{'PASS' if o.passed else 'FAIL'}] {o.name}: {o.detail}" for o in graded],
            )
        )
        orch.router.close()
    return outcomes, summarize(outcomes)


def summarize(outcomes: list[EvalOutcome]) -> dict:
    n = len(outcomes) or 1
    successes = sum(o.graded_pass for o in outcomes)
    return {
        "tasks": len(outcomes),
        "task_success_rate": successes / n,
        "verified_wrong_rate": sum(o.verified_wrong for o in outcomes) / n,
        "unapproved_outbound_actions": sum(o.unapproved_outbound for o in outcomes),
        "human_interventions_per_task": sum(o.interventions for o in outcomes) / n,
        "cost_per_successful_task_usd": (sum(o.cost_usd for o in outcomes) / successes) if successes else None,
        "pilot_gate_met": (successes / n) >= 0.85 and sum(o.unapproved_outbound for o in outcomes) == 0,
    }


def format_eval(outcomes: list[EvalOutcome], summary: dict) -> str:
    lines = [f"{'task':<28} {'split':<8} {'status':<12} {'graded':<7} {'sec':>6} {'cost$':>8}"]
    for o in outcomes:
        lines.append(f"{o.task_id:<28} {o.split:<8} {o.status[:12]:<12} {'PASS' if o.graded_pass else 'FAIL':<7} {o.seconds:6.1f} {o.cost_usd:8.4f}")
        if not o.graded_pass:
            lines += [f"    {d}" for d in o.grader_details if d.startswith("[FAIL")]
    lines.append("")
    lines += [f"{k}: {v}" for k, v in summary.items()]
    return "\n".join(lines)
