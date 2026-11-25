"""Command line.

  python -m analyst_agent status
  python -m analyst_agent gateway-check
  python -m analyst_agent playbooks
  python -m analyst_agent run "Reconcile October" --playbook erp-crm-reconciliation --param period=2026-10
  python -m analyst_agent run "Q3 churn by region?"            (planner builds the steps; needs the model)
  python -m analyst_agent eval [--split holdout]
  python -m analyst_agent stop <session-id>                     (kill switch)
  python -m analyst_agent portal [--host 127.0.0.1] [--port 8765] (web portal)
  python -m analyst_agent portal-user add <name> --role analyst|reviewer|admin
  python -m analyst_agent vault set <name> --allow-host h       (value is prompted, never on argv)
  python -m analyst_agent vault list | vault remove <name>
  python -m analyst_agent teach from-session|record|promote|drafts   (draft playbooks; see teach.py)
  python -m analyst_agent schedule list|add|remove|run-due|daemon|install-hint   (see scheduler.py)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_settings
from .gateway_check import config_error, format_results, run_gateway_check, write_report
from .orchestrator import Orchestrator
from .playbook import PlaybookRegistry
from .policy import ConsoleApprover, UnattendedApprover
from .router import Router
from . import scheduler, teach

ROOT = Path(__file__).resolve().parent.parent


def _settings(args):
    cfg = args.config or (ROOT / "config" / "default.json")
    s = load_settings(cfg)
    if getattr(args, "enable_desktop", False):
        s.data["tiers"]["desktop_pixels"]["enabled"] = True
    if getattr(args, "dry_run_desktop", False):
        s.data["tiers"]["desktop_pixels"]["enabled"] = True
        s.data["tiers"]["desktop_pixels"]["dry_run"] = True
    return s


def _ask_console(questions: list[str]) -> dict[str, str] | None:
    print("\nThe agent needs some information first:")
    answers = {}
    for q in questions:
        a = input(f"- {q}\n  > ").strip()
        if not a:
            return None
        answers[q] = a
    return answers


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="analyst_agent")
    ap.add_argument("--config", help="settings JSON (default config/default.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="show which tool tiers are available")
    gw = sub.add_parser("gateway-check", help="run the 5-check gateway test (costs a few cents); exit 0 ok, 1 a check failed, 2 config error")
    gw.add_argument("--report", help="where to write the JSON report (default workspace/gateway_report.json)")
    sub.add_parser("playbooks", help="list playbooks")
    run = sub.add_parser("run", help="run a task")
    run.add_argument("request")
    run.add_argument("--playbook")
    run.add_argument("--param", action="append", default=[], help="name=value")
    run.add_argument("--unattended", action="store_true", help="no human present: approvals are declined and reported")
    run.add_argument("--resume", metavar="SESSION", help="resume a session from its last checkpoint")
    run.add_argument("--enable-desktop", action="store_true", help="allow the pixel tier (only on an isolated machine or with the window allowlist)")
    run.add_argument("--dry-run-desktop", action="store_true", help="pixel tier logs actions without sending input")
    ev = sub.add_parser("eval", help="run the evaluation set")
    ev.add_argument("--split", choices=["tune", "holdout"])
    ev.add_argument("--tasks", default=str(ROOT / "evals" / "tasks.json"))
    st = sub.add_parser("stop", help="kill switch for a running session")
    st.add_argument("session")
    from .portal.cli import add_parsers as _portal_parsers

    _portal_parsers(sub)

    from .vault import add_cli as _add_vault_cli

    _add_vault_cli(sub)

    teach.add_cli(sub)
    scheduler.add_cli(sub)
    args = ap.parse_args(argv)

    s = _settings(args)
    registry = PlaybookRegistry(ROOT / "playbooks")

    if args.cmd == "status":
        for name, (ok, why) in Router(s).status().items():
            print(f"{name:<15} {'available' if ok else 'unavailable'}  {'' if ok else why}")
        print(f"\nmodel backend: {s['gateway']['backend']}  gateway: {s['gateway']['base_url']}  token set: {bool(s.gateway_token())}")
        return 0
    if args.cmd == "gateway-check":
        problem = config_error(s)
        if problem:
            print(f"gateway-check: configuration error: {problem}")
            return 2
        results = run_gateway_check(s)
        print(format_results(results))
        report = write_report(results, s, Path(args.report) if args.report else s.workspace_root / "gateway_report.json")
        print(f"\nreport for the gateway team: {report}")
        return 0 if all(r.passed for r in results) else 1
    if args.cmd == "playbooks":
        for pb in registry.all():
            print(f"{pb.name:<28} v{pb.version}  owner={pb.owner:<18} steps={len(pb.steps)}  params={list(pb.parameters)}")
        return 0
    if args.cmd == "vault":
        from .vault import run_cli

        return run_cli(args, s)
    if args.cmd == "stop":
        d = s.audit_dir / args.session
        if not d.exists():
            print(f"no session {args.session}")
            return 1
        (d / "STOP").write_text("stop requested\n")
        print(f"stop requested for {args.session}; the agent stops before its next action")
        return 0
    if args.cmd == "portal":
        from .portal.cli import run_portal_cmd

        return run_portal_cmd(args, s, ROOT)
    if args.cmd == "portal-user":
        from .portal.cli import run_user_cmd

        return run_user_cmd(args, s)
    if args.cmd == "teach":
        return teach.cli(args, s, ROOT)
    if args.cmd == "schedule":
        return scheduler.cli(args, s, ROOT)
    if args.cmd == "eval":
        from .evals import format_eval, run_evals

        outcomes, summary = run_evals(s, args.tasks, ROOT / "playbooks", split=args.split)
        print(format_eval(outcomes, summary))
        return 0 if summary["pilot_gate_met"] else 1
    if args.cmd == "run":
        params = dict(p.split("=", 1) for p in args.param)
        pb = registry.get(args.playbook) if args.playbook else None
        guide = None if pb else registry.match(args.request)
        if guide:
            print(f"matching playbook {guide.name} v{guide.version} given to the planner as a guide")
        approver = UnattendedApprover() if args.unattended else ConsoleApprover()
        orch = Orchestrator(s, approver=approver, ask=None if args.unattended else _ask_console, knowledge_dir=ROOT / "knowledge", require_plan_approval=not args.unattended)
        try:
            result = orch.run(args.request, playbook=pb, params=params, session_id=args.resume, resume=bool(args.resume), guide=guide)
        finally:
            orch.router.close()
        print(f"\nstatus: {result.status}   session: {result.session_id}")
        for r in result.records:
            print(f"  [{r.status:<8}] {r.step.id} ({r.tier_used or r.step.tier})")
        if result.questions:
            print("questions:\n  " + "\n  ".join(result.questions))
        if result.report_path:
            print(f"report: {result.report_path}")
        print("usage: " + json.dumps({k: v for k, v in result.usage.items() if k != "by_model"}))
        return 0 if result.status in ("success", "partial") else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
