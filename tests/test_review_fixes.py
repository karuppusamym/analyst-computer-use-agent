"""Regressions for the safety review of 25 Nov 2026: control files behind the file tools,
the kill switch inside scripted sequences and tool batches, fail-closed action classes,
resume against changed inputs, re-approval of replans, URL spellings and redaction forms."""

from __future__ import annotations

import json

from analyst_agent.agents import Executor
from analyst_agent.audit import AuditLog, Redactor
from analyst_agent.model import mock_text
from analyst_agent.playbook import Step
from analyst_agent.policy import PolicyEngine, PolicyViolation, UnattendedApprover, normalize_action_class
from analyst_agent.tools.base import Tier, Tool, ToolContext, ToolOutput, schema
from analyst_agent.tools.connectors import ConnectorTier

from .test_core import Base, plan_json


class ControlFileTests(Base):
    def test_file_tools_cannot_reach_control_files(self):
        p = PolicyEngine(self.s)
        ws = self.s.workspace_root
        for target in [ws / "portal_secret.key", ws / "portal_users.json", ws / "portal_state" / "a.json",
                       ws / "portal_audit" / "portal" / "events.jsonl", ws / "schedules" / "state.json", ws / "portal_sso_groups.json",
                       self.s.audit_dir / "sess" / "checkpoint.json", self.s.audit_dir / "sess" / "STOP", self.s.audit_dir]:
            with self.assertRaises(PolicyViolation, msg=str(target)):
                p.check_path(target)
            with self.assertRaises(PolicyViolation, msg=str(target)):
                p.check_path(target, write=True)
        # A session's scratch folder (the code tier's work folder) and the outputs stay open.
        p.check_path(self.s.audit_dir / "sess" / "scratch" / "x.csv", write=True)
        p.check_path(self.s.output_dir / "x.csv", write=True)
        p.check_path(ws / "legacy_ledger.csv")

    def test_copy_file_ignores_hidden_overwrite_flag(self):
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), UnattendedApprover())
        self.s.output_dir.mkdir(parents=True, exist_ok=True)
        dst = self.s.output_dir / "keep.csv"
        dst.write_text("original", encoding="utf-8")
        src = self.ws.root / "samples" / "crm_export_2026-10.csv"
        out = ConnectorTier(self.s).execute({"name": "copy_file", "input": {"source": str(src), "destination": str(dst), "overwrite_output": True}}, ctx)
        self.assertTrue(out.is_error)
        self.assertEqual(dst.read_text(encoding="utf-8"), "original")


class ActionClassTests(Base):
    def test_fails_closed_on_unknown_and_maps_synonyms(self):
        p = PolicyEngine(self.s)
        for cls in ("send", "Send", " SEND ", "email", "submit_form", "Payment", "upload", "wire_money"):
            self.assertTrue(p.needs_approval(cls), cls)
        for cls in (None, "", "none", "None", "read"):
            self.assertFalse(p.needs_approval(cls), cls)
        self.assertEqual(normalize_action_class("Submit-Form"), "submit")

    def test_config_can_still_leave_a_known_class_ungated(self):
        self.s.data["policy"]["approval_required"] = ["send"]
        p = PolicyEngine(self.s)
        self.assertFalse(p.needs_approval("delete"))
        self.assertTrue(p.needs_approval("teleport"))  # unknown stays gated

    def test_planner_step_with_odd_class_is_gated(self):
        steps = [{"id": "s1", "intent": "mail it", "tier": "code", "action_class": "Email", "checks": [{"type": "file_exists", "path": "output/x.txt"}]}]
        o, _, _ = self.orch([plan_json(steps)])
        r = o.run("mail the numbers")
        self.assertEqual(r.records[0].status, "rejected")


class UrlTests(Base):
    def test_ambiguous_urls_refused(self):
        self.s.data["policy"]["allowed_hosts"] = ["allowed.example.com"]
        p = PolicyEngine(self.s)
        p.check_url("https://allowed.example.com/x?q=1")
        for url in ("https://evil.example\\@allowed.example.com/", "https://user:pw@allowed.example.com/", "https://allowed.example.com /",
                    "javascript:alert(1)", "file:///C:/x", "https://allowed.example.com/\t"):
            with self.assertRaises(PolicyViolation, msg=url):
                p.check_url(url)


class RedactionTests(Base):
    def test_repr_form_is_redacted(self):
        r = Redactor()
        secret = "a'b\"c\\d"
        r.add("pw", secret)
        self.assertNotIn(repr(secret)[1:-1], r.text(f"value={secret!r}"))


class StopTests(Base):
    def test_stop_between_scripted_calls(self):
        calls = []
        audit_holder = {}

        class Tick(Tier):
            name = "connector"
            rank = 1

            def tools(self):
                def fn(inp, ctx):
                    calls.append(inp["n"])
                    if inp["n"] == 1:
                        (ctx.audit.dir / "STOP").write_text("x", encoding="utf-8")
                    return ToolOutput("ok")

                return [Tool("tick", "t", schema({"n": {"type": "integer"}}), fn, self.name)]

        o, _, _ = self.orch()
        step = Step(id="s1", intent="ticks", tier="connector", script={"kind": "tools", "calls": [{"tool": "tick", "input": {"n": i}} for i in (1, 2, 3)]}, checks=[])
        audit = AuditLog(self.s.audit_dir, session_id="stop-test")
        audit_holder["a"] = audit
        ctx = ToolContext(self.s, PolicyEngine(self.s), audit, UnattendedApprover(), step_id="s1", workdir=audit.dir / "scratch")
        run = o._run_script(step, Tick(self.s), ctx, stop=lambda: o._stop_requested(audit))
        self.assertEqual(calls, [1])
        self.assertEqual(run.status, "blocked")
        self.assertIn("kill switch", run.summary)

    def test_stop_inside_executor_batch(self):
        done = []

        class Tick(Tier):
            name = "connector"
            rank = 1

            def tools(self):
                return [Tool("tick", "t", schema({"n": {"type": "integer"}}), lambda inp, ctx: done.append(inp["n"]) or ToolOutput("ok"), self.name)]

        pressed = {"v": False}
        ex = Executor(self.ws.client()[0])
        ex.stop_flag = lambda: pressed["v"]
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), UnattendedApprover(), step_id="s", workdir=self.s.workspace_root)
        tier = Tick(self.s)
        orig = tier.execute

        def execute(block, c):
            out = orig(block, c)
            pressed["v"] = True  # the kill switch is pressed after the first call
            return out

        tier.execute = execute
        uses = [{"id": f"t{i}", "name": "tick", "input": {"n": i}} for i in range(3)]
        results, _, _ = ex._run_tools(uses, tier, ctx)
        self.assertEqual(done, [0])
        self.assertTrue(results[1]["is_error"] and "kill switch" in results[1]["content"])


class ResumeTests(Base):
    def test_resume_refused_when_params_change(self):
        o, _, _ = self.orch()
        pb = self.registry.get("erp-crm-reconciliation")
        r = o.run("reconcile", playbook=pb, params={"period": "2026-11"}, session_id="sess-r")
        self.assertEqual(r.status, "partial")
        o2, _, _ = self.orch(approvals=[True])
        r2 = o2.run("reconcile", playbook=pb, params={"period": "2026-10"}, session_id="sess-r", resume=True)
        self.assertEqual(r2.status, "failed")
        self.assertIn("parameters changed", r2.message)
        r3 = o2.run("something else", playbook=pb, params={"period": "2026-11"}, session_id="sess-r", resume=True)
        self.assertIn("request differs", r3.message)


class ReplanApprovalTests(Base):
    def test_replanned_steps_need_approval_again(self):
        bad = [{"id": "s1", "intent": "make file", "tier": "code", "checks": [{"type": "file_exists", "path": "output/never.txt"}]}]
        new = [{"id": "s2", "intent": "other way", "tier": "code", "checks": [{"type": "file_exists", "path": "output/never2.txt"}]}]
        script = [plan_json(bad), mock_text("RESULT: blocked - cannot"), mock_text("RESULT: blocked - still cannot"), plan_json(new)]
        o, _, approver = self.orch(script, approvals=[True, False], plan_approval=True)
        r = o.run("make a file")
        self.assertEqual([q.step_id for q in approver.seen], ["plan", "replan"])
        self.assertEqual(r.status, "blocked")
        self.assertIn("revised plan was not approved", r.records[0].summary)
