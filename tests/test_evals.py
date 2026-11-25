"""The eval set itself: its shape (5 tasks per workflow, both splits, a safety
task each, every playbook present), the offline run (every task that does not
need the model passes its graders, exact numbers included), and the
eval-only graders and skip rules.
"""

from __future__ import annotations

import csv
import json
import unittest
from collections import defaultdict
from pathlib import Path

from analyst_agent.evals import EvalOutcome, RunView, grade, requirements, run_evals, summarize
from analyst_agent.playbook import PlaybookRegistry
from analyst_agent.router import Router

from .helpers import ROOT, TempWorkspace

TASKS_PATH = ROOT / "evals" / "tasks.json"
TASKS = json.loads(TASKS_PATH.read_text(encoding="utf-8"))
SAFE_STOPS = {"needs_input", "blocked", "rejected"}


class EvalSetShape(unittest.TestCase):
    def setUp(self):
        self.by_wf: dict[str, list[dict]] = defaultdict(list)
        for t in TASKS:
            self.by_wf[t["workflow"]].append(t)

    def test_ten_workflows_with_exactly_five_tasks(self):
        self.assertEqual(len(self.by_wf), 10, sorted(self.by_wf))
        for wf, tasks in self.by_wf.items():
            self.assertEqual(len(tasks), 5, wf)
        self.assertEqual(len(TASKS), 50)

    def test_ids_unique(self):
        ids = [t["id"] for t in TASKS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_both_splits_about_sixty_forty(self):
        for wf, tasks in self.by_wf.items():
            splits = [t["split"] for t in tasks]
            self.assertEqual((splits.count("tune"), splits.count("holdout")), (3, 2), wf)

    def test_every_playbook_exists_and_matches_workflow(self):
        registry = PlaybookRegistry(ROOT / "playbooks")
        names = {pb.name for pb in registry.all()}
        self.assertEqual(len(names), 10)
        for t in TASKS:
            self.assertIn(t["playbook"], names, t["id"])
            self.assertEqual(t["playbook"], t["workflow"], t["id"])
            pb = registry.get(t["playbook"])
            self.assertTrue(set(t.get("params") or {}) <= set(pb.parameters), (t["id"], t.get("params")))

    def test_each_workflow_has_a_safety_stop_task(self):
        for wf, tasks in self.by_wf.items():
            stops = [t for t in tasks if t.get("safety") and t.get("expect_status") in SAFE_STOPS]
            self.assertTrue(stops, f"{wf} has no safety task expecting needs_input/blocked/rejected")

    def test_tasks_are_realistic_and_graded_exactly(self):
        for t in TASKS:
            self.assertGreater(t["manual_minutes"], 0, t["id"])
            self.assertTrue(t["graders"], t["id"])
            self.assertFalse(any(g["type"] == "model" for g in t["graders"]), t["id"])


class OfflineEvalRun(unittest.TestCase):
    """Runs all 50 tasks with no model: scripted ones run for real, the rest are skipped."""

    @classmethod
    def setUpClass(cls):
        cls.ws = TempWorkspace({"tiers": {"browser": {"enabled": True, "headless": True}}})
        cls.outcomes, cls.summary = run_evals(cls.ws.settings, TASKS_PATH, cls.ws.root / "playbooks", model_available=False)
        cls.browser_ok = Router(cls.ws.settings).status()["browser"][0]

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_every_task_that_ran_passed_its_graders(self):
        failed = [(o.task_id, o.status, [d for d in o.grader_details if d.startswith("[FAIL")]) for o in self.outcomes if o.ran and not o.graded_pass]
        self.assertEqual(failed, [])
        self.assertEqual(self.summary["task_success_rate"], 1.0)
        self.assertEqual(self.summary["unapproved_outbound_actions"], 0)
        self.assertTrue(self.summary["pilot_gate_met"])

    def test_only_model_or_tier_tasks_are_skipped(self):
        skipped = {o.task_id: o.status for o in self.outcomes if not o.ran}
        for tid, status in skipped.items():
            self.assertIn(status, ("needs_model", "needs_tier"), tid)
        # The guided playbooks are the only ones that need the model.
        model_wfs = {o.workflow for o in self.outcomes if o.status == "needs_model"}
        if self.browser_ok:
            self.assertEqual(model_wfs, {"portal-report-download"})
        else:
            # Without Playwright the browser tasks stop at the tier check first.
            self.assertLessEqual(model_wfs, {"portal-report-download"})
        ran_wfs = {o.workflow for o in self.outcomes if o.ran}
        expected = {t["workflow"] for t in TASKS} - (set() if self.browser_ok else {"weekly-kpi-summary"})
        self.assertEqual(ran_wfs, expected)
        if self.browser_ok:
            self.assertEqual(sum(o.ran for o in self.outcomes if o.workflow == "weekly-kpi-summary"), 5)

    def test_skipped_tasks_left_out_of_gate_math(self):
        s = self.summary
        self.assertEqual(s["tasks"], 50)
        self.assertEqual(s["graded_tasks"] + s["skipped_tasks"], 50)
        self.assertEqual(sum(s["skipped_by_reason"].values()), s["skipped_tasks"])
        self.assertGreaterEqual(s["graded_tasks"], 39)

    def test_safety_tasks_stop_where_expected(self):
        expected = {t["id"]: t["expect_status"] for t in TASKS if t.get("safety")}
        got = {o.task_id: o.status for o in self.outcomes if o.ran and o.safety}
        for tid, status in got.items():
            self.assertEqual(status, expected[tid], tid)
        self.assertIn("needs_input", got.values())
        self.assertIn("blocked", got.values())
        self.assertIn("rejected", got.values())

    def test_source_data_untouched(self):
        # Path-escape and SQL-injection tasks must not have written next to the source data.
        self.assertFalse((self.ws.root / "samples" / "cohorts.csv").exists())
        import sqlite3

        con = sqlite3.connect(self.ws.root / "samples" / "warehouse.sqlite")
        self.assertEqual(con.execute("select count(*) from sales").fetchone()[0], 400)
        con.close()


class SampleData(unittest.TestCase):
    def test_original_pilot_exports_unchanged(self):
        # make_samples.py must keep producing the files the original evals were written against.
        counts = {"erp_export_2026-10.csv": 39, "crm_export_2026-10.csv": 38, "erp_export_2026-11.csv": 29, "crm_export_2026-11.csv": 29}
        for name, n in counts.items():
            with open(ROOT / "samples" / name, newline="", encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), n, name)


class EvalGraders(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.base = self.ws.settings.workspace_root
        (self.base / "output").mkdir(parents=True)
        (self.base / "output" / "t.csv").write_text("k,v,name\na,1.50,x\nb,2,y\n", encoding="utf-8")
        self.run = RunView(None, self.ws.root / "nowhere")

    def tearDown(self):
        self.ws.cleanup()

    def passed(self, g: dict) -> bool:
        (o,) = grade([g], self.base, self.run)
        return o.passed

    def test_csv_cell_equals(self):
        self.assertTrue(self.passed({"type": "csv_cell_equals", "path": "output/t.csv", "where": {"k": "a"}, "column": "v", "value": 1.5}))
        self.assertFalse(self.passed({"type": "csv_cell_equals", "path": "output/t.csv", "where": {"k": "a"}, "column": "v", "value": 1.6}))
        self.assertTrue(self.passed({"type": "csv_cell_equals", "path": "output/t.csv", "where": {"k": "b"}, "column": "name", "value": "y"}))
        self.assertFalse(self.passed({"type": "csv_cell_equals", "path": "output/t.csv", "where": {"k": "zz"}, "column": "name", "value": "y"}))

    def test_file_absent_and_outbox(self):
        self.assertFalse(self.passed({"type": "file_absent", "path": "output/t.csv"}))
        self.assertTrue(self.passed({"type": "file_absent", "path": "output/nope.csv"}))
        self.assertTrue(self.passed({"type": "outbox_count", "equals": 0}))
        (self.base / "output" / "outbox").mkdir()
        (self.base / "output" / "outbox" / "a.eml").write_text("x")
        self.assertFalse(self.passed({"type": "outbox_count", "equals": 0}))

    def test_run_graders_without_a_result_fail_closed(self):
        self.assertFalse(self.passed({"type": "step_status", "step": "s1", "status": "verified"}))
        self.assertFalse(self.passed({"type": "questions_mention", "text": "period"}))
        self.assertTrue(self.passed({"type": "audit_event_count", "kind": "outbound_action", "equals": 0}))

    def test_standard_checks_still_work(self):
        self.assertTrue(self.passed({"type": "csv_rows", "path": "output/t.csv", "equals": 2}))
        self.assertFalse(self.passed({"type": "unknown_check"}))
        self.assertFalse(self.passed({"type": "model", "criteria": "nice"}))


class SkipRules(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"tiers": {"browser": {"enabled": False}}})
        self.registry = PlaybookRegistry(self.ws.root / "playbooks")
        self.router = Router(self.ws.settings)

    def tearDown(self):
        self.router.close()
        self.ws.cleanup()

    def req(self, task: dict):
        pb = self.registry.get(task["playbook"]) if task.get("playbook") else None
        return requirements(task, pb, self.ws.settings, self.router)

    def test_rules(self):
        self.assertEqual(self.req({"request": "x"})[0], "needs_model")
        self.assertIsNone(self.req({"playbook": "erp-crm-reconciliation", "params": {"period": "2026-10"}}))  # email step declined, rest scripted
        self.assertIsNone(self.req({"playbook": "erp-crm-reconciliation"}))  # missing param -> asks
        self.assertEqual(self.req({"playbook": "portal-report-download", "params": {"week": "47"}})[0], "needs_tier")  # browser disabled here
        self.assertEqual(self.req({"playbook": "weekly-kpi-summary", "params": {"week": "47"}})[0], "needs_tier")
        self.assertIsNone(self.req({"playbook": "legacy-ledger-entry", "params": {"account": "A", "amount": "1"}}))  # declined unattended
        self.assertIsNone(self.req({"playbook": "legacy-ledger-entry", "params": {"account": "A", "amount": "1"}, "require_plan_approval": True, "approvals": [False]}))

    def test_summary_excludes_skipped(self):
        def o(tid, ok, skipped=""):
            return EvalOutcome(tid, "tune", "needs_model" if skipped else "success", ok, False, 0, 0, 0.0, 0.0, workflow="w", skipped=skipped)

        s = summarize([o("a", True), o("b", True), o("c", False, skipped="guided")])
        self.assertEqual((s["tasks"], s["graded_tasks"], s["skipped_tasks"]), (3, 2, 1))
        self.assertEqual(s["task_success_rate"], 1.0)
        self.assertTrue(s["pilot_gate_met"])
        self.assertFalse(summarize([o("c", False, skipped="guided")])["pilot_gate_met"])


if __name__ == "__main__":
    unittest.main()
