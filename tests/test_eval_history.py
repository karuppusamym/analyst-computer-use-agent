"""Eval history: rows appended per run, trend table, run compare, the HTML report and the CLI."""

from __future__ import annotations

import contextlib
import io
import json
import re
import unittest
from types import SimpleNamespace
from unittest import mock

from analyst_agent import eval_history as eh
from analyst_agent.evals import EvalOutcome, summarize

from .helpers import ROOT, TempWorkspace


def outcome(tid, graded, status=None, wf="w1", cost=0.01, safety=False):
    skipped = "needs the model" if graded == "skip" else ""
    return EvalOutcome(
        tid, "tune", status or ("needs_model" if skipped else "success"), graded == "pass", False, 0, 0, 1.5, cost,
        grader_details=[] if graded != "fail" else ["[FAIL] csv_rows output/x.csv == 3: 2 rows"], workflow=wf, skipped=skipped, safety=safety,
    )


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.s = self.ws.settings

    def tearDown(self):
        self.ws.cleanup()

    def record(self, outs, config="default"):
        return eh.record_run(self.s, outs, summarize(outs), config_name=config, root=ROOT, split=None)

    def test_row_has_commit_models_tasks_and_pilot_metrics(self):
        outs = [outcome("a", "pass"), outcome("b", "fail"), outcome("c", "skip")]
        row, hist, report = self.record(outs, config="openrouter")
        self.assertEqual(hist, self.s.workspace_root / "evals" / "history.jsonl")
        (stored,) = eh.load_history(self.s)
        self.assertEqual(stored, row)
        self.assertRegex(row["run_id"], r"^\d{8}T\d{6}Z-[0-9a-f]{4}$")
        self.assertRegex(row["git_commit"], r"^[0-9a-f]{7,40}$")  # the tests run inside a git checkout
        self.assertEqual(row["config"], "openrouter")
        self.assertEqual(row["models"]["planner"], self.s["models"]["planner"]["model"])
        self.assertEqual(row["models"]["executor"], self.s["models"]["executor"]["model"])
        self.assertEqual([(t["id"], t["graded"], t["status"]) for t in row["tasks"]], [("a", "pass", "success"), ("b", "fail", "success"), ("c", "skip", "needs_model")])
        self.assertEqual(row["tasks"][1]["failures"], ["[FAIL] csv_rows output/x.csv == 3: 2 rows"])
        self.assertEqual(row["tasks"][0]["cost_usd"], 0.01)
        self.assertEqual(row["tasks"][0]["seconds"], 1.5)
        self.assertEqual(row["pilot"]["graded_tasks"], 2)
        self.assertEqual(row["pilot"]["task_success_rate"], 0.5)
        self.assertIn("unapproved_outbound_actions", row["pilot"])
        self.assertIn("pilot_gate_met", row["pilot"])
        self.assertEqual(report, self.s.workspace_root / "evals" / f"{row['run_id']}.html")

    def test_no_git_and_torn_line(self):
        commit, dirty = eh.git_info(self.ws.root)  # a temp dir outside any repo
        self.assertEqual((commit, dirty), ("", False))
        self.record([outcome("a", "pass")])
        with open(eh.history_path(self.s), "a", encoding="utf-8") as f:
            f.write('{"run_id": "torn')  # a crash mid-write
        self.assertEqual(len(eh.load_history(self.s)), 1)

    def test_history_table_and_last(self):
        for outs in ([outcome("a", "pass"), outcome("b", "fail")], [outcome("a", "pass"), outcome("b", "pass")], [outcome("a", "fail"), outcome("b", "pass")]):
            self.record(outs)
        rows = eh.load_history(self.s)
        text = eh.format_history(rows, last=2)
        self.assertNotIn(rows[0]["run_id"], text)
        self.assertIn(rows[1]["run_id"], text)
        self.assertIn(rows[2]["run_id"], text)
        self.assertIn("2 of 3 runs shown", text)
        self.assertIn("+50pt", text)  # run 2 vs run 1 (from before the window)
        self.assertIn("-50pt", text)
        self.assertIn("no eval history", eh.format_history([]))

    def test_compare_lists_regressions_and_improvements(self):
        a, _, _ = self.record([outcome("a", "pass"), outcome("b", "fail"), outcome("c", "pass"), outcome("d", "skip"), outcome("old", "pass")])
        b, _, _ = self.record([outcome("a", "fail"), outcome("b", "pass"), outcome("c", "skip"), outcome("d", "pass"), outcome("new", "pass")])
        diff = eh.compare(a, b)
        self.assertEqual([x["id"] for x in diff["regressed"]], ["a"])
        self.assertEqual(diff["regressed"][0]["failures"], ["[FAIL] csv_rows output/x.csv == 3: 2 rows"])
        self.assertEqual([x["id"] for x in diff["improved"]], ["b"])
        self.assertEqual([x["id"] for x in diff["newly_skipped"]], ["c"])
        self.assertEqual([x["id"] for x in diff["newly_graded"]], ["d"])
        self.assertEqual((diff["only_in_a"], diff["only_in_b"]), (["old"], ["new"]))
        text = eh.format_compare(a, b, diff)
        self.assertRegex(text, r"REGRESSED \(pass -> fail\): 1\n  a ")
        self.assertRegex(text, r"IMPROVED \(fail -> pass\): 1\n  b ")
        rows = eh.load_history(self.s)
        self.assertIs(eh.find_run(rows, "-1"), rows[-1])
        self.assertEqual(eh.find_run(rows, a["run_id"])["run_id"], a["run_id"])
        with self.assertRaises(LookupError):
            eh.find_run(rows, "-9")
        with self.assertRaises(LookupError):
            eh.find_run(rows, "nope")

    def test_html_report_is_self_contained_and_escaped(self):
        row, _, report = self.record([outcome("<script>alert(1)</script>", "fail"), outcome("ok", "pass", safety=True)])
        page = report.read_text(encoding="utf-8")
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertIn("prefers-color-scheme: dark", page)
        self.assertIn(row["run_id"], page)
        self.assertNotIn("<script", page)  # the task id is escaped; the page has no scripts
        self.assertIn("&lt;script&gt;", page)
        self.assertIsNone(re.search(r"(src|href)\s*=\s*['\"]?(https?:)?//", page))  # nothing loaded from elsewhere
        self.assertNotIn("<link", page)
        self.assertIn("pill fail", page)
        self.assertIn("safety", page)

    def test_cli_history_and_compare_exit_codes(self):
        a, _, _ = self.record([outcome("a", "pass")])
        b, _, _ = self.record([outcome("a", "fail")])

        def run(**kw):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = eh.cli(SimpleNamespace(**{"runs": [], "last": 10, **kw}), self.s)
            return code, buf.getvalue()

        code, out = run(action="history")
        self.assertEqual(code, 0)
        self.assertIn(b["run_id"], out)
        code, out = run(action="compare", runs=[a["run_id"], "-1"])
        self.assertEqual(code, 1)  # a regression fails the command, for CI
        self.assertIn("REGRESSED (pass -> fail): 1", out)
        code, out = run(action="compare", runs=["-1", a["run_id"]])
        self.assertEqual(code, 0)
        self.assertIn("IMPROVED (fail -> pass): 1", out)
        code, out = run(action="compare", runs=["-1"])
        self.assertEqual(code, 2)

    def test_eval_command_appends_a_row(self):
        from analyst_agent import __main__ as cli

        cfg_dir = self.ws.root / "config"
        cfg_dir.mkdir()
        cfg = cfg_dir / "nightly.json"
        cfg.write_text(json.dumps({"gateway": {"backend": "mock"}, "models": {"planner": {"model": "claude-test-planner"}}}), encoding="utf-8")
        outs = [outcome("a", "pass")]
        buf = io.StringIO()
        with mock.patch("analyst_agent.evals.run_evals", return_value=(outs, summarize(outs))), contextlib.redirect_stdout(buf):
            code = cli.main(["--config", str(cfg), "eval"])
        self.assertEqual(code, 0, buf.getvalue())
        settings_root = self.ws.root / "workspace"
        rows = [json.loads(x) for x in (settings_root / "evals" / "history.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["config"], "nightly")
        self.assertEqual(rows[0]["models"]["planner"], "claude-test-planner")
        self.assertTrue((settings_root / "evals" / f"{rows[0]['run_id']}.html").is_file())
        self.assertIn("appended to", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
