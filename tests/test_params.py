"""Playbook parameter validation: malformed values never reach a step."""

import unittest

from analyst_agent.playbook import param_problem, playbook_from_dict


class ParamValidationTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(param_problem("2026-09-30", {"format": "date"}), "")
        self.assertIn("YYYY-MM-DD", param_problem("2026-09-30'; drop table sales; --", {"format": "date"}))
        self.assertIn("calendar", param_problem("2026-02-30", {"format": "date"}))
        self.assertEqual(param_problem("2026-10", {"format": "month"}), "")
        self.assertTrue(param_problem("2026-13", {"format": "month"}))
        self.assertEqual(param_problem("47", {"format": "week"}), "")
        self.assertTrue(param_problem("54", {"format": "week"}))
        self.assertEqual(param_problem(5, {"type": "number"}), "")
        self.assertTrue(param_problem("5; rm", {"type": "number"}))
        self.assertTrue(param_problem("x@y", {"format": "email"}))
        self.assertTrue(param_problem("javascript:alert(1)", {"format": "url"}))

    def test_enum_and_pattern(self):
        self.assertEqual(param_problem("west", {"enum": ["North", "West"]}), "")
        self.assertTrue(param_problem("Mars", {"enum": ["North", "West"]}))
        self.assertTrue(param_problem("abc", {"pattern": r"\d+"}))

    def test_invalid_params(self):
        pb = playbook_from_dict({"name": "p", "steps": [], "parameters": {"start": {"format": "date"}, "note": {}}})
        self.assertEqual(pb.invalid_params({"start": "2026-01-01", "note": "anything ' goes"}), {})
        self.assertIn("start", pb.invalid_params({"start": "yesterday"}))

    def test_shipped_playbooks_declare_formats(self):
        from pathlib import Path

        from analyst_agent.playbook import PlaybookRegistry

        reg = PlaybookRegistry(Path(__file__).resolve().parent.parent / "playbooks")
        for pb in reg.all():
            for k, spec in pb.parameters.items():
                if k in ("start_date", "end_date", "period", "week", "start_month", "end_month"):
                    self.assertTrue(spec.get("format"), f"{pb.name}.{k} has no format")
                if "default" in spec:
                    self.assertEqual(param_problem(spec["default"], spec), "", f"{pb.name}.{k} default")


if __name__ == "__main__":
    unittest.main()


class AuditResumeSeqTests(unittest.TestCase):
    def test_resumed_session_continues_seq(self):
        import json
        import tempfile

        from analyst_agent.audit import AuditLog

        with tempfile.TemporaryDirectory() as d:
            a = AuditLog(d, session_id="s1")
            a.event("one")
            a.event("two")
            b = AuditLog(d, session_id="s1")
            b.event("three")
            seqs = [json.loads(x)["seq"] for x in (a.path.read_text(encoding="utf-8").splitlines())]
            self.assertEqual(seqs, [1, 2, 3])
