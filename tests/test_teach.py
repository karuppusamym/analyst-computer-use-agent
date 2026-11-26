"""Teach mode: drafts from finished sessions, the browser recorder, promotion, and
the registry keeping drafts out of match/get."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

from analyst_agent.audit import AuditLog
from analyst_agent.model import mock_text, mock_tool
from analyst_agent.orchestrator import Orchestrator
from analyst_agent.playbook import PlaybookError, PlaybookRegistry, load_playbook, playbook_from_dict
from analyst_agent.policy import ScriptedApprover, UnattendedApprover
from analyst_agent.router import Router
from analyst_agent.teach import (
    TeachError,
    clean_event,
    draft_from_session,
    events_to_steps,
    infer_parameters,
    list_drafts,
    parameterize,
    playwright_status,
    promote,
    record_draft,
    recording_to_draft,
    validate_draft,
    write_draft,
)

from .helpers import ROOT, TempWorkspace
from .test_core import plan_json

SECRET = "s3cret-Value!"


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.s = self.ws.settings
        self.pbdir = self.ws.root / "playbooks"
        self.registry = PlaybookRegistry(self.pbdir)

    def tearDown(self):
        self.ws.cleanup()

    def orch(self, script=None, approvals=None):
        client, backend = self.ws.client(script)
        approver = ScriptedApprover(approvals) if approvals is not None else UnattendedApprover()
        return Orchestrator(self.s, client=client, approver=approver, require_plan_approval=False), backend


class ParameterTests(unittest.TestCase):
    def test_parameterize_respects_boundaries_and_keys(self):
        obj = {"id": "step-2026-10", "intent": "Reconcile 2026-10", "path": "output/x_2026-10.csv", "other": "2026-10-05 and 12026-10", "tier": "code"}
        out = parameterize(obj, {"period": "2026-10"})
        self.assertEqual(out["id"], "step-2026-10")  # ids are never parameterised
        self.assertEqual(out["intent"], "Reconcile {period}")
        self.assertEqual(out["path"], "output/x_{period}.csv")
        self.assertEqual(out["other"], "2026-10-05 and 12026-10")  # a date and a longer number are left alone

    def test_url_prefix_value_is_replaced(self):
        out = parameterize({"url": "http://127.0.0.1:9/reports"}, {"portal_url": "http://127.0.0.1:9/"})
        self.assertEqual(out["url"], "{portal_url}reports")

    def test_infer_from_request_only_when_values_repeat(self):
        values, specs = infer_parameters("Reconcile 2026-10 and mail bob@example.com for Q3 2026", {}, {}, ["file_2026-10.csv", "to bob@example.com"])
        self.assertEqual(values, {"period": "2026-10", "recipient": "bob@example.com"})  # Q3 2026 never repeats
        self.assertTrue(specs["period"]["required"])

    def test_known_and_default_values(self):
        values, specs = infer_parameters("x", {"week": "47", "unused": "zzz"}, {"recipient": "a@b.co"}, ["week 47", "send to a@b.co"])
        self.assertEqual(values, {"week": "47", "recipient": "a@b.co"})
        self.assertEqual(specs["recipient"], {"type": "string", "default": "a@b.co"})


class FromSessionTests(Base):
    def test_scripted_session_round_trips_into_a_runnable_draft(self):
        o, _ = self.orch(approvals=[True])
        r = o.run("Reconcile ERP and CRM for 2026-10", playbook=self.registry.get("erp-crm-reconciliation"), params={"period": "2026-10"})
        self.assertEqual(r.status, "success")
        path, data = draft_from_session(self.s, r.session_id, "recon-taught", self.pbdir, created_by="tester")
        self.assertEqual(path, self.pbdir / "drafts" / "recon-taught.json")
        self.assertEqual(data["status"], "draft")
        self.assertEqual([s["id"] for s in data["steps"]], ["profile-inputs", "reconcile", "write-summary", "draft-email"])
        self.assertTrue(all(s.get("script") for s in data["steps"]))
        self.assertEqual(data["parameters"]["period"]["example"], "2026-10")
        self.assertEqual(data["parameters"]["recipient"]["default"], "finance-lead@example.com")
        self.assertIn("{period}", data["steps"][0]["intent"])
        self.assertEqual(data["steps"][0]["checks"][0]["path"], "output/input_profile_{period}.json")
        self.assertEqual(data["steps"][3]["script"]["input"]["to"], ["{recipient}"])
        self.assertEqual(data["steps"][3]["approval"], "required")
        self.assertNotIn("2026-10", json.dumps(data["steps"]) + json.dumps(data["final_checks"]))
        prov = data["provenance"]
        self.assertEqual((prov["source_session"], prov["created_by"], prov["source_playbook"]), (r.session_id, "tester", "erp-crm-reconciliation"))
        self.assertTrue(prov["created_at"])
        self.assertEqual(validate_draft(data), [])

        # The registry never offers the draft ...
        self.assertNotIn("recon-taught", [p.name for p in self.registry.all()])
        with self.assertRaisesRegex(PlaybookError, "promote it first"):
            self.registry.get("recon-taught")
        self.assertEqual([p.name for p in self.registry.drafts()], ["recon-taught"])
        self.assertIn("recon-taught", [p.name for p in PlaybookRegistry(self.pbdir, include_drafts=True).all()])
        # ... but the draft itself replays, for another period, with no model calls.
        o2, backend = self.orch(approvals=[True])
        r2 = o2.run("reconcile november", playbook=load_playbook(path), params={"period": "2026-11"})
        self.assertEqual(r2.status, "success", [(x.step.id, x.status, x.summary) for x in r2.records])
        self.assertEqual(backend.requests, [])
        self.assertTrue((self.s.output_dir / "outbox" / "draft-email-2026-11.eml").exists())

    def test_declined_step_is_skipped_and_reported(self):
        o, _ = self.orch()  # unattended: the email approval is declined
        r = o.run("reconcile", playbook=self.registry.get("erp-crm-reconciliation"), params={"period": "2026-11"})
        self.assertEqual(r.status, "partial")
        _, data = draft_from_session(self.s, r.session_id, "recon-partial", self.pbdir)
        self.assertEqual([s["id"] for s in data["steps"]], ["profile-inputs", "reconcile", "write-summary"])
        self.assertEqual(data["provenance"]["skipped_steps"], [{"id": "draft-email", "reason": "approval was declined"}])

    def test_guided_code_step_becomes_scripted_with_inferred_parameter(self):
        code = "open(OUTPUT_DIR + '/count_2026-10.txt', 'w').write('42'); print('wrote count_2026-10.txt')"
        script = [
            plan_json([{"id": "count", "intent": "Count invoices for 2026-10", "tier": "code", "checks": [{"type": "file_exists", "path": "output/count_2026-10.txt"}]}]),
            mock_tool("run_python", {"code": "raise SystemExit('first try fails')"}),
            mock_tool("run_python", {"code": code}),
            mock_text("Wrote the count.\nRESULT: done"),
        ]
        o, _ = self.orch(script)
        r = o.run("How many invoices in 2026-10?")
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        _, data = draft_from_session(self.s, r.session_id, "count-invoices", self.pbdir)
        step = data["steps"][0]
        self.assertEqual(step["tier"], "code")
        self.assertEqual(step["script"]["kind"], "python")
        self.assertIn("count_{period}.txt", step["script"]["code"])  # the failed call was not learned
        self.assertNotIn("SystemExit", step["script"]["code"])
        self.assertEqual(step["checks"], [{"type": "file_exists", "path": "output/count_{period}.txt"}])
        self.assertIn("period", data["parameters"])
        self.assertEqual(validate_draft(data), [])
        pb = playbook_from_dict(data)
        o2, backend = self.orch([])
        r2 = o2.run("count", playbook=pb, params={"period": "2027-01"})
        self.assertEqual(r2.status, "success")
        self.assertEqual(backend.requests, [])
        self.assertTrue((self.s.output_dir / "count_2027-01.txt").exists())

    def test_pixel_actions_stay_guided_with_hints(self):
        audit = AuditLog(self.s.audit_dir, session_id="pixel-sess")
        audit.event("task_started", request="enter ledger row ACC-9", playbook=None, params={})
        audit.event("plan", source="planner", steps=[{"id": "enter", "intent": "Enter ACC-9 into Legacy Ledger", "tier": "desktop_pixels", "checks": [{"type": "file_exists", "path": "legacy_ledger.csv"}]}])
        audit.event("step_started", step="enter", intent="Enter", tier="desktop_pixels")
        audit.event("computer_action", member="left_click", input={"coordinate": [120, 80]}, foreground=["Legacy Ledger - TEST", "python.exe"], step="enter")
        audit.event("tool_call", step="enter", tool="left_click", input={"coordinate": [120, 80]}, is_error=False, output="OK", files=[])
        audit.event("tool_call", step="enter", tool="screenshot", input={}, is_error=False, output="", files=[])
        audit.event("step_verdict", step="enter", attempt=1, passed=True, outcomes=[], problems="")
        audit.event("task_finished", status="success")
        _, data = draft_from_session(self.s, "pixel-sess", "ledger-taught", self.pbdir)
        step = data["steps"][0]
        self.assertNotIn("script", step)
        self.assertEqual(step["tier"], "desktop_pixels")
        self.assertEqual(step["recorded_actions"], ["left_click at [120, 80] in window 'Legacy Ledger - TEST'"])
        self.assertIn("hints, not coordinates to trust", step["instructions"])

    def test_unfinished_or_missing_session_refused(self):
        audit = AuditLog(self.s.audit_dir, session_id="open-sess")
        audit.event("task_started", request="x", playbook=None, params={})
        with self.assertRaisesRegex(TeachError, "not finished"):
            draft_from_session(self.s, "open-sess", "x", self.pbdir)
        with self.assertRaisesRegex(TeachError, "no audit log"):
            draft_from_session(self.s, "nope", "x", self.pbdir)


class PromoteTests(Base):
    def _draft(self, **over):
        data = {
            "name": "tiny-flow", "version": 0, "status": "draft", "owner": "ops", "parameters": {"period": {"type": "string", "required": True}},
            "steps": [
                {"id": "a", "intent": "Write {period}", "tier": "code", "script": {"kind": "python", "code": "print(1)"}, "no_check_reason": "smoke step"},
                {"id": "b", "intent": "Check", "tier": "code", "script": {"kind": "python", "code": "print(2)"}, "checks": [{"type": "file_exists", "path": "output/{period}.txt"}]},
            ],
            "provenance": {"method": "record", "created_by": "me", "created_at": "2026-11-24T00:00:00+00:00"},
        }
        data.update(over)
        return data

    def test_validation_lists_every_problem(self):
        bad = self._draft(steps=[
            {"id": "a", "intent": "uses {missing}", "tier": "code", "script": {"kind": "python", "code": "x"}},
            {"id": "b", "intent": "b", "tier": "teleport", "checks": [{"type": "file_exists", "path": "x"}]},
            {"id": "c", "intent": "c", "tier": "browser", "script": {"kind": "tool"}, "no_check_reason": "ok"},
        ])
        problems = validate_draft(bad)
        joined = "\n".join(problems)
        self.assertIn("step a: needs a check or an explicit no_check_reason", joined)
        self.assertIn("step a: uses {missing}", joined)
        self.assertIn("step b: needs a tier", joined)
        self.assertIn("step c: tool script names no tool", joined)
        write_draft(self.pbdir, bad)
        with self.assertRaisesRegex(TeachError, "not ready to promote"):
            promote(self.pbdir, "tiny-flow")
        self.assertTrue((self.pbdir / "drafts" / "tiny-flow.json").exists())

    def test_secret_placeholders_are_not_parameters(self):
        d = self._draft()
        d["steps"][0]["script"] = {"kind": "tool", "tool": "browser_fill", "input": {"targets": [{"label": "Password"}], "text": "{{secret:password}}"}}
        d["steps"][0]["tier"] = "browser"
        self.assertEqual(validate_draft(d), [])

    def test_promote_moves_bumps_and_records_reviewer(self):
        write_draft(self.pbdir, self._draft())
        path, data = promote(self.pbdir, "tiny-flow", reviewer="lead")
        self.assertEqual(path, self.pbdir / "tiny-flow.json")
        self.assertFalse((self.pbdir / "drafts" / "tiny-flow.json").exists())
        self.assertEqual(data["version"], 1)
        self.assertNotIn("status", data)
        self.assertEqual(data["provenance"]["reviewer"], "lead")
        self.assertEqual(data["provenance"]["created_by"], "me")
        pb = self.registry.get("tiny-flow")
        self.assertEqual((pb.version, pb.status, pb.steps[0].no_check_reason), (1, "active", "smoke step"))
        # A second draft of the same playbook replaces it at the next version.
        write_draft(self.pbdir, self._draft())
        path2, data2 = promote(self.pbdir, "tiny-flow", reviewer="lead2")
        self.assertEqual((path2, data2["version"], data2["provenance"]["previous_version"]), (path, 2, 1))
        self.assertEqual(list_drafts(self.pbdir), [])

    def test_no_check_reason_step_passes_when_it_runs(self):
        write_draft(self.pbdir, self._draft())
        promote(self.pbdir, "tiny-flow")
        d = self._draft()
        d["steps"] = d["steps"][:1]
        o, backend = self.orch([])
        r = o.run("tiny", playbook=playbook_from_dict(d), params={"period": "p"})
        self.assertEqual(r.status, "success")
        self.assertEqual(r.records[0].verdict.outcomes[0].detail, "smoke step")
        self.assertEqual(backend.requests, [])

    def test_status_draft_in_main_folder_is_skipped(self):
        d = self._draft(name="sneaky")
        (self.pbdir / "sneaky.json").write_text(json.dumps(d), encoding="utf-8")
        self.assertNotIn("sneaky", [p.name for p in self.registry.all()])
        self.assertNotEqual(getattr(self.registry.match("sneaky tiny flow write check"), "name", None), "sneaky")


class RecorderConversionTests(unittest.TestCase):
    START = "http://127.0.0.1:9/"

    def ev(self, t, type, **kw):
        return {"t": t, "type": type, **kw}

    def test_events_become_replayable_steps_and_passwords_are_masked(self):
        link = [{"role": "link", "name": "Reports"}, {"css": "a:nth-of-type(1)"}]
        dl = [{"role": "link", "name": "Download week 47"}]
        note = [{"role": "textbox", "name": "Note"}, {"label": "Note"}, {"css": "#note"}]
        pw = [{"label": "Password"}, {"css": "#pw"}]
        region = [{"role": "combobox", "name": "Region"}]
        submit = [{"role": "button", "name": "Submit"}]
        events = [
            self.ev(1, "navigate", url=self.START),  # the start page itself
            self.ev(1000, "click", targets=link, role="link", name="Reports", href=self.START + "reports"),
            self.ev(1200, "navigate", url=self.START + "reports"),  # caused by the click
            self.ev(2000, "click", targets=dl, role="link", name="Download week 47", href=self.START + "download/report_wk47.csv"),
            self.ev(2100, "download", filename="report_wk47.csv"),
            self.ev(2500, "navigate", url=self.START + "form"),  # typed URL, not caused by the download click
            self.ev(3000, "fill", targets=note, name="Note", field="note", value="hel"),
            self.ev(3100, "fill", targets=note, name="Note", field="note", value="hello"),  # merged
            self.ev(3500, "fill", targets=pw, label="Password", field="pw", input_type="password", value=SECRET),  # value must be dropped
            self.ev(3600, "select", targets=region, name="Region", value="N", option="North"),
            self.ev(3700, "select", targets=region, name="Region", value="S", option="South"),  # merged
            self.ev(4000, "click", targets=submit, role="button", name="Submit"),
            self.ev(4001, "click", targets=submit, role="button", name="Submit"),  # double click
            self.ev(4010, "submit", targets=submit, name="Submit"),  # already submitted by the click
            self.ev(4300, "navigate", url=self.START + "done"),
            self.ev(5000, "navigate", url="https://evil.example.com/"),
            self.ev(5001, "blocked", url="https://evil.example.com/"),
        ]
        steps, params, warnings = events_to_steps(events, self.START)
        tools = [(s["script"]["tool"], s["script"]["input"].get("url") or s["script"]["input"].get("text") or s["script"]["input"].get("value") or s["script"]["input"]["targets"][0].get("name")) for s in steps]
        self.assertEqual(tools, [
            ("browser_goto", self.START),
            ("browser_click", "Reports"),
            ("browser_download", "Download week 47"),
            ("browser_goto", self.START + "form"),
            ("browser_fill", "{note}"),
            ("browser_fill", "{{secret:pw}}"),
            ("browser_select", "S"),
            ("browser_click", "Submit"),
            ("browser_goto", "https://evil.example.com/"),
        ])
        self.assertEqual(params, {"note": {"type": "string", "default": "hello", "description": "recorded value typed into 'Note'"}})
        self.assertEqual(steps[2]["checks"], [{"type": "file_exists", "path": "output/downloads/report_wk47.csv"}])
        self.assertEqual(steps[-1]["checks"][0]["type"], "model")
        self.assertTrue(all(s.get("checks") or s.get("no_check_reason") for s in steps))
        self.assertTrue(any("not on the allowlist" in w for w in warnings))
        data = recording_to_draft("portal-flow", self.START, events, created_by="tester")
        self.assertNotIn(SECRET, json.dumps(data))
        self.assertEqual(data["provenance"]["secrets"], ["pw"])
        self.assertEqual(data["permissions"]["hosts"], ["127.0.0.1", "evil.example.com"])
        self.assertEqual(validate_draft(data), [])

    def test_clean_event_never_keeps_secret_values(self):
        for ev in ({"type": "fill", "input_type": "password", "value": SECRET}, {"type": "fill", "secret": True, "value": SECRET}, {"type": "fill", "masked": True, "value": SECRET}):
            out = clean_event(dict(ev, targets=[{"css": "#x", "junk": "y"}]))
            self.assertNotIn("value", out)
            self.assertTrue(out["masked"])
            self.assertEqual(out["targets"], [{"css": "#x"}])
        self.assertIsNone(clean_event({"type": "eval", "code": "x"}))
        self.assertIsNone(clean_event("not a dict"))

    def test_submit_without_click_becomes_click(self):
        steps, _, _ = events_to_steps([self.ev(10, "fill", targets=[{"label": "Q"}], field="q", value="x"), self.ev(20, "submit", targets=[{"role": "button", "name": "Go"}], name="Go"), self.ev(30, "navigate", url=self.START + "results")], self.START)
        self.assertEqual([s["script"]["tool"] for s in steps], ["browser_goto", "browser_fill", "browser_click"])


class RecorderTabsConversionTests(unittest.TestCase):
    START = "http://127.0.0.1:9/tabs"
    B = "http://127.0.0.1:9/"

    def ev(self, t, type, tab=0, **kw):
        return {"t": t, "type": type, "tab": tab, **kw}

    def test_popups_switches_downloads_and_uploads(self):
        export = [{"role": "link", "name": "Open export window"}]
        dl = [{"role": "link", "name": "Download summary"}]
        helpb = [{"role": "button", "name": "Open help"}]
        att = [{"label": "Attachment"}, {"css": "#attachment"}]
        events = [
            self.ev(1, "navigate", url=self.START),
            self.ev(1000, "click", targets=export, role="link", name="Open export window", href=self.B + "export"),
            self.ev(1100, "navigate", tab=1, url=self.B + "export"),  # reported before the popup itself
            self.ev(1101, "popup", tab=1, opener=0, url=self.B + "export"),
            self.ev(2000, "click", tab=1, targets=dl, role="link", name="Download summary", href=self.B + "download/summary.csv"),
            self.ev(2100, "download", tab=1, filename="summary.csv"),
            self.ev(3000, "click", targets=helpb, role="button", name="Open help"),
            self.ev(3100, "popup", tab=2, opener=0, url="about:blank"),
            self.ev(3200, "navigate", tab=2, url=self.B + "help"),  # the popup's own load
            self.ev(4000, "popup", tab=3, opener=0, url=self.B + "help"),  # opened by a script, no click
            self.ev(5000, "upload", tab=0, targets=att, label="Attachment", field="attachment", files=["C:\\Users\\me\\secret\\pack.csv", "b.csv"], value="C:\\fakepath\\pack.csv"),
        ]
        steps, params, warnings = events_to_steps(events, self.START)
        got = [(s["script"]["tool"], s["script"]["input"]) for s in steps]
        self.assertEqual([g[0] for g in got], ["browser_goto", "browser_click", "browser_download", "browser_switch_tab", "browser_click", "browser_switch_tab", "browser_switch_tab", "browser_upload"], json.dumps(got, indent=1))
        self.assertTrue(got[1][1]["expect_popup"])
        self.assertEqual(got[1][1]["popup_url_contains"], "127.0.0.1:9/export")
        self.assertNotIn("expect_popup", got[2][1])
        self.assertEqual(got[3][1], {"url_contains": "127.0.0.1:9/tabs", "tab": 0})  # URL first, index as fallback
        self.assertTrue(got[4][1]["expect_popup"])
        self.assertEqual(got[4][1]["popup_url_contains"], "127.0.0.1:9/help")  # learned from the popup's first load
        self.assertEqual(got[5][1], {"url_contains": "127.0.0.1:9/help", "tab": 3, "new_tab": True, "wait_s": 10})  # script-opened tab: wait for it
        self.assertEqual(got[6][1], {"url_contains": "127.0.0.1:9/tabs", "tab": 0})
        self.assertEqual(got[7][1], {"targets": att, "paths": "{attachment_paths}"})  # two files: one list parameter
        self.assertEqual(steps[2]["checks"], [{"type": "file_exists", "path": "output/downloads/summary.csv"}])
        self.assertEqual(params["attachment_paths"]["type"], "list")
        self.assertTrue(params["attachment_paths"]["required"])
        self.assertNotIn("default", params["attachment_paths"])
        self.assertIn("pack.csv, b.csv", params["attachment_paths"]["description"])
        self.assertEqual(warnings, [])
        data = recording_to_draft("tabs-flow", self.START, events, created_by="tester")
        raw = json.dumps(data)
        self.assertNotIn("secret\\\\pack", raw)  # only the base name survives
        self.assertNotIn("fakepath", raw)
        self.assertEqual(data["provenance"]["tabs"], 4)
        self.assertEqual(validate_draft(data), [])

    def test_closes_frames_and_uploads(self):
        B = self.B
        fr = [{"name": "entry", "css": 'iframe[name="entry"]', "url_contains": "127.0.0.1:9/frames/entry"}]
        nested = fr + [{"name": "notes", "url_contains": "127.0.0.1:9/frames/notes"}]
        amount = [{"label": "Amount"}, {"css": "#amount"}]
        att = [{"label": "Attachments"}]
        events = [
            self.ev(1, "navigate", url=self.START),
            self.ev(100, "click", targets=[{"role": "button", "name": "Open help"}], role="button", name="Open help"),
            self.ev(200, "popup", tab=1, opener=0, url=B + "help?session=8f3a91&lang=en"),
            self.ev(300, "close", tab=1),  # the person closes the popup
            self.ev(400, "fill", targets=amount, field="amount", value="12", frame=fr),
            self.ev(450, "fill", targets=amount, field="amount", value="125", frame=fr),  # merged (same frame)
            self.ev(500, "fill", targets=amount, field="amount", value="7", frame=nested),  # another frame: its own step
            self.ev(600, "upload", targets=att, field="attachments", files=["a.csv"]),
            self.ev(700, "upload", targets=att, field="attachments", files=["a.csv", "b.csv"]),  # re-chosen: replaces
            self.ev(800, "close", tab=0),  # closing the last tab ends the recording; not a step
        ]
        steps, params, _ = events_to_steps(events, self.START)
        got = [(s["script"]["tool"], s["script"]["input"]) for s in steps]
        self.assertEqual([g[0] for g in got], ["browser_goto", "browser_click", "browser_close_tab", "browser_switch_tab", "browser_fill", "browser_fill", "browser_upload"], json.dumps(got, indent=1))
        self.assertEqual(got[1][1]["popup_url_contains"], "127.0.0.1:9/help")  # volatile query value dropped
        self.assertEqual(got[2][1], {"url_contains": "127.0.0.1:9/help", "tab": 1})
        self.assertEqual(got[3][1], {"url_contains": "127.0.0.1:9/tabs", "tab": 0})  # the current tab was closed
        self.assertEqual(got[4][1], {"targets": amount, "frame": fr, "text": "{amount}"})
        self.assertEqual(got[5][1]["frame"], nested)
        self.assertEqual(got[6][1], {"targets": att, "paths": "{attachments_paths}"})
        self.assertNotIn("attachments_path", params)  # the earlier single-file choice is gone
        data = recording_to_draft("frames-flow", self.START, events, created_by="t")
        self.assertEqual(validate_draft(data), [])
        # The whole browser being closed at the end is not a list of close steps either.
        tail = [self.ev(1, "navigate", url=self.START), self.ev(10, "popup", tab=1, opener=None, url=B + "help"), self.ev(20, "close", tab=1), self.ev(21, "close", tab=0)]
        self.assertNotIn("browser_close_tab", [s["script"]["tool"] for s in events_to_steps(tail, self.START)[0]])

    def test_stable_url_and_list_parameters(self):
        from analyst_agent.playbook import _fill
        from analyst_agent.tools.browser import parse_paths, stable_url

        self.assertEqual(stable_url("http://127.0.0.1:9/export"), "127.0.0.1:9/export")
        self.assertEqual(stable_url("https://Portal.example.com/a/b?view=summary&id=123&tab=x#top"), "portal.example.com/a/b?view=summary")
        self.assertEqual(stable_url("https://h.example/r?token=abc123"), "h.example/r")
        self.assertEqual(stable_url("http://h"), "h/")
        self.assertEqual(stable_url("about:blank"), "")
        self.assertEqual(parse_paths(["a", " ", "b"]), ["a", "b"])
        self.assertEqual(parse_paths('["C:/x/a.csv", "C:/x/b.csv"]'), ["C:/x/a.csv", "C:/x/b.csv"])
        import os

        self.assertEqual(parse_paths(f"a.csv{os.pathsep}b.csv\nc.csv"), ["a.csv", "b.csv", "c.csv"])
        self.assertEqual(_fill({"paths": "{f}", "label": "files {f}"}, {"f": ["a", "b"]}), {"paths": ["a", "b"], "label": "files ['a', 'b']"})

    def test_clean_event_frames(self):
        out = clean_event({"type": "click", "targets": [{"css": "#x"}], "frame": [{"name": "entry", "css": "#f", "url_contains": "h/x", "junk": "y"}, "bad"] + [{}] * 10})
        self.assertEqual(out["frame"][0], {"name": "entry", "css": "#f", "url_contains": "h/x"})
        self.assertEqual(out["frame"][1], {})
        self.assertEqual(len(out["frame"]), 6)
        self.assertNotIn("frame", clean_event({"type": "click", "targets": [], "frame": "nope"}))

    def test_clean_event_tabs_and_files(self):
        out = clean_event({"type": "upload", "tab": "2", "opener": "x", "files": ["/home/u/a.csv", "C:\\d\\b.csv"], "value": "C:\\fakepath\\a.csv", "targets": []})
        self.assertEqual(out["tab"], 2)
        self.assertNotIn("opener", out)
        self.assertEqual(out["files"], ["a.csv", "b.csv"])
        self.assertNotIn("value", out)


class RecordUnavailableTest(Base):
    def test_record_reports_unavailable_cleanly(self):
        import contextlib
        import io
        from types import SimpleNamespace
        from unittest import mock

        from analyst_agent import teach

        args = SimpleNamespace(teach_cmd="record", name="x", url="http://127.0.0.1/", headless=True, force=False)
        buf = io.StringIO()
        with mock.patch.object(teach, "playwright_status", return_value=(False, "playwright is not installed")), contextlib.redirect_stdout(buf):
            code = teach.cli(args, self.s, self.ws.root)
        self.assertEqual(code, 2)
        self.assertIn("unavailable: playwright is not installed", buf.getvalue())
        self.assertFalse((self.pbdir / "drafts").exists())


PW_OK, PW_WHY = playwright_status()


@unittest.skipUnless(PW_OK, f"playwright unavailable: {PW_WHY}")
class LiveBrowserTeachTests(unittest.TestCase):
    """Real Chromium against the local test portal (test_targets/portal.py)."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT))
        from test_targets import portal

        cls.portal = portal
        cls.server, _ = portal.start_portal(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.ws = TempWorkspace({"tiers": {"browser": {"enabled": True, "headless": True}}, "policy": {"allowed_hosts": ["127.0.0.1"]}})
        self.s = self.ws.settings
        self.pbdir = self.ws.root / "playbooks"

    def tearDown(self):
        self.ws.cleanup()

    def _replay(self, data: dict, params: dict, approvals=None):
        client, backend = self.ws.client([])
        orch = Orchestrator(self.s, client=client, approver=ScriptedApprover(approvals or []), require_plan_approval=False)
        try:
            return orch.run("replay", playbook=playbook_from_dict(data), params=params), backend
        finally:
            orch.router.close()

    def test_record_live_session_then_replay(self):
        self.portal.SUBMISSIONS.clear()

        def drive(page):
            page.get_by_role("link", name="Reports").click()
            page.wait_for_url("**/reports")
            with page.expect_download():
                page.get_by_role("link", name="Download week 47").click()
            page.goto(self.base + "/form")
            page.evaluate("""() => document.querySelector('form').insertAdjacentHTML('afterbegin',
                "<label for='pw'>Password</label><input id='pw' type='password'>")""")
            page.get_by_label("Note").fill("hello 47")
            page.get_by_label("Password").fill(SECRET)
            page.get_by_role("button", name="Submit").click()
            page.wait_for_url("**/done")
            page.wait_for_timeout(300)

        path, data = record_draft(self.s, "portal-recorded", self.base + "/", self.pbdir, headless=True, driver=drive, created_by="tester")
        self.assertTrue(path.exists())
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn(SECRET, raw)
        self.assertEqual(self.portal.SUBMISSIONS, [{"note": "hello 47"}])  # password field is not part of the real form
        tools = [s["script"]["tool"] for s in data["steps"]]
        self.assertEqual(tools, ["browser_goto", "browser_click", "browser_download", "browser_goto", "browser_fill", "browser_fill", "browser_click"], json.dumps(data["steps"], indent=1))
        self.assertEqual(data["steps"][1]["script"]["input"]["targets"][0], {"role": "link", "name": "Reports"})
        self.assertEqual(data["steps"][4]["script"]["input"]["targets"][0], {"role": "textbox", "name": "Note"})
        self.assertEqual(data["steps"][4]["script"]["input"]["text"], "{note}")
        self.assertEqual(data["parameters"]["note"]["default"], "hello 47")
        self.assertEqual(data["steps"][5]["script"]["input"]["text"], "{{secret:pw}}")
        self.assertEqual(data["steps"][2]["checks"], [{"type": "file_exists", "path": "output/downloads/report_wk47.csv"}])
        self.assertEqual(validate_draft(data), [])

        # Replay the recorded navigation + download with the browser tier and no model at all.
        part = dict(data, steps=data["steps"][:3])
        r, backend = self._replay(part, {})
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertEqual(backend.requests, [])
        self.assertTrue((self.s.output_dir / "downloads" / "report_wk47.csv").exists())

        # The secret placeholder is never typed into a page: the browser tier refuses it.
        from analyst_agent.policy import PolicyEngine
        from analyst_agent.tools.base import ToolContext
        from analyst_agent.tools.browser import BrowserTier

        tier = BrowserTier(self.s)
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), ScriptedApprover([]), step_id="t")
        try:
            tier.execute({"name": "browser_goto", "input": {"url": self.base + "/form"}}, ctx)
            out = tier.execute({"name": "browser_fill", "input": data["steps"][5]["script"]["input"] | {"targets": [{"label": "Note"}]}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("no secret named 'pw'", out.text)  # the vault resolves placeholders; an unknown secret is refused
            ok = tier.execute({"name": "browser_fill", "input": {"targets": [{"label": "Nope"}, {"css": "#note"}], "text": "via css fallback"}}, ctx)
            self.assertFalse(ok.is_error, ok.text)
        finally:
            tier.close()

    def test_guided_browser_session_becomes_scripted_draft(self):
        def pick_download(body):
            text = json.dumps(body["messages"][-1])
            m = re.search(r"\[(e\d+)\][^\[]*Download week 47", text)
            assert m, text[:2000]
            return mock_tool("browser_download", {"ref": m.group(1)})

        script = [mock_tool("browser_goto", {"url": self.base + "/reports"}), mock_tool("browser_snapshot", {}), pick_download, mock_text("Downloaded.\nRESULT: done")]
        client, _ = self.ws.client(script)
        orch = Orchestrator(self.s, client=client, approver=ScriptedApprover([]), require_plan_approval=False)
        pb = PlaybookRegistry(self.pbdir).get("portal-report-download")
        try:
            r = orch.run("get week 47 report", playbook=pb, params={"week": "47", "portal_url": self.base + "/"})
        finally:
            orch.router.close()
        self.assertEqual(r.status, "success")
        _, data = draft_from_session(self.s, r.session_id, "portal-taught", self.pbdir)
        steps = data["steps"]
        self.assertEqual([s["id"] for s in steps], ["download-report-1", "download-report-2"])
        self.assertEqual(steps[0]["script"]["input"]["url"], "{portal_url}reports")
        self.assertEqual(steps[1]["script"]["tool"], "browser_download")
        self.assertEqual(steps[1]["script"]["input"]["targets"][0], {"role": "link", "name": "Download week {week}"})
        self.assertEqual(steps[1]["checks"][0]["path"], "output/downloads/report_wk{week}.csv")
        self.assertEqual(steps[0]["no_check_reason"], "intermediate recorded action; the outcome is checked by a later step")
        self.assertEqual(validate_draft(data), [])
        # Replays for another week with no model calls.
        r2, backend = self._replay(data, {"week": "46", "portal_url": self.base + "/"})
        self.assertEqual(r2.status, "success", [(x.step.id, x.status, x.summary) for x in r2.records])
        self.assertEqual(backend.requests, [])
        self.assertTrue((self.s.output_dir / "downloads" / "report_wk46.csv").exists())

    def test_record_popups_download_upload_then_replay(self):
        self.portal.UPLOADS.clear()
        content = "region,amount\nNorth,PRIVATE-CONTENT-123\n"
        upload = self.ws.root / "samples" / "pack.csv"
        upload.write_bytes(content.encode())

        def drive(page):
            with page.expect_popup() as info:
                page.get_by_role("link", name="Open export window").click()
            export = info.value
            export.wait_for_load_state()
            with export.expect_download():
                export.get_by_role("link", name="Download summary").click()
            with page.expect_popup() as info:
                page.get_by_role("button", name="Open help").click()
            info.value.wait_for_load_state()
            info.value.close()
            page.bring_to_front()
            page.get_by_role("link", name="Upload a file").click()
            page.wait_for_url("**/upload")
            page.get_by_label("Attachment").set_input_files(str(upload))
            page.get_by_label("Comment").fill("monthly pack")
            page.get_by_role("button", name="Upload").click()
            page.wait_for_url("**/uploaded")
            page.wait_for_timeout(300)

        path, data = record_draft(self.s, "tabs-recorded", self.base + "/tabs", self.pbdir, headless=True, driver=drive, created_by="tester")
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("PRIVATE-CONTENT-123", raw)
        self.assertNotIn(str(upload.parent), raw)  # no local path, only the file name
        self.assertEqual(len(self.portal.UPLOADS), 1)
        steps = data["steps"]
        tools = [s["script"]["tool"] for s in steps]
        self.assertEqual(tools, ["browser_goto", "browser_click", "browser_download", "browser_switch_tab", "browser_click", "browser_close_tab", "browser_switch_tab", "browser_click", "browser_upload", "browser_fill", "browser_click"], json.dumps(steps, indent=1))
        host = self.base.split("//", 1)[1]
        self.assertTrue(steps[1]["script"]["input"]["expect_popup"])
        self.assertEqual(steps[1]["script"]["input"]["popup_url_contains"], host + "/export")
        self.assertTrue(steps[4]["script"]["input"]["expect_popup"])
        self.assertEqual(steps[3]["script"]["input"], {"url_contains": host + "/tabs", "tab": 0})
        self.assertEqual(steps[5]["script"]["input"], {"url_contains": host + "/help", "tab": 2})
        self.assertEqual(steps[6]["script"]["input"], {"url_contains": host + "/tabs", "tab": 0})
        self.assertEqual(steps[8]["script"]["input"]["path"], "{attachment_path}")
        self.assertEqual(steps[2]["checks"], [{"type": "file_exists", "path": "output/downloads/summary.csv"}])
        self.assertEqual(data["provenance"]["tabs"], 3)
        self.assertEqual(validate_draft(data), [])

        # Replay every step with the browser tier and no model; the upload is approved once.
        self.portal.UPLOADS.clear()
        steps[-1].pop("checks")
        steps[-1]["no_check_reason"] = "checked by the test against the portal's UPLOADS"
        r, backend = self._replay(data, {"attachment_path": str(upload), "comment": "replayed"}, approvals=[True, True])  # the file, then the form post
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertEqual(backend.requests, [])
        self.assertEqual(self.portal.UPLOADS, [{"filename": "pack.csv", "size": len(content.encode()), "sha256": __import__("hashlib").sha256(content.encode()).hexdigest(), "comment": "replayed"}])
        self.assertEqual((self.s.output_dir / "downloads" / "summary.csv").read_text(encoding="utf-8"), self.portal.SUMMARY_CSV)

        # Without approval nothing is uploaded; a path outside the allowed folders is refused.
        from analyst_agent.policy import PolicyEngine
        from analyst_agent.tools.base import ToolContext
        from analyst_agent.tools.browser import BrowserTier

        tier = BrowserTier(self.s)
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), ScriptedApprover([False]), step_id="t")
        try:
            tier.execute({"name": "browser_goto", "input": {"url": self.base + "/upload"}}, ctx)
            out = tier.execute({"name": "browser_upload", "input": {"targets": [{"label": "Attachment"}], "path": str(upload)}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("needs human approval", out.text)
            out = tier.execute({"name": "browser_upload", "input": {"targets": [{"label": "Attachment"}], "path": str(ROOT / "README.md")}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("may not read", out.text)
            out = tier.execute({"name": "browser_switch_tab", "input": {"tab": 5, "wait_s": 0.2}}, ctx)
            self.assertTrue(out.is_error)
            out = tier.execute({"name": "browser_close_tab", "input": {"tab": 0}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("last open tab", out.text)  # replay never closes the last tab
        finally:
            tier.close()

    def _tier_replay(self, data: dict, params: dict, approvals=None):
        """Run every step's tool on one BrowserTier (no model), so the test can look at its tabs."""
        from analyst_agent.policy import PolicyEngine
        from analyst_agent.tools.base import ToolContext
        from analyst_agent.tools.browser import BrowserTier

        tier = BrowserTier(self.s)
        audit = AuditLog(self.s.audit_dir)
        ctx = ToolContext(self.s, PolicyEngine(self.s), audit, ScriptedApprover(approvals or []), step_id="replay")
        outs = []
        for st in playbook_from_dict(data).bind(params).steps:
            outs.append((st.id, st.script["tool"], tier.execute({"name": st.script["tool"], "input": st.script["input"]}, ctx)))
            if outs[-1][2].is_error:
                break
        return tier, outs, audit

    def test_tabs_replay_by_url_when_the_site_opens_them_in_another_order(self):
        self.portal.WINDOW_ORDER[:] = ["export", "help"]

        def drive(page):
            with page.expect_popup() as info:
                page.get_by_role("button", name="Open both windows").click()
            info.value.wait_for_load_state()
            ctx = page.context
            for _ in range(50):
                if len(ctx.pages) >= 3:
                    break
                page.wait_for_timeout(100)
            export = next(p for p in ctx.pages if p.url.endswith("/export"))
            helpwin = next(p for p in ctx.pages if p.url.endswith("/help"))
            helpwin.wait_for_load_state()
            export.bring_to_front()
            with export.expect_download():
                export.get_by_role("link", name="Download summary").click()
            helpwin.close()
            page.bring_to_front()
            page.get_by_role("link", name="Upload a file").click()
            page.wait_for_url("**/upload")
            page.wait_for_timeout(300)

        try:
            _, data = record_draft(self.s, "order-recorded", self.base + "/tabs", self.pbdir, headless=True, driver=drive, created_by="tester")
            host = self.base.split("//", 1)[1]
            got = [(s["script"]["tool"], s["script"]["input"]) for s in data["steps"]]
            self.assertEqual([g[0] for g in got], ["browser_goto", "browser_click", "browser_switch_tab", "browser_switch_tab", "browser_download", "browser_close_tab", "browser_switch_tab", "browser_click"], json.dumps(got, indent=1))
            self.assertEqual(got[1][1]["popup_url_contains"], host + "/export")
            self.assertEqual(got[2][1], {"url_contains": host + "/help", "tab": 2, "new_tab": True, "wait_s": 10})
            self.assertEqual(got[3][1], {"url_contains": host + "/export", "tab": 1})
            self.assertEqual(got[5][1], {"url_contains": host + "/help", "tab": 2})
            self.assertEqual(validate_draft(data), [])

            # At replay the site opens the windows the other way round: /help is tab 1, /export tab 2.
            self.portal.WINDOW_ORDER[:] = ["help", "export"]
            tier, outs, audit = self._tier_replay(data, {})
            try:
                self.assertTrue(all(not o.is_error for _, _, o in outs), [(i, t, o.text) for i, t, o in outs])
                self.assertEqual(len(outs), len(data["steps"]))
                self.assertEqual((self.s.output_dir / "downloads" / "summary.csv").read_text(encoding="utf-8"), self.portal.SUMMARY_CSV)
                open_urls = sorted(p.url.rsplit("/", 1)[1] for p in tier._pages if not p.is_closed())
                self.assertEqual(open_urls, ["export", "upload"])  # the help window was closed, matched by URL
                self.assertTrue(tier._pages[1].is_closed() and tier._pages[1].url.endswith("/help"))
            finally:
                tier.close()
            events = [json.loads(x) for x in (audit.dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
            closes = [e for e in events if e.get("action") == "close_tab"]
            self.assertEqual([(e["tab"], e["matched"]) for e in closes], [(1, "url")])

            # By index alone the same draft would download from the wrong window.
            for st in data["steps"]:
                for k in ("url_contains", "popup_url_contains"):
                    st["script"]["input"].pop(k, None)
            tier, outs, _ = self._tier_replay(data, {})
            try:
                self.assertTrue(outs[-1][2].is_error, [(i, t, o.text) for i, t, o in outs])
                self.assertEqual(outs[-1][1], "browser_download")
            finally:
                tier.close()
        finally:
            self.portal.WINDOW_ORDER[:] = ["export", "help"]

    def test_record_multi_file_upload_then_replay_all(self):
        import hashlib

        self.portal.UPLOADS.clear()
        files = []
        for n, body in (("a.csv", "x,1\nPRIVATE-A\n"), ("b.csv", "y,2\nPRIVATE-B\n")):
            f = self.ws.root / "samples" / n
            f.write_bytes(body.encode())
            files.append(f)

        def drive(page):
            page.get_by_role("link", name="Upload several files").click()
            page.wait_for_url("**/upload-many")
            page.get_by_label("Attachments").set_input_files([str(f) for f in files])
            page.get_by_label("Comment").fill("two packs")
            page.get_by_role("button", name="Upload").click()
            page.wait_for_url("**/uploaded")
            page.wait_for_timeout(300)

        path, data = record_draft(self.s, "multi-recorded", self.base + "/tabs", self.pbdir, headless=True, driver=drive, created_by="tester")
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("PRIVATE-A", raw)
        self.assertNotIn(str(files[0].parent), raw)
        up = next(s for s in data["steps"] if s["script"]["tool"] == "browser_upload")
        self.assertEqual(up["script"]["input"]["paths"], "{attachments_paths}")
        self.assertEqual(data["parameters"]["attachments_paths"]["type"], "list")
        self.assertIn("a.csv, b.csv", data["parameters"]["attachments_paths"]["description"])
        self.assertEqual(data["provenance"]["warnings"], [])
        self.assertEqual(validate_draft(data), [])

        self.portal.UPLOADS.clear()
        data["steps"][-1].pop("checks")
        data["steps"][-1]["no_check_reason"] = "checked by the test against the portal's UPLOADS"
        approver_answers = [True, True]  # the file input, then the button that posts the form
        r, backend = self._replay(data, {"attachments_paths": [str(f) for f in files], "comment": "replayed"}, approvals=approver_answers)
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertEqual(backend.requests, [])
        want = [{"filename": f.name, "size": f.stat().st_size, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]
        self.assertEqual(self.portal.UPLOADS, [{"files": want, "comment": "replayed"}])

        # One path outside the allowed folders refuses the whole upload (nothing is set).
        from analyst_agent.policy import PolicyEngine
        from analyst_agent.tools.base import ToolContext
        from analyst_agent.tools.browser import BrowserTier

        tier = BrowserTier(self.s)
        approver = ScriptedApprover([True])
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), approver, step_id="t")
        try:
            tier.execute({"name": "browser_goto", "input": {"url": self.base + "/upload-many"}}, ctx)
            import os

            out = tier.execute({"name": "browser_upload", "input": {"targets": [{"label": "Attachments"}], "paths": f"{files[0]}{os.pathsep}{ROOT / 'README.md'}"}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("may not read", out.text)
            self.assertEqual(approver.seen, [])  # refused before anyone was asked
        finally:
            tier.close()

    def test_record_iframe_actions_then_replay_in_the_frame(self):
        self.portal.FRAME_SAVES.clear()
        self.portal.FRAME_NOTES.clear()

        def drive(page):
            entry = page.frame_locator("iframe[name=entry]")
            entry.get_by_label("Amount").fill("125")
            entry.get_by_label("Region").select_option("S")
            entry.get_by_role("button", name="Save").click()
            for _ in range(50):
                if self.portal.FRAME_SAVES:
                    break
                page.wait_for_timeout(100)
            notes = page.frame_locator("iframe[name=entry]").frame_locator("iframe[name=notes]")
            notes.get_by_label("Frame note").fill("checked")
            notes.get_by_role("button", name="Add note").click()
            for _ in range(50):
                if self.portal.FRAME_NOTES:
                    break
                page.wait_for_timeout(100)
            page.wait_for_timeout(300)

        _, data = record_draft(self.s, "frames-recorded", self.base + "/frames", self.pbdir, headless=True, driver=drive, created_by="tester")
        self.assertEqual(self.portal.FRAME_SAVES, [{"amount": "125", "region": "S"}])
        host = self.base.split("//", 1)[1]
        got = [(s["script"]["tool"], s["script"]["input"]) for s in data["steps"]]
        self.assertEqual([g[0] for g in got], ["browser_goto", "browser_fill", "browser_select", "browser_click", "browser_fill", "browser_click"], json.dumps(got, indent=1))
        entry_level = {"name": "entry", "url_contains": host + "/frames/entry", "css": 'iframe[name="entry"]'}
        self.assertEqual(got[1][1]["frame"], [entry_level])
        self.assertEqual(got[3][1]["frame"], [entry_level])
        self.assertEqual(got[4][1]["frame"], [entry_level, {"name": "notes", "url_contains": host + "/frames/notes", "css": 'iframe[name="notes"]'}])
        self.assertEqual(data["parameters"]["amount"]["default"], "125")
        self.assertEqual(validate_draft(data), [])

        self.portal.FRAME_SAVES.clear()
        self.portal.FRAME_NOTES.clear()
        data["steps"][-1].pop("checks")
        data["steps"][-1]["no_check_reason"] = "checked by the test against the portal's FRAME_NOTES"
        r, backend = self._replay(data, {"amount": "300", "note": "replayed note"}, approvals=[True, True])  # both frame forms post
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertEqual(backend.requests, [])
        self.assertEqual(self.portal.FRAME_SAVES, [{"amount": "300", "region": "S"}])
        self.assertEqual(self.portal.FRAME_NOTES, [{"note": "replayed note"}])

    def test_frame_off_the_allowlist_is_not_recorded_or_replayed(self):
        self.portal.FRAME_SAVES.clear()

        def drive(page):
            page.frame_locator("iframe[name=entry]").get_by_label("Amount").fill("9")
            page.frame_locator("iframe[name=entry]").get_by_label("Region").select_option("S")
            page.wait_for_timeout(300)

        _, data = record_draft(self.s, "frames-blocked", self.base + "/frames?via=localhost", self.pbdir, headless=True, driver=drive, created_by="tester")
        self.assertEqual([s["script"]["tool"] for s in data["steps"]], ["browser_goto"])
        self.assertTrue(any("frame on http://localhost" in w for w in data["provenance"]["warnings"]), data["provenance"]["warnings"])
        self.assertNotIn("localhost", data["permissions"]["hosts"])

        from analyst_agent.policy import PolicyEngine
        from analyst_agent.tools.base import ToolContext
        from analyst_agent.tools.browser import BrowserTier

        tier = BrowserTier(self.s)
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), ScriptedApprover([]), step_id="t")
        try:
            tier.execute({"name": "browser_goto", "input": {"url": self.base + "/frames?via=localhost"}}, ctx)
            out = tier.execute({"name": "browser_fill", "input": {"targets": [{"label": "Amount"}], "frame": [{"name": "entry"}], "text": "9"}}, ctx)
            self.assertTrue(out.is_error)
            self.assertIn("not allowed", out.text)
            out = tier.execute({"name": "browser_fill", "input": {"targets": [{"label": "Amount"}], "frame": [{"name": "nope"}], "text": "9"}}, ctx)
            self.assertTrue(out.is_error)
        finally:
            tier.close()

    def test_record_refuses_host_off_allowlist(self):
        with self.assertRaisesRegex(TeachError, "allowlist"):
            record_draft(self.s, "x", "https://example.com/", self.pbdir, headless=True, driver=lambda p: None)


if __name__ == "__main__":
    unittest.main()
