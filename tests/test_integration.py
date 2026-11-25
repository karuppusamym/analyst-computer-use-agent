"""End-to-end: the full orchestrator (playbook -> approval -> router -> executor ->
verifier -> report) driving the REAL browser tier against the local test portal
and the REAL pixel tier against the Legacy Ledger test app. The model is
scripted, so no gateway or tokens are needed.

The desktop test moves the real mouse; it runs only with RUN_DESKTOP_TESTS=1.
"""

from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

from analyst_agent.model import mock_text, mock_tool
from analyst_agent.orchestrator import Orchestrator
from analyst_agent.playbook import PlaybookRegistry
from analyst_agent.policy import ScriptedApprover
from analyst_agent.router import Router

from .helpers import ROOT, TempWorkspace

LIVE_DESKTOP = sys.platform == "win32" and os.environ.get("RUN_DESKTOP_TESTS") == "1"


def _last_tool_text(body: dict) -> str:
    out = []
    for block in body["messages"][-1]["content"]:
        content = block.get("content")
        if isinstance(content, list):
            out += [c.get("text", "") for c in content]
        elif isinstance(content, str):
            out.append(content)
    return "\n".join(out)


class BrowserEndToEnd(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"tiers": {"browser": {"enabled": True, "headless": True}}})
        ok, why = Router(self.ws.settings).status()["browser"]
        if not ok:
            self.skipTest(f"browser tier unavailable: {why}")
        sys.path.insert(0, str(ROOT))
        from test_targets.portal import start_portal

        self.server, _ = start_portal(0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.ws.cleanup()

    def test_download_weekly_report_from_portal(self):
        def pick_download(body):
            text = _last_tool_text(body)
            m = re.search(r"\[(e\d+)\][^\n]*Download week 47", text)
            assert m, text[:2000]
            return mock_tool("browser_download", {"ref": m.group(1)})

        script = [
            mock_tool("browser_goto", {"url": self.base + "/reports"}),
            mock_tool("browser_snapshot", {}),
            pick_download,
            mock_text("Downloaded report_wk47.csv.\nRESULT: done"),
        ]
        client, backend = self.ws.client(script)
        orch = Orchestrator(self.ws.settings, client=client, approver=ScriptedApprover([]), require_plan_approval=False)
        pb = PlaybookRegistry(self.ws.root / "playbooks").get("portal-report-download")
        try:
            r = orch.run("get week 47 report", playbook=pb, params={"week": "47", "portal_url": self.base + "/"})
        finally:
            orch.router.close()
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary, x.verdict and x.verdict.failure_text()) for x in r.records])
        self.assertTrue((self.ws.settings.output_dir / "downloads" / "report_wk47.csv").exists())
        tools = [t["name"] for t in backend.requests[0]["body"]["tools"]]
        self.assertIn("browser_snapshot", tools)
        self.assertIn("untrusted", _last_tool_text(backend.requests[2]["body"]))
        report = Path(r.report_path).read_text(encoding="utf-8")
        self.assertIn("report_wk47.csv", report)


@unittest.skipUnless(LIVE_DESKTOP, "set RUN_DESKTOP_TESTS=1 to drive the real mouse and keyboard")
class DesktopEndToEnd(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"tiers": {"desktop_pixels": {"enabled": True, "allowed_window_titles": ["Legacy Ledger - TEST"]}}})
        self.ws.settings.workspace_root.mkdir(parents=True, exist_ok=True)
        self.out = self.ws.settings.workspace_root / "legacy_ledger.csv"
        self.coords = self.ws.root / "coords.json"
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "test_targets" / "legacy_app.py"), "--out", str(self.out), "--coords", str(self.coords)])
        deadline = time.time() + 15
        while time.time() < deadline and not self.coords.exists():
            time.sleep(0.2)
        self.assertTrue(self.coords.exists(), "test app did not start")
        time.sleep(0.4)
        from analyst_agent.tools import screen_win as sw

        hwnd = sw.find_window("Legacy Ledger - TEST")
        sw.bring_to_front(hwnd)
        self.rects = json.loads(self.coords.read_text())

    def tearDown(self):
        self.proc.kill()
        self.proc.wait(5)
        self.ws.cleanup()

    def test_enter_ledger_row_through_orchestrator(self):
        router = Router(self.ws.settings)
        tier = router.route("desktop_pixels").tier
        _, s = tier.geometry()

        def c(name):
            r = self.rects[name]
            return [round((r["x"] + r["w"] / 2) * s), round((r["y"] + r["h"] / 2) * s)]

        def batch(_body):
            calls = [("left_click", {"coordinate": c("account")}), ("type", {"text": "4100-OPS"}),
                     ("left_click", {"coordinate": c("amount")}), ("type", {"text": "980.25"}),
                     ("left_click", {"coordinate": c("memo")}), ("type", {"text": "agent entry"}),
                     ("left_click", {"coordinate": c("save_entry")})]
            return {"content": [{"type": "tool_use", "id": f"toolu_{i}", "name": n, "toolset_name": "computer", "input": inp} for i, (n, inp) in enumerate(calls)], "stop_reason": "tool_use"}

        def done(body):
            # The executor attached a fresh screenshot after the batch (act-then-look).
            last = body["messages"][-1]["content"][-1]["content"]
            assert any(b.get("type") == "image" for b in last), last
            return mock_text("Saved the entry; status shows 1 entry.\nRESULT: done")

        script = [{"content": [{"type": "tool_use", "id": "toolu_s", "name": "screenshot", "toolset_name": "computer", "input": {}}], "stop_reason": "tool_use"}, batch, done]
        client, backend = self.ws.client(script)
        approver = ScriptedApprover([True])
        orch = Orchestrator(self.ws.settings, client=client, approver=approver, router=router, require_plan_approval=False)
        pb = PlaybookRegistry(self.ws.root / "playbooks").get("legacy-ledger-entry")
        r = orch.run("enter ledger row", playbook=pb, params={"account": "4100-OPS", "amount": "980.25"})
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary, x.verdict and x.verdict.failure_text()) for x in r.records])
        self.assertEqual(approver.seen[0].action_class, "submit")
        with open(self.out, newline="", encoding="utf-8") as f:
            self.assertEqual(list(csv.DictReader(f)), [{"account": "4100-OPS", "amount": "980.25", "memo": "agent entry"}])
        shots = list((self.ws.settings.audit_dir / r.session_id / "screenshots").glob("*.png"))
        self.assertGreaterEqual(len(shots), 2)


if __name__ == "__main__":
    unittest.main()
