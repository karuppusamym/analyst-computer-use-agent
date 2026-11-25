"""Human takeover (PAUSE), teams and session sharing.

- Orchestrator / executor pause and resume with the mock model (no gateway, no real input).
- Portal takeover over HTTP: roles, CSRF, the window allowlist guard for human input,
  coordinate scaling, dry_run, audit as actor=human:<user>. Real screen_win input functions
  are replaced by recorders, so nothing moves the real mouse.
- Teams and Share rules.
- A live input test on the Legacy Ledger test app only with RUN_DESKTOP_TESTS=1.
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from analyst_agent.agents import _LOOK_FIRST, _PAUSED, Executor
from analyst_agent.audit import AuditLog, append_event
from analyst_agent.model import mock_text
from analyst_agent.model.client import mock_tool
from analyst_agent.orchestrator import Orchestrator
from analyst_agent.playbook import Step
from analyst_agent.policy import PolicyEngine, UnattendedApprover
from analyst_agent.portal.auth import Identity
from analyst_agent.portal.takeover import TakeoverManager, frame_size, scale_point
from analyst_agent.portal.teams import Teams
from analyst_agent.router import Router
from analyst_agent.takeover import PAUSE_FILE, clear_pause, human_note, pause_info, write_pause
from analyst_agent.tools import screen_win as sw
from analyst_agent.tools.base import ToolContext
from analyst_agent.tools.computer import ComputerTier

from .helpers import TempWorkspace
from .test_core import Base, FakeComputer, plan_json
from .test_portal import PortalCase, wait_for

SID = "20990101-000000-7a4e01"
ROOT = Path(__file__).resolve().parent.parent
LIVE = sys.platform == "win32" and os.environ.get("RUN_DESKTOP_TESTS") == "1"


def kinds(session_dir: Path) -> list[str]:
    p = session_dir / "events.jsonl"
    return [json.loads(x)["kind"] for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def events(session_dir: Path) -> list[dict]:
    return [json.loads(x) for x in (session_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]


# --------------------------------------------------------------------------- pure helpers


class PureTests(unittest.TestCase):
    def test_scale_point_and_clamp(self):
        self.assertEqual(scale_point(100, 50, (960, 540), (1920, 1080)), (200, 100))
        self.assertEqual(scale_point(959, 539, (960, 540), (1920, 1080)), (1918, 1078))
        self.assertEqual(scale_point(5000, -3, (960, 540), (1920, 1080)), (1919, 0))
        self.assertEqual(scale_point(10, 10, (1280, 720), (1280, 720)), (10, 10))

    def test_frame_size(self):
        self.assertEqual(frame_size((1920, 1080), 960), (960, 540))
        self.assertEqual(frame_size((1280, 800), 1920), (1280, 800))  # never enlarged

    def test_human_note(self):
        evs = [
            {"kind": "human_action", "actor": "human:rita", "member": "left_click", "input": {"coordinate": [10, 20]}, "foreground": ["Legacy Ledger - TEST", "python.exe"]},
            {"kind": "human_action", "actor": "human:rita", "member": "type", "input": {"text": "secret-ish 123"}},
            {"kind": "human_action_refused", "actor": "human:rita", "member": "key", "input": {"text": "ctrl+s"}, "foreground": ["Notepad", "notepad.exe"]},
            {"kind": "executor_turn"},
        ]
        note = human_note(evs, "rita")
        self.assertIn("A human (rita) took over", note)
        self.assertIn("3 desktop action(s)", note)
        self.assertIn("left_click at [10, 20] in 'Legacy Ledger - TEST'", note)
        self.assertIn("typed 14 characters", note)
        self.assertNotIn("secret-ish", note)  # typed text is in the audit log, not sent to the model
        self.assertIn("REFUSED pressed ctrl+s", note)
        self.assertIn("fresh screenshot", note)

    def test_pause_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(pause_info(d))
            write_pause(d, "rita", role="reviewer")
            self.assertEqual(pause_info(d)["by"], "rita")
            (Path(d) / PAUSE_FILE).write_text("")  # a hand-made PAUSE file also pauses
            self.assertEqual(pause_info(d), {})
            self.assertTrue(clear_pause(d))
            self.assertFalse(clear_pause(d))

    def test_append_event_continues_auditlog_seq(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(d, session_id=SID)
            log.event("a")
            append_event(log.dir, "human_action", "rita", actor="human:rita", password="x")
            log.event("b")
            seqs = [e["seq"] for e in log.events()]
            self.assertEqual(seqs, [1, 2, 3])
            self.assertEqual(log.events()[1]["password"], "***")

    def test_teams_rules(self):
        t = Teams({"finance": {"members": ["alice", "bob"], "reviewers": ["rita"], "playbooks": ["erp-*"]}, "ops": {"members": ["carl"], "reviewers": ["rex", "rhea"], "playbooks": ["warehouse-region-question"]}, "all": {"reviewers": ["rhea"], "playbooks": ["*"]}})
        self.assertTrue(t.share_team("alice", "bob"))
        self.assertTrue(t.share_team("rita", "alice"))
        self.assertFalse(t.share_team("alice", "carl"))
        self.assertFalse(t.share_team("alice", None))
        self.assertTrue(t.may_review("rita", "erp-crm-reconciliation"))
        self.assertFalse(t.may_review("rita", "warehouse-region-question"))
        self.assertFalse(t.may_review("rita", None))  # planner-built sessions need "*"
        self.assertFalse(t.may_review("alice", "erp-crm-reconciliation"))  # members are not reviewers
        self.assertTrue(t.may_review("rhea", None))
        self.assertTrue(Teams({}).may_review("anyone", None))  # no teams: the old rule


# --------------------------------------------------------------------------- orchestrator pause / resume


class OrchestratorPauseTests(Base):
    CODE = "open(OUTPUT_DIR + '/answer.txt', 'w').write('answer 42'); print('ok')"

    def _steps(self, tier="code"):
        return [{"id": "s1", "intent": "write the answer", "tier": tier, "checks": [{"type": "text_contains", "path": "output/answer.txt", "text": "42"}]}]

    def _hand_back_later(self, d: Path, who="rita", delay=0.4, actions=1):
        def go():
            wait_for(lambda: "takeover_paused" in kinds(d), what="the run to pause")
            time.sleep(delay)
            for i in range(actions):
                append_event(d, "human_action", who, actor=f"human:{who}", member="left_click", input={"coordinate": [5 + i, 5]}, foreground=["Legacy Ledger - TEST", "python.exe"])
            append_event(d, "takeover_ended", who, by=who)
            clear_pause(d)

        t = threading.Thread(target=go, daemon=True)
        t.start()
        return t

    def test_pause_before_step_then_resume_with_note(self):
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        write_pause(d, "rita")
        o, backend, _ = self.orch([plan_json(self._steps()), mock_tool("run_python", {"code": self.CODE}), mock_text("RESULT: done")])
        o.pause_poll_s = 0.02
        t = self._hand_back_later(d)
        r = o.run("what is the answer?", session_id=SID)
        t.join(5)
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        ks = kinds(d)
        self.assertLess(ks.index("takeover_paused"), ks.index("takeover_resumed"))
        self.assertLess(ks.index("takeover_resumed"), ks.index("executor_turn"))  # nothing ran while paused
        resumed = next(e for e in events(d) if e["kind"] == "takeover_resumed")
        self.assertEqual((resumed["human_actions"], resumed["handed_back_by"]), (1, "rita"))
        prompt = backend.requests[1]["body"]["messages"][0]["content"]
        self.assertIn("A human (rita) took over", prompt)
        self.assertIn("left_click at [5, 5]", prompt)
        self.assertEqual(len(set(e["seq"] for e in events(d))), len(events(d)))  # no seq reused

    def test_kill_switch_while_paused(self):
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        write_pause(d, "rita")
        o, backend, _ = self.orch([plan_json(self._steps())])
        o.pause_poll_s = 0.02
        threading.Timer(0.3, lambda: (d / "STOP").write_text("stop requested\n")).start()
        r = o.run("answer?", session_id=SID)
        self.assertEqual(r.status, "blocked")
        self.assertEqual(r.records[0].summary, "stopped by kill switch")
        self.assertEqual(len(backend.requests), 1)  # only the planner; the executor never ran

    def test_takeover_timeout_stops(self):
        self.s.data["limits"]["takeover_timeout_s"] = 0.2
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        write_pause(d, "rita")
        o, _, _ = self.orch([plan_json(self._steps())])
        o.pause_poll_s = 0.02
        r = o.run("answer?", session_id=SID)
        self.assertEqual(r.status, "blocked")
        self.assertIn("not handed back within", r.records[0].summary)
        self.assertIn("takeover_timeout", kinds(d))

    def test_pause_mid_step_holds_batch_and_forces_fresh_screenshot(self):
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        self.s.output_dir.mkdir(parents=True, exist_ok=True)
        (self.s.output_dir / "answer.txt").write_text("answer 42")

        class TakeoverDuringClick(FakeComputer):
            def execute(self, block, ctx):
                out = super().execute(block, ctx)
                if block["name"] == "left_click" and len(self.done) == 1:
                    write_pause(d, "rita")  # someone presses Take over while the agent is mid-batch
                return out

        tier = TakeoverDuringClick(self.s)
        cu = lambda i, name, **inp: {"type": "tool_use", "id": i, "name": name, "toolset_name": "computer", "input": inp}  # noqa: E731
        script = [
            plan_json(self._steps("desktop_pixels")),
            {"content": [cu("a", "left_click", coordinate=[1, 1]), cu("b", "type", text="ACC-1")], "stop_reason": "tool_use"},
            {"content": [cu("c", "left_click", coordinate=[2, 2])], "stop_reason": "tool_use"},
            {"content": [cu("e", "screenshot")], "stop_reason": "tool_use"},
            mock_text("Checked the screen; the human already entered the row.\nRESULT: done"),
        ]
        o, backend, _ = self.orch(script, router=Router(self.s, tiers={"desktop_pixels": tier}))
        o.pause_poll_s = 0.02
        t = self._hand_back_later(d, actions=2)
        r = o.run("enter the row", session_id=SID)
        t.join(5)
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertEqual(tier.done, ["left_click", "screenshot"])  # "type" was held, the post-takeover click refused
        turn2 = backend.requests[2]["body"]["messages"]
        held = turn2[-1]["content"]
        self.assertEqual(held[1]["content"], _PAUSED)
        self.assertIn("A human (rita) took over", held[-1]["text"])
        self.assertIn("2 desktop action(s)", held[-1]["text"])
        turn3 = backend.requests[3]["body"]["messages"][-1]["content"]
        self.assertEqual(turn3[0]["content"], _LOOK_FIRST)
        self.assertIn("takeover_note_sent", kinds(d))

    def test_custom_tool_mode_must_look(self):
        tier = FakeComputer(self.s)
        tier.handles = lambda b: b.get("name") == "computer"
        ex = Executor(self.ws.client()[0])
        ex.must_look = True
        ctx = ToolContext(self.s, PolicyEngine(self.s), AuditLog(self.s.audit_dir), UnattendedApprover(), step_id="s", workdir=self.s.workspace_root)
        res, _, _ = ex._run_tools([{"id": "a", "name": "computer", "input": {"action": "left_click", "coordinate": [1, 1]}}], tier, ctx)
        self.assertEqual(res[0]["content"], _LOOK_FIRST)
        tier.execute = lambda block, ctx: FakeComputer.execute(tier, {**block, "name": block["input"]["action"]}, ctx)
        ex._run_tools([{"id": "b", "name": "computer", "input": {"action": "screenshot"}}], tier, ctx)
        self.assertFalse(ex.must_look)


# --------------------------------------------------------------------------- portal takeover over HTTP


class EnabledTier(ComputerTier):
    """The real ComputerTier (guard, dry_run, audit); available everywhere for the test."""

    def available(self):
        return True, "ok"


class FakeScreen:
    """Records what would have been sent with SendInput; nothing reaches the real desktop."""

    def __init__(self):
        self.fg = ("Untitled - Notepad", "notepad.exe")
        self.sent: list[tuple] = []
        self.captures: list[tuple] = []

    def patches(self):
        return [
            mock.patch.object(sw, "screen_size", lambda: (1920, 1080)),
            mock.patch.object(sw, "foreground_window", lambda: self.fg),
            mock.patch.object(sw, "click", lambda x, y, button="left", count=1, modifiers=None: self.sent.append(("click", x, y, button, count, tuple(modifiers or ())))),
            mock.patch.object(sw, "type_text", lambda text, delay=0.005: self.sent.append(("type", text))),
            mock.patch.object(sw, "key_combo", lambda combo, repeat=1: self.sent.append(("key", combo, repeat))),
            mock.patch.object(sw, "scroll", lambda x, y, d, amount=3, modifiers=None: self.sent.append(("scroll", x, y, d, amount))),
            mock.patch.object(sw, "move", lambda x, y: self.sent.append(("move", x, y))),
        ]

    def capture(self, size):
        self.captures.append(size)
        return b"\x89PNG\r\n\x1a\nfake-frame"


class TakeoverPortalCase(PortalCase):
    dry_run = False
    takeover_cfg: dict = {}

    def setUp(self):
        self.screen = FakeScreen()
        for p in self.screen.patches():
            p.start()
            self.addCleanup(p.stop)
        self._extra = {"tiers": {"desktop_pixels": {"enabled": True, "dry_run": self.dry_run, "allowed_window_titles": ["Legacy Ledger - TEST"]}}}
        self.start(portal_cfg={"takeover": {"frame_max_width": 960, **self.takeover_cfg}}, users={"alice": "analyst", "bob": "analyst", "rita": "reviewer", "ada": "admin"})

    def start(self, portal_cfg=None, dev=False, script=None, approval_timeout=30, users=None):
        orig = TempWorkspace.__init__
        extra = self._extra

        def init(ws, more=None):
            from analyst_agent.config import _deep_merge

            orig(ws, _deep_merge(more or {}, extra))

        with mock.patch.object(TempWorkspace, "__init__", init):
            super().start(portal_cfg, dev, script, approval_timeout, users)

    def _boot(self, script=None):
        from analyst_agent.model import MockBackend, ModelClient
        from analyst_agent.portal.server import PortalApp, make_server

        self.backend = MockBackend(script)
        self.app = PortalApp(self.s, self.ws.root / "playbooks", host="127.0.0.1", dev_no_auth=self._dev, client_factory=lambda s: ModelClient(s, backend=self.backend), quiet=True,
                             desktop_factory=EnabledTier, capture=self.screen.capture)
        self.srv = make_server(self.app, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def _stop_app(self):
        for sid in list(self.app.runs.runs):
            clear_pause(self.s.audit_dir / sid)  # a paused run would otherwise wait for its takeover timeout
        super()._stop_app()

    def send(self, c, sid, **form):
        s, _, body = c.post(f"/api/sessions/{sid}/takeover/input", {"csrf": c.csrf(f"/sessions/{sid}/live"), **form})
        return s, (json.loads(body) if body.startswith("{") else body)

    def finish_approving(self, sid, by):
        run = self.app.runs.runs[sid]
        end = time.time() + 30
        while run.alive and time.time() < end:
            for p in self.app.inbox.pending(sid):
                self.app.inbox.decide(p.id, True, by)
            time.sleep(0.05)
        return self.finished(sid)


class PortalTakeoverTests(TakeoverPortalCase):
    def test_takeover_input_guard_scaling_and_handback(self):
        alice, bob, rita, ada = (self.client(n) for n in ("alice", "bob", "rita", "ada"))
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        d = self.s.audit_dir / sid

        _, _, page = rita.get(f"/sessions/{sid}/live")
        self.assertIn(f'action="/sessions/{sid}/takeover"', page)
        # Hidden session: 404 like everywhere else. No CSRF token: 403. Neither pauses anything.
        self.assertEqual(bob.post(f"/sessions/{sid}/takeover", {"csrf": bob.csrf("/")})[0], 404)
        self.assertEqual(rita.post(f"/sessions/{sid}/takeover", {})[0], 403)
        self.assertEqual(rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")}, headers={"Origin": "http://evil.example"})[0], 403)
        self.assertFalse((d / PAUSE_FILE).exists())

        s, h, _ = rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}/live?m=takeover"))
        self.assertEqual(pause_info(d)["by"], "rita")
        self.assertEqual(alice.post(f"/sessions/{sid}/takeover", {"csrf": alice.csrf("/")})[0], 409)  # one holder at a time
        self.assertIn("taken over by rita", alice.get(f"/sessions/{sid}")[2])

        # The plan is approved while paused: the run must stop before step 1, not run it.
        ada.post(f"/approvals/{plan.id}", {"csrf": ada.csrf("/approvals"), "decision": "approve"})
        wait_for(lambda: "takeover_paused" in kinds(d), what="the run to pause")
        self.assertNotIn("step_started", kinds(d))
        # Rita keeps the session while she holds it, even with no approval pending.
        self.assertEqual(rita.get(f"/sessions/{sid}/live")[0], 200)

        # Only the holder sends input or sees the screen.
        self.assertEqual(self.send(alice, sid, action="click", x="10", y="10")[0], 403)
        self.assertEqual(alice.get(f"/api/sessions/{sid}/takeover/frame")[0], 403)
        s, _, png = rita.get(f"/api/sessions/{sid}/takeover/frame")
        self.assertEqual((s, png[:4]), (200, b"\x89PNG"))
        self.assertEqual(self.screen.captures[-1], (960, 540))
        self.assertEqual(ada.get(f"/api/sessions/{sid}/takeover/frame")[0], 200)  # admins may watch

        # Input without a CSRF token is refused before anything is sent.
        s, _, _ = rita.post(f"/api/sessions/{sid}/takeover/input", {"action": "click", "x": "1", "y": "1"})
        self.assertEqual(s, 403)

        # Foreground window not on the allowlist: refused, audited, nothing sent.
        s, j = self.send(rita, sid, action="click", x="100", y="50")
        self.assertEqual(s, 200)
        self.assertFalse(j["ok"])
        self.assertIn("refused", j["message"])
        self.assertEqual(self.screen.sent, [])

        # Allowlisted window: the frame point is scaled back to the screen (960x540 frame -> 1920x1080).
        self.screen.fg = ("Legacy Ledger - TEST", "python.exe")
        s, j = self.send(rita, sid, action="click", x="100", y="50")
        self.assertTrue(j["ok"], j)
        self.assertEqual(self.screen.sent[-1], ("click", 200, 100, "left", 1, ()))
        self.send(rita, sid, action="double_click", x="480", y="270", modifiers="shift")
        self.assertEqual(self.screen.sent[-1][:5], ("click", 960, 540, "left", 2))
        self.send(rita, sid, action="type", text="4000-SALES")
        self.assertEqual(self.screen.sent[-1], ("type", "4000-SALES"))
        self.send(rita, sid, action="key", text="Tab")
        self.assertEqual(self.screen.sent[-1], ("key", "Tab", 1))
        n_sent = len(self.screen.sent)
        # Never from a person: vault placeholders, Windows-key combos, unknown actions or keys.
        self.assertFalse(self.send(rita, sid, action="type", text="{{secret:portal-pw}}")[1]["ok"])
        self.assertFalse(self.send(rita, sid, action="key", text="win+r")[1]["ok"])
        self.assertFalse(self.send(rita, sid, action="key", text="super_l+r")[1]["ok"])  # alias of the Windows key
        self.assertFalse(self.send(rita, sid, action="click", x="1", y="1", modifiers="win+r")[1]["ok"])  # held during a click
        self.assertFalse(self.send(rita, sid, action="click", x="1", y="1", modifiers="ctrl+x")[1]["ok"])  # clicks hold modifiers only
        self.assertEqual(self.send(rita, sid, action="drag", x="1", y="1")[0], 400)
        self.assertEqual(self.send(rita, sid, action="key", text="notakey")[0], 400)
        self.assertEqual(len(self.screen.sent), n_sent)

        # Hand back: not by another user, by the holder.
        self.assertEqual(alice.post(f"/sessions/{sid}/handback", {"csrf": alice.csrf("/")})[0], 403)
        s, h, _ = rita.post(f"/sessions/{sid}/handback", {"csrf": rita.csrf("/")})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}/live?m=handback"))
        self.assertFalse((d / PAUSE_FILE).exists())
        # Handed back and nothing pending for her: the session is no longer rita's to see.
        self.assertEqual(self.send(rita, sid, action="click", x="1", y="1")[0], 404)
        self.assertEqual(self.send(ada, sid, action="click", x="1", y="1")[0], 403)  # no takeover any more

        run = self.finish_approving(sid, "ada")
        self.assertEqual(run.status, "success")
        evs = events(d)
        human = [e for e in evs if e["kind"] == "human_action"]
        refused = [e for e in evs if e["kind"] == "human_action_refused"]
        self.assertEqual(len(human), 4)
        self.assertTrue(all(e["actor"] == "human:rita" and e["user"] == "rita" for e in human + refused))
        self.assertEqual(human[0]["input"]["coordinate"], [200, 100])
        self.assertEqual(human[0]["foreground"], ["Legacy Ledger - TEST", "python.exe"])
        self.assertEqual(len(refused), 6)  # window, placeholder, win+r, super_l+r, click with win, click with a letter
        self.assertEqual(refused[0]["foreground"], ["Untitled - Notepad", "notepad.exe"])
        ks = [e["kind"] for e in evs]
        for k in ("takeover_started", "takeover_paused", "takeover_ended", "takeover_resumed"):
            self.assertIn(k, ks)
        started = next(e for e in evs if e["kind"] == "takeover_started")
        self.assertEqual((started["by"], started["actor"]), ("rita", "human:rita"))
        resumed = next(e for e in evs if e["kind"] == "takeover_resumed")
        self.assertEqual((resumed["human_actions"], resumed["human_refused"]), (4, 6))
        self.assertLess(ks.index("takeover_resumed"), ks.index("step_started"))
        self.assertEqual(len({e["seq"] for e in evs}), len(evs))
        portal_log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"takeover_started"', portal_log)
        self.assertIn('"human_action_refused"', portal_log)

    def test_who_may_take_over(self):
        alice, bob, rita, ada = (self.client(n) for n in ("alice", "bob", "rita", "ada"))
        sid = self.start_task(alice)
        self.pending(sid, "plan")
        d = self.s.audit_dir / sid
        # The analyst owner may (portal.takeover.owner_analysts defaults to true), and an admin may hand back.
        self.assertEqual(alice.post(f"/sessions/{sid}/takeover", {"csrf": alice.csrf("/")})[0], 303)
        self.assertEqual(ada.post(f"/sessions/{sid}/handback", {"csrf": ada.csrf("/")})[0], 303)
        self.assertFalse((d / PAUSE_FILE).exists())
        # A finished run cannot be taken over.
        ada.post(f"/approvals/{self.pending(sid, 'plan').id}", {"csrf": ada.csrf("/approvals"), "decision": "reject"})
        self.finished(sid)
        self.assertEqual(ada.post(f"/sessions/{sid}/takeover", {"csrf": ada.csrf("/")})[0], 409)
        self.assertNotIn(f'action="/sessions/{sid}/takeover"', ada.get(f"/sessions/{sid}/live")[2])


class OwnerAnalystsOffTests(TakeoverPortalCase):
    takeover_cfg = {"owner_analysts": False}

    def test_analyst_owner_refused(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        self.pending(sid, "plan")
        self.assertEqual(alice.post(f"/sessions/{sid}/takeover", {"csrf": alice.csrf("/")})[0], 403)
        self.assertNotIn(f'action="/sessions/{sid}/takeover"', alice.get(f"/sessions/{sid}/live")[2])
        self.assertFalse((self.s.audit_dir / sid / PAUSE_FILE).exists())


class DryRunTakeoverTests(TakeoverPortalCase):
    dry_run = True

    def test_dry_run_logs_but_sends_nothing(self):
        rita = self.client("rita")
        sid = self.start_task(rita)
        self.pending(sid, "plan")
        rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")})
        self.assertIn("Dry run", rita.get(f"/sessions/{sid}/live")[2])
        self.screen.fg = ("Legacy Ledger - TEST", "python.exe")
        s, j = self.send(rita, sid, action="click", x="10", y="10")
        self.assertTrue(j["ok"])
        self.assertIn("dry run", j["message"])
        self.assertEqual(self.screen.sent, [])
        ev = next(e for e in events(self.s.audit_dir / sid) if e["kind"] == "human_action")
        self.assertTrue(ev["dry_run"])
        rita.post(f"/sessions/{sid}/handback", {"csrf": rita.csrf("/")})


# --------------------------------------------------------------------------- teams and sharing


class TeamsPortalTests(PortalCase):
    def setUp(self):
        teams = {
            "finance": {"members": ["alice", "bob"], "reviewers": ["rita"], "playbooks": ["erp-crm-*"]},
            "ops": {"members": ["carl"], "reviewers": ["rex"], "playbooks": ["warehouse-region-question"]},
            "audit": {"members": [], "reviewers": ["rhea"], "playbooks": ["*"]},
        }
        self.start(portal_cfg={"teams": teams}, users={n: "analyst" for n in ("alice", "bob", "carl")} | {n: "reviewer" for n in ("rita", "rex", "rhea")} | {"ada": "admin"})

    def test_team_visibility_and_reviewer_playbooks(self):
        c = {n: self.client(n) for n in ("alice", "bob", "carl", "rita", "rex", "rhea", "ada")}
        sid = self.start_task(c["alice"], request="finance team reconcile")
        plan = self.pending(sid, "plan")
        self.assertEqual(c["bob"].get(f"/sessions/{sid}")[0], 200)  # same team as the owner
        self.assertIn(sid, c["bob"].get("/sessions")[2])
        self.assertEqual(c["carl"].get(f"/sessions/{sid}")[0], 404)  # other team
        # rex reviews only warehouse playbooks: alice's session is hidden from him, approval included.
        self.assertEqual(c["rex"].get(f"/sessions/{sid}")[0], 404)
        self.assertNotIn("finance team reconcile", c["rex"].get("/approvals")[2])
        self.assertEqual(c["rex"].post(f"/approvals/{plan.id}", {"csrf": c["rex"].csrf("/approvals"), "decision": "approve"})[0], 404)
        # Team member analysts see it but cannot decide.
        self.assertEqual(c["bob"].post(f"/approvals/{plan.id}", {"csrf": c["bob"].csrf("/approvals"), "decision": "approve"})[0], 403)
        self.assertIsNone(self.app.inbox.get(plan.id).decision)
        # Shared with rex: he can see it now, but his team still does not review this playbook.
        c["alice"].post(f"/sessions/{sid}/share", {"csrf": c["alice"].csrf("/"), "user": "rex"})
        self.assertEqual(c["rex"].get(f"/sessions/{sid}")[0], 200)
        self.assertIn("your team does not review this playbook", c["rex"].get(f"/sessions/{sid}")[2])
        s, _, _ = c["rex"].post(f"/approvals/{plan.id}", {"csrf": c["rex"].csrf("/approvals"), "decision": "approve"})
        self.assertEqual(s, 403)
        self.assertIsNone(self.app.inbox.get(plan.id).decision)
        log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"approval_forbidden"', log)
        # rita (finance reviewer, erp-crm-*) and rhea ("*") may decide; rita does.
        self.assertEqual(c["rhea"].get(f"/sessions/{sid}")[0], 200)
        self.assertIn(f'action="/approvals/{plan.id}"', c["rita"].get("/approvals")[2])
        s, h, _ = c["rita"].post(f"/approvals/{plan.id}", {"csrf": c["rita"].csrf("/approvals"), "decision": "reject"})
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=rejected"))
        self.finished(sid)
        self.assertEqual(c["rita"].get(f"/sessions/{sid}")[0], 200)  # a finance reviewer is in alice's team
        self.assertEqual(c["rhea"].get(f"/sessions/{sid}")[0], 404)  # nothing pending any more, not in the team
        self.assertEqual(c["ada"].get(f"/sessions/{sid}")[0], 200)

    def test_planner_session_needs_star_reviewer(self):
        c = {n: self.client(n) for n in ("alice", "rita", "rhea")}
        sid = self.start_task(c["alice"], request="something with no playbook", playbook="none", params="")
        # The mock model has no script, so planning fails; build the pending check on may_decide directly.
        self.finished(sid)
        rita, rhea = Identity("rita", "reviewer"), Identity("rhea", "reviewer")
        self.assertFalse(self.app.may_decide(rita, sid))
        self.assertTrue(self.app.may_decide(rhea, sid))
        self.assertTrue(self.app.may_decide(Identity("ada", "admin"), sid))
        self.assertFalse(self.app.may_decide(Identity("bob", "analyst"), sid))


class ShareTests(PortalCase):
    def setUp(self):
        self.start(users={"alice": "analyst", "bob": "analyst", "carl": "analyst", "rita": "reviewer", "ada": "admin"})

    def test_share_and_unshare(self):
        alice, bob, carl, ada = (self.client(n) for n in ("alice", "bob", "carl", "ada"))
        sid = self.start_task(alice)
        ada.post(f"/approvals/{self.pending(sid, 'plan').id}", {"csrf": ada.csrf("/approvals"), "decision": "reject"})
        self.finished(sid)
        self.assertEqual(bob.get(f"/sessions/{sid}")[0], 404)
        self.assertIn(f'action="/sessions/{sid}/share"', alice.get(f"/sessions/{sid}")[2])
        # CSRF, hidden session, bad names.
        self.assertEqual(alice.post(f"/sessions/{sid}/share", {"user": "bob"})[0], 403)
        self.assertEqual(carl.post(f"/sessions/{sid}/share", {"csrf": carl.csrf("/"), "user": "carl"})[0], 404)
        self.assertEqual(alice.post(f"/sessions/{sid}/share", {"csrf": alice.csrf("/"), "user": "bad name<>"})[0], 400)
        self.assertEqual(alice.post(f"/sessions/{sid}/share", {"csrf": alice.csrf("/"), "user": "alice"})[0], 400)
        s, h, _ = alice.post(f"/sessions/{sid}/share", {"csrf": alice.csrf("/"), "user": "bob"})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}?m=shared"))
        meta = json.loads((self.s.audit_dir / sid / "portal_meta.json").read_text(encoding="utf-8"))
        self.assertEqual((meta["owner"], meta["viewers"]), ("alice", ["bob"]))
        for path in (f"/sessions/{sid}", f"/sessions/{sid}/live", f"/api/sessions/{sid}/live"):
            self.assertEqual(bob.get(path)[0], 200, path)
        self.assertIn(sid, bob.get("/sessions")[2])
        self.assertEqual(carl.get(f"/sessions/{sid}")[0], 404)
        # A viewer cannot re-share; an admin can.
        self.assertEqual(bob.post(f"/sessions/{sid}/share", {"csrf": bob.csrf("/"), "user": "carl"})[0], 403)
        self.assertNotIn(f'action="/sessions/{sid}/share"', bob.get(f"/sessions/{sid}")[2])
        self.assertEqual(ada.post(f"/sessions/{sid}/share", {"csrf": ada.csrf("/"), "user": "carl"})[0], 303)
        self.assertEqual(carl.get(f"/sessions/{sid}")[0], 200)
        # Remove.
        alice.post(f"/sessions/{sid}/share", {"csrf": alice.csrf("/"), "user": "bob", "op": "remove"})
        self.assertEqual(bob.get(f"/sessions/{sid}")[0], 404)
        self.assertEqual(carl.get(f"/sessions/{sid}")[0], 200)
        ks = kinds(self.s.audit_dir / sid)
        self.assertEqual(ks.count("session_shared"), 2)
        self.assertEqual(ks.count("session_unshared"), 1)


# --------------------------------------------------------------------------- live (real mouse) test


class _Runs:
    def __init__(self):
        self.runs = {}

    def owner(self, sid):
        return "tester"

    def playbook_of(self, sid):
        return None

    def runnable_playbooks(self):
        return []


@unittest.skipUnless(LIVE, "set RUN_DESKTOP_TESTS=1 to drive the real mouse and keyboard")
class LiveTakeoverTest(unittest.TestCase):
    def test_human_types_into_legacy_ledger(self):
        tmp = Path(tempfile.mkdtemp())
        out, coords = tmp / "ledger.csv", tmp / "coords.json"
        proc = subprocess.Popen([sys.executable, str(ROOT / "test_targets" / "legacy_app.py"), "--out", str(out), "--coords", str(coords)])
        try:
            wait_for(coords.exists, 15, "test app")
            time.sleep(0.3)
            rects = json.loads(coords.read_text())
            hwnd = sw.find_window("Legacy Ledger - TEST")
            self.assertTrue(hwnd)
            sw.bring_to_front(hwnd)
            ws = TempWorkspace({"tiers": {"desktop_pixels": {"enabled": True, "allowed_window_titles": ["Legacy Ledger - TEST"]}}})
            self.addCleanup(ws.cleanup)
            audit = AuditLog(ws.settings.workspace_root / "portal_audit", session_id="portal")
            mgr = TakeoverManager(ws.settings, _Runs(), audit)
            d = ws.settings.audit_dir / SID
            d.mkdir(parents=True)
            (d / "events.jsonl").write_text("")
            write_pause(d, "tester")
            me = Identity("tester", "reviewer")
            model, fsize = mgr.sizes()
            (w, h), _ = mgr.tier().geometry()

            def at(name):  # centre of a field in streamed-frame pixels
                r = rects[name]
                return {"x": str((r["x"] + r["w"] / 2) * fsize[0] / w), "y": str((r["y"] + r["h"] / 2) * fsize[1] / h)}

            for form in ({"action": "click", **at("account")}, {"action": "type", "text": "4000-SALES"}, {"action": "click", **at("amount")}, {"action": "type", "text": "12.50"},
                         {"action": "click", **at("memo")}, {"action": "type", "text": "human takeover"}, {"action": "click", **at("save_entry")}):
                ok, msg = mgr.human_input(me, SID, form)
                self.assertTrue(ok, f"{form}: {msg}")
            self.assertTrue(mgr.frame(me, SID).startswith(b"\x89PNG"))
            time.sleep(0.5)
            with open(out, newline="", encoding="utf-8") as f:
                self.assertEqual(list(csv.DictReader(f)), [{"account": "4000-SALES", "amount": "12.50", "memo": "human takeover"}])
            self.assertEqual(sum(1 for e in events(d) if e["kind"] == "human_action"), 7)
        finally:
            proc.kill()
            proc.wait(5)


if __name__ == "__main__":
    unittest.main()
