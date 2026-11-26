"""Portal resilience: takeovers and plan approvals across a portal restart, the task deadline
during a takeover, the maximum hold time, and drag / key-chord input.

Nothing here moves the real mouse: screen_win's input functions are replaced by the recorders
in tests/test_takeover.py (FakeScreen), and runs use the scripted reconciliation playbook or the
mock model.
"""

from __future__ import annotations

import json
import threading
import time
import unittest

from analyst_agent.audit import append_event
from analyst_agent.model import mock_text
from analyst_agent.model.client import mock_tool
from analyst_agent.orchestrator import plan_fingerprint
from analyst_agent.agents import Plan
from analyst_agent.playbook import PlaybookRegistry
from analyst_agent.policy import ApprovalDecision, ApprovalRequest
from analyst_agent.portal.approvals import ApprovalInbox, WebApprover
from analyst_agent.portal.state import PendingStore
from analyst_agent.takeover import PAUSE_FILE, clear_pause, human_note, pause_info, write_pause

from .test_core import Base, plan_json
from .test_portal import wait_for
from .test_takeover import SID, TakeoverPortalCase, events, kinds


def portal_log(case) -> list[dict]:
    p = case.s.workspace_root / "portal_audit" / "portal" / "events.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


# --------------------------------------------------------------------------- deadline and max hold


class DeadlineAndHoldTests(Base):
    CODE = "open(OUTPUT_DIR + '/answer.txt', 'w').write('answer 42'); print('ok')"
    STEPS = [{"id": "s1", "intent": "write the answer", "tier": "code", "checks": [{"type": "text_contains", "path": "output/answer.txt", "text": "42"}]}]

    def _script(self):
        return [plan_json(self.STEPS), mock_tool("run_python", {"code": self.CODE}), mock_text("RESULT: done")]

    def test_task_deadline_is_extended_by_the_hold(self):
        # A 0.5 s task time-out and a 1 s takeover: the held time does not count against the task.
        self.s.data["limits"]["task_timeout_s"] = 0.5
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        write_pause(d, "rita")
        o, _, _ = self.orch(self._script())
        o.pause_poll_s = 0.02

        def hand_back():
            wait_for(lambda: "takeover_paused" in kinds(d), what="the run to pause")
            time.sleep(1.0)
            append_event(d, "takeover_ended", "rita", by="rita")
            clear_pause(d)

        t = threading.Thread(target=hand_back, daemon=True)
        t.start()
        r = o.run("what is the answer?", session_id=SID)
        t.join(5)
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        resumed = next(e for e in events(d) if e["kind"] == "takeover_resumed")
        self.assertGreaterEqual(resumed["deadline_extended_s"], 0.9)
        self.assertFalse(resumed["expired"])
        self.assertEqual(resumed["handed_back_by"], "rita")

    def test_without_a_hold_the_deadline_still_applies(self):
        self.s.data["limits"]["task_timeout_s"] = -1
        o, _, _ = self.orch(self._script())
        r = o.run("what is the answer?", session_id=SID)
        self.assertEqual(r.status, "failed")
        self.assertEqual(r.records[0].summary, "task time-out reached")

    def test_hold_expires_after_max_hold(self):
        self.s.data["limits"]["takeover_max_hold_s"] = 0.3
        self.s.data["limits"]["takeover_timeout_s"] = 30
        d = self.s.audit_dir / SID
        d.mkdir(parents=True)
        write_pause(d, "rita")
        o, backend, _ = self.orch(self._script())
        o.pause_poll_s = 0.02
        r = o.run("what is the answer?", session_id=SID)  # nobody hands back
        self.assertEqual(r.status, "success", [(x.step.id, x.status, x.summary) for x in r.records])
        self.assertFalse((d / PAUSE_FILE).exists())  # the run removed the expired hold
        ks = kinds(d)
        self.assertLess(ks.index("takeover_expired"), ks.index("takeover_resumed"))
        self.assertLess(ks.index("takeover_resumed"), ks.index("executor_turn"))
        expired = next(e for e in events(d) if e["kind"] == "takeover_expired")
        self.assertEqual((expired["by"], expired["max_hold_s"]), ("rita", 0.3))
        resumed = next(e for e in events(d) if e["kind"] == "takeover_resumed")
        self.assertTrue(resumed["expired"])
        self.assertIsNone(resumed["handed_back_by"])
        prompt = backend.requests[1]["body"]["messages"][0]["content"]
        self.assertIn("The takeover hold expired after", prompt)
        self.assertIn("fresh screenshot", prompt)

    def test_drag_in_human_note(self):
        note = human_note([{"kind": "human_action", "actor": "human:rita", "member": "left_click_drag", "input": {"start_coordinate": [1, 2], "coordinate": [30, 40]}}], "rita")
        self.assertIn("dragged from [1, 2] to [30, 40]", note)


# --------------------------------------------------------------------------- plan fingerprint and the carried approval


class FingerprintTests(Base):
    def test_fingerprint_covers_plan_version_params_and_preview(self):
        pb = PlaybookRegistry(self.ws.root / "playbooks").get("erp-crm-reconciliation")
        bound = pb.bind({"period": "2026-10"})
        plan = Plan(bound.steps, bound.final_checks, [], {}, "playbook")
        fp = plan_fingerprint("reconcile", pb, plan, {"period": "2026-10"}, "1. x")
        self.assertEqual(fp, plan_fingerprint("reconcile", pb, plan, {"period": "2026-10"}, "1. x"))
        self.assertEqual(len(fp), 64)
        other = pb.bind({"period": "2026-11"})
        self.assertNotEqual(fp, plan_fingerprint("reconcile", pb, Plan(other.steps, other.final_checks, [], {}, "playbook"), {"period": "2026-10"}, "1. x"))
        self.assertNotEqual(fp, plan_fingerprint("reconcile", pb, plan, {"period": "2026-11"}, "1. x"))
        self.assertNotEqual(fp, plan_fingerprint("reconcile", pb, plan, {"period": "2026-10"}, "1. y"))
        self.assertNotEqual(fp, plan_fingerprint("reconcile!", pb, plan, {"period": "2026-10"}, "1. x"))
        pb.version = 99
        self.assertNotEqual(fp, plan_fingerprint("reconcile", pb, plan, {"period": "2026-10"}, "1. x"))

    def test_web_approver_uses_carried_plan_once_and_only_on_a_match(self):
        seen = []
        inbox = ApprovalInbox(store=PendingStore(self.s.workspace_root / "st"))
        submitted = []
        inbox.submit = lambda sid, by, req, t: submitted.append(req) or ApprovalDecision(False, "inbox")  # noqa: E731
        plan = ApprovalRequest("plan", "plan", "Plan for: x", "1. a", fingerprint="f" * 64)
        carried = {"fingerprint": "f" * 64, "by": "rita", "request_id": "abc"}
        w = WebApprover(inbox, SID, "alice", 5, carried=carried, on_event=lambda k, **d: seen.append(k))
        d = w.request(plan)
        self.assertEqual((d.approved, d.by), (True, "rita"))
        self.assertIn("approved after a portal restart", d.note)
        self.assertFalse(w.request(plan).approved)  # used at most once
        self.assertEqual(len(submitted), 1)
        # A changed plan, a plan without a fingerprint or a first request that is not the plan: ask again.
        for req in (ApprovalRequest("plan", "plan", "s", "p", fingerprint="0" * 64), ApprovalRequest("plan", "plan", "s", "p"), ApprovalRequest("draft-email", "send", "s", "p", fingerprint="f" * 64)):
            w = WebApprover(inbox, SID, "alice", 5, carried=carried, on_event=lambda k, **d: seen.append(k))
            self.assertFalse(w.request(req).approved)
        self.assertEqual(seen, ["plan_approval_reused"] + ["plan_approval_mismatch"] * 3)
        self.assertEqual(len(submitted), 4)


# --------------------------------------------------------------------------- the portal across a restart


class RestartResilienceTests(TakeoverPortalCase):
    def approve(self, c, item_id):
        return c.post(f"/approvals/{item_id}", {"csrf": c.csrf("/approvals"), "decision": "approve"})

    def take_over_while_draft_waits(self, holder="rita"):
        alice, rita, ada = (self.client(n) for n in ("alice", "rita", "ada"))
        sid = self.start_task(alice)
        self.approve(rita, self.pending(sid, "plan").id)
        self.pending(sid, "draft-email")
        d = self.s.audit_dir / sid
        self.assertTrue((d / "checkpoint.json").exists())
        c = {"rita": rita, "ada": ada, "alice": alice}[holder]
        self.assertEqual(c.post(f"/sessions/{sid}/takeover", {"csrf": c.csrf("/")})[0], 303)
        self.assertEqual(pause_info(d)["portal_instance"], self.app.state.instance)
        return sid, d

    def test_leftover_hold_recorded_shown_and_released_by_holder(self):
        sid, d = self.take_over_while_draft_waits()
        self.restart()
        alice, bob, rita, ada = (self.client(n) for n in ("alice", "bob", "rita", "ada"))
        # Recorded once, with who held it, in portal_state and both audit logs.
        rec = self.app.state.get("takeover", sid)
        self.assertEqual((rec["status"], rec["by"], rec["role"]), ("held", "rita", "reviewer"))
        orphaned = [e for e in events(d) if e["kind"] == "takeover_orphaned"]
        self.assertEqual([(e["held_by"], e["by"]) for e in orphaned], [("rita", "portal-restart")])
        self.assertIn("takeover_orphaned", [e["kind"] for e in portal_log(self)])
        self.assertTrue(self.app.takeover.stale(sid)["from_restart"])
        # Shown as such; the owner learns who must release it and cannot resume or release it herself.
        page = alice.get(f"/sessions/{sid}")[2]
        self.assertIn("held by rita (from before restart)", page)
        self.assertIn("rita or an admin must release it", page)
        self.assertNotIn("Resume from checkpoint", page)
        self.assertNotIn("Release hold and resume", page)
        s, _, body = alice.post(f"/sessions/{sid}/resume", {"csrf": alice.csrf(f"/sessions/{sid}")})
        self.assertEqual(s, 409)
        self.assertIn("rita holds a takeover of this session from before the portal restarted", body)
        self.assertEqual(alice.post(f"/sessions/{sid}/handback", {"csrf": alice.csrf("/")})[0], 403)
        self.assertTrue((d / PAUSE_FILE).exists())
        # The holder still sees the session (with no approval pending) but gets no screen or input.
        live = rita.get(f"/sessions/{sid}/live")[2]
        self.assertIn("Held by rita (from before restart)", live)
        self.assertIn("Release hold", live)
        self.assertNotIn('id="tk"', live)
        self.assertEqual(rita.get(f"/api/sessions/{sid}/takeover/frame")[0], 409)
        self.screen.fg = ("Legacy Ledger - TEST", "python.exe")
        self.assertEqual(self.send(rita, sid, action="click", x="1", y="1")[0], 409)
        self.assertEqual(self.screen.sent, [])
        self.assertEqual(bob.get(f"/sessions/{sid}")[0], 404)
        # A second restart does not log the same hold again.
        self.restart()
        self.assertEqual(sum(1 for e in events(d) if e["kind"] == "takeover_orphaned"), 1)
        rita = self.client("rita")
        s, h, _ = rita.post(f"/sessions/{sid}/handback", {"csrf": rita.csrf("/")})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}/live?m=released"))
        self.assertFalse((d / PAUSE_FILE).exists())
        rel = next(e for e in events(d) if e["kind"] == "takeover_released")
        self.assertEqual((rel["by"], rel["held_by"], rel["from_restart"], rel["reason"], rel["actor"]), ("rita", "rita", True, "hand back", "human:rita"))
        self.assertEqual((self.app.state.get("takeover", sid)["status"], self.app.state.get("takeover", sid)["outcome"]), ("closed", "released"))
        self.assertIn("takeover_released", [e["kind"] for e in portal_log(self)])
        alice = self.client("alice")
        self.assertIn("Resume from checkpoint", alice.get(f"/sessions/{sid}")[2])

    def test_resume_by_admin_releases_the_hold_with_an_audit_event(self):
        sid, d = self.take_over_while_draft_waits()
        self.restart()
        ada = self.client("ada")
        page = ada.get(f"/sessions/{sid}")[2]
        self.assertIn("Release hold and resume", page)
        s, h, _ = ada.post(f"/sessions/{sid}/resume", {"csrf": ada.csrf(f"/sessions/{sid}")})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}?m=resumed_released"))
        rel = next(e for e in events(d) if e["kind"] == "takeover_released")
        self.assertEqual((rel["by"], rel["held_by"], rel["reason"]), ("ada", "rita", "resume"))
        # The run was waiting on a step, not on the plan, so the plan is asked for again.
        self.approve(ada, self.pending(sid, "plan").id)
        self.approve(ada, self.pending(sid, "draft-email").id)
        run = self.finished(sid)
        self.assertEqual(run.status, "success", run.message)
        ks = kinds(d)
        released = ks.index("takeover_released")
        self.assertLess(released, max(i for i, k in enumerate(ks) if k == "task_started"))  # released before the resumed run started
        self.assertNotIn("takeover_paused", ks[released:])

    def test_hand_made_pause_needs_an_admin(self):
        sid, d = self.take_over_while_draft_waits()
        self.restart()
        (d / PAUSE_FILE).write_text("")  # replace rita's hold by a hand-made PAUSE file
        alice, rita, ada = self.client("alice"), self.client("rita"), self.client("ada")
        self.assertEqual(rita.get(f"/sessions/{sid}")[0], 404)  # no longer the holder, nothing to decide
        s, _, body = alice.post(f"/sessions/{sid}/handback", {"csrf": alice.csrf("/")})
        self.assertEqual(s, 403)
        self.assertIn("only an admin", body)
        self.assertEqual(ada.post(f"/sessions/{sid}/handback", {"csrf": ada.csrf("/")})[0], 303)
        self.assertFalse((d / PAUSE_FILE).exists())

    def test_plan_approval_survives_restart_and_resumes_without_asking_again(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        rec = self.app.state.get("approval", plan.id)
        self.assertEqual(len(rec["fingerprint"]), 64)
        req_ev = next(e for e in events(self.s.audit_dir / sid) if e["kind"] == "approval_requested")
        self.assertEqual(req_ev["plan_fingerprint"], rec["fingerprint"])
        self.restart()
        d = self.s.audit_dir / sid
        parked = self.app.inbox.get(plan.id)
        self.assertTrue(parked is not None and parked.parked)
        rec = self.app.state.get("approval", plan.id)
        self.assertEqual((rec["status"], rec["instance"]), ("pending", self.app.state.instance))
        self.assertIn("approval_parked", kinds(d))
        self.assertNotIn("approval_orphaned", kinds(d))
        rita, alice = self.client("rita"), self.client("alice")
        inbox = rita.get("/approvals")[2]
        self.assertIn("Carried over a portal restart", inbox)
        self.assertIn(f'action="/approvals/{plan.id}"', inbox)
        self.assertIn(">waiting for approval<", alice.get(f"/sessions/{sid}")[2])
        # Analysts still cannot approve it; a reviewer can, and that resumes the session.
        self.assertEqual(self.approve(alice, plan.id)[0], 403)
        s, h, _ = self.approve(rita, plan.id)
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=plan_resumed"))
        self.assertEqual(self.app.state.get("approval", plan.id)["outcome"], "approved")
        send = self.pending(sid, "draft-email")  # no second plan approval
        self.assertEqual([p.req.step_id for p in self.app.inbox.pending(sid)], ["draft-email"])
        self.approve(rita, send.id)
        run = self.finished(sid)
        self.assertEqual(run.status, "success", run.message)
        evs = events(d)
        ks = [e["kind"] for e in evs]
        self.assertIn("plan_approval_reused", ks)
        self.assertNotIn("plan_approval_mismatch", ks)
        decided = [e for e in evs if e["kind"] == "approval_decided" and e["step"] == "plan"]
        self.assertEqual([(e["approved"], e["by"]) for e in decided], [(True, "rita")])
        self.assertIn("after a portal restart", decided[0]["note"])
        pd = next(e for e in evs if e["kind"] == "approval_parked_decided")
        self.assertEqual((pd["approved"], pd["by"], pd["request_id"]), (True, "rita", plan.id))
        meta = json.loads((d / "portal_meta.json").read_text(encoding="utf-8"))
        self.assertEqual((meta["owner"], meta["resumes"][-1]["by"], meta["resumes"][-1]["plan_request"]), ("alice", "rita", plan.id))
        plog = [e["kind"] for e in portal_log(self)]
        for k in ("approval_parked", "approval_decided", "run_resumed", "plan_approval_reused"):
            self.assertIn(k, plog)

    def test_changed_playbook_fails_closed_and_asks_again(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        pb_file = self.ws.root / "playbooks" / "erp_crm_reconciliation.json"
        data = json.loads(pb_file.read_text(encoding="utf-8"))
        data["version"] = int(data.get("version", 1)) + 1
        pb_file.write_text(json.dumps(data), encoding="utf-8")
        self.restart()
        rita = self.client("rita")
        self.assertEqual(self.approve(rita, plan.id)[0], 303)
        plan2 = self.pending(sid, "plan")  # the new version's plan is not covered by the old approval
        self.assertNotEqual(plan2.id, plan.id)
        self.assertFalse(plan2.parked)
        mismatch = next(e for e in events(self.s.audit_dir / sid) if e["kind"] == "plan_approval_mismatch")
        self.assertEqual(mismatch["expected"], self.app.state.get("approval", plan.id)["fingerprint"])
        self.assertNotEqual(mismatch["got"], mismatch["expected"])
        rita.post(f"/approvals/{plan2.id}", {"csrf": rita.csrf("/approvals"), "decision": "reject"})
        self.assertEqual(self.finished(sid).status, "rejected")
        self.assertNotIn("plan_approval_reused", kinds(self.s.audit_dir / sid))

    def test_parked_plan_rejected_or_timed_out_never_resumes(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        self.restart()
        rita = self.client("rita")
        s, h, _ = rita.post(f"/approvals/{plan.id}", {"csrf": rita.csrf("/approvals"), "decision": "reject"})
        self.assertEqual(h["Location"], "/approvals?m=rejected")
        self.assertNotIn(sid, self.app.runs.runs)
        pd = next(e for e in events(self.s.audit_dir / sid) if e["kind"] == "approval_parked_decided")
        self.assertEqual((pd["approved"], pd["outcome"]), (False, "declined"))
        self.assertIn(">declined<", self.client("alice").get(f"/sessions/{sid}")[2])
        # A second session: the parked plan times out (applied when the inbox is read).
        sid2 = self.start_task(self.client("alice"))
        plan2 = self.pending(sid2, "plan")
        self.restart()
        item = self.app.inbox.get(plan2.id)
        item.timeout_s = 0
        self.assertEqual(self.app.inbox.pending(sid2), [])
        self.assertEqual(self.app.state.get("approval", plan2.id)["outcome"], "timeout")
        pd = next(e for e in events(self.s.audit_dir / sid2) if e["kind"] == "approval_parked_decided")
        self.assertEqual((pd["approved"], pd["outcome"], pd["by"]), (False, "timeout", "timeout"))
        self.assertNotIn(sid2, self.app.runs.runs)

    def test_parked_plan_with_stale_hold(self):
        # Taken over while the plan waited, then a restart: approving needs the hold released;
        # the holder approving releases it on the way.
        alice, rita = self.client("alice"), self.client("rita")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        self.assertEqual(rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")})[0], 303)
        self.restart()
        d = self.s.audit_dir / sid
        self.assertTrue(self.app.inbox.get(plan.id).parked)
        self.assertIn("takeover_orphaned", kinds(d))
        rita = self.client("rita")
        s, h, _ = self.approve(rita, plan.id)
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=plan_resumed"))
        rel = next(e for e in events(d) if e["kind"] == "takeover_released")
        self.assertEqual((rel["by"], rel["reason"]), ("rita", "resume"))
        self.approve(rita, self.pending(sid, "draft-email").id)
        self.assertEqual(self.finished(sid).status, "success")

    def test_parked_plan_refused_when_resume_is_impossible(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        rita = self.client("rita")
        self.assertEqual(rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")})[0], 303)
        self.restart()
        write_pause(self.s.audit_dir / sid, "carl")  # held by someone else: rita cannot release it
        rita = self.client("rita")
        s, _, body = self.approve(rita, plan.id)
        self.assertEqual(s, 409)
        self.assertIn("carl holds a takeover", body)
        self.assertIsNone(self.app.inbox.get(plan.id).decision)  # still waiting; nothing decided
        self.assertEqual(self.app.state.get("approval", plan.id)["status"], "pending")


class KillSwitchClosesParkedPlanTests(TakeoverPortalCase):
    def test_parked_plan_not_parked_after_kill_switch(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        (self.s.audit_dir / sid / "STOP").write_text("stop requested\n")
        self.restart()
        self.assertIsNone(self.app.inbox.get(plan.id))
        self.assertEqual(self.app.state.get("approval", plan.id)["outcome"], "orphaned")


class CarryOffTests(TakeoverPortalCase):
    def test_carry_off_declines_as_before(self):
        self.s.data["portal"]["carry_plan_approvals"] = False  # read by the next PortalApp
        sid = self.start_task(self.client("alice"))
        plan = self.pending(sid, "plan")
        self.restart()
        self.assertIsNone(self.app.inbox.get(plan.id))
        self.assertEqual(self.app.state.get("approval", plan.id)["outcome"], "orphaned")
        self.assertIn("approval_orphaned", kinds(self.s.audit_dir / sid))


# --------------------------------------------------------------------------- drag and key chords


class DragAndChordTests(TakeoverPortalCase):
    takeover_cfg = {"forbidden_keys": ["alt+F4"]}

    def test_drag_and_chords_go_through_the_guard_and_audit(self):
        rita = self.client("rita")
        sid = self.start_task(rita)
        self.pending(sid, "plan")
        rita.post(f"/sessions/{sid}/takeover", {"csrf": rita.csrf("/")})
        d = self.s.audit_dir / sid
        live = rita.get(f"/sessions/{sid}/live")[2]
        self.assertIn('id=tk-chord', live)
        self.assertIn('data-key="ctrl+c"', live)
        # Not on the allowlist: the drag is refused as one action and nothing is sent.
        s, j = self.send(rita, sid, action="drag", x="10", y="20", x2="100", y2="50")
        self.assertEqual(s, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(self.screen.sent, [])
        self.screen.fg = ("Legacy Ledger - TEST", "python.exe")
        s, j = self.send(rita, sid, action="drag", x="10", y="20", x2="100", y2="50", modifiers="shift")
        self.assertTrue(j["ok"], j)
        self.assertEqual(self.screen.sent[-1][:3], ("drag", (20, 40), (200, 100)))  # 960x540 frame -> 1920x1080
        self.assertEqual(len(self.screen.sent[-1][3]), 1)  # shift held during the drag
        self.assertEqual(self.send(rita, sid, action="drag", x="1", y="1", x2="a", y2="2")[0], 400)
        # Chords.
        self.assertTrue(self.send(rita, sid, action="key", text="ctrl+c")[1]["ok"])
        self.assertEqual(self.screen.sent[-1], ("key", "ctrl+c", 1))
        self.assertTrue(self.send(rita, sid, action="key", text="ctrl+shift+Tab")[1]["ok"])
        n = len(self.screen.sent)
        for combo in ("alt+tab", "Tab+Alt", "control+shift+escape", "ctrl+alt+del", "alt+f4"):
            s, j = self.send(rita, sid, action="key", text=combo)
            self.assertEqual(s, 200, combo)
            self.assertFalse(j["ok"], combo)
            self.assertIn("not allowed during a takeover", j["message"])
        self.assertEqual(self.send(rita, sid, action="key", text="ctrl+alt+shift+a+b")[0], 400)  # too many keys
        self.assertEqual(len(self.screen.sent), n)
        evs = events(d)
        drags = [e for e in evs if e.get("member") == "left_click_drag"]
        self.assertEqual([e["kind"] for e in drags], ["human_action_refused", "human_action"])
        self.assertEqual((drags[1]["input"]["start_coordinate"], drags[1]["input"]["coordinate"], drags[1]["actor"]), ([20, 40], [200, 100], "human:rita"))
        refused_keys = [e["input"]["text"] for e in evs if e["kind"] == "human_action_refused" and e.get("member") == "key"]
        self.assertEqual(refused_keys, ["alt+tab", "Tab+Alt", "control+shift+escape", "ctrl+alt+del", "alt+f4"])
        rita.post(f"/sessions/{sid}/handback", {"csrf": rita.csrf("/")})


if __name__ == "__main__":
    unittest.main()
