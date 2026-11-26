"""Teams from SSO groups, membership checks against the user store, and reviewer limits
by approval type (action_class) and amount."""

from __future__ import annotations

import contextlib
import io
import json
import threading
import time
import unittest
from decimal import Decimal
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from analyst_agent.playbook import playbook_from_dict
from analyst_agent.policy import ApprovalRequest
from analyst_agent.portal.auth import Identity, OidcClient, UserStore
from analyst_agent.portal.cli import run_teams_check
from analyst_agent.portal.teams import ReviewerLimits, SsoGroupDirectory, Teams, parse_amount

from .helpers import TempWorkspace
from .test_portal import Client, PortalCase, _FakeIdp, test_key

PAYMENT_PLAYBOOK = {
    "name": "vendor-payment",
    "version": 1,
    "owner": "finance",
    "workflow": "pay vendor invoice",
    "description": "Pay one vendor invoice (test playbook).",
    "parameters": {"vendor": {"format": "identifier"}, "amount": {"format": "number"}},
    "steps": [
        {
            "id": "pay",
            "intent": "Pay {vendor} {amount}",
            "tier": "code",
            "approval": "required",
            "action_class": "submit",
            "approval_amount": "{amount}",
            "script": {"kind": "python", "code": "import os\nopen(os.path.join(OUTPUT_DIR, 'paid_{vendor}.txt'), 'w').write('ok')\n"},
            "checks": [{"type": "file_exists", "path": "output/paid_{vendor}.txt"}],
        }
    ],
}


def events(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# --------------------------------------------------------------------------- pure rules


class TeamRulesTests(unittest.TestCase):
    CFG = {
        "finance": {
            "members": ["alice"],
            "reviewers": ["rita", {"name": "rob", "action_classes": ["plan", "submit"], "max_amount": "1,000"}],
            "playbooks": ["vendor-*", "erp-*"],
            "sso_groups": ["fin-analysts"],
            "sso_reviewer_groups": ["fin-approvers"],
            "reviewer_limits": {"action_classes": ["plan"]},
        },
        "treasury": {"reviewers": [{"name": "rob", "max_amount": 50000}], "playbooks": ["vendor-payment"]},
    }

    def test_parse_amount(self):
        self.assertEqual(parse_amount("12,500.50"), Decimal("12500.50"))
        self.assertEqual(parse_amount(" 4 000 "), Decimal("4000"))
        self.assertEqual(parse_amount(-3), Decimal("-3"))
        for bad in ("abc", "{amount}", "", "NaN", "inf", True):
            with self.assertRaises(ValueError, msg=bad):
                parse_amount(bad)

    def test_sso_group_mapping_only_with_sso(self):
        seen = {"olga": ["fin-analysts"], "petra": ["fin-approvers"]}
        sso = Teams(self.CFG, groups_of=lambda u: seen.get(u, []))
        self.assertEqual(sso.teams_of("sam", ["fin-analysts", "staff"]), ["finance"])
        self.assertEqual(sso.teams_of("sam", ["staff"]), [])
        self.assertEqual(sso.teams_of("olga"), ["finance"])  # last-seen groups from the directory
        self.assertTrue(sso.share_team("alice", "olga"))  # config member + group member
        self.assertTrue(sso.share_team("sam", "alice", ["fin-analysts"]))
        self.assertTrue(sso.may_review("petra", "vendor-payment"))  # reviewer via group
        self.assertFalse(sso.may_review("olga", "vendor-payment"))  # member groups do not make reviewers
        self.assertEqual(sso.known_groups(), {"fin-analysts", "fin-approvers"})
        # Local sign-in (no groups_of): groups are ignored, config names only.
        local = Teams(self.CFG)
        self.assertEqual(local.teams_of("sam", ["fin-analysts"]), [])
        self.assertFalse(local.may_review("petra", "vendor-payment", ["fin-approvers"]))
        self.assertTrue(local.share_team("rita", "alice"))

    def test_limits_by_type_and_amount(self):
        t = Teams(self.CFG, groups_of=lambda u: [])
        # rita: plain name, gets the team's reviewer_limits (plan only).
        self.assertTrue(t.rights("rita", "erp-x", "plan").approve)
        r = t.rights("rita", "erp-x", "send")
        self.assertEqual((r.decide, r.approve), (True, False))
        self.assertIn("allow only plan", r.reason)
        # rob in finance: plan/submit up to 1,000; in treasury: any type up to 50,000 for vendor-payment.
        self.assertTrue(t.rights("rob", "erp-x", "submit", "999.99").approve)
        r = t.rights("rob", "erp-x", "submit", "1000.01")
        self.assertFalse(r.approve)
        self.assertIn("above your limit of 1,000", r.reason)
        self.assertTrue(t.rights("rob", "vendor-payment", "submit", "20,000").approve)  # treasury allows it
        self.assertFalse(t.rights("rob", "vendor-payment", "submit", "60000").approve)
        self.assertTrue(t.rights("rob", "vendor-payment", "submit", "-20000").approve)  # absolute value
        self.assertFalse(t.rights("rob", "vendor-payment", "submit", "-60000").approve)
        r = t.rights("rob", "vendor-payment", "submit", "lots")
        self.assertFalse(r.approve)
        self.assertIn("not a number", r.reason)
        self.assertTrue(t.rights("rob", "erp-x", "submit", None).approve)  # no amount on the request
        self.assertFalse(t.rights("rob", "erp-x", "delete").approve)
        # Group reviewers get the team limits.
        g = t.rights("petra", "vendor-payment", "submit", groups=["fin-approvers"])
        self.assertEqual((g.decide, g.approve), (True, False))
        # Outside the playbook rule: cannot even reject.
        r = t.rights("rita", "warehouse", "plan")
        self.assertEqual((r.decide, r.approve, r.reason), (False, False, "your team does not review this playbook"))
        self.assertTrue(Teams({}).rights("anyone", None, "send", "1e9").approve)  # no teams: old rule

    def test_bad_limits_fail_closed_with_warning(self):
        t = Teams({"x": {"reviewers": [{"name": "rex", "max_amount": "a lot"}, {"action_classes": ["plan"]}], "playbooks": ["*"]}})
        self.assertEqual(len(t.warnings), 2)
        r = t.rights("rex", None, "plan")
        self.assertFalse(r.approve)
        self.assertTrue(r.decide)
        self.assertIn("invalid", r.reason)
        self.assertFalse(ReviewerLimits(max_amount=Decimal(0)).refusal("send", None))

    def test_unknown_users(self):
        t = Teams(self.CFG)
        w = t.unknown_users(["alice", "rita"])
        self.assertEqual(w, ["team finance: reviewer rob is not in the local user store", "team treasury: reviewer rob is not in the local user store"])

    def test_step_amount_is_bound_from_params(self):
        pb = playbook_from_dict(PAYMENT_PLAYBOOK).bind({"vendor": "acme", "amount": "2500"})
        self.assertEqual(pb.steps[0].approval_amount, "2500")
        self.assertIsNone(playbook_from_dict({"name": "n", "steps": [{"id": "a", "approval": "required"}]}).steps[0].approval_amount)

    def test_in_step_tool_approvals_carry_the_step_amount(self):
        from analyst_agent.orchestrator import _StepAmountApprover
        from analyst_agent.policy import ApprovalDecision

        seen = []

        class Inner:
            def request(self, req):
                seen.append(req)
                return ApprovalDecision(False, "t")

        a = _StepAmountApprover(Inner(), {"pay": "2500"})
        a.request(ApprovalRequest("pay", "submit", "browser submit"))
        a.request(ApprovalRequest("other", "submit", "x"))
        a.request(ApprovalRequest("pay", "submit", "y", amount="10"))
        self.assertEqual([r.amount for r in seen], ["2500", None, "10"])

    def test_group_directory_persists(self):
        ws = TempWorkspace()
        self.addCleanup(ws.cleanup)
        p = ws.root / "g.json"
        d = SsoGroupDirectory(p)
        self.assertTrue(d.record("sam", ["b", "a"], "oidc"))
        self.assertFalse(d.record("sam", ["a", "b"], "oidc"))  # unchanged: no write
        self.assertEqual(SsoGroupDirectory(p).get("sam"), ["a", "b"])
        self.assertEqual(SsoGroupDirectory(p).get("nobody"), [])


class OidcGroupsClaimTests(unittest.TestCase):
    def test_configurable_groups_claim(self):
        c = OidcClient({"issuer": "https://idp", "client_id": "p", "redirect_uri": "https://portal/cb", "groups_claim": "grp", "group_roles": {"fin-approvers": "reviewer"}})
        ident = c.identity_from_claims({"preferred_username": "olivia", "grp": ["fin-approvers", "staff"], "groups": ["ignored"]})
        self.assertEqual((ident.role, ident.groups), ("reviewer", ("fin-approvers", "staff")))
        ident = OidcClient({"issuer": "https://idp", "client_id": "p", "redirect_uri": "x"}).identity_from_claims({"sub": "u", "groups": "a, b"})
        self.assertEqual(ident.groups, ("a", "b"))  # default claim "groups"


# --------------------------------------------------------------------------- through the portal


class LocalLimitsPortalTests(PortalCase):
    def setUp(self):
        teams = {
            "finance": {
                "members": ["alice", "ghost"],
                "reviewers": ["rita", {"name": "rob", "action_classes": ["plan", "submit"], "max_amount": 1000}],
                "playbooks": ["vendor-*"],
                "sso_groups": ["fin-analysts"],
            }
        }
        self.start(portal_cfg={"teams": teams}, users={"alice": "analyst", "rita": "reviewer", "rob": "reviewer", "ada": "admin"})
        (self.ws.root / "playbooks" / "vendor_payment.json").write_text(json.dumps(PAYMENT_PLAYBOOK), encoding="utf-8")

    def test_startup_warns_about_unknown_members(self):
        self.assertIn("team finance: member ghost is not in the local user store", self.app.team_warnings)
        self.assertIn("sso_groups / sso_reviewer_groups are ignored with portal.auth.mode local", self.app.team_warnings)
        log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"teams_config_warning"', log)
        self.assertEqual(self.client("alice").get("/")[0], 200)  # warnings never stop the portal
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = run_teams_check(self.s, UserStore(self.s.workspace_root / "portal_users.json"))
        self.assertEqual(code, 0)
        self.assertIn("warning: team finance: member ghost is not in the local user store", out.getvalue())
        self.assertIn("reviewer rob: action classes plan, submit; max amount 1,000", out.getvalue())

    def test_amount_limit_refused_server_side_and_audited(self):
        alice, rob, rita = self.client("alice"), self.client("rob"), self.client("rita")
        sid = self.start_task(alice, request="pay acme", playbook="vendor-payment", params="vendor=acme\namount=5000")
        plan = self.pending(sid, "plan")
        self.assertIn("amount 5000", plan.req.preview)
        s, h, _ = rob.post(f"/approvals/{plan.id}", {"csrf": rob.csrf("/approvals"), "decision": "approve"})
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=approved"))
        pay = self.pending(sid, "pay")
        self.assertEqual((pay.req.action_class, pay.req.amount), ("submit", "5000"))
        rec = json.loads((self.s.workspace_root / "portal_state" / f"approval-{pay.id}.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["amount"], "5000")
        # The inbox says why, and disables Approve only.
        inbox = rob.get("/approvals")[2]
        self.assertIn("You can reject but not approve this: the amount 5,000 is above your limit of 1,000", inbox)
        self.assertIn("amount <strong>5000</strong>", inbox)
        self.assertRegex(inbox, r'value=approve disabled>Approve')
        # A hand-made POST is refused all the same.
        s, _, body = rob.post(f"/approvals/{pay.id}", {"csrf": rob.csrf("/approvals"), "decision": "approve"})
        self.assertEqual(s, 403)
        self.assertIn("above your limit", body)
        self.assertIsNone(self.app.inbox.get(pay.id).decision)
        portal = [e for e in events(self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl") if e["kind"] == "approval_forbidden"]
        self.assertEqual(len(portal), 1)
        self.assertEqual((portal[0]["by"], portal[0]["amount"], portal[0]["action_class"], portal[0]["decision"]), ("rob", "5000", "submit", "approve"))
        sess = [e for e in events(self.s.audit_dir / sid / "events.jsonl") if e["kind"] == "approval_forbidden"]
        self.assertEqual(len(sess), 1)
        self.assertIn("above your limit", sess[0]["reason"])
        # rita (no limits) approves; the run finishes.
        self.assertNotIn("You can reject but not approve", rita.get("/approvals")[2])
        rita.post(f"/approvals/{pay.id}", {"csrf": rita.csrf("/approvals"), "decision": "approve"})
        run = self.finished(sid)
        self.assertEqual(run.status, "success", run.message)
        requested = [e for e in events(self.s.audit_dir / sid / "events.jsonl") if e["kind"] == "approval_requested" and e["step"] == "pay"]
        self.assertEqual(requested[0]["amount"], "5000")

    def test_type_limit_and_reject_still_allowed(self):
        alice, rob = self.client("alice"), self.client("rob")
        self.app.teams.teams["finance"].reviewers["rob"] = ReviewerLimits(frozenset({"submit"}), None)  # no "plan"
        sid = self.start_task(alice, request="pay acme", playbook="vendor-payment", params="vendor=acme\namount=10")
        plan = self.pending(sid, "plan")
        s, _, body = rob.post(f"/approvals/{plan.id}", {"csrf": rob.csrf("/approvals"), "decision": "approve"})
        self.assertEqual(s, 403)
        self.assertIn("allow only submit", body)
        s, h, _ = rob.post(f"/approvals/{plan.id}", {"csrf": rob.csrf("/approvals"), "decision": "reject"})
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=rejected"))
        self.assertEqual(self.finished(sid).status, "rejected")

    def test_forged_groups_in_session_or_form_are_ignored_in_local_mode(self):
        # A validly signed session that carries groups (e.g. from an earlier SSO setup) gives local users none.
        ident = self.app.auth.resolve({"u": "alice", "r": "analyst", "src": "oidc", "g": ["fin-analysts"], "n": "x", "exp": time.time() + 60}, {}, "127.0.0.1")
        self.assertEqual(ident.groups, ())
        alice = self.client("alice")
        s, h, _ = alice.post("/tasks", {"csrf": alice.csrf("/"), "request": "x", "playbook": "vendor-payment", "params": "vendor=a\namount=1", "groups": "fin-approvers"})
        self.assertEqual(s, 303)
        sid = parse_qs(urlsplit(h["Location"]).query)["session"][0]
        self.pending(sid, "plan")  # so teardown declines it (the run must not outlive the test)
        self.assertFalse(self.app.rights(Identity("alice", "analyst"), self.app.inbox.pending(sid)[0]).decide)


class TrustedHeaderGroupsPortalTests(PortalCase):
    def setUp(self):
        teams = {"finance": {"playbooks": ["vendor-*"], "sso_groups": ["fin-analysts"], "sso_reviewer_groups": ["fin-approvers"], "reviewer_limits": {"action_classes": ["plan"], "max_amount": 100}}}
        th = {"header": "X-Forwarded-User", "groups_header": "X-Forwarded-Groups", "proxy_ips": ["127.0.0.1/32"], "group_roles": {"fin-approvers": "reviewer"}}
        self.start({"auth": {"mode": "trusted_header", "trusted_header": th}, "teams": teams})
        (self.ws.root / "playbooks" / "vendor_payment.json").write_text(json.dumps(PAYMENT_PLAYBOOK), encoding="utf-8")

    def as_user(self, name, groups=""):
        hdr = {"X-Forwarded-User": name, **({"X-Forwarded-Groups": groups} if groups else {})}
        c = Client(self.base)
        orig = c.request

        def request(method, path, form=None, headers=None):
            return orig(method, path, form, {**hdr, **(headers or {})})

        c.request = request
        return c

    def test_groups_header_maps_to_teams_and_limits(self):
        sam = self.as_user("sam", "staff, fin-analysts")
        sid = self.start_task(sam, request="pay acme", playbook="vendor-payment", params="vendor=acme\namount=500")
        plan = self.pending(sid, "plan")
        self.assertEqual(self.app.sso_groups.get("sam"), ["fin-analysts"])  # only mapped groups are kept
        # Same team through the groups header: visible. No group: hidden.
        self.assertEqual(self.as_user("olga", "fin-analysts").get(f"/sessions/{sid}")[0], 200)
        self.assertEqual(self.as_user("quinn", "staff").get(f"/sessions/{sid}")[0], 404)
        # A forged "groups" form field does not make quinn a member or a reviewer.
        q = self.as_user("quinn", "staff")
        s, _, _ = q.post(f"/approvals/{plan.id}", {"csrf": q.csrf("/"), "decision": "approve", "groups": "fin-approvers", "X-Forwarded-Groups": "fin-approvers"})
        self.assertEqual(s, 403)  # analyst role: the groups header gave no reviewer group
        # petra is a reviewer through her group; team limits: plan only, max 100.
        petra = self.as_user("petra", "fin-approvers")
        s, h, _ = petra.post(f"/approvals/{plan.id}", {"csrf": petra.csrf("/approvals"), "decision": "approve"})
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=approved"))
        pay = self.pending(sid, "pay")
        self.assertIn("this request is &#x27;submit&#x27;", petra.get("/approvals")[2])
        s, _, _ = petra.post(f"/approvals/{pay.id}", {"csrf": petra.csrf("/approvals"), "decision": "approve"})
        self.assertEqual(s, 403)
        # Without the group header petra is no reviewer in this team (and no reviewer at all).
        bare = self.as_user("petra")
        self.assertEqual(bare.post(f"/approvals/{pay.id}", {"csrf": bare.csrf("/"), "decision": "reject"})[0], 403)
        self.assertIsNone(self.app.inbox.get(pay.id).decision)
        log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"sso_groups_seen"', log)
        self.assertIn('"approval_forbidden"', log)

    def test_groups_header_not_believed_from_other_peers(self):
        self.app.auth.acfg["trusted_header"]["proxy_ips"] = ["10.9.9.9"]
        s, _, _ = self.as_user("sam", "fin-approvers").get("/api/state")
        self.assertEqual(s, 401)
        self.assertEqual(self.app.sso_groups.get("sam"), [])


class OidcGroupsPortalTests(PortalCase):
    def test_groups_claim_captured_at_login_into_signed_session(self):
        n, e, d = test_key()
        idp = ThreadingHTTPServer(("127.0.0.1", 0), _FakeIdp)
        idp.state = {"base": f"http://127.0.0.1:{idp.server_address[1]}", "n": n, "e": e, "d": d}
        threading.Thread(target=idp.serve_forever, daemon=True).start()
        self.addCleanup(idp.server_close)
        self.addCleanup(idp.shutdown)
        teams = {"analytics": {"playbooks": ["*"], "sso_reviewer_groups": ["analytics-reviewers"], "reviewer_limits": {"action_classes": ["plan"]}}}
        self.start({"auth": {"mode": "oidc", "oidc": {"issuer": idp.state["base"], "client_id": "portal-client", "redirect_uri": "http://127.0.0.1/oidc/callback", "group_roles": {"analytics-reviewers": "reviewer"}}}, "teams": teams})
        self.app.auth.oidc.redirect_uri = self.base + "/oidc/callback"
        c = Client(self.base)
        s, h, _ = c.get("/login/oidc")
        q = {k: v[0] for k, v in parse_qs(urlsplit(h["Location"]).query).items()}
        idp.state.update(challenge=q["code_challenge"], nonce=q["nonce"])
        s, _, body = c.get(f"/oidc/callback?code=code-123&state={q['state']}")
        self.assertEqual(s, 200, body)
        sess = self.app.auth.signer.unsign(c.cookies["aa_session"])
        self.assertEqual(sess["g"], ["analytics-reviewers"])
        ident = self.app.auth.resolve(sess, {}, "127.0.0.1")
        self.assertEqual((ident.name, ident.groups), ("olivia", ("analytics-reviewers",)))
        self.assertEqual(self.app.teams.teams_of("olivia", ident.groups), ["analytics"])
        self.assertEqual(self.app.sso_groups.get("olivia"), ["analytics-reviewers"])
        # Tampering with the groups in the cookie breaks the signature: signed out.
        body_part, mac = c.cookies["aa_session"].split(".")
        forged = dict(sess, g=["admins"])
        from analyst_agent.portal.auth import b64url_encode

        c.cookies["aa_session"] = b64url_encode(json.dumps(forged, separators=(",", ":"), sort_keys=True).encode()) + "." + mac
        s, h, _ = c.get("/")
        self.assertEqual((s, h["Location"]), (303, "/login"))
        # Rights use the session's groups: plan yes, anything else no.
        self.assertTrue(self.app.teams.rights("olivia", None, "plan", groups=ident.groups).approve)
        self.assertFalse(self.app.teams.rights("olivia", None, "send", groups=ident.groups).approve)
        self.assertFalse(self.app.teams.rights("olivia", None, "plan", groups=()).decide)


if __name__ == "__main__":
    unittest.main()
