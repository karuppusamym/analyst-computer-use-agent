"""Portal tests: a real server on an ephemeral port, driven over HTTP.

Runs use the scripted reconciliation playbook (no model calls) or the mock
model client from tests/helpers.py, so no gateway is needed.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from analyst_agent.model import MockBackend, ModelClient, mock_text
from analyst_agent.portal.auth import (
    AuthError,
    Signer,
    UserStore,
    b64url_encode,
    hash_password,
    peer_is_trusted,
    rsa_pkcs1v15_sha256_verify,
    verify_id_token,
    verify_password,
)
from analyst_agent.portal.runs import safe_child
from analyst_agent.portal.server import PortalApp, make_server

from .helpers import TempWorkspace
from .test_core import plan_json

FAST = 1000  # PBKDF2 iterations for test users (production default is 600,000)


# --------------------------------------------------------------------------- tiny HTTP client


class Client:
    def __init__(self, base: str):
        u = urlsplit(base)
        self.host, self.port = u.hostname, u.port
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, form: dict | None = None, headers: dict | None = None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        h = dict(headers or {})
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        for c in r.headers.get_all("Set-Cookie") or []:
            name, _, rest = c.partition("=")
            value = rest.split(";")[0]
            if "Max-Age=0" in c:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        conn.close()
        return r.status, r.headers, data

    def get(self, path, headers=None):
        s, h, d = self.request("GET", path, headers=headers)
        return s, h, d.decode("utf-8", "replace") if not (h.get("Content-Type") or "").startswith("image/") else d

    def post(self, path, form, headers=None):
        s, h, d = self.request("POST", path, form, headers)
        return s, h, d.decode("utf-8", "replace")

    def csrf(self, path="/"):
        _, _, body = self.get(path)
        m = re.search(r'<meta name=csrf content="([^"]*)"', body)
        assert m, body[:500]
        return m.group(1)

    def login(self, name, password):
        tok = self.csrf("/login")
        return self.post("/login", {"csrf": tok, "username": name, "password": password})


def wait_for(fn, timeout=20.0, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


class PortalCase(unittest.TestCase):
    """Starts a portal per test. Subclasses set auth config through start()."""

    def start(self, portal_cfg: dict | None = None, dev: bool = False, script=None, approval_timeout: int = 30, users: dict | None = None):
        self.ws = TempWorkspace({"portal": portal_cfg or {}, "policy": {"approval_timeout_s": approval_timeout}})
        self.s = self.ws.settings
        self.s.workspace_root.mkdir(parents=True, exist_ok=True)
        store = UserStore(self.s.workspace_root / "portal_users.json")
        for name, role in (users or {}).items():
            store.add(name, role, f"pw-{name}-secret", iterations=FAST)
        self.backend = MockBackend(script)
        self.app = PortalApp(self.s, self.ws.root / "playbooks", host="127.0.0.1", dev_no_auth=dev, client_factory=lambda s: ModelClient(s, backend=self.backend), quiet=True)
        self.srv = make_server(self.app, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.addCleanup(self._stop)

    def _stop(self):
        for p in self.app.inbox.pending():
            self.app.inbox.decide(p.id, False, "test-teardown")
        for q in self.app.questions.all():
            self.app.questions.answer(q.session_id, None, "test-teardown")
        for r in self.app.runs.runs.values():
            if r.thread:
                r.thread.join(10)
        self.srv.shutdown()
        self.srv.server_close()
        self.ws.cleanup()

    def client(self, name: str | None = None) -> Client:
        c = Client(self.base)
        if name:
            s, h, _ = c.login(name, f"pw-{name}-secret")
            self.assertEqual(s, 303, f"login {name} failed")
        return c

    def start_task(self, c: Client, request="reconcile october", playbook="erp-crm-reconciliation", params="period=2026-10") -> str:
        s, h, body = c.post("/tasks", {"csrf": c.csrf("/"), "request": request, "playbook": playbook, "params": params})
        self.assertEqual(s, 303, body[:500])
        return parse_qs(urlsplit(h["Location"]).query)["session"][0]

    def pending(self, sid: str, step: str | None = None):
        def find():
            items = [p for p in self.app.inbox.pending(sid) if step is None or p.req.step_id == step]
            return items[0] if items else None

        return wait_for(find, what=f"approval {step} in {sid}")

    def finished(self, sid: str):
        run = self.app.runs.runs[sid]
        wait_for(lambda: not run.alive and run.status not in ("starting", "running"), what=f"run {sid} to finish")
        return run


# --------------------------------------------------------------------------- end-to-end through the portal


class PortalRunTests(PortalCase):
    def setUp(self):
        self.start(users={"alice": "analyst", "rita": "reviewer", "ada": "admin"})

    def test_playbook_run_with_web_approvals(self):
        alice, rita = self.client("alice"), self.client("rita")
        sid = self.start_task(alice)
        plan = self.pending(sid, "plan")
        s, _, inbox = rita.get("/approvals")
        self.assertEqual(s, 200)
        self.assertIn("Plan for: reconcile october", inbox)
        self.assertIn(f'action="/approvals/{plan.id}"', inbox)
        # Analysts cannot approve.
        s, _, body = alice.post(f"/approvals/{plan.id}", {"csrf": alice.csrf("/approvals"), "decision": "approve"})
        self.assertEqual(s, 403)
        self.assertIn("needs the reviewer role", body)
        self.assertIsNotNone(self.app.inbox.get(plan.id))
        s, h, _ = rita.post(f"/approvals/{plan.id}", {"csrf": rita.csrf("/approvals"), "decision": "approve", "note": "plan looks right"})
        self.assertEqual((s, h["Location"]), (303, "/approvals?m=approved"))
        send = self.pending(sid, "draft-email")
        self.assertEqual(send.req.action_class, "send")
        s, _, page = rita.get(f"/sessions/{sid}")
        self.assertIn("Waiting for approval", page)
        rita.post(f"/approvals/{send.id}", {"csrf": rita.csrf(f"/sessions/{sid}"), "decision": "approve", "back": "session"})
        run = self.finished(sid)
        self.assertEqual(run.status, "success", run.message)
        self.assertEqual(self.backend.requests, [])  # scripted replay: no model calls

        s, _, page = alice.get(f"/sessions/{sid}")
        self.assertEqual(s, 200)
        for text in ("success", "draft-email", "rita", "mismatches_2026-10.csv", "approval_decided", "task_finished"):
            self.assertIn(text, page)
        events = [json.loads(x) for x in (self.s.audit_dir / sid / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        decided = [e for e in events if e["kind"] == "approval_decided"]
        self.assertEqual([(e["step"], e["approved"], e["by"]) for e in decided], [("plan", True, "rita"), ("draft-email", True, "rita")])
        self.assertIn("plan looks right", decided[0]["note"])
        self.assertEqual(events[0]["user"], "alice")
        portal_log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"by": "rita"', portal_log)
        s, _, rep = alice.get(f"/sessions/{sid}/report")
        self.assertEqual(s, 200)
        self.assertIn("Task report", rep)
        s, h, csv_text = alice.get("/out/mismatches_2026-10.csv")
        self.assertEqual(s, 200)
        self.assertTrue(csv_text.startswith("invoice_id,issue"))
        s, _, lst = alice.get("/sessions")
        self.assertIn(sid, lst)
        s, _, chat = alice.get("/")
        self.assertIn("reconcile october", chat)

    def test_reject_and_timeout_decline(self):
        rita = self.client("rita")
        sid = self.start_task(rita)
        plan = self.pending(sid, "plan")
        rita.post(f"/approvals/{plan.id}", {"csrf": rita.csrf("/approvals"), "decision": "reject"})
        run = self.finished(sid)
        self.assertEqual(run.status, "rejected")
        self.assertFalse((self.s.output_dir / "mismatches_2026-10.csv").exists())
        s, h, _ = rita.post(f"/approvals/{plan.id}", {"csrf": rita.csrf("/approvals"), "decision": "approve"})
        self.assertEqual(h["Location"], "/approvals?m=gone")  # already decided

    def test_kill_switch(self):
        alice = self.client("alice")
        sid = self.start_task(alice)
        self.pending(sid, "plan")
        s, h, _ = alice.post(f"/sessions/{sid}/stop", {"csrf": alice.csrf(f"/sessions/{sid}")})
        self.assertEqual((s, h["Location"]), (303, f"/sessions/{sid}?m=stopped"))
        self.assertEqual((self.s.audit_dir / sid / "STOP").read_text(), "stop requested\n")  # same file as the `stop` command
        run = self.finished(sid)
        self.assertEqual(run.status, "rejected")  # the waiting plan approval is declined at once
        decided = [json.loads(x) for x in (self.s.audit_dir / sid / "events.jsonl").read_text(encoding="utf-8").splitlines() if '"approval_decided"' in x]
        self.assertEqual(decided[0]["by"], "alice")
        self.assertIn("kill switch", decided[0]["note"])
        s, _, page = alice.get(f"/sessions/{sid}")
        self.assertIn("STOP requested", page)

    def test_csrf_rejected(self):
        alice = self.client("alice")
        form = {"request": "reconcile october", "playbook": "erp-crm-reconciliation", "params": "period=2026-10"}
        s, _, _ = alice.post("/tasks", form)
        self.assertEqual(s, 403)
        s, _, _ = alice.post("/tasks", {**form, "csrf": "forged"})
        self.assertEqual(s, 403)
        # A token from another browser session does not work either.
        other = self.client("rita")
        s, _, _ = alice.post("/tasks", {**form, "csrf": other.csrf("/")})
        self.assertEqual(s, 403)
        # Cross-origin post with a valid token is refused too.
        s, _, _ = alice.post("/tasks", {**form, "csrf": alice.csrf("/")}, headers={"Origin": "http://evil.example"})
        self.assertEqual(s, 403)
        s, _, _ = alice.post("/tasks", {**form, "csrf": alice.csrf("/")}, headers={"Origin": "null"})
        self.assertEqual(s, 403)
        s, h, _ = alice.get("/")
        self.assertEqual(h["Referrer-Policy"], "same-origin")  # "no-referrer" makes browsers send Origin: null on form posts
        self.assertEqual(self.app.runs.runs, {})
        self.assertIn("csrf_rejected", (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8"))

    def test_auth_required_and_login(self):
        anon = Client(self.base)
        s, h, _ = anon.get("/")
        self.assertEqual((s, h["Location"]), (303, "/login"))
        s, _, _ = anon.get("/api/state")
        self.assertEqual(s, 401)
        s, _, body = anon.login("alice", "wrong-password")
        self.assertEqual(s, 401)
        self.assertIn("Wrong user name or password", body)
        s, _, _ = anon.login("alice", "pw-alice-secret")
        self.assertEqual(s, 303)
        s, h, body = anon.get("/")
        self.assertEqual(s, 200)
        self.assertIn("alice", body)
        for header in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            self.assertIn(header, h)
        cookie = [c for c in h.get_all("Set-Cookie") or []]
        self.assertEqual(cookie, [])  # session already set at login
        s, _, _ = anon.post("/logout", {"csrf": anon.csrf("/")})
        self.assertEqual(s, 303)
        s, h, _ = anon.get("/")
        self.assertEqual(s, 303)
        # Tampered session cookie is ignored.
        anon.cookies["aa_session"] = anon.cookies["aa_session"][:-2] + "xx"
        s, _, _ = anon.get("/sessions")
        self.assertEqual(s, 303)

    def test_cookie_flags(self):
        c = Client(self.base)
        tok = c.csrf("/login")
        s, h, _ = c.request("POST", "/login", {"csrf": tok, "username": "alice", "password": "pw-alice-secret"})
        sc = h["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, sc)

    def test_bad_host_header_refused(self):
        s, _, _ = Client(self.base).get("/login", headers={"Host": "evil.example:80"})
        self.assertEqual(s, 421)

    def test_path_traversal_refused(self):
        alice = self.client("alice")
        sid = "20990101-000000-abcdef"
        d = self.s.audit_dir / sid
        (d / "screenshots").mkdir(parents=True)
        (d / "events.jsonl").write_text(json.dumps({"seq": 1, "ts": time.time(), "kind": "task_started", "request": "x", "user": "alice"}) + "\n")
        (d / "screenshots" / "00001-screen.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
        bad = [
            f"/sessions/{sid}/file/../../portal_users.json",
            f"/sessions/{sid}/file/..%2f..%2fportal_users.json",
            f"/sessions/{sid}/file/%2e%2e/%2e%2e/portal_secret.key",
            f"/sessions/{sid}/file/..%5c..%5cportal_secret.key",
            f"/sessions/{sid}/file/C:/Windows/win.ini",
            f"/sessions/{sid}/file//etc/passwd",
            "/sessions/../file/portal_users.json",
            "/sessions/..%2f..%2f/file/portal_users.json",
            "/out/../portal_users.json",
            "/out/..%2f..%2fportal_secret.key",
        ]
        for path in bad:
            s, _, body = alice.get(path)
            self.assertIn(s, (400, 404), path)
            self.assertNotIn("pbkdf2_sha256", body if isinstance(body, str) else "", path)
        s, h, data = alice.get(f"/sessions/{sid}/file/screenshots/00001-screen.png")
        self.assertEqual((s, h["Content-Type"]), (200, "image/png"))
        # The live view lists the screenshot and the audit tail.
        s, _, body = alice.get(f"/api/sessions/{sid}/live?after=0")
        live = json.loads(body)
        self.assertEqual([x["name"] for x in live["screenshots"]], ["00001-screen.png"])
        self.assertEqual(live["events"][0]["kind"], "task_started")
        s, _, page = alice.get(f"/sessions/{sid}/live")
        self.assertIn(f'data-api="/api/sessions/{sid}/live"', page)
        root = self.s.workspace_root
        self.assertIsNone(safe_child(root / "audit", "../portal_users.json"))
        self.assertIsNone(safe_child(root / "audit", "a/../../x"))
        self.assertIsNone(safe_child(root / "audit", "C:\\x"))
        self.assertIsNotNone(safe_child(root / "audit", "a/b.png"))

    def test_html_is_escaped(self):
        alice = self.client("alice")
        sid = self.start_task(alice, request="<script>alert(1)</script> reconcile")
        self.pending(sid, "plan")
        s, _, page = alice.get(f"/sessions/{sid}")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)


class PortalQuestionTests(PortalCase):
    def test_clarifying_questions_surface_and_block(self):
        script = [plan_json([], questions=["Which period?"]), plan_json([], questions=["Still unclear: which region?"])]
        self.start(users={"alice": "analyst", "bob": "analyst"}, script=script)
        alice = self.client("alice")
        sid = self.start_task(alice, request="something vague", playbook="none", params="")
        wait_for(lambda: self.app.questions.get(sid), what="question")
        s, _, chat = alice.get("/")
        self.assertIn("Which period?", chat)
        self.assertIn(f'action="/sessions/{sid}/answer"', chat)
        bob = self.client("bob")
        s, _, _ = bob.post(f"/sessions/{sid}/answer", {"csrf": bob.csrf("/"), "a0": "2026-10"})
        self.assertEqual(s, 403)  # only the requester (or an admin) answers
        s, h, _ = alice.post(f"/sessions/{sid}/answer", {"csrf": alice.csrf("/"), "a0": "2026-10"})
        self.assertEqual((s, h["Location"]), (303, "/?m=answered"))
        run = self.finished(sid)
        self.assertEqual(run.status, "needs_input")
        self.assertIn("Answers:", json.dumps(self.backend.requests[1]["body"]["messages"]))
        self.assertIn("2026-10", json.dumps(self.backend.requests[1]["body"]["messages"]))


class PortalTimeoutTests(PortalCase):
    def test_approval_timeout_declines(self):
        self.start(users={"alice": "analyst"}, approval_timeout=1)
        sid = self.start_task(self.client("alice"))
        run = self.finished(sid)
        self.assertEqual(run.status, "rejected")
        self.assertEqual(run.result.approvals[0]["by"], "timeout")
        self.assertEqual(self.app.inbox.history()[0].decision.by, "timeout")


# --------------------------------------------------------------------------- playbook review


class PlaybookReviewTests(PortalCase):
    def setUp(self):
        self.start(users={"alice": "analyst", "rita": "reviewer", "ada": "admin"})
        src = json.loads((self.ws.root / "playbooks" / "warehouse_region_question.json").read_text(encoding="utf-8"))
        drafts = self.ws.root / "playbooks" / "drafts"
        drafts.mkdir()
        for stem, author in (("ok_draft", "alice"), ("bad_idea", "alice"), ("ritas_own", "rita")):
            d = dict(src, name=f"draft-{stem}", version=1, status="draft", author=author, teach_session="t-1")
            (drafts / f"{stem}.json").write_text(json.dumps(d), encoding="utf-8")
        (drafts / "broken.json").write_text("{not json", encoding="utf-8")

    def test_list_view_approve_reject(self):
        alice, rita = self.client("alice"), self.client("rita")
        s, _, page = alice.get("/playbooks")
        self.assertEqual(s, 200)
        for t in ("erp-crm-reconciliation", "draft-ok_draft", "drafts/broken.json", "finance-analytics"):
            self.assertIn(t, page)
        s, _, view = alice.get("/playbooks/view?id=drafts%2Fok_draft.json")
        self.assertEqual(s, 200)
        self.assertIn("Review this draft", view)
        # Drafts never run.
        s, _, body = alice.post("/tasks", {"csrf": alice.csrf("/"), "request": "x", "playbook": "draft-ok_draft", "params": ""})
        self.assertEqual(s, 400)
        self.assertNotIn("draft-ok_draft", alice.get("/")[2].split("<h2>Conversations</h2>")[0])
        # Analysts cannot review.
        s, _, body = alice.post("/playbooks/review", {"csrf": alice.csrf("/playbooks"), "id": "drafts/ok_draft.json", "decision": "approve"})
        self.assertEqual(s, 403)
        self.assertIn("needs the reviewer role", body)
        s, h, _ = rita.post("/playbooks/review", {"csrf": rita.csrf("/playbooks"), "id": "drafts/ok_draft.json", "decision": "approve", "note": "checked"})
        self.assertEqual((s, h["Location"]), (303, "/playbooks?m=pb_approved"))
        published = json.loads((self.ws.root / "playbooks" / "ok_draft.json").read_text(encoding="utf-8"))
        self.assertEqual((published["status"], published["reviewed_by"], published["teach_session"]), ("approved", "rita", "t-1"))
        self.assertFalse((self.ws.root / "playbooks" / "drafts" / "ok_draft.json").exists())
        self.assertIn("draft-ok_draft", [p.name for p in self.app.runs.runnable_playbooks()])
        s, h, _ = rita.post("/playbooks/review", {"csrf": rita.csrf("/playbooks"), "id": "drafts/bad_idea.json", "decision": "reject", "note": "no"})
        self.assertEqual(h["Location"], "/playbooks?m=pb_rejected")
        rej = json.loads((self.ws.root / "playbooks" / "drafts" / "rejected" / "bad_idea.json").read_text(encoding="utf-8"))
        self.assertEqual((rej["status"], rej["reviewed_by"]), ("rejected", "rita"))
        # Four eyes: the author cannot approve their own draft; an admin can.
        s, _, body = rita.post("/playbooks/review", {"csrf": rita.csrf("/playbooks"), "id": "drafts/ritas_own.json", "decision": "approve"})
        self.assertEqual(s, 409)
        ada = self.client("ada")
        s, _, _ = ada.post("/playbooks/review", {"csrf": ada.csrf("/playbooks"), "id": "drafts/ritas_own.json", "decision": "approve"})
        self.assertEqual(s, 303)
        # A broken draft cannot be approved but can be rejected.
        s, _, _ = rita.post("/playbooks/review", {"csrf": rita.csrf("/playbooks"), "id": "drafts/broken.json", "decision": "approve"})
        self.assertEqual(s, 409)
        log = (self.s.workspace_root / "portal_audit" / "portal" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn("playbook_approved", log)
        self.assertIn("playbook_rejected", log)


# --------------------------------------------------------------------------- auth modes


class AuthModeTests(unittest.TestCase):
    def test_refuses_without_users_and_dev_only_on_loopback(self):
        ws = TempWorkspace()
        self.addCleanup(ws.cleanup)
        with self.assertRaises(AuthError):
            PortalApp(ws.settings, ws.root / "playbooks")
        with self.assertRaises(AuthError):
            PortalApp(ws.settings, ws.root / "playbooks", host="0.0.0.0", dev_no_auth=True)
        app = PortalApp(ws.settings, ws.root / "playbooks", host="127.0.0.1", dev_no_auth=True)
        self.assertEqual(app.auth.mode, "dev")
        self.assertTrue((ws.settings.workspace_root / "portal_secret.key").exists())

    def test_pbkdf2_and_user_store(self):
        h = hash_password("correct horse", iterations=FAST)
        self.assertTrue(h.startswith(f"pbkdf2_sha256${FAST}$"))
        self.assertTrue(verify_password("correct horse", h))
        self.assertFalse(verify_password("correct horsE", h))
        self.assertFalse(verify_password("x", "garbage"))
        self.assertNotEqual(h, hash_password("correct horse", iterations=FAST))  # salted
        ws = TempWorkspace()
        self.addCleanup(ws.cleanup)
        store = UserStore(ws.root / "users.json")
        store.add("eve", "reviewer", "long-enough-pw", iterations=FAST)
        self.assertNotIn("long-enough-pw", (ws.root / "users.json").read_text())
        self.assertEqual(store.authenticate("eve", "long-enough-pw").role, "reviewer")
        self.assertIsNone(store.authenticate("eve", "nope"))
        with self.assertRaises(AuthError):
            store.add("x", "superuser", "long-enough-pw")
        with self.assertRaises(AuthError):
            store.add("x", "analyst", "short")

    def test_signer(self):
        s = Signer(secrets.token_bytes(32))
        tok = s.sign({"u": "a", "exp": time.time() + 60})
        self.assertEqual(s.unsign(tok)["u"], "a")
        self.assertIsNone(s.unsign(tok[:-1] + ("A" if tok[-1] != "A" else "B")))
        self.assertIsNone(Signer(secrets.token_bytes(32)).unsign(tok))
        self.assertIsNone(s.unsign(s.sign({"u": "a", "exp": time.time() - 1})))

    def test_peer_is_trusted(self):
        self.assertTrue(peer_is_trusted("10.0.0.5", ["10.0.0.0/24"]))
        self.assertTrue(peer_is_trusted("::ffff:10.0.0.5", ["10.0.0.5"]))
        self.assertFalse(peer_is_trusted("10.0.1.5", ["10.0.0.0/24"]))
        self.assertFalse(peer_is_trusted("not-an-ip", ["10.0.0.0/24"]))


class TrustedHeaderTests(PortalCase):
    def test_header_only_believed_from_proxy(self):
        self.start({"auth": {"mode": "trusted_header", "trusted_header": {"header": "X-Forwarded-User", "groups_header": "X-Forwarded-Groups", "proxy_ips": ["10.9.9.9"], "group_roles": {"ops-reviewers": "reviewer"}}}})
        c = Client(self.base)
        s, h, _ = c.get("/", headers={"X-Forwarded-User": "mallory"})
        self.assertEqual((s, h["Location"]), (303, "/login"))  # 127.0.0.1 is not the proxy
        s, _, _ = c.get("/api/state", headers={"X-Forwarded-User": "mallory"})
        self.assertEqual(s, 401)

    def test_header_from_proxy_with_roles(self):
        self.start({"auth": {"mode": "trusted_header", "trusted_header": {"header": "X-Forwarded-User", "groups_header": "X-Forwarded-Groups", "proxy_ips": ["127.0.0.1/32"], "group_roles": {"ops-reviewers": "reviewer"}}}})
        hdr = {"X-Forwarded-User": "sam", "X-Forwarded-Groups": "staff, ops-reviewers"}
        c = Client(self.base)
        s, _, body = c.get("/", headers=hdr)
        self.assertEqual(s, 200)
        self.assertIn("sam", body)
        self.assertIn(">reviewer<", body)
        tok = re.search(r'<meta name=csrf content="([^"]*)"', body).group(1)
        s, _, _ = c.post("/tasks", {"csrf": tok, "request": "x", "playbook": "erp-crm-reconciliation", "params": "period=2026-10"}, headers=hdr)
        self.assertEqual(s, 303)
        # A plain analyst (no group) cannot review.
        s, _, _ = Client(self.base).get("/approvals", headers={"X-Forwarded-User": "pat"})
        self.assertEqual(s, 200)
        c2 = Client(self.base)
        tok2 = re.search(r'<meta name=csrf content="([^"]*)"', c2.get("/", headers={"X-Forwarded-User": "pat"})[2]).group(1)
        s, _, body = c2.post("/playbooks/review", {"csrf": tok2, "id": "x", "decision": "approve"}, headers={"X-Forwarded-User": "pat"})
        self.assertEqual(s, 403)
        self.assertIn("needs the reviewer role", body)


# --------------------------------------------------------------------------- RS256 / OIDC


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(c):
            return c


def generate_rsa(bits: int = 2048) -> tuple[int, int, int]:
    """Pure-Python RSA key: (n, e, d)."""
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        n = p * q
        if p != q and n.bit_length() == bits and phi % e:
            return n, e, pow(e, -1, phi)


def rsa_sign(n: int, d: int, message: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def make_jwt(n: int, d: int, claims: dict, kid: str = "k1", alg: str = "RS256") -> str:
    head = b64url_encode(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    signed = f"{head}.{body}".encode()
    return f"{head}.{body}.{b64url_encode(rsa_sign(n, d, signed))}"


def jwk(n: int, e: int, kid: str = "k1") -> dict:
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")), "e": b64url_encode(e.to_bytes(3, "big"))}


_KEY: tuple[int, int, int] | None = None


def test_key() -> tuple[int, int, int]:
    global _KEY
    if _KEY is None:
        _KEY = generate_rsa(2048)
    return _KEY


class Rs256Tests(unittest.TestCase):
    def setUp(self):
        self.n, self.e, self.d = test_key()
        self.jwks = {"keys": [jwk(self.n, self.e)]}
        self.claims = {"iss": "https://idp.example", "aud": "portal", "sub": "u1", "exp": time.time() + 300, "iat": time.time(), "nonce": "n-1"}

    def verify(self, tok, **kw):
        args = dict(issuer="https://idp.example", audience="portal", nonce="n-1")
        args.update(kw)
        return verify_id_token(tok, self.jwks, **args)

    def test_valid_token(self):
        self.assertEqual(self.verify(make_jwt(self.n, self.d, self.claims))["sub"], "u1")

    def test_rejections(self):
        good = make_jwt(self.n, self.d, self.claims)
        h, b, sig = good.split(".")
        tampered = h + "." + b64url_encode(json.dumps({**self.claims, "sub": "admin"}).encode()) + "." + sig
        cases = {
            "signature": tampered,
            "issuer": make_jwt(self.n, self.d, {**self.claims, "iss": "https://evil.example"}),
            "audience": make_jwt(self.n, self.d, {**self.claims, "aud": "other"}),
            "expired": make_jwt(self.n, self.d, {**self.claims, "exp": time.time() - 3600}),
            "nonce": make_jwt(self.n, self.d, {**self.claims, "nonce": "n-2"}),
            "kid": make_jwt(self.n, self.d, self.claims, kid="unknown"),
            "alg": make_jwt(self.n, self.d, self.claims, alg="HS256"),
            "none": b64url_encode(json.dumps({"alg": "none", "kid": "k1"}).encode()) + "." + b + ".",
        }
        for why, tok in cases.items():
            with self.assertRaises(AuthError, msg=why):
                self.verify(tok)
        self.assertTrue(rsa_pkcs1v15_sha256_verify(self.n, self.e, b"m", rsa_sign(self.n, self.d, b"m")))
        self.assertFalse(rsa_pkcs1v15_sha256_verify(self.n, self.e, b"m2", rsa_sign(self.n, self.d, b"m")))
        self.assertFalse(rsa_pkcs1v15_sha256_verify(self.n, self.e, b"m", rsa_sign(self.n, self.d, b"m"), min_bits=4096))

    def test_cross_check_with_cryptography(self):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
        except ImportError:
            self.skipTest("cryptography is not installed (the pure-Python key tests above still ran)")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = key.public_key().public_numbers()
        msg = b"header.payload"
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        self.assertTrue(rsa_pkcs1v15_sha256_verify(nums.n, nums.e, msg, sig))
        self.assertFalse(rsa_pkcs1v15_sha256_verify(nums.n, nums.e, msg + b"x", sig))


class _FakeIdp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        st = self.server.state
        if self.path == "/.well-known/openid-configuration":
            b = st["base"]
            return self._json({"issuer": b, "authorization_endpoint": b + "/authorize", "token_endpoint": b + "/token", "jwks_uri": b + "/jwks"})
        if self.path == "/jwks":
            return self._json({"keys": [jwk(st["n"], st["e"])]})
        self._json({"error": "not_found"}, 404)

    def do_POST(self):  # noqa: N802
        st = self.server.state
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        st["token_form"] = form
        challenge = b64url_encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
        if self.path != "/token" or form.get("code") != "code-123" or challenge != st.get("challenge"):
            return self._json({"error": "invalid_grant"}, 400)
        claims = {"iss": st["base"], "aud": "portal-client", "sub": "s-9", "preferred_username": "olivia", "groups": ["analytics-reviewers"], "exp": time.time() + 300, "iat": time.time(), "nonce": st["nonce"]}
        self._json({"id_token": make_jwt(st["n"], st["d"], claims), "token_type": "Bearer"})


class OidcFlowTests(PortalCase):
    def test_authorization_code_pkce_flow(self):
        n, e, d = test_key()
        idp = ThreadingHTTPServer(("127.0.0.1", 0), _FakeIdp)
        idp.state = {"base": f"http://127.0.0.1:{idp.server_address[1]}", "n": n, "e": e, "d": d}
        threading.Thread(target=idp.serve_forever, daemon=True).start()
        self.addCleanup(idp.server_close)
        self.addCleanup(idp.shutdown)
        self.start({"auth": {"mode": "oidc", "oidc": {"issuer": idp.state["base"], "client_id": "portal-client", "redirect_uri": "http://127.0.0.1/oidc/callback", "group_roles": {"analytics-reviewers": "reviewer"}}}})
        self.app.auth.oidc.redirect_uri = self.base + "/oidc/callback"
        c = Client(self.base)
        s, h, body = c.get("/login")
        self.assertIn("/login/oidc", body)
        s, h, _ = c.get("/login/oidc")
        self.assertEqual(s, 302)
        loc = urlsplit(h["Location"])
        q = {k: v[0] for k, v in parse_qs(loc.query).items()}
        self.assertEqual((q["response_type"], q["client_id"], q["code_challenge_method"]), ("code", "portal-client", "S256"))
        self.assertIn("SameSite=Lax", h["Set-Cookie"])
        idp.state.update(challenge=q["code_challenge"], nonce=q["nonce"])
        # Wrong state is refused.
        s, _, _ = c.get("/oidc/callback?code=code-123&state=forged")
        self.assertEqual(s, 400)
        s, h, body = c.get(f"/oidc/callback?code=code-123&state={q['state']}")
        self.assertEqual(s, 200, body)
        self.assertIn('http-equiv="refresh"', body)
        self.assertEqual(idp.state["token_form"]["grant_type"], "authorization_code")
        s, _, page = c.get("/")
        self.assertEqual(s, 200)
        self.assertIn("olivia", page)
        self.assertIn(">reviewer<", page)
        # The state is single-use.
        s, _, _ = Client(self.base).get(f"/oidc/callback?code=code-123&state={q['state']}")
        self.assertEqual(s, 400)


if __name__ == "__main__":
    unittest.main()
