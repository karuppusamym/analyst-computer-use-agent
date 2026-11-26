"""Regressions for the second round of the 25 Nov 2026 safety review: portal session ids,
login limits, sign-out revocation, OIDC user names, vault redirects, teach-mode secret
detection, form-posting clicks and the desktop guard under the pointer and while typing."""

from __future__ import annotations

import http.server
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from analyst_agent import teach
from analyst_agent.audit import AuditLog
from analyst_agent.policy import PolicyEngine, ScriptedApprover, UnattendedApprover
from analyst_agent.portal.auth import AuthError, Authenticator, Identity, OidcClient
from analyst_agent.portal.runs import valid_session_id
from analyst_agent.tools import screen_win as sw
from analyst_agent.tools.base import ToolContext
from analyst_agent.tools.computer import ComputerTier
from analyst_agent.vault import EnvVault, SecretRefused, resolve_secrets
from analyst_agent.vault_remote import RemoteError, http_json

from .helpers import TempWorkspace


class SessionIdTests(unittest.TestCase):
    def test_only_one_spelling_per_folder(self):
        for ok in ("20261125-101010-abc123", "eval-kpi-wk47-1795643851", "sess-1", "a"):
            self.assertTrue(valid_session_id(ok), ok)
        for bad in ("20261125-101010-ABC123", "sess-1.", "sess-1 ", "..", "a/b", "", "-x"):
            self.assertFalse(valid_session_id(bad), bad)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def auth(self, **portal):
        a = Authenticator({"auth": {"mode": "dev"}, **portal}, self.root, dev_no_auth=True)
        return a

    def test_lockout_is_per_address_and_flood_skips_hashing(self):
        a = self.auth()
        calls = []
        a.users.authenticate = lambda n, p: calls.append(n) or (Identity(n, "admin", "local") if p == "right" else None)
        for _ in range(5):
            self.assertIsNone(a.login_local("admin", "wrong", "10.0.0.9"))
        with self.assertRaises(AuthError):
            a.login_local("admin", "right", "10.0.0.9")  # locked from the attacker's address...
        self.assertIsNotNone(a.login_local("admin", "right", "10.0.0.1"))  # ...not from the real user's
        for i in range(15):
            a.login_local(f"user{i}", "wrong", "10.0.0.9")
        before = len(calls)
        with self.assertRaises(AuthError):
            a.login_local("someone", "wrong", "10.0.0.9")  # 20 failures from this address
        self.assertEqual(len(calls), before)  # refused before the password hash ran

    def test_sign_out_revokes_every_copy_and_survives_restart(self):
        a = self.auth()
        tok = a.new_session(Identity("alice", "analyst", "local"))
        sess = a.signer.unsign(tok)
        self.assertFalse(a.is_revoked(sess))
        a.revoke(sess)
        self.assertTrue(a.is_revoked(a.signer.unsign(tok)))
        self.assertTrue(self.auth().is_revoked(sess))  # a restarted portal still refuses it

    def test_oidc_email_only_when_verified_and_role_follows_config(self):
        cfg = {"issuer": "https://idp.example", "client_id": "c", "redirect_uri": "https://p/cb", "username_claim": "preferred_username",
               "user_roles": {"boss@example.com": "admin"}, "default_role": "analyst"}
        o = OidcClient(cfg)
        self.assertEqual(o.identity_from_claims({"email": "boss@example.com", "email_verified": False, "sub": "u-123"}).name, "u-123")
        self.assertEqual(o.identity_from_claims({"email": "boss@example.com", "email_verified": True, "sub": "u-123"}).role, "admin")
        a = Authenticator({"auth": {"mode": "dev", "oidc": cfg}}, self.root, dev_no_auth=True)
        a.mode = "oidc"
        sess = a.signer.unsign(a.new_session(Identity("bob", "admin", "oidc")))
        self.assertEqual(a.resolve(sess, {}, "127.0.0.1").role, "analyst")  # not the admin frozen in the cookie


class _Redirect(http.server.BaseHTTPRequestHandler):
    target = ""
    seen: list = []

    def do_GET(self):  # noqa: N802
        _Redirect.seen.append((self.path, self.headers.get("X-Vault-Token")))
        if self.path == "/same":
            self.send_response(307)
            self.send_header("Location", "/final")
            self.end_headers()
        elif self.path == "/other":
            self.send_response(307)
            self.send_header("Location", _Redirect.target)
            self.end_headers()
        else:
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


class VaultRedirectTests(unittest.TestCase):
    def test_token_never_follows_a_redirect_to_another_host(self):
        a = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
        b = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
        for srv in (a, b):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            _Redirect.seen = []
            _Redirect.target = f"http://localhost:{b.server_address[1]}/final"
            base = f"http://127.0.0.1:{a.server_address[1]}"
            self.assertEqual(http_json("GET", base + "/same", headers={"X-Vault-Token": "tok"})[1], {"ok": True})
            with self.assertRaises(RemoteError) as e:
                http_json("GET", base + "/other", headers={"X-Vault-Token": "tok"})
            self.assertIn("refused a redirect", str(e.exception))
            self.assertEqual([p for p, _ in _Redirect.seen], ["/same", "/final", "/other"])  # nothing reached the other host
        finally:
            a.shutdown()
            b.shutdown()


class TeachSecretTests(unittest.TestCase):
    def test_secret_names_and_sticky_detection(self):
        for name in ("Password", "One-time code", "OTP", "Your PIN", "MFA code"):
            self.assertTrue(teach._SECRET_NAME.search(name), name)
        for name in ("Spinner", "Region", "Amount"):
            self.assertFalse(teach._SECRET_NAME.search(name), name)
        js = teach.RECORDER_JS
        self.assertIn("everSecret", js)  # a "show password" toggle keeps the field secret
        self.assertIn("one-time-code", js)
        self.assertNotIn("\x08", js)


class DesktopGuardTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"tiers": {"desktop_pixels": {"enabled": True, "allowed_window_titles": ["Legacy Ledger*"]}}})
        self.s = self.ws.settings
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, UnattendedApprover(), step_id="s", workdir=self.audit.dir / "scratch")
        self.sent = []

    def tearDown(self):
        self.ws.cleanup()

    def run_action(self, block, under=("Legacy Ledger - TEST", "python.exe")):
        tier = ComputerTier(self.s)
        with mock.patch.object(sw, "screen_size", lambda: (1920, 1080)), \
             mock.patch.object(sw, "foreground_window", lambda: ("Legacy Ledger - TEST", "python.exe")), \
             mock.patch.object(sw, "window_at", lambda x, y: under), \
             mock.patch.object(sw, "cursor_pos", lambda: (5, 5)), \
             mock.patch.object(sw, "click", lambda *a, **k: self.sent.append("click")), \
             mock.patch.object(sw, "type_text", lambda text, delay=0.005: self.sent.append(("type", text))):
            return tier.execute(block, self.ctx)

    def test_click_on_another_window_is_refused(self):
        out = self.run_action({"name": "left_click", "toolset_name": "computer", "input": {"coordinate": [100, 100]}}, under=("Inbox - Outlook", "olk.exe"))
        self.assertTrue(out.is_error)
        self.assertIn("window under", out.text)
        self.assertEqual(self.sent, [])
        out = self.run_action({"name": "left_click", "toolset_name": "computer", "input": {"coordinate": [100, 100]}})
        self.assertFalse(out.is_error, out.text)
        self.assertEqual(self.sent, ["click"])

    def test_typing_stops_when_focus_moves(self):
        hwnds = iter([1, 1, 1, 2, 2, 2])
        keys = []
        with mock.patch.object(sw, "foreground_hwnd", lambda: next(hwnds)), mock.patch.object(sw, "_send", lambda *a: keys.append(a)), \
             mock.patch.object(sw, "_need_windows", lambda: None):
            with self.assertRaises(sw.FocusChanged):
                sw.type_text("secret", delay=0)
        self.assertEqual(len(keys), 2)  # two characters, then the focus changed


class VaultTitleTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.s = self.ws.settings
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, ScriptedApprover([]), step_id="s1", workdir=self.audit.dir / "scratch")
        self.ctx.vault = EnvVault("T_SECRET_", {"T_SECRET_SAP": "S3cr3t-Pa55word!", "T_SECRET_SAP__APPS": "*sap logon*"})

    def tearDown(self):
        self.ws.cleanup()

    def test_title_from_a_browser_never_matches(self):
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:sap}}", self.ctx, tool="computer.type", app="chrome.exe", window="SAP Logon - Google Chrome")
        self.assertEqual(resolve_secrets("{{secret:sap}}", self.ctx, tool="computer.type", app="saplogon.exe", window="SAP Logon 770"), "S3cr3t-Pa55word!")


class _FakeKeyring:
    def __init__(self):
        self.d = {}

    def get_password(self, service, name):
        return self.d.get((service, name))

    def set_password(self, service, name, value):
        self.d[(service, name)] = value

    def delete_password(self, service, name):
        self.d.pop((service, name), None)


class KeyringTamperTests(unittest.TestCase):
    def setUp(self):
        import json
        import sys
        import types

        from analyst_agent.vault import KeyringVault, VaultError

        self.json, self.VaultError = json, VaultError
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = _FakeKeyring()
        mod = types.ModuleType("keyring")
        for n in ("get_password", "set_password", "delete_password"):
            setattr(mod, n, getattr(self.fake, n))
        with mock.patch.dict(sys.modules, {"keyring": mod}):
            self.v = KeyringVault(Path(self.tmp.name) / "vault")
        self.v.set("portal-pw", "S3cr3t-Pa55word!", allow_hosts=["portal.example.com"], users=["alice"])

    def tearDown(self):
        self.tmp.cleanup()

    def edit(self, **changes):
        f = self.v.store.file
        data = self.json.loads(f.read_text(encoding="utf-8"))
        data["secrets"]["portal-pw"].update(changes)
        f.write_text(self.json.dumps(data), encoding="utf-8")

    def test_untouched_metadata_gives_the_value(self):
        self.assertEqual(self.v.get("portal-pw"), "S3cr3t-Pa55word!")
        self.assertNotEqual(self.fake.d[("analyst_agent", "portal-pw")], "S3cr3t-Pa55word!")  # stored with its binding

    def test_widened_hosts_or_sharing_refused(self):
        for change in ({"allow_hosts": ["*"]}, {"allow_apps": ["*"]}, {"users": ["*"]}, {"owners": ["mallory"]}, {"expires_at": 4102444800.0}):
            self.tearDown()
            self.setUp()  # a fresh vault for each edit
            self.edit(**change)
            with self.assertRaises(self.VaultError, msg=str(change)) as e:
                self.v.get("portal-pw")
            self.assertIn("changed outside the vault CLI", str(e.exception))

    def test_rotate_keeps_the_binding_and_legacy_entries_are_refused(self):
        self.v.rotate("portal-pw", "N3w-Pa55word-2026!")
        self.assertEqual(self.v.get("portal-pw"), "N3w-Pa55word-2026!")
        self.fake.d[("analyst_agent", "portal-pw")] = "plain-old-value-1234"  # written by an older version
        with self.assertRaises(self.VaultError) as e:
            self.v.get("portal-pw")
        self.assertIn("set it again", str(e.exception))


if __name__ == "__main__":
    unittest.main()
