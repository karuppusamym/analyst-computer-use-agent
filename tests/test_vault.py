"""Credential vault: backends, placeholder resolution, allowlists and redaction."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.agents import Executor  # noqa: E402
from analyst_agent.audit import AuditLog, Redactor  # noqa: E402
from analyst_agent.config import load_settings  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.tools.base import Tier, Tool, ToolContext, ToolOutput, schema  # noqa: E402
from analyst_agent.vault import (  # noqa: E402
    DpapiVault,
    EnvVault,
    SecretRefused,
    VaultError,
    add_cli,
    dpapi_protect,
    dpapi_unprotect,
    resolve_secrets,
    run_cli,
)
from tests.helpers import TempWorkspace  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
SECRET = "S3cr3t-Pa55word!"


def env_vault(hosts="127.0.0.1", apps="legacy*"):
    return EnvVault("T_SECRET_", {"T_SECRET_PORTAL_NOTE": SECRET, "T_SECRET_PORTAL_NOTE__HOSTS": hosts, "T_SECRET_PORTAL_NOTE__APPS": apps, "T_SECRET_OTHER": "other-value-9876"})


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"policy": {"allowed_hosts": ["127.0.0.1", "localhost"]}})
        self.s = self.ws.settings
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, ScriptedApprover([]), step_id="s1", workdir=self.audit.dir / "scratch")
        self.ctx.vault = env_vault()

    def tearDown(self):
        self.ws.cleanup()

    def log_text(self) -> str:
        return self.audit.path.read_text(encoding="utf-8") if self.audit.path.exists() else ""


@unittest.skipUnless(IS_WINDOWS, "DPAPI needs Windows")
class DpapiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "vault"

    def tearDown(self):
        self.tmp.cleanup()

    def test_protect_roundtrip_and_entropy(self):
        blob = dpapi_protect(SECRET.encode(), b"ent")
        self.assertNotIn(SECRET.encode(), blob)
        self.assertEqual(dpapi_unprotect(blob, b"ent").decode(), SECRET)
        with self.assertRaises(VaultError):
            dpapi_unprotect(blob, b"other")

    def test_vault_set_get_list_remove(self):
        v = DpapiVault(self.dir)
        v.set("portal-pw", SECRET, ["127.0.0.1"], ["Legacy*"])
        self.assertEqual(v.get("portal-pw"), SECRET)
        raw = (self.dir / "vault.json").read_text()
        self.assertNotIn(SECRET, raw)
        metas = v.list()
        self.assertEqual([(m.name, m.allow_hosts, m.allow_apps) for m in metas], [("portal-pw", ["127.0.0.1"], ["legacy*"])])
        self.assertNotIn(SECRET, json.dumps([m.public() for m in metas]))
        v.remove("portal-pw")
        self.assertEqual(v.list(), [])
        with self.assertRaises(VaultError):
            v.get("portal-pw")

    def test_widening_allowlist_in_file_breaks_decryption(self):
        v = DpapiVault(self.dir)
        v.set("pw", SECRET, ["127.0.0.1"])
        data = json.loads((self.dir / "vault.json").read_text())
        data["secrets"]["pw"]["allow_hosts"] = ["*"]
        (self.dir / "vault.json").write_text(json.dumps(data))
        with self.assertRaises(VaultError):
            v.get("pw")

    def test_rejects_bad_names_and_short_values(self):
        v = DpapiVault(self.dir)
        with self.assertRaises(VaultError):
            v.set("../x", SECRET)
        with self.assertRaises(VaultError):
            v.set("ok", "abc")

    def test_cli_set_list_remove_never_prints_value(self):
        import argparse

        ap = argparse.ArgumentParser()
        add_cli(ap.add_subparsers(dest="cmd"))
        s = load_settings(overrides={"vault": {"backend": "dpapi", "path": str(self.dir)}})
        printed: list[str] = []
        answers = iter([SECRET, SECRET])
        rc = run_cli(ap.parse_args(["vault", "set", "pw", "--allow-host", "127.0.0.1", "--allow-app", "legacy*"]), s, getpass_fn=lambda _p: next(answers), out=printed.append)
        self.assertEqual(rc, 0, printed)
        self.assertEqual(run_cli(ap.parse_args(["vault", "list"]), s, out=printed.append), 0)
        self.assertTrue(any(line.startswith("pw ") and "127.0.0.1" in line for line in printed), printed)
        self.assertEqual(run_cli(ap.parse_args(["vault", "remove", "pw"]), s, out=printed.append), 0)
        self.assertNotIn(SECRET, "\n".join(printed))
        # mismatched confirmation stores nothing
        answers = iter([SECRET, SECRET + "x"])
        self.assertEqual(run_cli(ap.parse_args(["vault", "set", "pw2", "--allow-host", "h"]), s, getpass_fn=lambda _p: next(answers), out=printed.append), 1)
        self.assertEqual(DpapiVault(self.dir).list(), [])


class EnvBackendTests(unittest.TestCase):
    def test_env_backend_read_only_with_allowlists(self):
        v = env_vault()
        self.assertEqual(v.get("portal-note"), SECRET)
        m = v.meta("portal_note")
        self.assertEqual((m.allow_hosts, m.allow_apps), (["127.0.0.1"], ["legacy*"]))
        self.assertEqual(sorted(x.name for x in v.list()), ["other", "portal_note"])
        self.assertEqual(v.meta("other").allow_hosts, [])
        with self.assertRaises(VaultError):
            v.set("x", "value-1234")
        with self.assertRaises(VaultError):
            v.get("missing")


class RedactionTests(Base):
    def test_audit_redacts_registered_values_everywhere(self):
        self.audit.redactor.add("portal_note", SECRET)
        self.audit.event("tool_call", output=f"page says {SECRET}", nested={"list": [SECRET, {"k": "x" + SECRET}]}, obj=SimpleNamespace(v=SECRET))
        text = self.log_text()
        self.assertNotIn(SECRET, text)
        self.assertIn("[REDACTED:portal_note]", text)

    def test_redactor_handles_escaped_forms(self):
        r = Redactor()
        r.add("pw", 'a b&"c<d')
        self.assertEqual(r.apply("x a%20b%26%22c%3Cd y"), "x [REDACTED:pw] y")
        self.assertEqual(r.apply({"q": "a+b%26%22c%3Cd"}), {"q": "[REDACTED:pw]"})
        self.assertEqual(r.apply("a b&amp;&quot;c&lt;d"), "[REDACTED:pw]")


class ResolutionTests(Base):
    def test_resolves_for_allowed_host_and_audits_without_value(self):
        out = resolve_secrets("user={{secret:portal_note}}", self.ctx, tool="browser_fill", url="http://127.0.0.1:8000/form")
        self.assertEqual(out, "user=" + SECRET)
        events = self.audit.events()
        used = [e for e in events if e["kind"] == "secret_used"]
        self.assertEqual(len(used), 1)
        self.assertEqual((used[0]["name"], used[0]["url"], used[0]["step"]), ("portal_note", "http://127.0.0.1:8000/form", "s1"))
        self.audit.event("echo", text=out)
        self.assertNotIn(SECRET, self.log_text())

    def test_refused_when_host_not_on_secret_allowlist(self):
        self.ctx.vault = env_vault(hosts="intranet.example")
        with self.assertRaises(SecretRefused) as cm:
            resolve_secrets("{{secret:portal_note}}", self.ctx, tool="browser_fill", url="http://127.0.0.1/form")
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertEqual([e["kind"] for e in self.audit.events()], ["secret_refused"])

    def test_refused_when_host_not_on_policy_allowlist(self):
        self.ctx.vault = env_vault(hosts="*")
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:portal_note}}", self.ctx, tool="browser_fill", url="https://evil.example/login")

    def test_secret_without_allowlist_is_unusable(self):
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:other}}", self.ctx, tool="browser_fill", url="http://127.0.0.1/")

    def test_window_allowlist_for_desktop_tiers(self):
        self.assertEqual(resolve_secrets("{{secret:portal_note}}", self.ctx, tool="computer.type", app="python.exe", window="Legacy Ledger - TEST"), SECRET)
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:portal_note}}", self.ctx, tool="computer.type", app="notepad.exe", window="Untitled - Notepad")
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:portal_note}}", self.ctx, tool="computer.type")

    def test_unknown_secret_refused(self):
        with self.assertRaises(SecretRefused):
            resolve_secrets("{{secret:nope}}", self.ctx, tool="browser_fill", url="http://127.0.0.1/")

    def test_file_tools_cannot_touch_vault_folder(self):
        from analyst_agent.policy import PolicyViolation
        from analyst_agent.vault import vault_dir

        with self.assertRaises(PolicyViolation):
            self.ctx.policy.check_path(vault_dir(self.s) / "vault.json")
        with self.assertRaises(PolicyViolation):
            self.ctx.policy.check_path(vault_dir(self.s) / "x", write=True)
        self.ctx.policy.check_path(self.s.output_dir / "ok.txt", write=True)

    def test_no_placeholder_untouched(self):
        self.assertEqual(resolve_secrets("plain {secret:x} text", self.ctx, tool="t", url="http://127.0.0.1/"), "plain {secret:x} text")
        self.assertEqual(self.audit.events(), [])


class EchoTier(Tier):
    """A fake typing tool whose target echoes what was typed (like a page showing an input's value)."""

    name = "echo"

    def tools(self):
        def fill(inp, ctx):
            value = resolve_secrets(inp["text"], ctx, tool="echo_fill", url="http://127.0.0.1/form")
            return ToolOutput(f"typed; the page now shows: {value}")

        return [Tool("echo_fill", "fill", schema({"text": {"type": "string"}}), fill, self.name)]


class ToolResultTests(Base):
    def test_secret_never_in_tool_result_or_audit(self):
        client, _ = self.ws.client()
        uses = [{"type": "tool_use", "id": "t1", "name": "echo_fill", "input": {"text": "{{secret:portal_note}}"}}]
        results, _, _ = Executor(client)._run_tools(uses, EchoTier(self.s), self.ctx)
        dumped = json.dumps(results)
        self.assertNotIn(SECRET, dumped)
        self.assertIn("[REDACTED:portal_note]", dumped)
        self.assertNotIn(SECRET, self.log_text())
        self.assertIn("secret_used", self.log_text())

    def test_report_and_checkpoint_redacted(self):
        from analyst_agent.model import MockBackend, ModelClient  # noqa: F401
        from analyst_agent.orchestrator import Orchestrator
        from analyst_agent.playbook import playbook_from_dict

        marker = self.s.output_dir / "marker.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("x")
        pb = playbook_from_dict({"name": "secret-echo", "steps": [{"id": "s1", "intent": "type it", "tier": "browser", "script": {"kind": "tool", "tool": "echo_fill", "input": {"text": "{{secret:portal_note}}"}}, "checks": [{"type": "file_exists", "path": "output/marker.txt"}]}]})
        client, _ = self.ws.client()
        orch = Orchestrator(self.s, client=client, approver=ScriptedApprover([]), require_plan_approval=False)
        tier = EchoTier(self.s)
        tier.name = "browser"
        orch.router.route = lambda requested: SimpleNamespace(tier=tier, requested=requested, note="")
        orig = ToolContext.__init__

        def init(this, *a, **kw):
            orig(this, *a, **kw)
            this.vault = env_vault()

        ToolContext.__init__ = init
        try:
            r = orch.run("type the secret", playbook=pb)
        finally:
            ToolContext.__init__ = orig
        session = self.s.audit_dir / r.session_id
        for f in ("events.jsonl", "report.md", "checkpoint.json"):
            p = session / f
            if p.exists():
                self.assertNotIn(SECRET, p.read_text(encoding="utf-8"), f)
        self.assertNotIn(SECRET, r.records[0].summary)
        self.assertIn("[REDACTED:portal_note]", r.records[0].summary)


def _browser_ok():
    from analyst_agent.tools.browser import BrowserTier

    tmp = tempfile.mkdtemp()
    return BrowserTier(load_settings(overrides={"workspace": {"root": tmp}})).available()


BROWSER_OK, BROWSER_WHY = _browser_ok()


@unittest.skipUnless(BROWSER_OK, f"browser tier unavailable: {BROWSER_WHY}")
class BrowserSecretTests(Base):
    @classmethod
    def setUpClass(cls):
        from test_targets import portal

        cls.portal = portal
        cls.server, _ = portal.start_portal(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        super().setUp()
        from analyst_agent.tools.browser import BrowserTier

        self.s.data["tiers"]["browser"]["enabled"] = True
        self.tier = BrowserTier(self.s)
        self.client, _ = self.ws.client()

    def tearDown(self):
        self.tier.close()
        super().tearDown()

    def run_tools(self, *calls, approvals=None):
        if approvals is not None:
            self.ctx.approver = ScriptedApprover(approvals)
        uses = [{"type": "tool_use", "id": f"t{i}", "name": n, "input": inp} for i, (n, inp) in enumerate(calls)]
        results, _, _ = Executor(self.client)._run_tools(uses, self.tier, self.ctx)
        return results

    def ref_for(self, snapshot_text: str, needle: str) -> str:
        import re

        for line in snapshot_text.splitlines():
            if needle in line:
                return re.search(r"\[(e\d+)\]", line).group(1)
        raise AssertionError(f"{needle} not in snapshot")

    def test_fill_resolves_placeholder_and_never_leaks(self):
        res = self.run_tools(("browser_goto", {"url": self.base + "/form"}), ("browser_snapshot", {}))
        snap = res[1]["content"][0]["text"]
        note, submit = self.ref_for(snap, "'Note'"), self.ref_for(snap, "'Submit'")
        res = self.run_tools(("browser_fill", {"ref": note, "text": "{{secret:portal_note}}"}), ("browser_snapshot", {}))
        self.assertFalse(res[0].get("is_error"), res[0])
        dumped = json.dumps(res)
        self.assertNotIn(SECRET, dumped)  # the snapshot shows the input value, redacted
        self.assertIn("[REDACTED:portal_note]", dumped)
        before = len(self.portal.SUBMISSIONS)
        self.run_tools(("browser_click", {"ref": submit}), approvals=[True])
        self.assertEqual(self.portal.SUBMISSIONS[before:], [{"note": SECRET}])  # the real value was typed
        self.assertNotIn(SECRET, self.log_text())
        used = [e for e in self.audit.events() if e["kind"] == "secret_used"]
        self.assertEqual(used[0]["name"], "portal_note")
        self.assertTrue(used[0]["url"].startswith(self.base))

    def test_fill_refused_for_host_outside_secret_allowlist(self):
        self.ctx.vault = env_vault(hosts="intranet.example")
        res = self.run_tools(("browser_goto", {"url": self.base + "/form"}), ("browser_snapshot", {}))
        note = self.ref_for(res[1]["content"][0]["text"], "'Note'")
        res = self.run_tools(("browser_fill", {"ref": note, "text": "{{secret:portal_note}}"}), ("browser_snapshot", {}))
        self.assertTrue(res[0].get("is_error"))
        self.assertIn("not allowed for host", res[0]["content"])
        self.assertNotIn(SECRET, json.dumps(res))
        self.assertIn("secret_refused", self.log_text())


if __name__ == "__main__":
    unittest.main()
