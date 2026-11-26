"""Vault sharing with teams and SSO groups, `vault share`, `vault rotate --generate`,
and the scheduled vault_check job."""

import argparse
import json
import string
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.audit import AuditLog  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.portal.teams import SsoGroupDirectory  # noqa: E402
from analyst_agent.scheduler import ScheduleError, ScheduleStore, run_due, schedule_from_dict  # noqa: E402
from analyst_agent.tools.base import ToolContext  # noqa: E402
from analyst_agent.vault import (  # noqa: E402
    GEN_SYMBOLS,
    DpapiVault,
    EnvVault,
    Principal,
    SecretDenied,
    SecretMeta,
    VaultError,
    add_cli,
    generate_value,
    is_owner,
    principal_for,
    resolve_secrets,
    run_cli,
    user_allowed,
)
from analyst_agent.vault_remote import AzureKeyVault, HashiCorpVault  # noqa: E402
from tests.helpers import TempWorkspace  # noqa: E402
from tests.test_vault_central import Clock, FakeAzure, FakeHashiCorp  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
SECRET = "Team-Sh4red-Pa55!"
NOW = time.time()

TEAMS = {
    "Finance": {"members": ["alice"], "reviewers": ["rita"], "playbooks": ["*"], "sso_groups": ["fin-analysts"], "sso_reviewer_groups": ["fin-approvers"]},
    "ops": {"members": ["olga"], "playbooks": ["*"]},
}


def parser():
    ap = argparse.ArgumentParser()
    add_cli(ap.add_subparsers(dest="cmd"))
    return ap


def env_vault(**extra):
    e = {"T_SECRET_PW": SECRET, "T_SECRET_PW__HOSTS": "127.0.0.1"}
    e.update({f"T_SECRET_PW__{k.upper()}": v for k, v in extra.items()})
    return EnvVault("T_SECRET_", e)


def workspace(mode="local"):
    return TempWorkspace({"policy": {"allowed_hosts": ["127.0.0.1"]}, "portal": {"teams": TEAMS, "auth": {"mode": mode}}})


class PrincipalTests(unittest.TestCase):
    def setUp(self):
        self.ws = workspace("oidc")
        self.s = self.ws.settings
        SsoGroupDirectory(self.s.workspace_root / "portal_sso_groups.json").record("gina", ["fin-analysts"], "oidc")
        SsoGroupDirectory(self.s.workspace_root / "portal_sso_groups.json").record("alice", ["fin-approvers"], "oidc")

    def tearDown(self):
        self.ws.cleanup()

    def test_config_members_and_reviewers_everywhere(self):
        for source in ("cli", "schedule", "portal", ""):
            self.assertEqual(principal_for(self.s, "alice", source).teams, {"finance"}, source)
            self.assertEqual(principal_for(self.s, "rita", source).teams, {"finance"}, source)
        p = principal_for(self.s, "olga", "cli")
        self.assertEqual((p.teams, p.known_teams, p.groups), ({"ops"}, {"finance", "ops"}, None))

    def test_sso_groups_only_for_portal_runs(self):
        p = principal_for(self.s, "gina", "portal")
        self.assertEqual((p.teams, p.groups), ({"finance"}, {"fin-analysts"}))
        for source in ("cli", "schedule"):
            p = principal_for(self.s, "gina", source)
            self.assertEqual((p.teams, p.groups), (frozenset(), None), source)
        self.assertEqual(principal_for(self.s, "nobody", "portal").groups, frozenset())
        self.assertEqual(principal_for(self.s, "gina", "portal", groups=["other"]).teams, frozenset())  # the run's own groups win

    def test_local_sign_in_ignores_groups(self):
        self.s.data["portal"]["auth"]["mode"] = "local"
        p = principal_for(self.s, "gina", "portal")
        self.assertEqual((p.teams, p.groups), (frozenset(), None))

    def test_broken_team_config_grants_nothing(self):
        self.s.data["portal"]["teams"] = ["not", "a", "dict"]
        p = principal_for(self.s, "alice", "cli")
        self.assertEqual((p.teams, p.known_teams), (frozenset(), frozenset()))

    def test_matching_rules(self):
        fin = Principal("alice", frozenset({"finance"}), None, frozenset({"finance", "ops"}))
        self.assertTrue(user_allowed("alice", SecretMeta("pw", users=["team:finance"]), fin))
        self.assertFalse(user_allowed("alice", SecretMeta("pw", users=["team:ops"]), fin))
        self.assertFalse(user_allowed("alice", SecretMeta("pw", users=["team:typo"]), fin))
        self.assertFalse(user_allowed("alice", SecretMeta("pw", users=["group:fin-analysts"]), fin))  # no SSO groups
        self.assertFalse(user_allowed("alice", SecretMeta("pw", users=["team:finance"])))  # no principal: team entries grant nothing
        self.assertTrue(user_allowed("alice", SecretMeta("pw", users=["team:typo", "ali*"]), fin))  # other entries still apply
        sso = Principal("gina", frozenset(), frozenset({"fin-analysts"}), frozenset({"finance"}))
        self.assertTrue(user_allowed("gina", SecretMeta("pw", users=["group:FIN-analysts"]), sso))
        self.assertTrue(is_owner("alice", SecretMeta("pw", owners=["team:finance"]), fin))
        self.assertFalse(is_owner("olga", SecretMeta("pw", owners=["team:finance"]), Principal("olga", frozenset({"ops"}), None, frozenset({"finance", "ops"}))))


class ResolveTeamTests(unittest.TestCase):
    def setUp(self):
        self.ws = workspace("trusted_header")
        SsoGroupDirectory(self.ws.settings.workspace_root / "portal_sso_groups.json").record("gina", ["fin-analysts"], "trusted_header")
        self.audit = AuditLog(self.ws.settings.audit_dir, user="alice")

    def tearDown(self):
        self.ws.cleanup()

    def resolve(self, vault, user, source="cli"):
        self.audit.user = user
        ctx = ToolContext(self.ws.settings, PolicyEngine(self.ws.settings), self.audit, ScriptedApprover([]), step_id="s1", user_source=source)
        ctx.vault = vault
        return resolve_secrets("{{secret:pw}}", ctx, tool="browser_fill", url="http://127.0.0.1/form")

    def denied(self):
        return [e for e in self.audit.events() if e["kind"] == "secret_denied"]

    def test_team_member_allowed_other_denied_with_audit(self):
        v = env_vault(users="team:finance")
        self.assertEqual(self.resolve(v, "alice"), SECRET)
        self.assertEqual(self.resolve(v, "rita", "schedule"), SECRET)
        with self.assertRaises(SecretDenied) as cm:
            self.resolve(v, "olga")
        self.assertIn("not shared with user 'olga', teams: ops", str(cm.exception))
        d = self.denied()
        self.assertEqual((len(d), d[0]["user"], d[0]["name"]), (1, "olga", "pw"))
        self.assertNotIn(SECRET, self.audit.path.read_text(encoding="utf-8"))

    def test_unknown_team_fails_closed_with_reason(self):
        with self.assertRaises(SecretDenied) as cm:
            self.resolve(env_vault(owners="team:finanse"), "alice")
        self.assertIn("team 'finanse' is not in portal.teams", str(cm.exception))
        self.assertIn("team 'finanse' is not in portal.teams", self.denied()[0]["reason"])

    def test_sso_group_and_team_from_group_only_in_portal_runs(self):
        for entry in ("group:fin-analysts", "team:finance"):
            v = env_vault(users=entry)
            self.assertEqual(self.resolve(v, "gina", "portal"), SECRET, entry)
            with self.assertRaises(SecretDenied, msg=entry) as cm:
                self.resolve(v, "gina", "cli")
        self.assertIn("not shared with user 'gina'", str(cm.exception))
        with self.assertRaises(SecretDenied) as cm:
            self.resolve(env_vault(users="group:fin-analysts"), "gina", "schedule")
        self.assertIn("only portal runs with SSO sign-in have", str(cm.exception))

    def test_plain_user_entries_unchanged(self):
        self.assertEqual(self.resolve(env_vault(users="schedule:*"), "schedule:fin"), SECRET)
        self.assertEqual(self.resolve(env_vault(), "anyone"), SECRET)


class OrchestratorSourceTests(unittest.TestCase):
    def test_user_source(self):
        from analyst_agent.orchestrator import Orchestrator
        from analyst_agent.portal.approvals import WebApprover

        self.assertEqual(WebApprover.user_source, "portal")
        ws = TempWorkspace()
        try:
            client, _ = ws.client()

            class Portalish(ScriptedApprover):
                user_source = "portal"

            cases = [({}, "cli"), ({"user": "schedule:fin"}, "schedule"), ({"approver": Portalish([])}, "portal"), ({"user_source": "schedule"}, "schedule")]
            for kw, want in cases:
                o = Orchestrator(ws.settings, client=client, **kw)
                try:
                    self.assertEqual(o.user_source, want, kw)
                finally:
                    o.router.close()
        finally:
            ws.cleanup()


class ShareCliTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHashiCorp(Clock(NOW))
        self.vault = HashiCorpVault({"url": self.fake.url, "cache_ttl_s": 0}, environ={"VAULT_TOKEN": "root-token"})
        self.ws = workspace()
        self.out: list[str] = []

    def tearDown(self):
        self.fake.close()
        self.ws.cleanup()

    def cli(self, *argv, answers=(), actor="alice"):
        it = iter(answers)
        return run_cli(parser().parse_args(["vault", *argv]), self.ws.settings, getpass_fn=lambda _p: next(it), out=self.out.append, vault=self.vault, actor=actor)

    def test_set_with_team_entries_and_warnings(self):
        rc = self.cli("set", "pw", "--allow-host", "127.0.0.1", "--owner", "team:Finance", "--user", "team:nope", "--user", "group:fin-analysts", answers=[SECRET, SECRET])
        self.assertEqual(rc, 0, self.out)
        text = "\n".join(self.out)
        self.assertIn("team 'nope' is not in portal.teams", text)
        self.assertIn("portal.auth.mode is 'local'", text)
        self.assertNotIn("team 'finance'", text)
        m = self.vault.meta("pw")
        self.assertEqual((m.owners, m.users), (["team:finance"], ["team:nope", "group:fin-analysts"]))
        self.assertEqual(self.cli("set", "pw", "--allow-host", "h", "--user", "team:", answers=[SECRET, SECRET]), 1)
        self.assertIn("names no team", self.out[-1])

    def test_share_changes_lists_only_and_needs_owner(self):
        self.vault.set("pw", SECRET, ["127.0.0.1"], owners=["team:finance"], rotate_after_days=30)
        before = self.vault.meta("pw")
        self.assertEqual(self.cli("share", "pw", "--add-user", "team:ops", "--add-user", "bob", actor="olga"), 1)  # ops is not an owner team
        self.assertIn("not an owner", self.out[-1])
        self.assertEqual(self.cli("share", "pw", "--add-user", "team:ops", "--add-user", "BOB", actor="rita"), 0, self.out)  # finance reviewer = member
        after = self.vault.meta("pw")
        self.assertEqual((after.owners, after.users, after.version, after.updated, after.rotate_after_days), (["team:finance"], ["team:ops", "bob"], before.version, before.updated, 30))
        self.assertEqual(self.vault.get("pw"), SECRET)
        self.assertEqual(self.cli("share", "pw", "--remove-user", "nobody"), 1)
        self.assertIn("not in the list: nobody", self.out[-1])
        self.assertEqual(self.cli("share", "pw", "--remove-user", "bob"), 0)
        self.assertEqual(self.cli("share", "pw"), 0)
        self.assertEqual(self.out[-1], "pw: owners=team:finance users=team:ops")
        self.assertEqual(self.cli("share", "pw", "--remove-owner", "team:finance", "--remove-user", "team:ops"), 0)
        self.assertIn("no owners now", "\n".join(self.out[-2:]))
        self.assertIn("any run user may use it", self.out[-1])

    def test_share_on_read_only_backend(self):
        self.vault = env_vault(owners="alice")
        self.assertEqual(self.cli("share", "pw"), 0)
        self.assertEqual(self.cli("share", "pw", "--add-user", "bob"), 1)
        self.assertIn("read-only", self.out[-1])


class AzureShareTests(unittest.TestCase):
    def test_update_sharing_patches_tags_without_new_version(self):
        clock = Clock()
        fake = FakeAzure(clock)
        try:
            v = AzureKeyVault({"vault_url": fake.url, "authority_host": fake.url, "tenant_id": "tenant-1", "client_id": "client-1", "cache_ttl_s": 0},
                              environ={"AZURE_CLIENT_SECRET": "client-secret-1"}, clock=clock)
            v.set("pw", SECRET, ["h"], owners=["alice"], rotate_after_days=10)
            m = v.update_sharing("pw", ["alice"], ["team:finance"])
            self.assertEqual((m.owners, m.users, m.rotate_after_days, len(fake.secrets["pw"])), (["alice"], ["team:finance"], 10, 1))
            self.assertEqual(fake.count("PATCH", "/secrets/pw/"), 1)
            self.assertEqual(v.get("pw"), SECRET)
        finally:
            fake.close()


@unittest.skipUnless(IS_WINDOWS, "DPAPI needs Windows")
class DpapiShareTests(unittest.TestCase):
    def test_update_sharing_rebinds_entropy_and_keeps_previous(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "vault"
            v = DpapiVault(folder)
            v.set("pw", SECRET, ["h"], users=["bob"])
            v.rotate("pw", "Second-Val-123")
            before = json.loads((folder / "vault.json").read_text())["secrets"]["pw"]
            m = v.update_sharing("pw", ["team:finance"], ["bob", "group:fin"])
            rec = json.loads((folder / "vault.json").read_text())["secrets"]["pw"]
            self.assertEqual((m.owners, m.users, m.version), (["team:finance"], ["bob", "group:fin"], 2))
            self.assertEqual((rec["updated"], rec["previous"]), (before["updated"], before["previous"]))
            self.assertEqual(v.get("pw"), "Second-Val-123")
            v.rollback("pw")
            self.assertEqual(v.get("pw"), SECRET)
            data = json.loads((folder / "vault.json").read_text())
            data["secrets"]["pw"]["users"] = ["*"]
            (folder / "vault.json").write_text(json.dumps(data))
            with self.assertRaises(VaultError):
                v.get("pw")


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHashiCorp(Clock(NOW))
        self.vault = HashiCorpVault({"url": self.fake.url, "cache_ttl_s": 0}, environ={"VAULT_TOKEN": "root-token"})
        self.vault.set("pw", SECRET, ["127.0.0.1"], users=["bob"])
        self.ws = TempWorkspace()
        self.out: list[str] = []

    def tearDown(self):
        self.fake.close()
        self.ws.cleanup()

    def cli(self, *argv):
        def no_prompt(_p):
            raise AssertionError("--generate must not prompt")

        return run_cli(parser().parse_args(["vault", *argv]), self.ws.settings, getpass_fn=no_prompt, out=self.out.append, vault=self.vault, actor="alice")

    def test_generate_value(self):
        for n in (12, 24, 64):
            v = generate_value(n)
            self.assertEqual(len(v), n)
            for cls in (string.ascii_lowercase, string.ascii_uppercase, string.digits, GEN_SYMBOLS):
                self.assertTrue(any(c in cls for c in v))
        self.assertEqual(len({generate_value() for _ in range(50)}), 50)
        for bad in (4, 11, 257):
            with self.assertRaises(VaultError):
                generate_value(bad)

    def test_rotate_generate_hidden_keeps_previous(self):
        self.assertEqual(self.cli("rotate", "pw", "--generate"), 0, self.out)
        new = self.vault.get("pw")
        self.assertNotEqual(new, SECRET)
        self.assertEqual(len(new), 24)
        text = "\n".join(self.out)
        self.assertNotIn(new, text)
        self.assertIn("Only the STORED value changed", text)
        self.assertIn("not shown", text)
        m = self.vault.meta("pw")
        self.assertEqual((m.version, m.users, m.allow_hosts), (2, ["bob"], ["127.0.0.1"]))
        self.assertEqual(self.cli("rollback", "pw"), 0)
        self.assertEqual(self.vault.get("pw"), SECRET)

    def test_rotate_generate_show_and_errors(self):
        self.assertEqual(self.cli("rotate", "pw", "--generate", "--length", "40", "--show"), 0, self.out)
        new = self.vault.get("pw")
        self.assertEqual((len(new), self.out[-1]), (40, new))
        self.assertIn("warning: printing the generated value", self.out[-2])
        self.assertEqual(self.cli("rotate", "pw", "--generate", "--length", "8"), 1)
        self.assertIn("between 12 and 256", self.out[-1])
        self.assertEqual(self.cli("rotate", "pw", "--show"), 1)
        self.assertIn("need --generate", self.out[-1])
        self.assertEqual(self.vault.get("pw"), new)


class VaultCheckScheduleTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.s = self.ws.settings
        self.s.data["schedules"] = {"path": str(self.ws.root / "config" / "schedules.json"), "state_dir": str(self.ws.root / "workspace" / "schedules"), "lock_stale_s": 7200}
        self.store = ScheduleStore(self.s)
        self.logs: list[str] = []

    def tearDown(self):
        self.ws.cleanup()

    def write(self, **kw):
        e = {"id": "vault-daily", "kind": "vault_check", "cron": "0 6 * * *", "timezone": "UTC", "owner": "secops", "created_at": "2026-11-01T00:00:00+00:00", **kw}
        self.store.path.parent.mkdir(parents=True, exist_ok=True)
        self.store.path.write_text(json.dumps({"schedules": [e]}), encoding="utf-8")

    def due(self, vault, day=2):
        def no_runner(*_a):
            raise AssertionError("vault_check runs no playbook")

        return run_due(self.s, self.ws.root / "playbooks", now=datetime(2026, 11, day, 6, 1, tzinfo=timezone.utc), runner=no_runner, log=self.logs.append,
                       vault_factory=lambda _s: vault)

    def events(self, rec):
        return AuditLog(self.s.audit_dir, session_id=rec["session_id"]).events()

    def test_validation_and_shape(self):
        s = schedule_from_dict({"id": "v", "kind": "vault_check", "cron": "@daily", "params": {"warn_days": 3}})
        self.assertEqual((s.playbook, s.label, s.to_dict()["kind"]), ("", "[vault_check]", "vault_check"))
        self.assertNotIn("playbook", s.to_dict())
        p = schedule_from_dict({"id": "p", "playbook": "x", "cron": "@daily"})
        self.assertNotIn("kind", p.to_dict())
        for bad in ({"kind": "nope", "playbook": "x"}, {"kind": "vault_check", "playbook": "x"}, {"kind": "vault_check", "params": {"warn_days": "soon"}}, {}):
            with self.assertRaises(ScheduleError, msg=bad):
                schedule_from_dict({"id": "b", "cron": "@daily", **bad})

    def test_expired_secret_fails_entry_and_audits(self):
        self.write(params={"warn_days": 10})
        v = EnvVault("T_SECRET_", {"T_SECRET_OLD": SECRET, "T_SECRET_OLD__EXPIRES_AT": "2020-01-01", "T_SECRET_DUE": SECRET, "T_SECRET_DUE__ROTATE_AFTER_DAYS": "1",
                                   "T_SECRET_DUE__UPDATED": "2020-01-01", "T_SECRET_FINE": SECRET})
        (rec,) = self.due(v)
        self.assertEqual((rec["status"], rec["kind"], rec["checked"], rec["backend"], rec["params"]), ("failed", "vault_check", 3, "env", {"warn_days": 10.0}))
        self.assertEqual({x["name"]: x["status"] for x in rec["secrets"]}, {"old": "expired", "due": "rotate-due"})
        self.assertIn("2 secret(s) expired or due", rec["error"])
        self.assertEqual(self.store.history()[-1]["status"], "failed")
        self.assertEqual(self.store.state()["vault-daily"]["last_status"], "failed")
        kinds = [(e["kind"], e.get("name")) for e in self.events(rec)]
        self.assertIn(("secret_expired", "old"), kinds)
        self.assertIn(("secret_rotation_due", "due"), kinds)
        self.assertEqual(kinds[-1][0], "vault_check")
        self.assertEqual(self.events(rec)[-1]["user"], "schedule:secops")
        self.assertNotIn(SECRET, (self.store.history_path.read_text() + AuditLog(self.s.audit_dir, session_id=rec["session_id"]).path.read_text()))

    def test_ok_and_store_error(self):
        self.write(notify="workspace/output/vault-check.md")
        (rec,) = self.due(env_vault())
        self.assertEqual((rec["status"], rec["secrets"]), ("success", []))
        self.assertIn("Secrets checked: 1", (self.ws.root / "workspace" / "output" / "vault-check.md").read_text())

        class Broken(EnvVault):
            def list(self):
                raise VaultError("cannot reach the store")

        (rec,) = self.due(Broken(), day=3)
        self.assertEqual(rec["status"], "error")
        self.assertIn("cannot reach the store", rec["error"])
        self.assertEqual(self.events(rec)[-1]["status"], "error")

    def test_cli_add_vault_check(self):
        from analyst_agent.scheduler import add_cli as sched_cli, cli

        ap = argparse.ArgumentParser()
        sched_cli(ap.add_subparsers(dest="cmd"))
        import contextlib
        import io

        def run(*argv):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli(ap.parse_args(["schedule", *argv]), self.s, self.ws.root)
            return code, buf.getvalue()

        code, out = run("add", "vault-daily", "--vault-check", "--cron", "0 6 * * *", "--warn-days", "14", "--owner", "secops")
        self.assertEqual(code, 0, out)
        saved = json.loads(self.store.path.read_text())["schedules"][0]
        self.assertEqual((saved["kind"], saved["params"], "playbook" in saved), ("vault_check", {"warn_days": 14.0}, False))
        code, out = run("list")
        self.assertIn("[vault_check]", out)
        self.assertEqual(run("add", "x", "--vault-check", "--cron", "@daily", "--param", "a=b")[0], 1)
        self.assertEqual(run("add", "x", "--playbook", "erp-crm-reconciliation", "--cron", "@daily", "--warn-days", "3")[0], 1)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                ap.parse_args(["schedule", "add", "x", "--cron", "@daily"])  # neither --playbook nor --vault-check


if __name__ == "__main__":
    unittest.main()
