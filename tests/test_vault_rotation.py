"""Vault rotation (status, expiry refusal, check/rotate/rollback CLI) and per-user sharing."""

import argparse
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.audit import AuditLog  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.tools.base import ToolContext  # noqa: E402
from analyst_agent.vault import (  # noqa: E402
    DAY,
    DpapiVault,
    EnvVault,
    SecretDenied,
    SecretExpired,
    SecretMeta,
    VaultError,
    add_cli,
    resolve_secrets,
    run_cli,
    secret_status,
    user_allowed,
)
from analyst_agent.vault_remote import HashiCorpVault  # noqa: E402
from tests.helpers import TempWorkspace  # noqa: E402
from tests.test_vault_central import FakeHashiCorp  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
SECRET = "Rot8-Me-Pa55word!"
NEW = "N3w-Rot8d-Value#"
NOW = time.time()


def parser():
    ap = argparse.ArgumentParser()
    add_cli(ap.add_subparsers(dest="cmd"))
    return ap


def env_with(**extra):
    e = {"T_SECRET_PW": SECRET, "T_SECRET_PW__HOSTS": "127.0.0.1"}
    e.update({f"T_SECRET_PW__{k.upper()}": v for k, v in extra.items()})
    return EnvVault("T_SECRET_", e)


class StatusTests(unittest.TestCase):
    def m(self, **kw):
        return SecretMeta("pw", ["h"], updated=kw.pop("updated", NOW - 10 * DAY), **kw)

    def test_statuses(self):
        self.assertEqual(secret_status(self.m(), NOW), ("ok", ""))
        self.assertEqual(secret_status(self.m(rotate_after_days=30), NOW)[0], "ok")
        self.assertEqual(secret_status(self.m(rotate_after_days=15), NOW), ("rotate-soon", "rotation due in 5d"))
        self.assertEqual(secret_status(self.m(rotate_after_days=7), NOW), ("rotate-due", "rotation overdue by 3d"))
        self.assertEqual(secret_status(self.m(expires_at=NOW + 3 * DAY), NOW)[0], "rotate-soon")
        self.assertEqual(secret_status(self.m(expires_at=NOW - 1, rotate_after_days=1), NOW)[0], "expired")
        self.assertEqual(secret_status(self.m(rotate_after_days=7, updated=0.0), NOW), ("ok", "age unknown"))
        self.assertEqual(secret_status(self.m(expires_at=NOW + 3 * DAY), NOW, warn_days=1)[0], "ok")

    def test_user_matching(self):
        self.assertTrue(user_allowed("anyone", SecretMeta("pw")))
        m = SecretMeta("pw", owners=["alice"], users=["bob", "schedule:*"])
        for u in ("alice", "ALICE", "bob", "schedule:finance"):
            self.assertTrue(user_allowed(u, m), u)
        for u in ("mallory", "", None, "schedule"):
            self.assertFalse(user_allowed(u, m), u)


class EnvMetadataTests(unittest.TestCase):
    def test_env_rotation_and_sharing_vars(self):
        v = env_with(owners="alice", users="bob,carol", rotate_after_days="30", expires_at="2030-01-31", updated="2026-01-01")
        m = v.meta("pw")
        self.assertEqual((m.owners, m.users, m.rotate_after_days), (["alice"], ["bob", "carol"], 30.0))
        self.assertEqual(time.strftime("%Y-%m-%d", time.localtime(m.expires_at)), "2030-01-31")
        self.assertEqual(time.strftime("%Y-%m-%d", time.localtime(m.updated)), "2026-01-01")
        self.assertEqual([x.name for x in v.list()], ["pw"])  # the __ variables are not secrets
        with self.assertRaises(VaultError):
            env_with(expires_at="not a date").meta("pw")


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace({"policy": {"allowed_hosts": ["127.0.0.1"]}})
        self.audit = AuditLog(self.ws.settings.audit_dir, user="alice")
        self.ctx = ToolContext(self.ws.settings, PolicyEngine(self.ws.settings), self.audit, ScriptedApprover([]), step_id="s1")

    def tearDown(self):
        self.ws.cleanup()

    def resolve(self, vault):
        self.ctx.vault = vault
        return resolve_secrets("{{secret:pw}}", self.ctx, tool="browser_fill", url="http://127.0.0.1/form")

    def test_expired_refused_with_secret_expired_event(self):
        with self.assertRaises(SecretExpired) as cm:
            self.resolve(env_with(expires_at="2020-01-01"))
        self.assertIn("vault rotate pw", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        ev = self.audit.events()
        self.assertEqual([e["kind"] for e in ev], ["secret_expired"])
        self.assertEqual((ev[0]["name"], ev[0]["step"]), ("pw", "s1"))

    def test_rotate_due_still_usable(self):
        self.assertEqual(self.resolve(env_with(rotate_after_days="1", updated="2020-01-01")), SECRET)

    def test_sharing_allows_listed_users_and_denies_others(self):
        self.assertEqual(self.resolve(env_with(users="alice")), SECRET)
        self.assertEqual(self.resolve(env_with(owners="ali*")), SECRET)
        self.assertEqual(self.resolve(env_with()), SECRET)  # no lists = any user
        self.audit.user = "schedule:finance"
        self.assertEqual(self.resolve(env_with(users="schedule:*")), SECRET)
        self.audit.user = "mallory"
        with self.assertRaises(SecretDenied) as cm:
            self.resolve(env_with(owners="alice", users="bob"))
        self.assertIn("not shared with user 'mallory'", str(cm.exception))
        denied = [e for e in self.audit.events() if e["kind"] == "secret_denied"]
        self.assertEqual((len(denied), denied[0]["user"], denied[0]["name"]), (1, "mallory", "pw"))
        self.assertNotIn(SECRET, self.audit.path.read_text(encoding="utf-8"))

    def test_context_user_overrides_audit_user(self):
        self.ctx.user = "bob"
        self.assertEqual(self.resolve(env_with(users="bob")), SECRET)


class CliTests(unittest.TestCase):
    """CLI against the HashiCorp fake (versioned, works on every OS)."""

    def setUp(self):
        from tests.test_vault_central import Clock

        self.fake = FakeHashiCorp(Clock(NOW))
        self.vault = HashiCorpVault({"url": self.fake.url, "cache_ttl_s": 0}, environ={"VAULT_TOKEN": "root-token"})
        self.ws = TempWorkspace()
        self.out: list[str] = []

    def tearDown(self):
        self.fake.close()
        self.ws.cleanup()

    def cli(self, *argv, answers=(), actor="alice"):
        it = iter(answers)
        return run_cli(parser().parse_args(["vault", *argv]), self.ws.settings, getpass_fn=lambda _p: next(it), out=self.out.append, vault=self.vault, actor=actor)

    def test_set_list_check_rotate_rollback(self):
        rc = self.cli("set", "pw", "--allow-host", "127.0.0.1", "--owner", "alice", "--user", "bob", "--rotate-after-days", "30", "--expires-in-days", "3", answers=[SECRET, SECRET])
        self.assertEqual(rc, 0, self.out)
        self.assertEqual(self.cli("list"), 0)
        line = [x for x in self.out if x.startswith("pw ")][-1]
        for part in ("status=rotate-soon", "age=", "owners=alice users=bob", "rotate_after=30d", "expires=", "v1", "backend=hashicorp"):
            self.assertIn(part, line)
        self.assertEqual(self.cli("check"), 0)  # rotate-soon warns but passes
        self.assertEqual(self.cli("check", "--warn-days", "1"), 0)
        self.vault.set("old", SECRET, ["h"], rotate_after_days=1)
        self.fake.store["analyst_agent/old"]["versions"][1]["created_time"] = "2020-01-01T00:00:00Z"
        self.assertEqual(self.cli("check"), 1)
        self.assertIn("status=rotate-due", "\n".join(self.out))
        self.vault.remove("old")
        # rotate: same value refused, then new value kept with metadata, previous kept
        self.assertEqual(self.cli("rotate", "pw", answers=[SECRET, SECRET]), 1)
        self.assertIn("same as the current one", self.out[-1])
        self.assertEqual(self.cli("rotate", "pw", "--expires-in-days", "90", answers=[NEW, NEW]), 0, self.out)
        self.assertIn("now v2", self.out[-1])
        m = self.vault.meta("pw")
        self.assertEqual((self.vault.get("pw"), m.users, m.allow_hosts), (NEW, ["bob"], ["127.0.0.1"]))
        self.assertGreater(m.expires_at, NOW + 80 * DAY)
        self.assertEqual(self.cli("rollback", "pw"), 0, self.out)
        self.assertEqual(self.vault.get("pw"), SECRET)
        self.assertNotIn(SECRET, "\n".join(self.out))
        self.assertNotIn(NEW, "\n".join(self.out))

    def test_check_fails_on_expired_and_rotate_clears_past_expiry(self):
        self.vault.set("pw", SECRET, ["h"], expires_at=NOW - 60)
        self.assertEqual(self.cli("check"), 1)
        self.assertIn("status=expired", "\n".join(self.out))
        self.assertEqual(self.cli("rotate", "pw", answers=[NEW, NEW]), 0, self.out)
        self.assertIsNone(self.vault.meta("pw").expires_at)
        self.assertEqual(self.cli("check"), 0)

    def test_only_owners_manage(self):
        self.vault.set("pw", SECRET, ["h"], owners=["alice"], users=["bob"])
        for argv, answers in ((["rotate", "pw"], [NEW, NEW]), (["rollback", "pw"], []), (["remove", "pw"], []), (["set", "pw", "--allow-host", "*"], [NEW, NEW])):
            self.assertEqual(self.cli(*argv, answers=answers, actor="bob"), 1, argv)
            self.assertIn("not an owner", self.out[-1])
        self.assertEqual(self.vault.get("pw"), SECRET)
        self.assertEqual(self.cli("remove", "pw", actor="alice"), 0)

    def test_read_only_backend_cannot_rotate(self):
        self.vault = env_with()
        self.assertEqual(self.cli("rotate", "pw", answers=[NEW, NEW]), 1)
        self.assertIn("read-only", self.out[-1])


@unittest.skipUnless(IS_WINDOWS, "DPAPI needs Windows")
class DpapiRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "vault"

    def tearDown(self):
        self.tmp.cleanup()

    def test_rotate_keeps_one_previous_and_rollback_swaps(self):
        v = DpapiVault(self.dir)
        v.set("pw", SECRET, ["127.0.0.1"], users=["bob"], rotate_after_days=30)
        m = v.rotate("pw", NEW)
        self.assertEqual((v.get("pw"), m.version, m.users, m.rotate_after_days), (NEW, 2, ["bob"], 30))
        raw = (self.dir / "vault.json").read_text()
        self.assertNotIn(SECRET, raw)
        self.assertNotIn(NEW, raw)
        v.rotate("pw", "third-value-xyz")
        rec = json.loads((self.dir / "vault.json").read_text())["secrets"]["pw"]
        self.assertNotIn("previous", rec["previous"])  # one level only
        m = v.rollback("pw")
        self.assertEqual((v.get("pw"), m.version), (NEW, 4))
        v.rollback("pw")
        self.assertEqual(v.get("pw"), "third-value-xyz")

    def test_rollback_without_previous(self):
        v = DpapiVault(self.dir)
        v.set("pw", SECRET, ["h"])
        with self.assertRaisesRegex(VaultError, "no previous value"):
            v.rollback("pw")

    def test_editing_sharing_or_expiry_in_file_breaks_decryption(self):
        v = DpapiVault(self.dir)
        v.set("pw", SECRET, ["h"], users=["bob"], expires_at=NOW + DAY)
        for key, val in (("users", ["*"]), ("expires_at", NOW + 999 * DAY)):
            data = json.loads((self.dir / "vault.json").read_text())
            orig = data["secrets"]["pw"][key]
            data["secrets"]["pw"][key] = val
            (self.dir / "vault.json").write_text(json.dumps(data))
            with self.assertRaises(VaultError, msg=key):
                v.get("pw")
            data["secrets"]["pw"][key] = orig
            (self.dir / "vault.json").write_text(json.dumps(data))
            self.assertEqual(v.get("pw"), SECRET)

    def test_records_without_new_fields_keep_old_entropy(self):
        v = DpapiVault(self.dir)
        old = b"analyst_agent/vault/v1\0pw\0" + json.dumps({"hosts": ["h"], "apps": []}, sort_keys=True).encode() + b"\0"
        self.assertEqual(v._entropy("pw", {"allow_hosts": ["h"], "allow_apps": []}), old)
        v.set("pw", SECRET, ["h"])
        self.assertEqual(sorted(json.loads((self.dir / "vault.json").read_text())["secrets"]["pw"]), ["allow_apps", "allow_hosts", "blob", "created", "updated"])


if __name__ == "__main__":
    unittest.main()
