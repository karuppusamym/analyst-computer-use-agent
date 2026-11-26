"""Central vault backends (HashiCorp KV v2, Azure Key Vault) against local fake HTTP servers."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.audit import AuditLog  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.tools.base import ToolContext  # noqa: E402
from analyst_agent.vault import SecretDenied, SecretExpired, VaultError, open_vault, resolve_secrets  # noqa: E402
from analyst_agent.vault_remote import KV_SCOPE, AzureKeyVault, HashiCorpVault, parse_time  # noqa: E402
from tests.helpers import TempWorkspace  # noqa: E402

SECRET = "C3ntral-Pa55word!"
NEW = "R0tated-Pa55word#"
T0 = 1_790_000_000.0  # fixed clock start (2026-09)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class FakeServer:
    """ThreadingHTTPServer on 127.0.0.1:0; subclasses implement handle()."""

    def __init__(self):
        fake = self
        self.requests: list[dict] = []
        self.lock = threading.Lock()

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                u = urlparse(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                req = {"method": self.command, "path": unquote(u.path), "query": {k: v[0] for k, v in parse_qs(u.query).items()}, "headers": {k.lower(): v for k, v in self.headers.items()}, "raw": raw}
                with fake.lock:
                    fake.requests.append(req)
                    status, body = fake.handle(req)
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _do

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def count(self, method, path_part):
        return sum(1 for r in self.requests if r["method"] == method and path_part in r["path"])


# --------------------------------------------------------------------------- HashiCorp fake


def iso(t: float) -> str:
    import datetime as dt

    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"  # nanoseconds, like Vault


class FakeHashiCorp(FakeServer):
    def __init__(self, clock, mount="secret", lease=3600):
        super().__init__()
        self.clock, self.mount, self.lease = clock, mount, lease
        self.tokens = {"root-token"}
        self.role = ("role-1", "secret-id-1")
        self.store: dict[str, dict] = {}
        self.logins = 0

    def handle(self, r):
        p = r["path"]
        body = json.loads(r["raw"] or b"{}")
        if p == "/v1/auth/approle/login" and r["method"] == "POST":
            if (body.get("role_id"), body.get("secret_id")) != self.role:
                return 400, {"errors": ["invalid role or secret ID"]}
            self.logins += 1
            tok = f"approle-token-{self.logins}"
            self.tokens.add(tok)
            return 200, {"auth": {"client_token": tok, "lease_duration": self.lease, "renewable": True}}
        if r["headers"].get("x-vault-token") not in self.tokens:
            return 403, {"errors": ["permission denied"]}
        pre = f"/v1/{self.mount}/"
        if not p.startswith(pre):
            return 404, {"errors": []}
        kind, _, path = p[len(pre):].partition("/")
        e = self.store.get(path)
        if kind == "data":
            if r["method"] == "GET":
                if not e:
                    return 404, {"errors": []}
                v = int(r["query"].get("version") or e["current"])
                ver = e["versions"].get(v)
                if not ver or ver["deletion_time"]:
                    return 404, {"errors": []}
                return 200, {"data": {"data": {"value": ver["value"]}, "metadata": {"version": v, "created_time": ver["created_time"]}}}
            if r["method"] == "POST":
                e = self.store.setdefault(path, {"versions": {}, "current": 0, "custom_metadata": {}, "created_time": iso(self.clock())})
                e["current"] += 1
                e["versions"][e["current"]] = {"value": body["data"]["value"], "created_time": iso(self.clock()), "deletion_time": "", "destroyed": False}
                return 200, {"data": {"version": e["current"]}}
        if kind == "metadata":
            if r["method"] == "GET" and r["query"].get("list") == "true":
                prefix = path.rstrip("/") + "/" if path else ""
                keys = sorted({k[len(prefix):].split("/")[0] + ("/" if "/" in k[len(prefix):] else "") for k in self.store if k.startswith(prefix)})
                return (200, {"data": {"keys": keys}}) if keys else (404, {"errors": []})
            if not e:
                return 404, {"errors": []}
            if r["method"] == "GET":
                return 200, {"data": {"current_version": e["current"], "created_time": e["created_time"], "updated_time": iso(self.clock()), "custom_metadata": e["custom_metadata"],
                                      "versions": {str(k): {"created_time": v["created_time"], "deletion_time": v["deletion_time"], "destroyed": v["destroyed"]} for k, v in e["versions"].items()}}}
            if r["method"] == "POST":
                assert all(isinstance(v, str) for v in body["custom_metadata"].values())
                e["custom_metadata"] = body["custom_metadata"]
                return 204, None
            if r["method"] == "DELETE":
                del self.store[path]
                return 204, None
        return 405, {"errors": ["unsupported"]}


def hc_cfg(fake, **kw):
    return {"url": fake.url, "namespace": "team-a", "cache_ttl_s": 60, **kw}


class HashiCorpTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fake = FakeHashiCorp(self.clock)
        self.env = {"VAULT_TOKEN": "root-token"}

    def tearDown(self):
        self.fake.close()

    def vault(self, env=None, **kw):
        return HashiCorpVault(hc_cfg(self.fake, **kw), environ=self.env if env is None else env, clock=self.clock)

    def test_set_get_metadata_namespace_and_list(self):
        v = self.vault()
        exp = T0 + 30 * 86400
        m = v.set("portal_pw", SECRET, ["Portal.Example.com"], ["legacy*"], owners=["alice"], users=["bob", "schedule:*"], rotate_after_days=90, expires_at=exp)
        self.assertEqual((m.allow_hosts, m.allow_apps, m.owners, m.users), (["portal.example.com"], ["legacy*"], ["alice"], ["bob", "schedule:*"]))
        self.assertEqual((m.rotate_after_days, m.expires_at, m.version, m.backend), (90, int(exp), 1, "hashicorp"))
        self.assertAlmostEqual(m.updated, T0, delta=1)
        entry = self.fake.store["analyst_agent/portal_pw"]
        self.assertEqual(entry["custom_metadata"]["users"], "bob,schedule:*")
        self.assertEqual(entry["versions"][1]["value"], SECRET)
        self.assertEqual(v.get("portal_pw"), SECRET)
        self.assertEqual([x.name for x in v.list()], ["portal_pw"])
        self.assertTrue(all(r["headers"].get("x-vault-namespace") == "team-a" for r in self.fake.requests))
        self.assertNotIn(SECRET, json.dumps([x.public() for x in v.list()]))

    def test_value_cached_in_memory_with_ttl(self):
        v = self.vault(cache_ttl_s=30)
        v.set("pw", SECRET, ["h"])
        before = self.fake.count("GET", "/data/")
        v.get("pw"), v.get("pw")
        self.assertEqual(self.fake.count("GET", "/data/") - before, 1)
        self.clock.t += 31
        v.get("pw")
        self.assertEqual(self.fake.count("GET", "/data/") - before, 2)
        no_cache = self.vault(cache_ttl_s=0)
        no_cache.get("pw"), no_cache.get("pw")
        self.assertEqual(self.fake.count("GET", "/data/") - before, 4)

    def test_missing_secret_and_empty_list(self):
        v = self.vault()
        self.assertEqual(v.list(), [])
        with self.assertRaisesRegex(VaultError, "no secret named 'nope'"):
            v.get("nope")
        with self.assertRaisesRegex(VaultError, "no secret named"):
            v.meta("nope")

    def test_bad_static_token_is_clear_error(self):
        v = self.vault(env={"VAULT_TOKEN": "wrong-token-value"})
        with self.assertRaisesRegex(VaultError, "denied access") as cm:
            v.get("pw")
        self.assertNotIn("wrong-token-value", str(cm.exception))

    def test_needs_some_credential(self):
        with self.assertRaisesRegex(VaultError, "needs a token"):
            self.vault(env={})

    def test_approle_login_token_expiry_and_relogin(self):
        v = self.vault(env={"VAULT_ROLE_ID": "role-1", "VAULT_SECRET_ID": "secret-id-1"}, cache_ttl_s=0)
        v.set("pw", SECRET, ["h"])
        self.assertEqual(self.fake.logins, 1)
        self.fake.tokens.discard("approle-token-1")  # revoked / expired server-side
        self.assertEqual(v.get("pw"), SECRET)
        self.assertEqual(self.fake.logins, 2)
        self.clock.t += 3600  # lease over: logs in again before the call, no 403 round trip
        denied_before = sum(1 for r in self.fake.requests if "/auth/" not in r["path"] and r["headers"].get("x-vault-token") not in self.fake.tokens)
        self.assertEqual(v.get("pw"), SECRET)
        self.assertEqual(self.fake.logins, 3)
        self.assertEqual(sum(1 for r in self.fake.requests if "/auth/" not in r["path"] and r["headers"].get("x-vault-token") not in self.fake.tokens), denied_before)

    def test_approle_bad_secret_id(self):
        v = self.vault(env={"VAULT_ROLE_ID": "role-1", "VAULT_SECRET_ID": "wrong-secret-id-77"})
        with self.assertRaisesRegex(VaultError, "AppRole login failed") as cm:
            v.get("pw")
        self.assertNotIn("wrong-secret-id-77", str(cm.exception))

    def test_rotate_keeps_versions_and_rollback(self):
        v = self.vault()
        v.set("pw", SECRET, ["h"], users=["bob"], rotate_after_days=30)
        self.clock.t += 40 * 86400
        m = v.rotate("pw", NEW)
        self.assertEqual((m.version, m.users, m.rotate_after_days), (2, ["bob"], 30))
        self.assertAlmostEqual(m.updated, self.clock.t, delta=1)
        self.assertEqual(v.get("pw"), NEW)
        self.assertEqual(self.fake.store["analyst_agent/pw"]["versions"][1]["value"], SECRET)
        m = v.rollback("pw")
        self.assertEqual((m.version, v.get("pw")), (3, SECRET))
        v.remove("pw")
        self.assertEqual(v.list(), [])

    def test_https_required_except_loopback(self):
        with self.assertRaisesRegex(VaultError, "https"):
            HashiCorpVault({"url": "http://vault.example:8200"}, environ=self.env)
        HashiCorpVault({"url": "https://vault.example:8200"}, environ=self.env)

    def test_open_vault_from_settings_and_resolve(self):
        ws = TempWorkspace({"policy": {"allowed_hosts": ["127.0.0.1"]}, "vault": {"backend": "hashicorp", "hashicorp": {"url": self.fake.url}}})
        try:
            with mock.patch.dict(os.environ, {"VAULT_TOKEN": "root-token"}):
                v = open_vault(ws.settings)
                self.assertIsInstance(v, HashiCorpVault)
                v.set("portal_note", SECRET, ["127.0.0.1"], users=["alice"])
                audit = AuditLog(ws.settings.audit_dir, user="alice")
                ctx = ToolContext(ws.settings, PolicyEngine(ws.settings), audit, ScriptedApprover([]), step_id="s1")
                self.assertEqual(resolve_secrets("{{secret:portal_note}}", ctx, tool="browser_fill", url="http://127.0.0.1/f"), SECRET)
                audit.user = "mallory"
                ctx.vault = None
                with self.assertRaises(SecretDenied):
                    resolve_secrets("{{secret:portal_note}}", ctx, tool="browser_fill", url="http://127.0.0.1/f")
            kinds = [e["kind"] for e in audit.events()]
            self.assertEqual(kinds, ["secret_used", "secret_denied"])
            self.assertNotIn(SECRET, audit.path.read_text(encoding="utf-8"))
            on_disk = [p for p in ws.root.rglob("*") if p.is_file() and SECRET.encode() in p.read_bytes()]
            self.assertEqual(on_disk, [])  # values are never cached on disk
        finally:
            ws.cleanup()


# --------------------------------------------------------------------------- Azure fake


class FakeAzure(FakeServer):
    """Entra ID token endpoint + IMDS + Key Vault secrets API on one server."""

    def __init__(self, clock, page_size=2):
        super().__init__()
        self.clock, self.page_size = clock, page_size
        self.tenant, self.client_id, self.client_secret = "tenant-1", "client-1", "client-secret-1"
        self.tokens: set[str] = set()
        self.issued = 0
        self.secrets: dict[str, list[dict]] = {}  # name -> versions, newest last
        self.n = 0

    def _token(self, prefix, expires_in):
        self.issued += 1
        tok = f"{prefix}-{self.issued}"
        self.tokens.add(tok)
        return tok, expires_in

    def _bundle(self, name, ver, with_value=True):
        b = {"id": f"{self.url}/secrets/{name}/{ver['version']}", "attributes": dict(ver["attributes"]), "tags": dict(ver["tags"]), "contentType": ver.get("contentType")}
        if with_value:
            b["value"] = ver["value"]
        return b

    def handle(self, r):
        p, q = r["path"], r["query"]
        if p == f"/{self.tenant}/oauth2/v2.0/token" and r["method"] == "POST":
            form = {k: v[0] for k, v in parse_qs(r["raw"].decode()).items()}
            if form.get("grant_type") != "client_credentials" or form.get("scope") != KV_SCOPE:
                return 400, {"error": "invalid_request", "error_description": "bad grant or scope"}
            if (form.get("client_id"), form.get("client_secret")) != (self.client_id, self.client_secret):
                return 401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}
            tok, exp = self._token("aad", 3599)
            return 200, {"token_type": "Bearer", "expires_in": exp, "access_token": tok}
        if p == "/metadata/identity/oauth2/token":
            if r["headers"].get("metadata") != "true" or q.get("resource") != "https://vault.azure.net":
                return 400, {"error": "invalid_request", "error_description": "Required metadata header not specified"}
            tok, exp = self._token("mi", 86399)
            return 200, {"access_token": tok, "expires_in": str(exp), "token_type": "Bearer"}
        if q.get("api-version") != "7.4":
            return 400, {"error": {"code": "BadParameter", "message": "api-version missing"}}
        auth = r["headers"].get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return 401, {"error": {"code": "Unauthorized", "message": "AKV10000: Request is missing a Bearer or PoP token."}}
        parts = [x for x in p.split("/") if x]
        if parts == ["secrets"] and r["method"] == "GET":
            names = sorted(self.secrets)
            start = int(q.get("skip") or 0)
            page = names[start:start + self.page_size]
            d = {"value": [{k: v for k, v in self._bundle(n, self.secrets[n][-1], False).items() if k != "value"} for n in page]}
            d["value"] = [{**x, "id": f"{self.url}/secrets/{n}"} for x, n in zip(d["value"], page)]
            if start + self.page_size < len(names):
                d["nextLink"] = f"{self.url}/secrets?api-version=7.4&maxresults={self.page_size}&skip={start + self.page_size}"
            return 200, d
        if len(parts) >= 2 and parts[0] == "secrets":
            name = parts[1]
            vers = self.secrets.get(name)
            if r["method"] == "PUT" and len(parts) == 2:
                body = json.loads(r["raw"])
                self.n += 1
                ver = {"version": f"v{self.n:04d}abc", "value": body["value"], "tags": body.get("tags") or {}, "contentType": body.get("contentType"),
                       "attributes": {"enabled": True, "created": int(self.clock()), "updated": int(self.clock())}}
                self.secrets.setdefault(name, []).append(ver)
                return 200, self._bundle(name, ver)
            if not vers:
                return 404, {"error": {"code": "SecretNotFound", "message": f"A secret with (name/id) {name} was not found in this key vault."}}
            if r["method"] == "DELETE":
                del self.secrets[name]
                return 200, {"recoveryId": f"{self.url}/deletedsecrets/{name}"}
            if r["method"] == "PATCH" and len(parts) == 3:  # Update Secret: attributes / tags of one version
                for x in vers:
                    if x["version"] == parts[2]:
                        x["tags"] = json.loads(r["raw"]).get("tags", x["tags"])
                        x["attributes"]["updated"] = int(self.clock())
                        return 200, self._bundle(name, x, False)
                return 404, {"error": {"code": "SecretNotFound", "message": "version not found"}}
            if len(parts) == 3 and parts[2] == "versions":
                return 200, {"value": [{k: v for k, v in self._bundle(name, x, False).items()} for x in vers]}
            if len(parts) == 3:
                for x in vers:
                    if x["version"] == parts[2]:
                        return 200, self._bundle(name, x)
                return 404, {"error": {"code": "SecretNotFound", "message": "version not found"}}
            return 200, self._bundle(name, vers[-1])
        return 404, {"error": {"code": "NotFound", "message": p}}


class AzureTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fake = FakeAzure(self.clock)
        self.env = {"AZURE_CLIENT_SECRET": "client-secret-1"}

    def tearDown(self):
        self.fake.close()

    def cfg(self, **kw):
        return {"vault_url": self.fake.url, "authority_host": self.fake.url, "tenant_id": "tenant-1", "client_id": "client-1",
                "imds_endpoint": self.fake.url + "/metadata/identity/oauth2/token", **kw}

    def vault(self, env=None, **kw):
        return AzureKeyVault(self.cfg(**kw), environ=self.env if env is None else env, clock=self.clock)

    def test_client_credentials_set_get_tags_and_name_mapping(self):
        v = self.vault()
        m = v.set("portal_note", SECRET, ["127.0.0.1"], owners=["alice"], rotate_after_days=60)
        self.assertEqual((m.allow_hosts, m.owners, m.rotate_after_days, m.backend), (["127.0.0.1"], ["alice"], 60, "azure_keyvault"))
        stored = self.fake.secrets["portal-note"][-1]
        self.assertEqual(stored["tags"]["agent_name"], "portal_note")
        self.assertEqual(stored["tags"]["allow_hosts"], "127.0.0.1")
        self.assertEqual(v.get("portal_note"), SECRET)
        token_req = [r for r in self.fake.requests if r["path"].endswith("/oauth2/v2.0/token")]
        self.assertEqual(len(token_req), 1)
        self.assertIn(b"scope=https%3A%2F%2Fvault.azure.net%2F.default", token_req[0]["raw"])
        with self.assertRaisesRegex(VaultError, "belongs to 'portal_note'"):
            v.set("portal.note", SECRET, ["h"])  # maps to the same Key Vault name

    def test_missing_secret(self):
        with self.assertRaisesRegex(VaultError, "no secret named 'nope'"):
            self.vault().get("nope")

    def test_bad_client_secret(self):
        v = self.vault(env={"AZURE_CLIENT_SECRET": "wrong-client-secret-9"})
        with self.assertRaisesRegex(VaultError, "invalid_client") as cm:
            v.get("x-pw")
        self.assertNotIn("wrong-client-secret-9", str(cm.exception))
        self.assertNotIn("Trace ID", str(cm.exception))

    def test_missing_config_for_client_credentials(self):
        with self.assertRaisesRegex(VaultError, "tenant_id"):
            AzureKeyVault({"vault_url": "https://kv.vault.azure.net", "auth": "client_secret"}, environ={})

    def test_token_expiry_and_refresh(self):
        v = self.vault(cache_ttl_s=0)
        v.set("pw", SECRET, ["h"])
        self.assertEqual(self.fake.issued, 1)
        self.fake.tokens.clear()  # revoked: 401, then one refresh
        self.assertEqual(v.get("pw"), SECRET)
        self.assertEqual(self.fake.issued, 2)
        self.clock.t += 3600  # expired by clock: refreshed before the call
        n401 = sum(1 for r in self.fake.requests if "/secrets" in r["path"] and r["headers"].get("authorization", "")[7:] not in self.fake.tokens)
        self.assertEqual(v.get("pw"), SECRET)
        self.assertEqual(self.fake.issued, 3)
        self.assertEqual(sum(1 for r in self.fake.requests if "/secrets" in r["path"] and r["headers"].get("authorization", "")[7:] not in self.fake.tokens), n401)

    def test_vault_denies_after_refresh(self):
        v = self.vault(cache_ttl_s=0)
        v.set("pw", SECRET, ["h"])
        orig = self.fake.handle
        self.fake.handle = lambda r: (403, {"error": {"code": "Forbidden", "message": "Caller is not authorized"}}) if "/secrets" in r["path"] else orig(r)
        with self.assertRaisesRegex(VaultError, "denied access"):
            v.get("pw")

    def test_managed_identity_via_imds(self):
        v = self.vault(env={}, auth="auto", tenant_id="", client_id="")
        self.assertEqual(v.mode, "managed_identity")
        v.set("mi-pw", SECRET, ["h"])
        self.assertEqual(v.get("mi-pw"), SECRET)
        imds = [r for r in self.fake.requests if r["path"] == "/metadata/identity/oauth2/token"]
        self.assertEqual(len(imds), 1)
        self.assertEqual(imds[0]["headers"]["metadata"], "true")

    def test_list_follows_next_link(self):
        v = self.vault()
        for n in ("a-pw", "b_pw", "c-pw"):
            v.set(n, SECRET, ["h"])
        self.assertEqual([m.name for m in v.list()], ["a-pw", "b_pw", "c-pw"])
        self.assertEqual(self.fake.count("GET", "/secrets") >= 2, True)

    def test_rotate_and_rollback_use_versions(self):
        v = self.vault()
        v.set("pw", SECRET, ["h"], users=["bob"])
        self.clock.t += 10
        m = v.rotate("pw", NEW, expires_at=T0 + 86400 * 90)
        self.assertEqual((v.get("pw"), m.users, m.expires_at), (NEW, ["bob"], int(T0 + 86400 * 90)))
        self.assertAlmostEqual(m.updated, self.clock.t, delta=1)
        self.assertAlmostEqual(m.created, T0, delta=1)
        self.assertEqual(len(self.fake.secrets["pw"]), 2)
        self.clock.t += 10
        v.rollback("pw")
        self.assertEqual(v.get("pw"), SECRET)
        self.assertEqual(len(self.fake.secrets["pw"]), 3)

    def test_native_expiry_refused_at_use(self):
        ws = TempWorkspace({"policy": {"allowed_hosts": ["127.0.0.1"]}})
        try:
            v = self.vault()
            v.set("pw", SECRET, ["127.0.0.1"])
            self.fake.secrets["pw"][-1]["attributes"]["exp"] = int(T0) - 60  # expiry set in the Azure portal
            v.cache.clear()
            audit = AuditLog(ws.settings.audit_dir)
            ctx = ToolContext(ws.settings, PolicyEngine(ws.settings), audit, ScriptedApprover([]), step_id="s1")
            ctx.vault = v
            with self.assertRaisesRegex(SecretExpired, "has expired"):
                resolve_secrets("{{secret:pw}}", ctx, tool="browser_fill", url="http://127.0.0.1/")
            self.assertEqual([e["kind"] for e in audit.events()], ["secret_expired"])
        finally:
            ws.cleanup()


class HelperTests(unittest.TestCase):
    def test_parse_time(self):
        self.assertEqual(parse_time(1700000000), 1700000000.0)
        self.assertAlmostEqual(parse_time("2023-11-14T22:13:20.123456789Z"), 1700000000.123456, places=3)
        self.assertEqual(parse_time(""), 0.0)


if __name__ == "__main__":
    unittest.main()
