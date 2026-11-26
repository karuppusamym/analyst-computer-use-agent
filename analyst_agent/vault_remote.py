"""Central secret stores for the credential vault, over stdlib urllib (no SDKs).

- HashiCorpVault  HashiCorp Vault KV version 2. Auth: a token from an env var
                  (`token_env`, default VAULT_TOKEN), or AppRole with role_id /
                  secret_id from env vars (`role_id_env`, `secret_id_env`).
                  Optional namespace header (Vault Enterprise / HCP).
                  Value: field `value` of the KV entry. Metadata: the entry's
                  custom_metadata. Versions: KV v2 versions (rotate writes a new
                  version, rollback copies the previous one forward).
- AzureKeyVault   Azure Key Vault secrets, REST API-version 7.4. Auth: OAuth2
                  client credentials against
                  {authority_host}/{tenant}/oauth2/v2.0/token for scope
                  https://vault.azure.net/.default (client secret from an env
                  var), or managed identity through the IMDS endpoint.
                  Metadata: the secret's tags. Versions: Key Vault versions.

Values are cached in memory only (`cache_ttl_s`, default 60 s, 0 = off) and
never written to disk. Errors never include a value or a credential. Base URLs
must be https, except loopback hosts (for local testing) and the IMDS address.

The access control that matters is the store's own: HashiCorp policies or Key
Vault RBAC decide who can read a value and who can change its metadata. The
allowlists and sharing lists in the metadata are enforced by this agent at use
time, so whoever can write a secret's metadata can widen them; grant metadata
write to the secret's owners only.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import threading
import time
from datetime import datetime
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


def _origin(url: str) -> tuple[str, str, int | None]:
    u = urlparse(url)
    return (u.scheme.lower(), (u.hostname or "").lower(), u.port)


class _SameOriginRedirects(HTTPRedirectHandler):
    """urllib copies every header, the Vault token and the bearer token included, to wherever a
    redirect points. Follow a redirect only to the same scheme, host and port; refuse the rest."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != _origin(req.full_url):
            raise RemoteError(code, f"refused a redirect from {urlparse(req.full_url).hostname} to {urlparse(newurl).scheme}://{urlparse(newurl).hostname}: "
                                    "the token is never sent to another host. Point the backend's url at the active node.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

from .vault import _KEEP, SecretMeta, Vault, VaultError, _num, _validate_value, check_name

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
IMDS_DEFAULT = "http://169.254.169.254/metadata/identity/oauth2/token"
KV_SCOPE = "https://vault.azure.net/.default"
KV_RESOURCE = "https://vault.azure.net"


class RemoteError(VaultError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def check_base_url(url: str, what: str, allow_http_hosts: set[str] = LOOPBACK) -> str:
    u = urlparse(url or "")
    if u.scheme == "https" and u.hostname:
        return url.rstrip("/")
    if u.scheme == "http" and (u.hostname or "") in allow_http_hosts:
        return url.rstrip("/")
    raise VaultError(f"{what} must be an https:// URL (got {url!r})")


def ssl_context(cfg: dict) -> ssl.SSLContext:
    ca = cfg.get("ca_bundle") or None
    if ca and not os.path.exists(ca):
        raise VaultError(f"ca_bundle {ca!r} does not exist")
    ctx = ssl.create_default_context(cafile=ca)
    if cfg.get("verify_tls", True) is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _error_text(raw: bytes) -> str:
    try:
        d = json.loads(raw or b"{}")
    except ValueError:
        return raw[:200].decode("utf-8", "replace")
    if isinstance(d.get("errors"), list):  # HashiCorp
        return "; ".join(str(x) for x in d["errors"])[:300]
    err = d.get("error")
    if isinstance(err, dict):  # Key Vault
        return f"{err.get('code', '')}: {err.get('message', '')}"[:300]
    if err:  # Entra ID token endpoint
        return f"{err}: {str(d.get('error_description', '')).splitlines()[0] if d.get('error_description') else ''}"[:300]
    return ""


def http_json(method: str, url: str, *, headers: dict | None = None, body: Any = None, form: dict | None = None,
              ssl_ctx: ssl.SSLContext | None = None, timeout: float = 10.0) -> tuple[int, dict]:
    """One request; JSON in, JSON out. Raises RemoteError(status, message) on HTTP errors."""
    data = None
    h = {"Accept": "application/json", **(headers or {})}
    if form is not None:
        data = urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=h, method=method)
    try:
        handlers = [_SameOriginRedirects()] + ([HTTPSHandler(context=ssl_ctx)] if ssl_ctx is not None and url.startswith("https") else [])
        with build_opener(*handlers).open(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except HTTPError as e:
        raw = e.read() if e.fp else b""
        raise RemoteError(e.code, f"HTTP {e.code} from {urlparse(url).hostname}: {_error_text(raw) or e.reason}") from None
    except (URLError, TimeoutError, OSError) as e:
        raise RemoteError(0, f"cannot reach {urlparse(url).hostname}: {getattr(e, 'reason', e)}") from None


class TTLCache:
    """Memory-only cache with a short time to live. Nothing here is ever persisted."""

    def __init__(self, ttl: float, clock: Callable[[], float] = time.monotonic):
        self.ttl, self.clock = ttl, clock
        self._d: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            hit = self._d.get(key)
            if hit and hit[0] > self.clock():
                return hit[1]
            self._d.pop(key, None)
            return None

    def put(self, key: str, value: Any) -> None:
        if self.ttl > 0:
            with self._lock:
                self._d[key] = (self.clock() + self.ttl, value)

    def drop(self, name: str) -> None:
        with self._lock:
            for k in [k for k in self._d if k.split(":", 1)[-1] == name]:
                del self._d[k]

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


def parse_time(v) -> float:
    """RFC 3339 (HashiCorp, with nanoseconds) or epoch seconds (Key Vault) -> epoch seconds; 0 if absent."""
    if v in (None, ""):
        return 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def _split(v) -> list[str]:
    return [x.strip().lower() for x in str(v or "").split(",") if x.strip()]


def encode_meta(m: dict, *, limit: int) -> dict[str, str]:
    """SecretMeta policy fields -> string map (custom_metadata / tags). Empty fields are left out."""
    out: dict[str, str] = {}
    for k in ("allow_hosts", "allow_apps", "owners", "users"):
        vals = [x.strip().lower() for x in (m.get(k) or []) if x and x.strip()]
        if any("," in x for x in vals):
            raise VaultError(f"{k} entries may not contain commas")
        if vals:
            out[k] = ",".join(vals)
    for k in ("rotate_after_days", "expires_at"):
        n = _num(m.get(k))
        if n:
            out[k] = f"{n:g}" if k == "rotate_after_days" else str(int(n))
    for k, v in out.items():
        if len(v) > limit:
            raise VaultError(f"metadata {k} is {len(v)} characters; this store allows {limit}")
    return out


def decode_meta(name: str, tags: dict, backend: str, created: float, updated: float, version: int | None) -> SecretMeta:
    t = tags or {}
    return SecretMeta(name, _split(t.get("allow_hosts")), _split(t.get("allow_apps")), created, updated, backend,
                      _split(t.get("owners")), _split(t.get("users")), _num(t.get("rotate_after_days")), _num(t.get("expires_at")), version)


class _RemoteVault(Vault):
    supports_versions = True

    def __init__(self, cfg: dict, environ: dict | None, clock: Callable[[], float]):
        self.cfg = cfg
        self.environ = os.environ if environ is None else environ
        self.clock = clock
        self.timeout = float(cfg.get("timeout_s", 10))
        self.cache = TTLCache(float(cfg.get("cache_ttl_s", 60)), clock)
        self._ssl = ssl_context(cfg)
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    def _env(self, key: str, default: str = "") -> str:
        return self.environ.get(self.cfg.get(key) or default, "") if (self.cfg.get(key) or default) else ""

    def _http(self, method: str, url: str, **kw) -> tuple[int, dict]:
        return http_json(method, url, ssl_ctx=self._ssl, timeout=self.timeout, **kw)

    def _cached_value(self, name: str, fetch: Callable[[], str]) -> str:
        v = self.cache.get("value:" + name)
        if v is None:
            v = fetch()
            self.cache.put("value:" + name, v)
        return v

    def _cached_meta(self, name: str, fetch: Callable[[], SecretMeta]) -> SecretMeta:
        m = self.cache.get("meta:" + name)
        if m is None:
            m = fetch()
            self.cache.put("meta:" + name, m)
        return m


# --------------------------------------------------------------------------- HashiCorp


class HashiCorpVault(_RemoteVault):
    backend = "hashicorp"

    def __init__(self, cfg: dict, environ: dict | None = None, clock: Callable[[], float] = time.time):
        super().__init__(cfg, environ, clock)
        self.url = check_base_url(cfg.get("url") or self.environ.get("VAULT_ADDR", ""), "vault.hashicorp.url")
        self.mount = (cfg.get("mount") or "secret").strip("/")
        prefix = (cfg.get("path_prefix", "analyst_agent/") or "").strip("/")
        self.prefix = prefix + "/" if prefix else ""
        self.namespace = cfg.get("namespace") or self.environ.get("VAULT_NAMESPACE", "")
        self.approle_mount = (cfg.get("approle_mount") or "approle").strip("/")
        self.role_id = self._env("role_id_env", "VAULT_ROLE_ID")
        self.secret_id = self._env("secret_id_env", "VAULT_SECRET_ID")
        self.static_token = self._env("token_env", "VAULT_TOKEN")
        if not (self.role_id and self.secret_id) and not self.static_token:
            raise VaultError("HashiCorp Vault needs a token (env var vault.hashicorp.token_env, default VAULT_TOKEN) "
                             "or AppRole credentials (role_id_env / secret_id_env, default VAULT_ROLE_ID / VAULT_SECRET_ID)")

    @property
    def approle(self) -> bool:
        return bool(self.role_id and self.secret_id)

    def _headers(self, token: str | None = None) -> dict:
        h = {}
        if token:
            h["X-Vault-Token"] = token
        if self.namespace:
            h["X-Vault-Namespace"] = self.namespace
        return h

    def _login(self) -> None:
        try:
            _, d = self._http("POST", f"{self.url}/v1/auth/{self.approle_mount}/login", headers=self._headers(), body={"role_id": self.role_id, "secret_id": self.secret_id})
        except RemoteError as e:
            raise VaultError(f"HashiCorp AppRole login failed: {e}") from None
        auth = d.get("auth") or {}
        if not auth.get("client_token"):
            raise VaultError("HashiCorp AppRole login returned no token")
        self._token = auth["client_token"]
        lease = float(auth.get("lease_duration") or 0)
        self._token_exp = self.clock() + lease if lease else float("inf")

    def _auth(self, force: bool = False) -> str:
        if not self.approle:
            return self.static_token
        with self._lock:
            if force or not self._token or self.clock() >= self._token_exp - 30:
                self._login()
            return self._token  # type: ignore[return-value]

    def _req(self, method: str, path: str, body: Any = None) -> dict:
        url = f"{self.url}/v1/{path}"
        try:
            return self._http(method, url, headers=self._headers(self._auth()), body=body)[1]
        except RemoteError as e:
            if e.status == 403 and self.approle:  # token expired or revoked: log in again once
                try:
                    return self._http(method, url, headers=self._headers(self._auth(force=True)), body=body)[1]
                except RemoteError as e2:
                    e = e2
            if e.status == 403:
                raise RemoteError(403, f"HashiCorp Vault denied access (token invalid, expired, or its policy lacks {path.split('?')[0]}): {e}") from None
            raise

    def _p(self, kind: str, name: str) -> str:
        return f"{self.mount}/{kind}/{quote(self.prefix + name, safe='/')}"

    def _missing(self, name: str, e: RemoteError):
        if e.status == 404:
            raise VaultError(f"no secret named {name!r} in HashiCorp Vault ({self.mount}/{self.prefix}{name})") from None
        raise e

    def list(self) -> list[SecretMeta]:
        try:
            d = self._req("GET", f"{self.mount}/metadata/{quote(self.prefix, safe='/')}?list=true")
        except RemoteError as e:
            if e.status == 404:
                return []
            raise
        keys = [k for k in (d.get("data") or {}).get("keys", []) if not k.endswith("/")]
        return [self.meta(k) for k in sorted(keys)]

    def _fetch_meta(self, name: str) -> SecretMeta:
        try:
            d = self._req("GET", self._p("metadata", name)).get("data") or {}
        except RemoteError as e:
            self._missing(name, e)
        cur = d.get("current_version")
        ver = (d.get("versions") or {}).get(str(cur)) or {}
        updated = parse_time(ver.get("created_time")) or parse_time(d.get("updated_time"))
        return decode_meta(name, d.get("custom_metadata") or {}, self.backend, parse_time(d.get("created_time")), updated, cur)

    def meta(self, name: str) -> SecretMeta:
        check_name(name)
        return self._cached_meta(name, lambda: self._fetch_meta(name))

    def _read(self, name: str, version: int | None = None) -> str:
        path = self._p("data", name) + (f"?version={int(version)}" if version else "")
        try:
            d = self._req("GET", path)
        except RemoteError as e:
            self._missing(name, e)
        data = (d.get("data") or {}).get("data") or {}
        if not isinstance(data.get("value"), str):
            raise VaultError(f"HashiCorp entry {self.prefix}{name} has no string field 'value' (deleted version, or not written by this agent)")
        return data["value"]

    def get(self, name: str) -> str:
        check_name(name)
        return self._cached_value(name, lambda: self._read(name))

    def _write(self, name: str, value: str) -> None:
        self._req("POST", self._p("data", name), {"data": {"value": value}})

    def _write_meta(self, name: str, pol: dict) -> None:
        self._req("POST", self._p("metadata", name), {"custom_metadata": encode_meta(pol, limit=512)})

    def set(self, name, value, allow_hosts=None, allow_apps=None, *, owners=None, users=None, rotate_after_days=None, expires_at=None):
        check_name(name)
        _validate_value(value)
        pol = {"allow_hosts": allow_hosts, "allow_apps": allow_apps, "owners": owners, "users": users, "rotate_after_days": rotate_after_days, "expires_at": expires_at}
        encode_meta(pol, limit=512)  # validate before writing anything
        self.cache.drop(name)
        self._write(name, value)
        self._write_meta(name, pol)
        self.cache.drop(name)
        return self.meta(name)

    def rotate(self, name, value, expires_at=_KEEP):
        _validate_value(value)
        pol = self._fetch_meta(name).policy()
        self.cache.drop(name)
        self._write(name, value)  # KV v2 keeps the earlier versions (up to the mount's max_versions)
        if expires_at is not _KEEP and expires_at != pol["expires_at"]:
            pol["expires_at"] = expires_at
            self._write_meta(name, pol)
        self.cache.drop(name)
        return self.meta(name)

    def rollback(self, name):
        try:
            d = self._req("GET", self._p("metadata", name)).get("data") or {}
        except RemoteError as e:
            self._missing(name, e)
        cur = int(d.get("current_version") or 0)
        versions = d.get("versions") or {}
        for v in range(cur - 1, 0, -1):
            info = versions.get(str(v)) or {}
            if info and not info.get("deletion_time") and not info.get("destroyed"):
                value = self._read(name, v)
                self.cache.drop(name)
                self._write(name, value)
                self.cache.drop(name)
                return self.meta(name)
        raise VaultError(f"secret {name!r} has no earlier live version in HashiCorp Vault")

    def remove(self, name):
        check_name(name)
        self.meta(name)
        self.cache.drop(name)
        self._req("DELETE", self._p("metadata", name))  # all versions and metadata


# --------------------------------------------------------------------------- Azure Key Vault


def azure_name(name: str) -> str:
    """Key Vault names allow letters, digits and '-'; '_' and '.' map to '-' (the real name is kept in tag agent_name)."""
    return re.sub(r"[_.]", "-", name)


class AzureKeyVault(_RemoteVault):
    backend = "azure_keyvault"
    TAG_LIMIT = 256

    def __init__(self, cfg: dict, environ: dict | None = None, clock: Callable[[], float] = time.time):
        super().__init__(cfg, environ, clock)
        self.vault_url = check_base_url(cfg.get("vault_url") or self.environ.get("AZURE_KEYVAULT_URL", ""), "vault.azure_keyvault.vault_url")
        self.api = cfg.get("api_version") or "7.4"
        self.authority = check_base_url(cfg.get("authority_host") or "https://login.microsoftonline.com", "vault.azure_keyvault.authority_host")
        self.tenant = cfg.get("tenant_id") or self.environ.get("AZURE_TENANT_ID", "")
        self.client_id = cfg.get("client_id") or self.environ.get("AZURE_CLIENT_ID", "")
        self.client_secret = self._env("client_secret_env", "AZURE_CLIENT_SECRET")
        self.imds = cfg.get("imds_endpoint") or IMDS_DEFAULT
        check_base_url(self.imds, "vault.azure_keyvault.imds_endpoint", LOOPBACK | {"169.254.169.254"})
        self.mi_client_id = cfg.get("managed_identity_client_id") or ""
        mode = cfg.get("auth") or "auto"
        if mode == "auto":
            mode = "client_secret" if self.client_secret else "managed_identity"
        if mode not in ("client_secret", "managed_identity"):
            raise VaultError(f"vault.azure_keyvault.auth must be client_secret, managed_identity or auto (got {mode!r})")
        if mode == "client_secret" and not (self.tenant and self.client_id and self.client_secret):
            raise VaultError("Azure client-credentials auth needs tenant_id, client_id and the client secret env var (client_secret_env, default AZURE_CLIENT_SECRET)")
        self.mode = mode

    def _fetch_token(self) -> None:
        try:
            if self.mode == "client_secret":
                _, d = self._http("POST", f"{self.authority}/{quote(self.tenant, safe='')}/oauth2/v2.0/token",
                                  form={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret, "scope": KV_SCOPE})
            else:
                q = {"api-version": "2018-02-01", "resource": KV_RESOURCE, **({"client_id": self.mi_client_id} if self.mi_client_id else {})}
                _, d = self._http("GET", f"{self.imds}?{urlencode(q)}", headers={"Metadata": "true"})
        except RemoteError as e:
            raise VaultError(f"Azure {'client-credentials' if self.mode == 'client_secret' else 'managed identity'} token request failed: {e}") from None
        if not d.get("access_token"):
            raise VaultError("Azure token response had no access_token")
        self._token = d["access_token"]
        self._token_exp = self.clock() + float(d.get("expires_in") or 300)

    def _auth(self, force: bool = False) -> str:
        with self._lock:
            if force or not self._token or self.clock() >= self._token_exp - 60:
                self._fetch_token()
            return self._token  # type: ignore[return-value]

    def _req(self, method: str, path: str, body: Any = None, full_url: str | None = None) -> dict:
        url = full_url or f"{self.vault_url}/{path}{'&' if '?' in path else '?'}api-version={self.api}"
        for attempt in (0, 1):
            try:
                return self._http(method, url, headers={"Authorization": "Bearer " + self._auth(force=attempt == 1)}, body=body)[1]
            except RemoteError as e:
                if e.status == 401 and attempt == 0:  # token expired or revoked: get a new one once
                    continue
                if e.status in (401, 403):
                    raise RemoteError(e.status, f"Azure Key Vault denied access (check the identity's secret permissions / RBAC role): {e}") from None
                raise
        raise AssertionError("unreachable")

    def _missing(self, name: str, e: RemoteError):
        if e.status == 404:
            raise VaultError(f"no secret named {name!r} in Azure Key Vault (as {azure_name(name)})") from None
        raise e

    def _bundle(self, name: str, version: str = "") -> dict:
        try:
            b = self._req("GET", f"secrets/{azure_name(name)}" + (f"/{quote(version, safe='')}" if version else ""))
        except RemoteError as e:
            self._missing(name, e)
        owner = (b.get("tags") or {}).get("agent_name")
        if owner and owner != name:
            raise VaultError(f"Azure secret {azure_name(name)} belongs to {owner!r}, not {name!r}")
        return b

    def _meta_from(self, name: str, item: dict) -> SecretMeta:
        tags = dict(item.get("tags") or {})
        attrs = item.get("attributes") or {}
        if not tags.get("expires_at") and attrs.get("exp"):
            tags["expires_at"] = str(attrs["exp"])  # a native expiry set in the portal counts too
        # attributes.created is when the current version (value) was written; Key Vault version ids are not numbers
        return decode_meta(name, tags, self.backend, _num(tags.get("created")) or parse_time(attrs.get("created")), parse_time(attrs.get("created")), None)

    def _load(self, name: str) -> tuple[SecretMeta, str]:
        b = self._bundle(name)
        if (b.get("attributes") or {}).get("enabled") is False:
            raise VaultError(f"Azure secret {azure_name(name)} is disabled")
        m = self._meta_from(name, b)
        self.cache.put("meta:" + name, m)
        self.cache.put("value:" + name, b.get("value"))
        return m, b.get("value")

    def meta(self, name: str) -> SecretMeta:
        check_name(name)
        return self._cached_meta(name, lambda: self._load(name)[0])

    def get(self, name: str) -> str:
        check_name(name)
        v = self._cached_value(name, lambda: self._load(name)[1])
        if not isinstance(v, str):
            raise VaultError(f"Azure secret {azure_name(name)} has no value")
        return v

    def list(self) -> list[SecretMeta]:
        out, url = [], f"{self.vault_url}/secrets?api-version={self.api}&maxresults=25"
        while url:
            d = self._req("GET", "", full_url=url)
            for item in d.get("value", []):
                rname = (item.get("id") or "").rstrip("/").split("/")[-1]
                name = (item.get("tags") or {}).get("agent_name") or rname
                out.append(self._meta_from(name, item))
            nxt = d.get("nextLink") or ""
            if nxt and not nxt.startswith(self.vault_url + "/"):
                raise VaultError("Azure Key Vault returned a nextLink to another host; stopped listing")
            url = nxt
        return sorted(out, key=lambda m: m.name)

    def _tags(self, name: str, pol: dict, created: float | None) -> dict:
        return {"agent_name": name, **encode_meta(pol, limit=self.TAG_LIMIT), "created": str(int(created or self.clock()))}

    def _put(self, name: str, value: str, tags: dict) -> None:
        self.cache.drop(name)
        self._req("PUT", f"secrets/{azure_name(name)}", {"value": value, "tags": tags, "contentType": "analyst_agent secret"})
        self.cache.drop(name)

    def _existing(self, name: str) -> dict | None:
        try:
            return self._bundle(name)
        except VaultError as e:
            if "no secret named" in str(e):
                return None
            raise

    def set(self, name, value, allow_hosts=None, allow_apps=None, *, owners=None, users=None, rotate_after_days=None, expires_at=None):
        check_name(name)
        _validate_value(value)
        pol = {"allow_hosts": allow_hosts, "allow_apps": allow_apps, "owners": owners, "users": users, "rotate_after_days": rotate_after_days, "expires_at": expires_at}
        old = self._existing(name)  # also refuses a name collision ('a_b' vs 'a.b')
        created = _num((old or {}).get("tags", {}).get("created")) if old else None
        self._put(name, value, self._tags(name, pol, created))
        return self.meta(name)

    def rotate(self, name, value, expires_at=_KEEP):
        _validate_value(value)
        b = self._bundle(name)
        m = self._meta_from(name, b)
        pol = m.policy()
        if expires_at is not _KEEP:
            pol["expires_at"] = expires_at
        self._put(name, value, self._tags(name, pol, m.created))  # a new version; Key Vault keeps the old ones
        return self.meta(name)

    def rollback(self, name):
        cur = self._bundle(name)
        cur_ver = (cur.get("id") or "").rstrip("/").split("/")[-1]
        cur_created = parse_time((cur.get("attributes") or {}).get("created"))
        versions, url = [], f"{self.vault_url}/secrets/{azure_name(name)}/versions?api-version={self.api}"
        while url:
            d = self._req("GET", "", full_url=url)
            versions += d.get("value", [])
            nxt = d.get("nextLink") or ""
            url = nxt if nxt.startswith(self.vault_url + "/") else ""
        older = [v for v in versions if (v.get("id") or "").rstrip("/").split("/")[-1] != cur_ver
                 and (v.get("attributes") or {}).get("enabled", True) and parse_time((v.get("attributes") or {}).get("created")) <= cur_created]
        if not older:
            raise VaultError(f"secret {name!r} has no earlier enabled version in Azure Key Vault")
        prev = max(older, key=lambda v: parse_time((v.get("attributes") or {}).get("created")))
        value = self._bundle(name, prev["id"].rstrip("/").split("/")[-1]).get("value")
        m = self._meta_from(name, cur)
        self._put(name, value, self._tags(name, m.policy(), m.created))
        return self.meta(name)

    def remove(self, name):
        check_name(name)
        self.meta(name)
        self.cache.drop(name)
        try:
            self._req("DELETE", f"secrets/{azure_name(name)}")  # soft delete if the vault has it enabled
        except RemoteError as e:
            self._missing(name, e)


def open_remote(backend: str, cfg: dict) -> Vault:
    if backend == "hashicorp":
        return HashiCorpVault(cfg)
    if backend == "azure_keyvault":
        return AzureKeyVault(cfg)
    raise VaultError(f"unknown remote vault backend {backend!r}")
