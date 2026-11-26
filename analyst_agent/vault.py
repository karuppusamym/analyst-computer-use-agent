"""Credential vault: named secrets that tools type into allowlisted targets.

Backends (config section `vault`):
- "dpapi"   Windows DPAPI (CryptProtectData, current-user scope) via ctypes.
            One JSON file at <vault.path>/vault.json holds a DPAPI blob plus
            metadata per secret. The entropy binds each blob to its name and
            allowlists, so editing the allowlist in the file breaks decryption
            instead of widening access. Optional extra entropy comes from the
            environment variable named in `vault.entropy_env`.
- "env"     Read-only. Secret `portal-pw` is the variable
            AGENT_SECRET_PORTAL_PW (prefix from `vault.env_prefix`); its
            allowlists are AGENT_SECRET_PORTAL_PW__HOSTS and __APPS
            (comma-separated). No allowlist means the secret cannot be used.
- "keyring" Only when the `keyring` package is installed: the value lives in
            the OS keyring, the metadata in vault.json.
- "hashicorp" / "azure_keyvault"  Central stores over stdlib HTTPS (see
            vault_remote.py). Metadata lives in the remote store as custom
            metadata / tags; values are cached in memory only, briefly.

Every secret can also carry rotation metadata (`rotate_after_days`,
`expires_at`; see secret_status) and a sharing list (`owners`, `users`: run
users allowed to use it; both empty = any run user). Entries are user fnmatch
patterns, `team:<name>` (a team in `portal.teams`, membership as the portal
computes it) or `group:<sso-group>` (portal runs with SSO sign-in only); see
Principal. An expired secret, or one the run's user may not use, is refused at
use time and audited as `secret_expired` / `secret_denied`.

Use: a tool input may contain `{{secret:name}}`. Only the tools that type or
fill (browser_fill, the pixel tier `type`, uia_set_text) resolve it, at the
last moment, and only if the target host / window / app is on both the
secret's allowlist and the policy allowlist. The value is registered with the
audit log's redactor first, so it is replaced by [REDACTED:name] in audit
events, tool results returned to the model, reports and checkpoints. The audit
log records `secret_used` (name, target, step), never the value.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import secrets as _secrets
import string
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .config import Settings
from .policy import PolicyViolation

if TYPE_CHECKING:  # pragma: no cover
    from .tools.base import ToolContext

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
PLACEHOLDER_RE = re.compile(r"\{\{secret:([A-Za-z0-9][A-Za-z0-9_.\-]{0,63})\}\}")
MIN_SECRET_LEN = 4  # shorter values cannot be redacted safely


class VaultError(Exception):
    pass


class SecretRefused(PolicyViolation):
    """A secret may not be used for this target. The message never holds the value."""

    audit_kind = "secret_refused"


class SecretDenied(SecretRefused):
    """The run's user is not on the secret's owners/users list."""

    audit_kind = "secret_denied"


class SecretExpired(SecretRefused):
    """The secret is past its expires_at."""

    audit_kind = "secret_expired"


DAY = 86400.0


@dataclass
class SecretMeta:
    name: str
    allow_hosts: list[str] = field(default_factory=list)
    allow_apps: list[str] = field(default_factory=list)
    created: float = 0.0
    updated: float = 0.0  # when the current value was set (last rotation)
    backend: str = ""
    owners: list[str] = field(default_factory=list)  # run users who may use and manage it
    users: list[str] = field(default_factory=list)  # run users who may use it
    rotate_after_days: float | None = None
    expires_at: float | None = None  # epoch seconds
    version: int | None = None  # backend version of the current value, if versioned

    def public(self) -> dict:
        return asdict(self)

    def policy(self) -> dict:
        """The metadata `set` takes, so a rotation can keep it unchanged."""
        return {"allow_hosts": list(self.allow_hosts), "allow_apps": list(self.allow_apps), "owners": list(self.owners), "users": list(self.users),
                "rotate_after_days": self.rotate_after_days, "expires_at": self.expires_at}


def secret_status(meta: SecretMeta, now: float | None = None, warn_days: float = 7.0) -> tuple[str, str]:
    """(status, detail). status: ok | rotate-soon | rotate-due | expired.

    expired: past expires_at (refused at use). rotate-due: the value is older
    than rotate_after_days (still usable; `vault check` fails). rotate-soon:
    either deadline is within warn_days.
    """
    now = time.time() if now is None else now
    if meta.expires_at and now >= meta.expires_at:
        return "expired", f"expired {time.strftime('%Y-%m-%d', time.localtime(meta.expires_at))}"
    due = meta.updated + meta.rotate_after_days * DAY if (meta.rotate_after_days and meta.updated) else None
    if due is not None and now >= due:
        return "rotate-due", f"rotation overdue by {(now - due) / DAY:.0f}d"
    soon = []
    if meta.expires_at and meta.expires_at - now <= warn_days * DAY:
        soon.append(f"expires in {(meta.expires_at - now) / DAY:.0f}d")
    if due is not None and due - now <= warn_days * DAY:
        soon.append(f"rotation due in {(due - now) / DAY:.0f}d")
    if soon:
        return "rotate-soon", ", ".join(soon)
    if meta.rotate_after_days and not meta.updated:
        return "ok", "age unknown"
    return "ok", ""


def _user_match(user: str | None, patterns: list[str]) -> bool:
    return bool(user) and any(fnmatch.fnmatch(user.lower(), p.lower()) for p in patterns)


TEAM_PREFIX = "team:"
GROUP_PREFIX = "group:"


@dataclass(frozen=True)
class Principal:
    """A run user and the teams / SSO groups it belongs to, for `team:` and `group:` entries.

    teams: lower-case names of the portal.teams teams the user is in. groups:
    lower-case SSO groups as last seen by the portal, or None when the run has
    no SSO identity (CLI and scheduled runs, or local portal sign-in): then
    `group:` entries match nobody. known_teams: every team in portal.teams; a
    `team:` entry naming any other team grants nothing (fail closed).
    """

    user: str
    teams: frozenset[str] = frozenset()
    groups: frozenset[str] | None = None
    known_teams: frozenset[str] = frozenset()
    source: str = ""


def _has_group_entries(meta: SecretMeta) -> bool:
    return any(e.lower().startswith((TEAM_PREFIX, GROUP_PREFIX)) for e in (*meta.owners, *meta.users))


def principal_for(settings: Settings | None, user: str | None, source: str = "", groups=None) -> Principal:
    """Resolve a run user to teams exactly as the portal does (portal/teams.py):
    config members and reviewers, plus SSO-group members (last-seen groups in
    workspace/portal_sso_groups.json) when `source` is "portal" and the portal
    signs in with oidc / trusted_header. CLI and scheduled runs: config only.
    `groups` (the run's own SSO groups) overrides the last-seen record."""
    user = str(user or "")
    if settings is None:
        return Principal(user, source=source)
    try:
        from .portal.teams import SsoGroupDirectory, Teams

        portal = settings.data.get("portal") or {}
        mode = (portal.get("auth") or {}).get("mode", "local")
        sso = source == "portal" and mode in ("oidc", "trusted_header")
        if sso and groups is None:
            groups = SsoGroupDirectory(settings.workspace_root / "portal_sso_groups.json").get(user) if user else []
        teams = Teams(portal.get("teams"), groups_of=(lambda _u: groups or []) if sso else None)
        mine = teams.teams_of(user, groups if sso else None) if user else []
        return Principal(user, frozenset(t.lower() for t in mine), frozenset(str(g).lower() for g in groups or []) if sso else None,
                         frozenset(t.lower() for t in teams.teams), source)
    except Exception:  # noqa: BLE001 - a broken team config grants no team access (fail closed)
        return Principal(user, source=source)


def share_check(principal: Principal, entries: list[str]) -> tuple[bool, list[str]]:
    """(matched, problems). problems explain entries that could not grant anything."""
    problems: list[str] = []
    for raw in entries:
        e = raw.strip().lower()
        if e.startswith(TEAM_PREFIX):
            name = e[len(TEAM_PREFIX):]
            if name not in principal.known_teams:
                problems.append(f"team '{name}' is not in portal.teams")
            elif name in principal.teams:
                return True, problems
        elif e.startswith(GROUP_PREFIX):
            g = e[len(GROUP_PREFIX):]
            if principal.groups is None:
                problems.append(f"group '{g}' needs SSO groups, which only portal runs with SSO sign-in have")
            elif g and g in principal.groups:
                return True, problems
        elif _user_match(principal.user, [e]):
            return True, problems
    return False, problems


def _principal(user, principal: Principal | None) -> Principal:
    return principal if principal is not None else Principal(str(user or ""))


def user_allowed(user: str | None, meta: SecretMeta, principal: Principal | None = None) -> bool:
    """Owners and users are fnmatch patterns (case-insensitive), `team:` or `group:` entries. Both empty = any user."""
    if not meta.owners and not meta.users:
        return True
    return share_check(_principal(user, principal), [*meta.owners, *meta.users])[0]


def is_owner(user: str | None, meta: SecretMeta, principal: Principal | None = None) -> bool:
    """No owners = anyone who can reach the store may manage it."""
    return not meta.owners or share_check(_principal(user, principal), meta.owners)[0]


def check_share_entries(settings: Settings | None, entries: list[str]) -> list[str]:
    """Warnings for `team:` / `group:` entries that cannot grant anything with this config."""
    portal = (settings.data.get("portal") or {}) if settings is not None else {}
    teams_cfg = portal.get("teams") if isinstance(portal.get("teams"), dict) else {}
    teams = {str(t).lower() for t in teams_cfg}
    sso_groups = {str(g).lower() for t in teams_cfg.values() if isinstance(t, dict) for k in ("sso_groups", "sso_reviewer_groups") for g in (t.get(k) or [])}
    mode = (portal.get("auth") or {}).get("mode", "local")
    out = []
    for raw in entries:
        e = raw.strip().lower()
        if e.startswith(TEAM_PREFIX) and e[len(TEAM_PREFIX):] not in teams:
            out.append(f"team '{e[len(TEAM_PREFIX):]}' is not in portal.teams; this entry grants nothing until it is")
        elif e.startswith(GROUP_PREFIX):
            g = e[len(GROUP_PREFIX):]
            if mode not in ("oidc", "trusted_header"):
                out.append(f"group '{g}': portal.auth.mode is {mode!r}, so no run has SSO groups; this entry grants nothing")
            elif g not in sso_groups:
                out.append(f"group '{g}' is not in any portal.teams sso_groups / sso_reviewer_groups; the portal does not record it, so this entry grants nothing")
    return out


def _check_entry_syntax(entries: list[str]) -> None:
    for raw in entries:
        e = raw.strip().lower()
        for pre in (TEAM_PREFIX, GROUP_PREFIX):
            if e.startswith(pre) and not e[len(pre):].strip():
                raise VaultError(f"sharing entry {raw!r} names no {pre[:-1]}")
        if "," in e:
            raise VaultError(f"sharing entry {raw!r} may not contain a comma")


def parse_when(value: str) -> float:
    """YYYY-MM-DD (local midnight) or an ISO 8601 time -> epoch seconds."""
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as e:
        raise VaultError(f"cannot read the date {value!r}: use YYYY-MM-DD or an ISO 8601 time") from e
    return dt.timestamp()


def _norm_list(v) -> list[str]:
    return [x.strip().lower() for x in (v or []) if x and x.strip()]


def _num(v) -> float | None:
    if v in (None, ""):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f > 0 else None


def check_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise VaultError(f"invalid secret name {name!r}: use letters, digits, '_', '.', '-' (max 64)")
    return name


def vault_dir(settings: Settings) -> Path:
    return settings.path(settings.data.get("vault", {}).get("path", "./workspace/vault"))


# --------------------------------------------------------------------------- DPAPI

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(data: bytes, entropy: bytes = b"", description: str = "analyst_agent secret") -> bytes:
    """CryptProtectData with CURRENT_USER scope (no CRYPTPROTECT_LOCAL_MACHINE)."""
    if sys.platform != "win32":
        raise VaultError("the dpapi backend needs Windows; use vault.backend 'env' or 'keyring'")
    inp, _keep1 = _blob(data)
    ent, _keep2 = _blob(entropy)
    out = DATA_BLOB()
    if not _crypt32.CryptProtectData(ctypes.byref(inp), description, ctypes.byref(ent) if entropy else None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise VaultError(f"CryptProtectData failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def dpapi_unprotect(blob: bytes, entropy: bytes = b"") -> bytes:
    if sys.platform != "win32":
        raise VaultError("the dpapi backend needs Windows")
    inp, _keep1 = _blob(blob)
    ent, _keep2 = _blob(entropy)
    out = DATA_BLOB()
    if not _crypt32.CryptUnprotectData(ctypes.byref(inp), None, ctypes.byref(ent) if entropy else None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise VaultError(f"CryptUnprotectData failed (error {ctypes.get_last_error()}): wrong user, or the entry was edited")
    try:
        raw = ctypes.string_at(out.pbData, out.cbData)
        ctypes.memset(out.pbData, 0, out.cbData)
        return raw
    finally:
        _kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


# --------------------------------------------------------------------------- backends


class _FileMeta:
    """vault.json: metadata (and, for dpapi, the encrypted blob) per secret."""

    def __init__(self, folder: Path, backend: str):
        self.folder = folder
        self.file = folder / "vault.json"
        self.backend = backend

    def load(self) -> dict:
        if not self.file.exists():
            return {"version": 1, "backend": self.backend, "secrets": {}}
        data = json.loads(self.file.read_text(encoding="utf-8"))
        if data.get("backend") not in (None, self.backend):
            raise VaultError(f"{self.file} belongs to backend {data.get('backend')!r}, not {self.backend!r}")
        return data

    def save(self, data: dict) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        tmp.replace(self.file)

    @staticmethod
    def meta(name: str, rec: dict, backend: str) -> SecretMeta:
        return SecretMeta(name, list(rec.get("allow_hosts", [])), list(rec.get("allow_apps", [])), rec.get("created", 0.0), rec.get("updated", 0.0), backend,
                          list(rec.get("owners", [])), list(rec.get("users", [])), _num(rec.get("rotate_after_days")), _num(rec.get("expires_at")), rec.get("version"))

    @staticmethod
    def policy_fields(allow_hosts, allow_apps, owners, users, rotate_after_days, expires_at) -> dict:
        rec = {"allow_hosts": _norm_list(allow_hosts), "allow_apps": _norm_list(allow_apps)}
        extra = {"owners": _norm_list(owners), "users": _norm_list(users), "rotate_after_days": _num(rotate_after_days), "expires_at": _num(expires_at)}
        rec.update({k: v for k, v in extra.items() if v})  # absent when unset: older records keep their exact shape
        return rec


_KEEP = object()


class Vault:
    backend = "base"
    read_only = False
    supports_versions = False  # rotate keeps the previous value and rollback restores it

    def list(self) -> list[SecretMeta]:
        raise NotImplementedError

    def meta(self, name: str) -> SecretMeta:
        for m in self.list():
            if m.name == name:
                return m
        raise VaultError(f"no secret named {name!r}")

    def get(self, name: str) -> str:
        raise NotImplementedError

    def set(self, name: str, value: str, allow_hosts: list[str] | None = None, allow_apps: list[str] | None = None, *,
            owners: list[str] | None = None, users: list[str] | None = None, rotate_after_days: float | None = None, expires_at: float | None = None) -> SecretMeta:
        raise VaultError(f"the {self.backend} backend is read-only")

    def remove(self, name: str) -> None:
        raise VaultError(f"the {self.backend} backend is read-only")

    def rotate(self, name: str, value: str, expires_at=_KEEP) -> SecretMeta:
        """New value, same allowlists and sharing. Versioned backends keep the previous value."""
        pol = self.meta(name).policy()
        if expires_at is not _KEEP:
            pol["expires_at"] = expires_at
        return self.set(name, value, **pol)

    def rollback(self, name: str) -> SecretMeta:
        raise VaultError(f"the {self.backend} backend keeps no previous versions; set the old value again with `vault rotate`")

    def update_sharing(self, name: str, owners: list[str], users: list[str]) -> SecretMeta:
        """Change owners/users only: the value, its age (rotation clock) and versions stay."""
        raise VaultError(f"the {self.backend} backend is read-only")


def _validate_value(value: str) -> None:
    if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
        raise VaultError(f"secret values must be at least {MIN_SECRET_LEN} characters (shorter values cannot be redacted safely)")


class DpapiVault(Vault):
    backend = "dpapi"

    def __init__(self, folder: Path, extra_entropy: bytes = b""):
        self.store = _FileMeta(folder, self.backend)
        self.extra_entropy = extra_entropy

    supports_versions = True  # one previous value

    def _entropy(self, name: str, rec: dict) -> bytes:
        """Binds the blob to its name, allowlists and (when set) sharing and expiry,
        so widening any of them by editing vault.json breaks decryption. A record
        without the newer fields gives the same entropy as before they existed."""
        b = {"hosts": sorted(rec.get("allow_hosts", [])), "apps": sorted(rec.get("allow_apps", []))}
        for k in ("owners", "users"):
            if rec.get(k):
                b[k] = sorted(rec[k])
        for k in ("rotate_after_days", "expires_at"):
            if rec.get(k):
                b[k] = repr(float(rec[k]))
        bound = json.dumps(b, sort_keys=True)
        return b"analyst_agent/vault/v1\0" + name.encode() + b"\0" + bound.encode() + b"\0" + self.extra_entropy

    def list(self) -> list[SecretMeta]:
        return [_FileMeta.meta(n, r, self.backend) for n, r in sorted(self.store.load()["secrets"].items())]

    def get(self, name: str) -> str:
        rec = self.store.load()["secrets"].get(name)
        if rec is None:
            raise VaultError(f"no secret named {name!r}")
        return dpapi_unprotect(base64.b64decode(rec["blob"]), self._entropy(name, rec)).decode("utf-8")

    def set(self, name, value, allow_hosts=None, allow_apps=None, *, owners=None, users=None, rotate_after_days=None, expires_at=None, _previous=None):
        check_name(name)
        _validate_value(value)
        rec = _FileMeta.policy_fields(allow_hosts, allow_apps, owners, users, rotate_after_days, expires_at)
        data = self.store.load()
        now = time.time()
        old = data["secrets"].get(name, {})
        blob = dpapi_protect(value.encode("utf-8"), self._entropy(name, rec), f"analyst_agent:{name}")
        rec = {"blob": base64.b64encode(blob).decode(), **rec, "created": old.get("created", now), "updated": now}
        if _previous is not None:
            rec["version"] = int(old.get("version") or 1) + 1
            rec["previous"] = _previous
        data["secrets"][name] = rec
        self.store.save(data)
        return _FileMeta.meta(name, rec, self.backend)

    def _snapshot(self, name: str) -> dict:
        rec = dict(self.store.load()["secrets"].get(name) or {})
        if not rec:
            raise VaultError(f"no secret named {name!r}")
        rec.pop("previous", None)  # keep one previous value, not a chain
        return rec

    def rotate(self, name, value, expires_at=_KEEP):
        prev = self._snapshot(name)
        pol = _FileMeta.meta(name, prev, self.backend).policy()
        if expires_at is not _KEEP:
            pol["expires_at"] = expires_at
        return self.set(name, value, **pol, _previous=prev)

    def rollback(self, name):
        cur = self._snapshot(name)
        prev = self.store.load()["secrets"][name].get("previous")
        if not prev:
            raise VaultError(f"secret {name!r} has no previous value to roll back to")
        old_value = dpapi_unprotect(base64.b64decode(prev["blob"]), self._entropy(name, prev)).decode("utf-8")
        return self.set(name, old_value, **_FileMeta.meta(name, cur, self.backend).policy(), _previous=cur)

    def remove(self, name):
        data = self.store.load()
        if data["secrets"].pop(name, None) is None:
            raise VaultError(f"no secret named {name!r}")
        self.store.save(data)

    def update_sharing(self, name, owners, users):
        data = self.store.load()
        rec = data["secrets"].get(name)
        if rec is None:
            raise VaultError(f"no secret named {name!r}")
        value = dpapi_unprotect(base64.b64decode(rec["blob"]), self._entropy(name, rec))  # the old binding must still verify
        pol = {**_FileMeta.meta(name, rec, self.backend).policy(), "owners": owners, "users": users}
        new = _FileMeta.policy_fields(**pol)
        blob = dpapi_protect(value, self._entropy(name, new), f"analyst_agent:{name}")
        keep = {k: rec[k] for k in ("created", "updated", "version", "previous") if k in rec}
        data["secrets"][name] = {"blob": base64.b64encode(blob).decode(), **new, **keep}
        self.store.save(data)
        return _FileMeta.meta(name, data["secrets"][name], self.backend)


class EnvVault(Vault):
    backend = "env"
    read_only = True

    def __init__(self, prefix: str = "AGENT_SECRET_", environ: dict | None = None):
        self.prefix = prefix
        self.environ = os.environ if environ is None else environ

    def _key(self, name: str) -> str:
        return self.prefix + re.sub(r"[^A-Za-z0-9]", "_", name).upper()

    @staticmethod
    def _split(v: str | None) -> list[str]:
        return [x.strip().lower() for x in (v or "").split(",") if x.strip()]

    def list(self) -> list[SecretMeta]:
        out = []
        for k in sorted(self.environ):
            if k.startswith(self.prefix) and "__" not in k[len(self.prefix):]:
                out.append(self._meta(k[len(self.prefix):].lower(), k))
        return out

    def _meta(self, name: str, k: str) -> SecretMeta:
        e = self.environ

        def when(suffix):
            v = e.get(k + suffix)
            return parse_when(v) if v else 0.0

        return SecretMeta(name, self._split(e.get(k + "__HOSTS")), self._split(e.get(k + "__APPS")), updated=when("__UPDATED"), backend=self.backend,
                          owners=self._split(e.get(k + "__OWNERS")), users=self._split(e.get(k + "__USERS")),
                          rotate_after_days=_num(e.get(k + "__ROTATE_AFTER_DAYS")), expires_at=when("__EXPIRES_AT") or None)

    def meta(self, name: str) -> SecretMeta:
        k = self._key(name)
        if k not in self.environ:
            raise VaultError(f"no secret named {name!r} (expected environment variable {k})")
        return self._meta(name, k)

    def get(self, name: str) -> str:
        k = self._key(name)
        if k not in self.environ:
            raise VaultError(f"no secret named {name!r} (expected environment variable {k})")
        return self.environ[k]


class KeyringVault(Vault):
    backend = "keyring"
    SERVICE = "analyst_agent"

    def __init__(self, folder: Path):
        import keyring  # noqa: F401 - only constructed when importable

        self.keyring = keyring
        self.store = _FileMeta(folder, self.backend)

    def list(self):
        return [_FileMeta.meta(n, r, self.backend) for n, r in sorted(self.store.load()["secrets"].items())]

    def get(self, name):
        self.meta(name)
        value = self.keyring.get_password(self.SERVICE, name)
        if value is None:
            raise VaultError(f"secret {name!r} is missing from the OS keyring")
        return value

    def set(self, name, value, allow_hosts=None, allow_apps=None, *, owners=None, users=None, rotate_after_days=None, expires_at=None):
        check_name(name)
        _validate_value(value)
        data = self.store.load()
        now = time.time()
        old = data["secrets"].get(name, {})
        self.keyring.set_password(self.SERVICE, name, value)
        data["secrets"][name] = {**_FileMeta.policy_fields(allow_hosts, allow_apps, owners, users, rotate_after_days, expires_at), "created": old.get("created", now), "updated": now}
        self.store.save(data)
        return _FileMeta.meta(name, data["secrets"][name], self.backend)

    def remove(self, name):
        data = self.store.load()
        if data["secrets"].pop(name, None) is None:
            raise VaultError(f"no secret named {name!r}")
        try:
            self.keyring.delete_password(self.SERVICE, name)
        except Exception:
            pass
        self.store.save(data)

    def update_sharing(self, name, owners, users):
        data = self.store.load()
        rec = data["secrets"].get(name)
        if rec is None:
            raise VaultError(f"no secret named {name!r}")
        pol = {**_FileMeta.meta(name, rec, self.backend).policy(), "owners": owners, "users": users}
        data["secrets"][name] = {**_FileMeta.policy_fields(**pol), **{k: rec[k] for k in ("created", "updated") if k in rec}}
        self.store.save(data)
        return _FileMeta.meta(name, data["secrets"][name], self.backend)


def open_vault(settings: Settings) -> Vault:
    cfg = settings.data.get("vault", {})
    backend = cfg.get("backend", "dpapi")
    if backend == "dpapi":
        env_name = cfg.get("entropy_env") or ""
        extra = os.environ.get(env_name, "") if env_name else ""
        return DpapiVault(vault_dir(settings), extra.encode())
    if backend == "env":
        return EnvVault(cfg.get("env_prefix", "AGENT_SECRET_"))
    if backend == "keyring":
        try:
            return KeyringVault(vault_dir(settings))
        except ImportError as e:
            raise VaultError("vault.backend is 'keyring' but the keyring package is not installed") from e
    if backend in ("hashicorp", "azure_keyvault"):
        from .vault_remote import open_remote

        return open_remote(backend, cfg.get(backend) or {})
    raise VaultError(f"unknown vault backend {backend!r} (use dpapi, env, keyring, hashicorp or azure_keyvault)")


def run_user(ctx) -> str:
    """The user a run acts for: ToolContext.user if a caller set one, else the audit log's user
    (the orchestrator's `user`: the portal login, `schedule:<owner>`, or "analyst" on the CLI)."""
    return str(getattr(ctx, "user", None) or getattr(getattr(ctx, "audit", None), "user", "") or "")


def run_principal(ctx, user: str) -> Principal:
    """Teams of the run's user. ToolContext.user_source says where the run came from
    ("portal", "schedule", "cli"); only portal runs use SSO groups. Cached on the context."""
    cached = getattr(ctx, "_vault_principal", None)
    if isinstance(cached, Principal) and cached.user == user:
        return cached
    p = principal_for(getattr(ctx, "settings", None), user, str(getattr(ctx, "user_source", "") or ""), getattr(ctx, "user_groups", None))
    try:
        ctx._vault_principal = p
    except Exception:
        pass
    return p


# --------------------------------------------------------------------------- resolution


def has_placeholder(text) -> bool:
    return isinstance(text, str) and bool(PLACEHOLDER_RE.search(text))


def _match(value: str, patterns: list[str]) -> bool:
    return bool(value) and any(fnmatch.fnmatch(value.lower(), p.lower()) for p in patterns)


def _vault_for(ctx: "ToolContext") -> Vault:
    v = getattr(ctx, "vault", None)
    if v is None:
        v = open_vault(ctx.settings)
        try:
            ctx.vault = v  # cache on the context (plain dataclass)
        except Exception:
            pass
    return v


def resolve_secrets(text: str, ctx: "ToolContext", *, tool: str, url: str | None = None, app: str | None = None, window: str | None = None) -> str:
    """Replace {{secret:name}} placeholders for one typing/filling action.

    url: the page the value goes to (browser). app/window: the exe name and
    window title that receive it (desktop tiers; the caller has already
    checked them against the policy). Raises SecretRefused when any secret is
    not allowed for the target; nothing is typed in that case.
    """
    names = list(dict.fromkeys(PLACEHOLDER_RE.findall(text or "")))
    if not names:
        return text
    target = {"url": url} if url else {"app": app, "window": window}
    vault = _vault_for(ctx)
    user = run_user(ctx)
    values: dict[str, str] = {}
    for name in names:
        try:
            meta = vault.meta(name)
            if meta.owners or meta.users:
                principal = run_principal(ctx, user) if _has_group_entries(meta) else Principal(user)
                ok, problems = share_check(principal, [*meta.owners, *meta.users])
                if not ok:
                    why = f"; {'; '.join(problems)}" if problems else ""
                    teams = f", teams: {', '.join(sorted(principal.teams))}" if principal.teams else ""
                    raise SecretDenied(f"secret '{name}' is not shared with user '{user or '?'}'{teams} (owners: {meta.owners or 'none'}, users: {meta.users or 'none'}){why}")
            status, detail = secret_status(meta)
            if status == "expired":
                raise SecretExpired(f"secret '{name}' has expired ({detail}); rotate it with `vault rotate {name}`")
            if url is not None:
                host = (urlparse(url).hostname or "").lower()
                ctx.policy.check_url(url)  # policy allowlist
                if not _match(host, meta.allow_hosts):
                    raise SecretRefused(f"secret '{name}' is not allowed for host {host or '?'} (its hosts: {meta.allow_hosts or 'none'})")
            elif app or window:
                if not (_match(app or "", meta.allow_apps) or _match(window or "", meta.allow_apps)):
                    raise SecretRefused(f"secret '{name}' is not allowed for window '{window}' ({app or 'unknown exe'}); its apps: {meta.allow_apps or 'none'}")
            else:
                raise SecretRefused(f"secret '{name}' needs a known target host or window")
            value = vault.get(name)
            if len(value) < MIN_SECRET_LEN:
                raise SecretRefused(f"secret '{name}' is shorter than {MIN_SECRET_LEN} characters and cannot be redacted safely")
        except (VaultError, PolicyViolation) as e:
            kind = getattr(e, "audit_kind", "secret_refused")
            extra = {"user": user} if kind == "secret_denied" else {}
            ctx.audit.event(kind, step=ctx.step_id, name=name, tool=tool, reason=str(e)[:300], **extra, **target)
            if isinstance(e, SecretRefused):
                raise
            raise SecretRefused(f"secret '{name}' cannot be used: {e}") from None
        redactor = getattr(ctx.audit, "redactor", None)
        if redactor is not None:
            redactor.add(name, value)
        values[name] = value
    for name in names:
        ctx.audit.event("secret_used", step=ctx.step_id, name=name, tool=tool, **target)
    return PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], text)


# --------------------------------------------------------------------------- CLI


def _add_expiry_args(p) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--expires-at", metavar="DATE", help="YYYY-MM-DD or ISO time after which the secret is refused")
    g.add_argument("--expires-in-days", type=float, metavar="N", help="expire N days from now")


def add_cli(sub) -> None:
    """Register `vault set|list|check|rotate|rollback|remove` on an argparse subparsers object."""
    v = sub.add_parser("vault", help="manage credentials for {{secret:name}} placeholders")
    vs = v.add_subparsers(dest="vault_cmd", required=True)
    s = vs.add_parser("set", help="store a secret (value is prompted, never taken from the command line)")
    s.add_argument("name")
    s.add_argument("--allow-host", action="append", default=[], metavar="HOST", help="host pattern the secret may be typed into (repeatable)")
    s.add_argument("--allow-app", action="append", default=[], metavar="APP", help="exe or window-title pattern for desktop tiers (repeatable)")
    s.add_argument("--owner", action="append", default=[], metavar="USER", help="run user who may use and manage it (repeatable, fnmatch, team:<name> or group:<sso-group>)")
    s.add_argument("--user", action="append", default=[], metavar="USER", help="run user who may use it (repeatable, fnmatch, team:<name> or group:<sso-group>); no --owner/--user = any user")
    s.add_argument("--rotate-after-days", type=float, metavar="N", help="flag the secret for rotation N days after its value was set")
    _add_expiry_args(s)
    vs.add_parser("list", help="list secret names, allowlists, sharing, age and status (never values)")
    c = vs.add_parser("check", help="exit 1 if any secret is expired or due for rotation (for a scheduled task)")
    c.add_argument("--warn-days", type=float, default=7.0, help="report rotate-soon this many days ahead (default 7)")
    sh = vs.add_parser("share", help="change who may use or manage a secret (value, age and versions unchanged); no options = show it")
    sh.add_argument("name")
    for flag, what in (("add-owner", "add an owner"), ("remove-owner", "remove an owner"), ("add-user", "add a user"), ("remove-user", "remove a user")):
        sh.add_argument(f"--{flag}", action="append", default=[], metavar="ENTRY", help=f"{what}: user pattern, team:<name> or group:<sso-group> (repeatable)")
    r = vs.add_parser("rotate", help="prompt for a new value (or --generate one); keeps allowlists and sharing (and the previous value where the backend has versions)")
    r.add_argument("name")
    r.add_argument("--generate", action="store_true", help="store a new random value from `secrets` instead of prompting; changes the STORED value only, not the target system")
    r.add_argument("--length", type=int, metavar="N", help=f"length of the generated value ({GEN_MIN_LEN}-{GEN_MAX_LEN}, default {GEN_DEFAULT_LEN})")
    r.add_argument("--show", action="store_true", help="print the generated value once (it then sits in your terminal scrollback)")
    _add_expiry_args(r)
    rb = vs.add_parser("rollback", help="restore the previous value (versioned backends only)")
    rb.add_argument("name")
    rm = vs.add_parser("remove", help="delete a secret")
    rm.add_argument("name")


GEN_MIN_LEN, GEN_DEFAULT_LEN, GEN_MAX_LEN = 12, 24, 256
GEN_SYMBOLS = "!#%+-=?@^_~"  # no quotes, backslash, spaces or shell/fnmatch specials


def generate_value(length: int = GEN_DEFAULT_LEN) -> str:
    """A random value from `secrets`: letters, digits and symbols, at least one of each."""
    if not GEN_MIN_LEN <= int(length) <= GEN_MAX_LEN:
        raise VaultError(f"--length must be between {GEN_MIN_LEN} and {GEN_MAX_LEN}")
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, GEN_SYMBOLS)
    alphabet = "".join(classes)
    while True:
        v = "".join(_secrets.choice(alphabet) for _ in range(int(length)))
        if all(any(c in cls for c in v) for cls in classes):
            return v


def check_secrets(vault: Vault, now: float | None = None, warn_days: float = 7.0) -> list[tuple[SecretMeta, str, str]]:
    """(meta, status, detail) for every secret; never reads a value. Raises VaultError if the store fails."""
    now = time.time() if now is None else now
    return [(m, *secret_status(m, now, warn_days)) for m in vault.list()]


FAILING_STATUSES = ("expired", "rotate-due")


def _expiry_from(args, keep):
    if getattr(args, "expires_at", None):
        return parse_when(args.expires_at)
    if getattr(args, "expires_in_days", None):
        return time.time() + args.expires_in_days * DAY
    return keep


def _ago(ts: float, now: float) -> str:
    if not ts:
        return "?"
    d = (now - ts) / DAY
    return f"{d:.0f}d" if d >= 1 else f"{(now - ts) / 3600:.0f}h"


def _line(m: SecretMeta, now: float, warn_days: float = 7.0) -> str:
    status, detail = secret_status(m, now, warn_days)
    parts = [f"{m.name:<24}", f"status={status}" + (f" ({detail})" if detail else ""), f"age={_ago(m.updated, now)}",
             f"hosts={','.join(m.allow_hosts) or '-'}", f"apps={','.join(m.allow_apps) or '-'}"]
    if m.owners or m.users:
        parts.append(f"owners={','.join(m.owners) or '-'} users={','.join(m.users) or '-'}")
    if m.rotate_after_days:
        parts.append(f"rotate_after={m.rotate_after_days:g}d")
    if m.expires_at:
        parts.append(f"expires={time.strftime('%Y-%m-%d', time.localtime(m.expires_at))}")
    if m.version:
        parts.append(f"v{m.version}")
    parts.append(f"backend={m.backend}")
    return "  ".join(parts)


def cli_actor() -> str:
    """Who runs the vault CLI: AGENT_USER if set, else the OS account name."""
    import getpass

    try:
        return os.environ.get("AGENT_USER") or getpass.getuser()
    except Exception:
        return ""


def _ask_twice(ask, name: str) -> str:
    value = ask(f"value for {name}: ")
    if value != ask(f"repeat value for {name}: "):
        raise VaultError("the two values differ; nothing stored")
    return value


def run_cli(args, settings: Settings, getpass_fn=None, out=print, vault: Vault | None = None, actor: str | None = None) -> int:
    import getpass

    ask = getpass_fn or getpass.getpass
    try:
        vault = vault or open_vault(settings)
        now = time.time()
        actor = cli_actor() if actor is None else actor

        def owned(name: str) -> SecretMeta:
            m = vault.meta(name)
            principal = principal_for(settings, actor, "cli") if _has_group_entries(m) else Principal(actor or "")
            if not is_owner(actor, m, principal):
                raise VaultError(f"'{actor or '?'}' is not an owner of {name!r} (owners: {', '.join(m.owners)}); set AGENT_USER if you are")
            return m

        def warn_entries(entries: list[str]) -> None:
            _check_entry_syntax(entries)
            for w in check_share_entries(settings, entries):
                out(f"warning: {w}")

        if args.vault_cmd == "list":
            items = vault.list()
            if not items:
                out(f"no secrets ({vault.backend} backend)")
            for m in items:
                out(_line(m, now))
            return 0
        if args.vault_cmd == "check":
            rows = check_secrets(vault, now, args.warn_days)
            bad = 0
            for m, status, _ in rows:
                if status != "ok":
                    out(_line(m, now, args.warn_days))
                bad += status in FAILING_STATUSES
            out(f"{len(rows)} secrets, {bad} expired or due for rotation ({vault.backend} backend)")
            return 1 if bad else 0
        if args.vault_cmd == "set":
            check_name(args.name)
            if vault.read_only:
                raise VaultError(f"the {vault.backend} backend is read-only; set the environment variables instead")
            try:
                existing = vault.meta(args.name)
            except VaultError:
                existing = None
            if existing is not None and not is_owner(actor, existing):  # overwriting needs ownership
                owned(args.name)
            warn_entries([*args.owner, *args.user])
            if not args.allow_host and not args.allow_app:
                out("warning: no --allow-host or --allow-app given; the secret cannot be used until you set it again with one")
            value = _ask_twice(ask, args.name)
            m = vault.set(args.name, value, args.allow_host, args.allow_app, owners=args.owner, users=args.user,
                          rotate_after_days=args.rotate_after_days, expires_at=_expiry_from(args, None))
            out(f"stored {m.name} ({m.backend}) hosts={m.allow_hosts} apps={m.allow_apps}" + (f" owners={m.owners} users={m.users}" if m.owners or m.users else ""))
            return 0
        if args.vault_cmd == "rotate":
            if vault.read_only:
                raise VaultError(f"the {vault.backend} backend is read-only; change the environment variable and its __UPDATED date instead")
            m = owned(args.name)
            if not args.generate and (args.length is not None or args.show):
                raise VaultError("--length and --show need --generate")
            value = generate_value(args.length or GEN_DEFAULT_LEN) if args.generate else _ask_twice(ask, args.name)
            if value == vault.get(args.name):
                raise VaultError("the new value is the same as the current one; nothing changed")
            expires = _expiry_from(args, _KEEP)
            if expires is _KEEP and m.expires_at and m.expires_at <= now:
                expires = None
                out("note: the old expiry has passed and was cleared; give --expires-at or --expires-in-days to set a new one")
            m = vault.rotate(args.name, value, expires)
            out(f"rotated {m.name} ({m.backend})" + (f" now v{m.version}" if m.version else "") + ("; previous value kept for `vault rollback`" if vault.supports_versions else "; this backend keeps no previous value"))
            if args.generate:
                out(f"generated a {len(value)}-character value. Only the STORED value changed: set the same value on the target system "
                    f"(or `vault rollback {m.name}`), or runs that type {{{{secret:{m.name}}}}} will fail to sign in.")
                if args.show:
                    out("warning: printing the generated value; it stays in your terminal scrollback and any captured output")
                    out(value)
                else:
                    out("the value is not shown (use --show to print it once)")
            return 0
        if args.vault_cmd == "share":
            m = owned(args.name)
            if not (args.add_owner or args.remove_owner or args.add_user or args.remove_user):
                out(f"{m.name}: owners={','.join(m.owners) or '-'} users={','.join(m.users) or '-'}" + ("" if m.owners or m.users else " (any run user may use it)"))
                return 0
            if vault.read_only:
                raise VaultError(f"the {vault.backend} backend is read-only; change {m.name}'s __OWNERS / __USERS variables instead")
            warn_entries([*args.add_owner, *args.add_user])

            def edit(cur: list[str], add: list[str], remove: list[str]) -> list[str]:
                drop = {x.strip().lower() for x in remove}
                missing = sorted(drop - set(cur))
                if missing:
                    raise VaultError(f"not in the list: {', '.join(missing)}")
                return [x for x in dict.fromkeys([*cur, *(a.strip().lower() for a in add if a.strip())]) if x not in drop]

            owners = edit(m.owners, args.add_owner, args.remove_owner)
            users = edit(m.users, args.add_user, args.remove_user)
            if m.owners and not owners:
                out("note: the secret has no owners now, so anyone who can reach the store may manage it")
            m = vault.update_sharing(args.name, owners, users)
            out(f"shared {m.name}: owners={','.join(m.owners) or '-'} users={','.join(m.users) or '-'}" + ("" if m.owners or m.users else " (any run user may use it)"))
            return 0
        if args.vault_cmd == "rollback":
            owned(args.name)
            m = vault.rollback(args.name)
            out(f"rolled back {m.name} to its previous value ({m.backend})" + (f", now v{m.version}" if m.version else ""))
            return 0
        if args.vault_cmd == "remove":
            owned(args.name)
            vault.remove(args.name)
            out(f"removed {args.name}")
            return 0
    except VaultError as e:
        out(f"error: {e}")
        return 1
    return 2
