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


@dataclass
class SecretMeta:
    name: str
    allow_hosts: list[str] = field(default_factory=list)
    allow_apps: list[str] = field(default_factory=list)
    created: float = 0.0
    updated: float = 0.0
    backend: str = ""

    def public(self) -> dict:
        return asdict(self)


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
        return SecretMeta(name, list(rec.get("allow_hosts", [])), list(rec.get("allow_apps", [])), rec.get("created", 0.0), rec.get("updated", 0.0), backend)


class Vault:
    backend = "base"
    read_only = False

    def list(self) -> list[SecretMeta]:
        raise NotImplementedError

    def meta(self, name: str) -> SecretMeta:
        for m in self.list():
            if m.name == name:
                return m
        raise VaultError(f"no secret named {name!r}")

    def get(self, name: str) -> str:
        raise NotImplementedError

    def set(self, name: str, value: str, allow_hosts: list[str] | None = None, allow_apps: list[str] | None = None) -> SecretMeta:
        raise VaultError(f"the {self.backend} backend is read-only")

    def remove(self, name: str) -> None:
        raise VaultError(f"the {self.backend} backend is read-only")


def _validate_value(value: str) -> None:
    if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
        raise VaultError(f"secret values must be at least {MIN_SECRET_LEN} characters (shorter values cannot be redacted safely)")


class DpapiVault(Vault):
    backend = "dpapi"

    def __init__(self, folder: Path, extra_entropy: bytes = b""):
        self.store = _FileMeta(folder, self.backend)
        self.extra_entropy = extra_entropy

    def _entropy(self, name: str, hosts: list[str], apps: list[str]) -> bytes:
        bound = json.dumps({"hosts": sorted(hosts), "apps": sorted(apps)}, sort_keys=True)
        return b"analyst_agent/vault/v1\0" + name.encode() + b"\0" + bound.encode() + b"\0" + self.extra_entropy

    def list(self) -> list[SecretMeta]:
        return [_FileMeta.meta(n, r, self.backend) for n, r in sorted(self.store.load()["secrets"].items())]

    def get(self, name: str) -> str:
        rec = self.store.load()["secrets"].get(name)
        if rec is None:
            raise VaultError(f"no secret named {name!r}")
        ent = self._entropy(name, rec.get("allow_hosts", []), rec.get("allow_apps", []))
        return dpapi_unprotect(base64.b64decode(rec["blob"]), ent).decode("utf-8")

    def set(self, name, value, allow_hosts=None, allow_apps=None):
        check_name(name)
        _validate_value(value)
        hosts, apps = [h.lower() for h in allow_hosts or []], [a.lower() for a in allow_apps or []]
        data = self.store.load()
        now = time.time()
        old = data["secrets"].get(name, {})
        blob = dpapi_protect(value.encode("utf-8"), self._entropy(name, hosts, apps), f"analyst_agent:{name}")
        data["secrets"][name] = {"blob": base64.b64encode(blob).decode(), "allow_hosts": hosts, "allow_apps": apps, "created": old.get("created", now), "updated": now}
        self.store.save(data)
        return _FileMeta.meta(name, data["secrets"][name], self.backend)

    def remove(self, name):
        data = self.store.load()
        if data["secrets"].pop(name, None) is None:
            raise VaultError(f"no secret named {name!r}")
        self.store.save(data)


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
            if k.startswith(self.prefix) and not k.endswith(("__HOSTS", "__APPS")):
                name = k[len(self.prefix):].lower()
                out.append(SecretMeta(name, self._split(self.environ.get(k + "__HOSTS")), self._split(self.environ.get(k + "__APPS")), backend=self.backend))
        return out

    def meta(self, name: str) -> SecretMeta:
        k = self._key(name)
        if k not in self.environ:
            raise VaultError(f"no secret named {name!r} (expected environment variable {k})")
        return SecretMeta(name, self._split(self.environ.get(k + "__HOSTS")), self._split(self.environ.get(k + "__APPS")), backend=self.backend)

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

    def set(self, name, value, allow_hosts=None, allow_apps=None):
        check_name(name)
        _validate_value(value)
        data = self.store.load()
        now = time.time()
        old = data["secrets"].get(name, {})
        self.keyring.set_password(self.SERVICE, name, value)
        data["secrets"][name] = {"allow_hosts": [h.lower() for h in allow_hosts or []], "allow_apps": [a.lower() for a in allow_apps or []], "created": old.get("created", now), "updated": now}
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
    raise VaultError(f"unknown vault backend {backend!r} (use dpapi, env or keyring)")


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
    values: dict[str, str] = {}
    for name in names:
        try:
            meta = vault.meta(name)
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
            ctx.audit.event("secret_refused", step=ctx.step_id, name=name, tool=tool, reason=str(e)[:300], **target)
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


def add_cli(sub) -> None:
    """Register `vault set|list|remove` on an argparse subparsers object."""
    v = sub.add_parser("vault", help="manage credentials for {{secret:name}} placeholders")
    vs = v.add_subparsers(dest="vault_cmd", required=True)
    s = vs.add_parser("set", help="store a secret (value is prompted, never taken from the command line)")
    s.add_argument("name")
    s.add_argument("--allow-host", action="append", default=[], metavar="HOST", help="host pattern the secret may be typed into (repeatable)")
    s.add_argument("--allow-app", action="append", default=[], metavar="APP", help="exe or window-title pattern for desktop tiers (repeatable)")
    vs.add_parser("list", help="list secret names and allowlists (never values)")
    r = vs.add_parser("remove", help="delete a secret")
    r.add_argument("name")


def run_cli(args, settings: Settings, getpass_fn=None, out=print) -> int:
    import getpass

    try:
        vault = open_vault(settings)
        if args.vault_cmd == "list":
            items = vault.list()
            if not items:
                out(f"no secrets ({vault.backend} backend)")
            for m in items:
                out(f"{m.name:<24} hosts={','.join(m.allow_hosts) or '-'}  apps={','.join(m.allow_apps) or '-'}  backend={m.backend}" + (f"  updated={time.strftime('%Y-%m-%d %H:%M', time.localtime(m.updated))}" if m.updated else ""))
            return 0
        if args.vault_cmd == "set":
            check_name(args.name)
            if vault.read_only:
                raise VaultError(f"the {vault.backend} backend is read-only; set the environment variables instead")
            if not args.allow_host and not args.allow_app:
                out("warning: no --allow-host or --allow-app given; the secret cannot be used until you set it again with one")
            ask = getpass_fn or getpass.getpass
            value = ask(f"value for {args.name}: ")
            if value != ask(f"repeat value for {args.name}: "):
                raise VaultError("the two values differ; nothing stored")
            m = vault.set(args.name, value, args.allow_host, args.allow_app)
            out(f"stored {m.name} ({m.backend}) hosts={m.allow_hosts} apps={m.allow_apps}")
            return 0
        if args.vault_cmd == "remove":
            vault.remove(args.name)
            out(f"removed {args.name}")
            return 0
    except VaultError as e:
        out(f"error: {e}")
        return 1
    return 2
