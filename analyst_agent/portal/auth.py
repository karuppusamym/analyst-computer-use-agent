"""Portal sign-in: local users, a trusted SSO proxy header, or OpenID Connect.

Everything here is standard library only:
- local users: PBKDF2-SHA256 password hashes in a JSON users file under workspace/.
- trusted_header: the user name comes from a header set by an SSO reverse proxy,
  and is only believed when the TCP peer is one of the configured proxy IPs.
- oidc: authorization-code flow with PKCE (S256) via urllib; the ID token's
  RS256 signature is checked against the issuer's JWKS in pure Python
  (RSASSA-PKCS1-v1_5 with SHA-256, using pow()), then iss/aud/exp/nonce.

Browser sessions are signed cookies (HMAC-SHA256, HttpOnly, SameSite=Strict)
with a secret generated into workspace/ on first run. Every POST carries a
CSRF token derived from the session cookie.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROLES = ("analyst", "reviewer", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}

PBKDF2_ITERATIONS = 600_000


class AuthError(Exception):
    pass


def role_at_least(role: str, needed: str) -> bool:
    return _RANK.get(role, -1) >= _RANK[needed]


@dataclass
class Identity:
    name: str
    role: str
    source: str = "local"
    # SSO groups from the ID token (captured at sign-in, kept in the signed session) or from the
    # trusted proxy's groups header. Never taken from a form or query. Empty for local users.
    groups: tuple[str, ...] = ()

    def can(self, needed: str) -> bool:
        return role_at_least(self.role, needed)


# --------------------------------------------------------------------------- helpers


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:  # pragma: no cover - best effort on Windows
        pass
    tmp.replace(path)


# --------------------------------------------------------------------------- passwords


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${b64url_encode(salt)}${b64url_encode(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b64url_decode(salt), int(iters))
        return hmac.compare_digest(got, b64url_decode(want))
    except (ValueError, TypeError):
        return False


# A fixed dummy hash so unknown user names take about as long as wrong passwords.
_dummy_hash: str | None = None


def _dummy() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("dummy-password", salt=b"\0" * 16)
    return _dummy_hash


class UserStore:
    """users.json: {"users": {"alice": {"role": "analyst", "password": "pbkdf2_sha256$..."}}}"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"users": {}}
        data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        data.setdefault("users", {})
        return data

    def users(self) -> dict[str, dict]:
        return self._load()["users"]

    def add(self, name: str, role: str, password: str, iterations: int = PBKDF2_ITERATIONS) -> None:
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        name = name.strip()
        if not name or any(c in name for c in " \t\r\n/\\<>\"'"):
            raise AuthError("user name must be non-empty and contain no spaces, slashes, quotes or angle brackets")
        if len(password) < 8:
            raise AuthError("password must be at least 8 characters")
        with self._lock:
            data = self._load()
            data["users"][name] = {"role": role, "password": hash_password(password, iterations), "updated_at": time.time()}
            _write_private(self.path, json.dumps(data, indent=1))

    def remove(self, name: str) -> bool:
        with self._lock:
            data = self._load()
            if data["users"].pop(name, None) is None:
                return False
            _write_private(self.path, json.dumps(data, indent=1))
            return True

    def authenticate(self, name: str, password: str) -> Identity | None:
        rec = self.users().get(name)
        if rec is None:
            verify_password(password, _dummy())
            return None
        if not verify_password(password, rec.get("password", "")):
            return None
        role = rec.get("role", "analyst")
        return Identity(name, role if role in ROLES else "analyst", "local")


# --------------------------------------------------------------------------- signed cookies


def load_or_create_secret(path: str | Path) -> bytes:
    p = Path(path)
    if p.exists():
        text = p.read_text(encoding="utf-8").strip()
        if len(text) >= 64:
            return bytes.fromhex(text)
    key = secrets.token_bytes(32)
    _write_private(p, key.hex())
    return key


class Signer:
    def __init__(self, key: bytes):
        self.key = key

    def sign(self, payload: dict) -> str:
        body = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        mac = hmac.new(self.key, body.encode("ascii"), hashlib.sha256).digest()
        return f"{body}.{b64url_encode(mac)}"

    def unsign(self, token: str | None) -> dict | None:
        if not token or token.count(".") != 1:
            return None
        body, mac = token.split(".")
        want = hmac.new(self.key, body.encode("ascii"), hashlib.sha256).digest()
        try:
            # Compare the canonical encoding, so a token has exactly one valid spelling
            # (non-canonical base64 could otherwise decode to the same MAC).
            if not hmac.compare_digest(b64url_encode(want), mac):
                return None
            data = json.loads(b64url_decode(body))
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict) or data.get("exp", 0) < time.time():
            return None
        return data

    def derive(self, label: str, value: str) -> str:
        return b64url_encode(hmac.new(self.key, f"{label}|{value}".encode("utf-8"), hashlib.sha256).digest())


# --------------------------------------------------------------------------- RS256 / JWT

# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2 note 1).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_pkcs1v15_sha256_verify(n: int, e: int, message: bytes, signature: bytes, min_bits: int = 2048) -> bool:
    """RSASSA-PKCS1-v1_5 verification with SHA-256, constant format comparison."""
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < min_bits or len(signature) != k or e < 3 or e % 2 == 0:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def jwk_to_rsa(jwk: dict) -> tuple[int, int]:
    if jwk.get("kty") != "RSA":
        raise AuthError("JWK is not an RSA key")
    return int.from_bytes(b64url_decode(jwk["n"]), "big"), int.from_bytes(b64url_decode(jwk["e"]), "big")


def decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("token is not a JWS compact serialization")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        sig = b64url_decode(parts[2])
    except (ValueError, TypeError) as e:
        raise AuthError(f"malformed token: {e}") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise AuthError("malformed token")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), sig


def verify_id_token(token: str, jwks: dict, issuer: str, audience: str, nonce: str | None, leeway_s: int = 60, now: float | None = None, min_bits: int = 2048) -> dict:
    """Verify an RS256 ID token. Returns the claims or raises AuthError."""
    header, claims, signed, sig = decode_jwt_unverified(token)
    if header.get("alg") != "RS256":
        raise AuthError(f"unsupported alg {header.get('alg')!r}; only RS256 is accepted")
    keys = [k for k in jwks.get("keys", []) if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and k.get("alg", "RS256") == "RS256"]
    kid = header.get("kid")
    if kid is not None:
        keys = [k for k in keys if k.get("kid") == kid]
    if not keys:
        raise AuthError(f"no matching RSA key in JWKS for kid {kid!r}")
    if not any(rsa_pkcs1v15_sha256_verify(*jwk_to_rsa(k), signed, sig, min_bits=min_bits) for k in keys):
        raise AuthError("ID token signature is invalid")
    now = time.time() if now is None else now
    if claims.get("iss") != issuer:
        raise AuthError("ID token issuer does not match")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if audience not in auds:
        raise AuthError("ID token audience does not match")
    if len(auds) > 1 and claims.get("azp") != audience:
        raise AuthError("ID token azp does not match")
    try:
        exp = float(claims["exp"])
    except (KeyError, TypeError, ValueError) as e:
        raise AuthError("ID token has no valid exp") from e
    if exp + leeway_s < now:
        raise AuthError("ID token has expired")
    if "nbf" in claims and float(claims["nbf"]) - leeway_s > now:
        raise AuthError("ID token is not valid yet")
    if "iat" in claims and float(claims["iat"]) - leeway_s > now:
        raise AuthError("ID token was issued in the future")
    if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise AuthError("ID token nonce does not match")
    return claims


# --------------------------------------------------------------------------- OIDC client


def _http_json(url: str, data: dict | None = None, timeout: float = 15, headers: dict | None = None) -> dict:
    if not url.lower().startswith(("https://", "http://")):
        raise AuthError(f"bad URL {url!r}")
    body = urllib.parse.urlencode(data).encode("ascii") if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured issuer only
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read()[:500].decode("utf-8", "replace")
        raise AuthError(f"{url} returned HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, ValueError, TimeoutError) as e:
        raise AuthError(f"could not reach {url}: {e}") from e


class OidcClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.issuer = cfg["issuer"]
        self.client_id = cfg["client_id"]
        self.redirect_uri = cfg["redirect_uri"]
        self._meta: dict | None = None
        self._jwks: dict | None = None
        self._jwks_at = 0.0
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()

    def metadata(self) -> dict:
        if self._meta is None:
            meta = _http_json(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if meta.get("issuer", "").rstrip("/") != self.issuer.rstrip("/"):
                raise AuthError("discovery document issuer does not match the configured issuer")
            self._meta = meta
        return self._meta

    def jwks(self, force: bool = False) -> dict:
        if force or self._jwks is None or time.time() - self._jwks_at > 3600:
            self._jwks = _http_json(self.metadata()["jwks_uri"])
            self._jwks_at = time.time()
        return self._jwks

    def begin(self) -> tuple[str, str]:
        """Returns (authorization URL, state)."""
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
        with self._lock:
            cutoff = time.time() - 600
            for k in [k for k, v in self._pending.items() if v["at"] < cutoff]:
                del self._pending[k]
            self._pending[state] = {"nonce": nonce, "verifier": verifier, "at": time.time()}
        q = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.cfg.get("scopes", "openid profile email"),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        ep = self.metadata()["authorization_endpoint"]
        return ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode(q), state

    def finish(self, code: str, state: str) -> Identity:
        with self._lock:
            pending = self._pending.pop(state, None)
        if not pending or pending["at"] < time.time() - 600:
            raise AuthError("unknown or expired sign-in state; start again")
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri, "client_id": self.client_id, "code_verifier": pending["verifier"]}
        secret_env = self.cfg.get("client_secret_env")
        if secret_env and os.environ.get(secret_env):
            form["client_secret"] = os.environ[secret_env]
        tokens = _http_json(self.metadata()["token_endpoint"], data=form)
        id_token = tokens.get("id_token")
        if not id_token:
            raise AuthError("token response has no id_token")
        kwargs = dict(issuer=self.metadata().get("issuer", self.issuer), audience=self.client_id, nonce=pending["nonce"], leeway_s=int(self.cfg.get("leeway_s", 60)), min_bits=int(self.cfg.get("min_key_bits", 2048)))
        try:
            claims = verify_id_token(id_token, self.jwks(), **kwargs)
        except AuthError as e:
            if "no matching RSA key" not in str(e):
                raise
            claims = verify_id_token(id_token, self.jwks(force=True), **kwargs)  # key rotation
        return self.identity_from_claims(claims)

    def identity_from_claims(self, claims: dict) -> Identity:
        name = ""
        for c in [self.cfg.get("username_claim", "preferred_username"), "email", "sub"]:
            if not claims.get(c):
                continue
            if c == "email" and claims.get("email_verified") is not True and not self.cfg.get("allow_unverified_email", False):
                continue  # an unverified address can be set to anyone's by the user at some providers
            name = str(claims[c])
            break
        if not name:
            raise AuthError("ID token has no usable user name claim")
        groups = _as_list(claims.get(self.cfg.get("groups_claim", "groups")))
        role = role_for(name, groups, self.cfg)
        if role is None:
            raise AuthError(f"user {name} has no portal role")
        return Identity(name, role, "oidc", tuple(groups))


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.replace(";", ",").split(",") if x.strip()]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def role_for(name: str, groups: list[str], cfg: dict) -> str | None:
    """Pick the highest role from user_roles[name] and group_roles[group]; else default_role (may be null = deny)."""
    found = []
    if name in cfg.get("user_roles", {}):
        found.append(cfg["user_roles"][name])
    for g in groups:
        if g in cfg.get("group_roles", {}):
            found.append(cfg["group_roles"][g])
    found = [r for r in found if r in ROLES]
    if found:
        return max(found, key=lambda r: _RANK[r])
    default = cfg.get("default_role", "analyst")
    return default if default in ROLES else None


# --------------------------------------------------------------------------- trusted header


def peer_is_trusted(peer_ip: str, proxies: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for p in proxies:
        try:
            if ip in ipaddress.ip_network(p, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- the authenticator


SESSION_COOKIE = "aa_session"
OIDC_COOKIE = "aa_oidc"


class Authenticator:
    """Resolves the signed-in user for a request and issues session cookies."""

    def __init__(self, portal_cfg: dict, workspace_root: Path, dev_no_auth: bool = False):
        self.cfg = portal_cfg
        acfg = dict(portal_cfg.get("auth", {}))
        self.acfg = acfg
        self.mode = "dev" if dev_no_auth else acfg.get("mode", "local")
        self.workspace_root = Path(workspace_root)
        self.signer = Signer(load_or_create_secret(self.workspace_root / acfg.get("secret_file", "portal_secret.key")))
        self.ttl = int(portal_cfg.get("session_ttl_s", 8 * 3600))
        self.cookie_secure = bool(portal_cfg.get("cookie_secure", False))
        self.users = UserStore(self.workspace_root / acfg.get("users_file", "portal_users.json"))
        self.oidc: OidcClient | None = None
        self._failures: dict[tuple[str, str], list[float]] = {}  # (user name, peer ip) -> failure times
        self._ip_failures: dict[str, list[float]] = {}  # peer ip -> failure times, any user name
        self._revoked: dict[str, float] = {}  # session nonce -> its expiry, for signed-out cookies
        self.revoked_path = self.workspace_root / portal_cfg.get("state_dir", "portal_state") / "revoked_sessions.json"
        self._load_revoked()
        # SSO group names worth keeping in the session cookie (those the team config maps);
        # set by the portal. None = keep none.
        self.session_groups: set[str] | None = None
        self._fail_lock = threading.Lock()
        if self.mode == "oidc":
            o = acfg.get("oidc", {})
            if not (o.get("issuer") and o.get("client_id") and o.get("redirect_uri")):
                raise AuthError("portal.auth.oidc needs issuer, client_id and redirect_uri")
            self.oidc = OidcClient(o)
        elif self.mode == "trusted_header":
            t = acfg.get("trusted_header", {})
            if not t.get("proxy_ips"):
                raise AuthError("portal.auth.trusted_header needs proxy_ips (the SSO proxy's addresses)")
        elif self.mode == "local":
            if not self.users.users():
                raise AuthError(f"no portal users in {self.users.path}; add one with: python -m analyst_agent portal-user add <name> --role admin")
        elif self.mode != "dev":
            raise AuthError(f"unknown portal.auth.mode {self.mode!r} (use local, trusted_header or oidc)")

    # ---- cookies
    def new_session(self, ident: Identity | None) -> str:
        payload = {"n": secrets.token_urlsafe(16), "exp": int(time.time() + self.ttl)}
        if ident:
            payload.update({"u": ident.name, "r": ident.role, "src": ident.source})
            keep = set(self.session_groups or ()) | set(self.acfg.get("oidc", {}).get("group_roles", {}))
            if ident.source == "oidc" and ident.groups and keep:
                payload["g"] = sorted({g for g in ident.groups if g in keep})[:100]
        return self.signer.sign(payload)

    def cookie_header(self, name: str, value: str, max_age: int | None = None, samesite: str = "Strict") -> str:
        parts = [f"{name}={value}", "Path=/", "HttpOnly", f"SameSite={samesite}"]
        parts.append(f"Max-Age={self.ttl if max_age is None else max_age}")
        if self.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    def csrf_for(self, session: dict | None) -> str:
        return self.signer.derive("csrf", session["n"]) if session else ""

    def check_csrf(self, session: dict | None, token: str | None) -> bool:
        return bool(session and token) and hmac.compare_digest(self.csrf_for(session), token)

    # ---- per-request identity
    def resolve(self, session: dict | None, headers: Any, peer_ip: str) -> Identity | None:
        """Identity from the trusted header (trusted_header mode), the fixed dev user, or the session cookie."""
        if self.mode == "dev":
            return Identity("dev", "admin", "dev-no-auth")
        if self.mode == "trusted_header":
            t = self.acfg.get("trusted_header", {})
            if not peer_is_trusted(peer_ip, t.get("proxy_ips", [])):
                return None
            name = (headers.get(t.get("header", "X-Forwarded-User")) or "").strip()
            if not name:
                return None
            groups = _as_list(headers.get(t["groups_header"])) if t.get("groups_header") else []
            role = role_for(name, groups, t)
            return Identity(name, role, "trusted_header", tuple(groups)) if role else None
        if session and session.get("u"):
            role = session.get("r", "analyst")
            groups: tuple[str, ...] = ()
            if self.mode == "local":
                rec = self.users.users().get(session["u"])
                if rec is None:
                    return None  # user removed: session ends
                role = rec.get("role", role)
            elif self.mode == "oidc" and session.get("src") == "oidc":
                if isinstance(session.get("g"), list):
                    groups = tuple(str(g) for g in session["g"])  # signed at sign-in; see new_session
                # The role follows the current config on every request, not the one frozen at sign-in.
                role = role_for(session["u"], list(groups), self.acfg.get("oidc", {}))
                if role is None:
                    return None
            return Identity(session["u"], role if role in ROLES else "analyst", session.get("src", self.mode), groups)
        return None

    # ---- signed-out sessions
    def _load_revoked(self) -> None:
        try:
            data = json.loads(self.revoked_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        now = time.time()
        self._revoked = {str(n): float(e) for n, e in (data.items() if isinstance(data, dict) else []) if float(e) > now}

    def is_revoked(self, session: dict | None) -> bool:
        return bool(session) and session.get("n") in self._revoked

    def revoke(self, session: dict | None) -> None:
        """Sign-out ends the session for every copy of its cookie, until the cookie would expire anyway."""
        if not session or not session.get("n"):
            return
        from .state import atomic_write_json

        now = time.time()
        with self._fail_lock:
            self._revoked = {n: e for n, e in self._revoked.items() if e > now}
            self._revoked[session["n"]] = float(session.get("exp") or now + self.ttl)
            snapshot = dict(self._revoked)
        atomic_write_json(self.revoked_path, snapshot)

    # ---- local login: lockouts per (user name, address) and per address
    USER_FAILS, IP_FAILS, WINDOW_S = 5, 20, 300

    def login_local(self, name: str, password: str, peer: str = "") -> Identity | None:
        now = time.time()
        key = (name, peer)
        with self._fail_lock:
            cut = now - self.WINDOW_S
            if len(self._failures) > 10000 or len(self._ip_failures) > 10000:  # bound the memory a flood can use
                self._failures = {k: [t for t in v if t > cut] for k, v in self._failures.items() if any(t > cut for t in v)}
                self._ip_failures = {k: [t for t in v if t > cut] for k, v in self._ip_failures.items() if any(t > cut for t in v)}
            ip_recent = [t for t in self._ip_failures.get(peer, []) if t > cut]
            self._ip_failures[peer] = ip_recent
            if len(ip_recent) >= self.IP_FAILS:
                # Checked before the password hash, so a flood from one address costs no hashing.
                raise AuthError("too many failed sign-ins from this address; wait 5 minutes")
            recent = [t for t in self._failures.get(key, []) if t > cut]
            self._failures[key] = recent
            if len(recent) >= self.USER_FAILS:
                # Per user name and address: someone elsewhere can't lock the real user out.
                raise AuthError("too many failed sign-ins for this user; wait 5 minutes")
        ident = self.users.authenticate(name, password)
        with self._fail_lock:
            if ident is None:
                self._failures.setdefault(key, []).append(now)
                self._ip_failures.setdefault(peer, []).append(now)
            else:
                self._failures.pop(key, None)
        return ident
