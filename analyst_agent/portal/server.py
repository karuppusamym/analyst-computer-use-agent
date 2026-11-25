"""The portal web server: stdlib ThreadingHTTPServer, server-rendered pages.

Screens: task chat, sessions + detail, live view, approval inbox, playbook review.
Runs execute in background threads through the normal Orchestrator, with a
WebApprover so every approval (including the plan) waits in the inbox.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sys
import time
import traceback
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote, urlsplit

from ..audit import AuditLog
from ..config import Settings
from ..playbook import PlaybookError
from . import views as V
from .approvals import ApprovalInbox, QuestionBox
from .auth import OIDC_COOKIE, SESSION_COOKIE, AuthError, Authenticator, Identity, peer_is_trusted
from .playbooks import ReviewError, approve_draft, find_entry, list_playbooks, reject_draft
from .runs import RunManager, read_events, safe_child, valid_session_id

MAX_BODY = 1_000_000
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1"}
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif"}
TEXT_TYPES = {".md", ".txt", ".csv", ".json", ".jsonl", ".log", ".sql", ".py", ".eml"}
FLASH = {
    "stopped": ("Stop requested. The agent stops before its next action.", True),
    "nostop": ("That session has no folder yet, so it could not be stopped.", False),
    "answered": ("Answers sent to the agent.", True),
    "approved": ("Approved.", True),
    "rejected": ("Rejected.", True),
    "gone": ("That request was already decided or timed out.", False),
    "started": ("Task started. The plan will appear in the approval inbox.", True),
    "pb_approved": ("Draft approved and published.", True),
    "pb_rejected": ("Draft rejected.", True),
}


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass
class Response:
    status: int = 200
    body: bytes | str = b""
    ctype: str = "text/html; charset=utf-8"
    headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Ctx:
    hd: BaseHTTPRequestHandler
    method: str
    path: str
    query: dict[str, str]
    form: dict[str, str]
    ident: Identity | None
    session: dict
    sent_session: dict | None
    nonce: str
    cookies: list[str]
    peer: str
    csrf: str = ""


class PortalApp:
    def __init__(
        self,
        settings: Settings,
        playbooks_dir: str | Path,
        knowledge_dir: str | Path | None = None,
        host: str = "127.0.0.1",
        dev_no_auth: bool = False,
        client_factory: Callable[[Settings], Any] | None = None,
        router_factory: Callable[[Settings], Any] | None = None,
        quiet: bool = False,
    ):
        if dev_no_auth and not is_loopback(host):
            raise AuthError("--dev-no-auth only binds to 127.0.0.1 (loopback); use real auth for any other address")
        self.settings = settings
        self.cfg = dict(settings.data.get("portal", {}))
        self.host = host
        self.quiet = quiet
        self.playbooks_dir = Path(playbooks_dir)
        settings.workspace_root.mkdir(parents=True, exist_ok=True)
        self.auth = Authenticator(self.cfg, settings.workspace_root, dev_no_auth=dev_no_auth)
        self.audit = AuditLog(settings.workspace_root / "portal_audit", session_id="portal", user="portal")
        self.inbox = ApprovalInbox(on_decided=self._approval_logged)
        self.questions = QuestionBox()
        self.runs = RunManager(settings, self.playbooks_dir, Path(knowledge_dir) if knowledge_dir else None, self.inbox, self.questions, client_factory, router_factory, on_event=self._event)
        allowed = self.cfg.get("allowed_hosts") or []
        self.allowed_hosts = {h.lower() for h in allowed} or (LOOPBACK_NAMES | {host.lower()} if is_loopback(host) else set())

    # ------------------------------------------------------------------ audit
    def _event(self, kind: str, **data: Any) -> None:
        self.audit.event(kind, **data)

    def _approval_logged(self, item) -> None:
        d = item.decision
        self.audit.event("approval_decided", session=item.session_id, step=item.req.step_id, action_class=item.req.action_class, summary=item.req.summary, approved=d.approved, by=d.by, note=d.note)

    # ------------------------------------------------------------------ plumbing
    def _host_ok(self, host_header: str | None) -> bool:
        if not self.allowed_hosts:
            return True
        if not host_header:
            return False
        hh = host_header.strip().lower()
        name = hh[1 : hh.index("]")] if hh.startswith("[") and "]" in hh else hh.split(":")[0]
        return name in self.allowed_hosts or f"[{name}]" in self.allowed_hosts

    def _origin_ok(self, ctx: Ctx) -> bool:
        origin = ctx.hd.headers.get("Origin")
        if not origin:
            return True  # same-origin form posts from older browsers; the CSRF token still applies
        netloc = urlsplit(origin).netloc.lower()
        ok = {(ctx.hd.headers.get("Host") or "").lower()}
        t = self.auth.acfg.get("trusted_header", {})
        if ctx.hd.headers.get("X-Forwarded-Host") and peer_is_trusted(ctx.peer, t.get("proxy_ips", [])):
            ok.add(ctx.hd.headers["X-Forwarded-Host"].lower())
        return netloc in ok

    def handle(self, hd: BaseHTTPRequestHandler, method: str) -> None:
        ctx = None
        try:
            if not self._host_ok(hd.headers.get("Host")):
                return self._send(hd, Response(421, "unexpected Host header", "text/plain; charset=utf-8"), None)
            url = urlsplit(hd.path)
            path = unquote(url.path)
            try:
                jar = SimpleCookie(hd.headers.get("Cookie") or "")
            except CookieError:
                jar = SimpleCookie()
            raw = jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else None
            sent = self.auth.signer.unsign(raw)
            session = sent
            cookies: list[str] = []
            peer = hd.client_address[0]
            ident = self.auth.resolve(sent, hd.headers, peer)
            if ident and self.auth.mode in ("trusted_header", "dev") and (not sent or sent.get("u") != ident.name):
                tok = self.auth.new_session(ident)
                session = self.auth.signer.unsign(tok)
                cookies.append(self.auth.cookie_header(SESSION_COOKIE, tok))
            if session is None:
                tok = self.auth.new_session(None)
                session = self.auth.signer.unsign(tok)
                cookies.append(self.auth.cookie_header(SESSION_COOKIE, tok))
            query = {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
            ctx = Ctx(hd, method, path, query, {}, ident, session, sent, secrets.token_urlsafe(12), cookies, peer)
            ctx.csrf = self.auth.csrf_for(session)
            if method == "POST":
                try:
                    length = int(hd.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if length < 0 or length > MAX_BODY:
                    return self._send(hd, Response(413, "request body too large", "text/plain; charset=utf-8"), ctx)
                body = hd.rfile.read(length) if length else b""
                ctype = (hd.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if ctype == "application/x-www-form-urlencoded":
                    ctx.form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
                elif ctype == "application/json" and body:
                    data = json.loads(body.decode("utf-8"))
                    ctx.form = {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
                token = ctx.form.get("csrf") or hd.headers.get("X-CSRF-Token")
                origin_ok = self._origin_ok(ctx)
                if not origin_ok or not self.auth.check_csrf(sent, token):
                    reason = "cross-origin request" if not origin_ok else ("no session cookie" if sent is None else "missing or wrong form token")
                    self.audit.event("csrf_rejected", path=path, peer=peer, user=ident.name if ident else None, reason=reason, origin=hd.headers.get("Origin"))
                    return self._send(hd, self._page(ctx, 403, "Forbidden", V.error_page(403, "The form token is missing or out of date. Reload the page and try again.")), ctx)
            resp = self.route(ctx)
        except Exception:  # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            resp = Response(500, "internal error", "text/plain; charset=utf-8")
        self._send(hd, resp, ctx)

    def _send(self, hd: BaseHTTPRequestHandler, resp: Response, ctx: Ctx | None) -> None:
        body = resp.body.encode("utf-8") if isinstance(resp.body, str) else resp.body
        hd.send_response(resp.status)
        nonce = ctx.nonce if ctx else "none"
        hd.send_header("Content-Type", resp.ctype)
        hd.send_header("Content-Length", str(len(body)))
        hd.send_header("Cache-Control", "no-store")
        hd.send_header("X-Content-Type-Options", "nosniff")
        hd.send_header("X-Frame-Options", "DENY")
        # same-origin, not no-referrer: with no-referrer, browsers send "Origin: null" on form posts.
        hd.send_header("Referrer-Policy", "same-origin")
        hd.send_header("Content-Security-Policy", f"default-src 'none'; img-src 'self'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for c in ctx.cookies if ctx else []:
            hd.send_header("Set-Cookie", c)
        for k, v in resp.headers:
            hd.send_header(k, v)
        hd.end_headers()
        if hd.command != "HEAD":
            hd.wfile.write(body)

    # ------------------------------------------------------------------ helpers
    def _counts(self) -> dict:
        drafts = sum(1 for e in list_playbooks(self.playbooks_dir) if e.is_draft and e.reviewable)
        return {"approvals": len(self.inbox.pending()), "playbooks": drafts, "chat": len(self.questions.all())}

    def _page(self, ctx: Ctx, status: int, title: str, body: str, active: str = "", poll: str = "") -> Response:
        flash, ok = FLASH.get(ctx.query.get("m", ""), ("", False))
        return Response(status, V.layout(title, body, ctx.ident, ctx.csrf, ctx.nonce, active, self._counts() if ctx.ident else {}, poll, flash, ok))

    @staticmethod
    def _redirect(location: str, status: int = 303) -> Response:
        return Response(status, "", "text/plain; charset=utf-8", [("Location", location)])

    @staticmethod
    def _json(data: Any, status: int = 200) -> Response:
        return Response(status, json.dumps(data, default=str), "application/json; charset=utf-8")

    def _error(self, ctx: Ctx, code: int, message: str) -> Response:
        if ctx.path.startswith("/api/"):
            return self._json({"error": message}, code)
        return self._page(ctx, code, str(code), V.error_page(code, message))

    def _session_exists(self, sid: str) -> bool:
        return valid_session_id(sid) and ((self.settings.audit_dir / sid).is_dir() or sid in self.runs.runs)

    def _file(self, path: Path | None) -> Response:
        if path is None or not path.is_file():
            return Response(404, "not found", "text/plain; charset=utf-8")
        suffix = path.suffix.lower()
        data = path.read_bytes()
        if suffix in IMAGE_TYPES:
            return Response(200, data, IMAGE_TYPES[suffix])
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", path.name)
        if suffix in TEXT_TYPES:
            return Response(200, data, "text/plain; charset=utf-8", [("Content-Disposition", f'inline; filename="{safe_name}"')])
        return Response(200, data, "application/octet-stream", [("Content-Disposition", f'attachment; filename="{safe_name}"')])

    # ------------------------------------------------------------------ routing
    ROUTES: list[tuple[str, str, str, str | None]] = [
        ("GET", r"/healthz", "healthz", None),
        ("GET", r"/login", "login_form", None),
        ("POST", r"/login", "login_post", None),
        ("GET", r"/login/oidc", "oidc_begin", None),
        ("GET", r"/oidc/callback", "oidc_callback", None),
        ("POST", r"/logout", "logout", "analyst"),
        ("GET", r"/", "chat", "analyst"),
        ("POST", r"/tasks", "start_task", "analyst"),
        ("GET", r"/sessions", "sessions", "analyst"),
        ("GET", r"/sessions/(?P<sid>[^/]+)", "session", "analyst"),
        ("POST", r"/sessions/(?P<sid>[^/]+)/stop", "stop", "analyst"),
        ("POST", r"/sessions/(?P<sid>[^/]+)/answer", "answer", "analyst"),
        ("GET", r"/sessions/(?P<sid>[^/]+)/live", "live", "analyst"),
        ("GET", r"/sessions/(?P<sid>[^/]+)/report", "report", "analyst"),
        ("GET", r"/sessions/(?P<sid>[^/]+)/file/(?P<rel>.+)", "session_file", "analyst"),
        ("GET", r"/out/(?P<rel>.+)", "output_file", "analyst"),
        ("GET", r"/api/state", "api_state", "analyst"),
        ("GET", r"/api/sessions/(?P<sid>[^/]+)/state", "api_session_state", "analyst"),
        ("GET", r"/api/sessions/(?P<sid>[^/]+)/live", "api_live", "analyst"),
        ("GET", r"/approvals", "approvals", "analyst"),
        ("POST", r"/approvals/(?P<aid>[A-Za-z0-9]+)", "decide", "reviewer"),
        ("GET", r"/playbooks", "playbooks", "analyst"),
        ("GET", r"/playbooks/view", "playbook_view", "analyst"),
        ("POST", r"/playbooks/review", "playbook_review", "reviewer"),
    ]

    def route(self, ctx: Ctx) -> Response:
        method = "GET" if ctx.method == "HEAD" else ctx.method
        path_known = False
        for m, pattern, name, role in self.ROUTES:
            match = re.fullmatch(pattern, ctx.path)
            if not match:
                continue
            path_known = True
            if m != method:
                continue
            if role is not None:
                if ctx.ident is None:
                    if method == "GET" and not ctx.path.startswith("/api/"):
                        return self._redirect("/login")
                    return self._error(ctx, 401, "sign in first")
                if not ctx.ident.can(role):
                    self.audit.event("forbidden", path=ctx.path, by=ctx.ident.name, role=ctx.ident.role, needed=role)
                    return self._error(ctx, 403, f"this needs the {role} role; you are {ctx.ident.role}")
            return getattr(self, "r_" + name)(ctx, **match.groupdict())
        return self._error(ctx, 405 if path_known else 404, "method not allowed" if path_known else "no such page")

    # ------------------------------------------------------------------ auth pages
    def r_healthz(self, ctx: Ctx) -> Response:
        return Response(200, "ok", "text/plain; charset=utf-8")

    def r_login_form(self, ctx: Ctx, error: str = "", status: int = 200) -> Response:
        if ctx.ident and not error:
            return self._redirect("/")
        return self._page(ctx, status, "Sign in", V.login_page(self.auth.mode, ctx.csrf, error))

    def r_login_post(self, ctx: Ctx) -> Response:
        if self.auth.mode != "local":
            return self._error(ctx, 404, "password sign-in is not enabled")
        name = ctx.form.get("username", "").strip()
        try:
            ident = self.auth.login_local(name, ctx.form.get("password", ""))
        except AuthError as e:
            self.audit.event("login_locked", user_name=name, peer=ctx.peer)
            return self.r_login_form(ctx, str(e), 429)
        if ident is None:
            self.audit.event("login_failed", user_name=name, peer=ctx.peer)
            return self.r_login_form(ctx, "Wrong user name or password.", 401)
        self.audit.event("login", by=ident.name, role=ident.role, source="local", peer=ctx.peer)
        ctx.cookies[:] = [self.auth.cookie_header(SESSION_COOKIE, self.auth.new_session(ident))]
        return self._redirect("/")

    def r_logout(self, ctx: Ctx) -> Response:
        self.audit.event("logout", by=ctx.ident.name)
        ctx.cookies[:] = [self.auth.cookie_header(SESSION_COOKIE, self.auth.new_session(None))]
        return self._redirect("/login")

    def r_oidc_begin(self, ctx: Ctx) -> Response:
        if self.auth.mode != "oidc" or not self.auth.oidc:
            return self._error(ctx, 404, "SSO sign-in is not enabled")
        try:
            url, state = self.auth.oidc.begin()
        except AuthError as e:
            return self._error(ctx, 502, f"the identity provider is not reachable: {e}")
        bind = self.auth.signer.sign({"state": state, "exp": int(time.time() + 600)})
        ctx.cookies.append(self.auth.cookie_header(OIDC_COOKIE, bind, max_age=600, samesite="Lax"))
        return self._redirect(url, 302)

    def r_oidc_callback(self, ctx: Ctx) -> Response:
        if self.auth.mode != "oidc" or not self.auth.oidc:
            return self._error(ctx, 404, "SSO sign-in is not enabled")
        if ctx.query.get("error"):
            return self._error(ctx, 401, f"sign-in was refused: {ctx.query.get('error')} {ctx.query.get('error_description', '')}")
        try:
            jar = SimpleCookie(ctx.hd.headers.get("Cookie") or "")
        except CookieError:
            jar = SimpleCookie()
        bound = self.auth.signer.unsign(jar[OIDC_COOKIE].value if OIDC_COOKIE in jar else None)
        state = ctx.query.get("state", "")
        if not bound or not state or not hmac.compare_digest(str(bound.get("state", "")), state):
            return self._error(ctx, 400, "sign-in state does not match this browser; start again")
        try:
            ident = self.auth.oidc.finish(ctx.query.get("code", ""), state)
        except AuthError as e:
            self.audit.event("login_failed", source="oidc", reason=str(e), peer=ctx.peer)
            return self._error(ctx, 401, f"sign-in failed: {e}")
        self.audit.event("login", by=ident.name, role=ident.role, source="oidc", peer=ctx.peer)
        ctx.cookies[:] = [self.auth.cookie_header(SESSION_COOKIE, self.auth.new_session(ident)), self.auth.cookie_header(OIDC_COOKIE, "", max_age=0, samesite="Lax")]
        # A same-site navigation from this page, so the SameSite=Strict cookie is sent on the next request.
        body = '<!doctype html><meta charset=utf-8><meta http-equiv="refresh" content="0;url=/"><title>Signed in</title><p>Signed in. <a href="/">Continue</a></p>'
        return Response(200, body)

    # ------------------------------------------------------------------ chat
    def _chat_body(self, ctx: Ctx) -> str:
        sessions = self.runs.sessions()
        pending: dict[str, list] = {}
        for p in self.inbox.pending():
            pending.setdefault(p.session_id, []).append(p)
        questions = {q.session_id: q for q in self.questions.all()}
        return V.chat_page(ctx.ident, ctx.csrf, self.runs.runnable_playbooks(), sessions, questions, pending)

    def r_chat(self, ctx: Ctx) -> Response:
        return self._page(ctx, 200, "Task chat", self._chat_body(ctx), "chat", poll="/api/state")

    def r_start_task(self, ctx: Ctx) -> Response:
        request = ctx.form.get("request", "").strip()
        params: dict[str, str] = {}
        error = ""
        for line in ctx.form.get("params", "").splitlines():
            line = line.strip()
            if not line:
                continue
            if "=" not in line:
                error = f"parameter line {line!r} needs the form name=value"
                break
            k, v = line.split("=", 1)
            params[k.strip()] = v.strip()
        if not request:
            error = "write what you need first"
        elif len(request) > 10000:
            error = "the request is too long (10,000 characters at most)"
        if not error:
            try:
                run = self.runs.start(request, ctx.form.get("playbook", "auto"), params, ctx.ident.name)
            except PlaybookError as e:
                error = str(e)
            else:
                return self._redirect(f"/?m=started&session={quote(run.session_id)}")
        return Response(400, V.layout("Task chat", f'<div class="msg err">{V.h(error)}</div>' + self._chat_body(ctx), ctx.ident, ctx.csrf, ctx.nonce, "chat", self._counts()))

    def r_answer(self, ctx: Ctx, sid: str) -> Response:
        pq = self.questions.get(sid)
        if pq is None:
            return self._redirect("/?m=gone")
        if ctx.ident.name != pq.asked_by and not ctx.ident.can("admin"):
            return self._error(ctx, 403, "only the person who started this task (or an admin) can answer")
        answers = {q: ctx.form.get(f"a{i}", "").strip() for i, q in enumerate(pq.questions)}
        if not all(answers.values()):
            return self._error(ctx, 400, "answer every question")
        if self.questions.answer(sid, answers, ctx.ident.name):
            self.audit.event("questions_answered", session=sid, by=ctx.ident.name, questions=pq.questions)
        return self._redirect("/?m=answered")

    # ------------------------------------------------------------------ sessions
    def r_sessions(self, ctx: Ctx) -> Response:
        return self._page(ctx, 200, "Sessions", V.sessions_page(self.runs.sessions()), "sessions", poll="/api/state")

    def r_session(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        info = self.runs.session_info(sid)
        events = read_events(self.settings.audit_dir / sid)
        body = V.session_page(info, events, ctx.ident, ctx.csrf, self.inbox.pending(sid), self.questions.get(sid))
        return self._page(ctx, 200, f"Session {sid}", body, "sessions", poll=f"/api/sessions/{quote(sid)}/state")

    def r_stop(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        ok = self.runs.stop(sid, ctx.ident.name)
        return self._redirect(f"/sessions/{quote(sid)}?m={'stopped' if ok else 'nostop'}")

    def r_live(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        info = self.runs.session_info(sid)
        return self._page(ctx, 200, f"Live {sid}", V.live_page(sid, ctx.csrf, info.get("stopped", False), info.get("status") in V.FINAL), "sessions")

    def r_report(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        p = self.settings.audit_dir / sid / "report.md"
        if not p.is_file():
            return self._error(ctx, 404, "this session has no report yet")
        return self._page(ctx, 200, f"Report {sid}", V.report_page(sid, p.read_text(encoding="utf-8", errors="replace")), "sessions")

    def r_session_file(self, ctx: Ctx, sid: str, rel: str) -> Response:
        if not valid_session_id(sid):
            return self._error(ctx, 404, "no such session")
        p = safe_child(self.settings.audit_dir / sid, rel)
        if p is None:
            self.audit.event("path_refused", path=ctx.path, by=ctx.ident.name)
            return self._error(ctx, 404, "no such file")
        if p.name == "STOP":
            return self._error(ctx, 404, "no such file")
        return self._file(p)

    def r_output_file(self, ctx: Ctx, rel: str) -> Response:
        p = safe_child(self.settings.output_dir, rel)
        if p is None:
            self.audit.event("path_refused", path=ctx.path, by=ctx.ident.name)
            return self._error(ctx, 404, "no such file")
        return self._file(p)

    # ------------------------------------------------------------------ JSON for polling
    def r_api_state(self, ctx: Ctx) -> Response:
        root = self.settings.audit_dir
        n_dirs = sum(1 for _ in root.iterdir()) if root.exists() else 0
        state = [[(sid, r.status, r.alive) for sid, r in sorted(list(self.runs.runs.items()))], [p.id for p in self.inbox.pending()], sorted(q.session_id for q in self.questions.all()), n_dirs]
        return self._json({"v": hashlib.sha256(json.dumps(state).encode()).hexdigest()[:16]})

    def r_api_session_state(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        info = self.runs.session_info(sid)
        ev = self.settings.audit_dir / sid / "events.jsonl"
        state = [info.get("status"), info.get("stopped"), [(s["id"], s["status"]) for s in info.get("steps", [])], [p.id for p in self.inbox.pending(sid)], ev.stat().st_size if ev.exists() else 0]
        return self._json({"v": hashlib.sha256(json.dumps(state, default=str).encode()).hexdigest()[:16], "status": info.get("status")})

    def r_api_live(self, ctx: Ctx, sid: str) -> Response:
        if not self._session_exists(sid):
            return self._error(ctx, 404, "no such session")
        try:
            after = int(ctx.query.get("after", "0"))
        except ValueError:
            after = 0
        events = [e for e in read_events(self.settings.audit_dir / sid) if int(e.get("seq", 0)) > after][-200:]
        info = self.runs.session_info(sid)
        shots = [{"name": n, "url": f"/sessions/{quote(sid)}/file/screenshots/{quote(n)}"} for n in self.runs.screenshots(sid, int(self.cfg.get("live_screenshots", 4)))]
        return self._json({
            "status": info.get("status"),
            "stopped": info.get("stopped"),
            "screenshots": shots,
            "events": [{"seq": e.get("seq"), "time": time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0))), "kind": e.get("kind"), "detail": V.event_detail(e)} for e in events],
        })

    # ------------------------------------------------------------------ approvals
    def r_approvals(self, ctx: Ctx) -> Response:
        return self._page(ctx, 200, "Approvals", V.approvals_page(self.inbox.pending(), self.inbox.history(), ctx.ident, ctx.csrf), "approvals", poll="/api/state")

    def r_decide(self, ctx: Ctx, aid: str) -> Response:
        decision = ctx.form.get("decision", "")
        if decision not in ("approve", "reject"):
            return self._error(ctx, 400, "decision must be approve or reject")
        note = ctx.form.get("note", "").strip()[:1000]
        full_note = f"portal ({ctx.ident.role}, {ctx.ident.source})" + (f": {note}" if note else "")
        item = self.inbox.decide(aid, decision == "approve", ctx.ident.name, full_note)
        if item is None:
            return self._redirect("/approvals?m=gone")
        m = "approved" if decision == "approve" else "rejected"
        if ctx.form.get("back") == "session":
            return self._redirect(f"/sessions/{quote(item.session_id)}?m={m}")
        return self._redirect("/approvals?m=" + m)

    # ------------------------------------------------------------------ playbooks
    def r_playbooks(self, ctx: Ctx) -> Response:
        return self._page(ctx, 200, "Playbooks", V.playbooks_page(list_playbooks(self.playbooks_dir)), "playbooks")

    def r_playbook_view(self, ctx: Ctx) -> Response:
        entry = find_entry(self.playbooks_dir, ctx.query.get("id", ""))
        if entry is None:
            return self._error(ctx, 404, "no such playbook")
        return self._page(ctx, 200, "Playbook", V.playbook_view(entry, ctx.ident, ctx.csrf), "playbooks")

    def r_playbook_review(self, ctx: Ctx) -> Response:
        entry_id, decision, note = ctx.form.get("id", ""), ctx.form.get("decision", ""), ctx.form.get("note", "").strip()[:1000]
        try:
            if decision == "approve":
                dest = approve_draft(self.playbooks_dir, entry_id, ctx.ident.name, note, reviewer_is_admin=ctx.ident.can("admin"))
                self.audit.event("playbook_approved", draft=entry_id, published=dest.name, by=ctx.ident.name, note=note)
                return self._redirect("/playbooks?m=pb_approved")
            if decision == "reject":
                dest = reject_draft(self.playbooks_dir, entry_id, ctx.ident.name, note)
                self.audit.event("playbook_rejected", draft=entry_id, moved_to=dest.relative_to(self.playbooks_dir).as_posix(), by=ctx.ident.name, note=note)
                return self._redirect("/playbooks?m=pb_rejected")
        except ReviewError as e:
            return self._error(ctx, 409, str(e))
        return self._error(ctx, 400, "decision must be approve or reject")


class _Handler(BaseHTTPRequestHandler):
    server_version = "AnalystPortal/1"
    sys_version = ""

    def do_GET(self):  # noqa: N802
        self.server.app.handle(self, "GET")

    def do_HEAD(self):  # noqa: N802
        self.server.app.handle(self, "HEAD")

    def do_POST(self):  # noqa: N802
        self.server.app.handle(self, "POST")

    def log_message(self, fmt, *args):
        if not self.server.app.quiet:
            sys.stderr.write("portal %s - %s\n" % (self.address_string(), fmt % args))


def make_server(app: PortalApp, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.daemon_threads = True
    srv.app = app  # type: ignore[attr-defined]
    return srv
