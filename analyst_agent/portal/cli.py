"""`portal` and `portal-user` subcommands."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from ..config import Settings
from .auth import ROLES, AuthError, UserStore
from .teams import Teams


def add_parsers(sub) -> None:
    p = sub.add_parser("portal", help="start the web portal (task chat, live view, approvals, playbook review)")
    p.add_argument("--host", default=None, help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="port (default 8765)")
    p.add_argument("--dev-no-auth", action="store_true", help="development only: no sign-in, everyone is admin; binds 127.0.0.1 only")
    p.add_argument("--enable-desktop", action="store_true", help="allow the pixel tier (only on an isolated machine or with the window allowlist)")
    p.add_argument("--dry-run-desktop", action="store_true", help="pixel tier logs actions without sending input")
    u = sub.add_parser("portal-user", help="manage local portal users (portal.auth.mode = local)")
    us = u.add_subparsers(dest="user_cmd", required=True)
    a = us.add_parser("add", help="add a user or reset their password and role")
    a.add_argument("name")
    a.add_argument("--role", choices=ROLES, default="analyst")
    r = us.add_parser("remove", help="remove a user")
    r.add_argument("name")
    us.add_parser("list", help="list users")
    us.add_parser("teams", help="show portal.teams (members, reviewers and their limits, SSO groups) and check names against the user store")


def users_file(s: Settings) -> Path:
    auth = s.data.get("portal", {}).get("auth", {})
    return s.workspace_root / auth.get("users_file", "portal_users.json")


def run_teams_check(s: Settings, store: UserStore) -> int:
    cfg = s.data.get("portal", {})
    mode = cfg.get("auth", {}).get("mode", "local")
    teams = Teams(cfg.get("teams"), groups_of=(lambda _u: []) if mode in ("oidc", "trusted_header") else None)
    if not teams.configured:
        print("no portal.teams configured: every reviewer may decide every approval")
        return 0
    for line in teams.describe():
        print(line)
    warnings = list(teams.warnings)
    if mode == "local":
        warnings += teams.unknown_users(store.users().keys())
        if any(t.sso_groups or t.sso_reviewer_groups for t in teams.teams.values()):
            warnings.append("sso_groups / sso_reviewer_groups are ignored with portal.auth.mode local")
    else:
        print(f"auth mode {mode}: user names come from SSO, so they are not checked against {store.path}")
    for w in warnings:
        print(f"warning: {w}")
    if not warnings:
        print("ok: no problems found")
    return 0  # warnings never fail: the portal starts with them too


def run_user_cmd(args: argparse.Namespace, s: Settings) -> int:
    store = UserStore(users_file(s))
    if args.user_cmd == "teams":
        return run_teams_check(s, store)
    if args.user_cmd == "list":
        users = store.users()
        if not users:
            print(f"no users in {store.path}")
        for name, rec in sorted(users.items()):
            print(f"{name:<24} {rec.get('role', '?')}")
        return 0
    if args.user_cmd == "remove":
        ok = store.remove(args.name)
        print(f"removed {args.name}" if ok else f"no user {args.name}")
        return 0 if ok else 1
    pw = getpass.getpass(f"Password for {args.name}: ")
    if pw != getpass.getpass("Again: "):
        print("passwords do not match")
        return 1
    try:
        store.add(args.name, args.role, pw)
    except AuthError as e:
        print(f"error: {e}")
        return 1
    print(f"saved {args.name} ({args.role}) in {store.path}")
    return 0


def run_portal_cmd(args: argparse.Namespace, s: Settings, root: Path) -> int:
    from .server import PortalApp, make_server

    cfg = s.data.get("portal", {})
    host = args.host or cfg.get("host", "127.0.0.1")
    port = args.port if args.port is not None else int(cfg.get("port", 8765))
    try:
        app = PortalApp(s, root / "playbooks", knowledge_dir=root / "knowledge", host=host, dev_no_auth=args.dev_no_auth)
    except AuthError as e:
        print(f"portal not started: {e}")
        if not args.dev_no_auth:
            print("For a local trial without sign-in use --dev-no-auth (binds 127.0.0.1 only).")
        return 2
    srv = make_server(app, host, port)
    shown = f"[{host}]" if ":" in host else host
    print(f"portal on http://{shown}:{srv.server_address[1]}/  auth={app.auth.mode}  (Ctrl+C to stop)")
    if app.auth.mode == "dev":
        print("WARNING: --dev-no-auth: no sign-in; anyone on this machine is admin.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
