"""Settings: one JSON file plus environment overrides.

Secrets are never stored in the config file. The gateway token is read from
the environment variable named in `gateway.token_env`.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "gateway": {
        # Native Anthropic Messages API route on the internal gateway.
        "base_url": "https://api.anthropic.com",
        "token_env": "ANTHROPIC_API_KEY",
        # "x-api-key" or "bearer" - how the gateway expects the token.
        "auth_style": "x-api-key",
        "api_version": "2026-10-21",
        # "http": stdlib HTTP straight to /v1/messages (default; needs no packages).
        # "sdk": the anthropic Python SDK. "auto": SDK if installed, else HTTP.
        "backend": "http",
        "timeout_s": 900,
        "max_retries": 3,
        "extra_headers": {},
        # Server-side refusal fallback. Set to null if the gateway rejects it.
        "fallbacks": "default",
        "fallback_beta": "server-side-fallback-2026-07-01",
    },
    "models": {
        "planner": {"model": "claude-fable-5-2", "effort": "high", "max_tokens": 32000},
        "executor": {"model": "claude-opus-5-5", "effort": "medium", "max_tokens": 32000},
        "routine_executor": {"model": "claude-opus-5-5", "effort": "medium", "max_tokens": 32000},
        "verifier": {"model": "claude-opus-5-5", "effort": "high", "max_tokens": 16000},
        "helper": {"model": "claude-haiku-5-5", "effort": "low", "max_tokens": 4000},
    },
    "workspace": {
        "root": "./workspace",
        "input_dirs": ["./samples"],
        "output_dir": "./workspace/output",
    },
    "policy": {
        "allowed_hosts": [],
        "allowed_apps": [],
        "approval_required": ["send", "submit", "delete", "pay", "upload_external", "change_settings"],
        "approval_timeout_s": 900,
    },
    "tiers": {
        "connector": {"enabled": True},
        # Code tier containment (see tools/code.py, tools/sandbox.py). cpu_s null = timeout_s.
        "code": {"enabled": True, "timeout_s": 300, "memory_mb": 1024, "max_processes": 1, "cpu_s": None,
                 "allow_network": False, "python_guard": True, "ui_restrictions": True, "require_job": True,
                 # backend "local" (Job Object + guard) or "docker" (disposable container per step, tools/docker_backend.py).
                 # docker fails closed when unavailable unless fallback_to_local. docker_cli: path or argv prefix.
                 "backend": "local", "fallback_to_local": False, "docker_cli": "docker",
                 "docker": {"image": "python:3.13-slim", "pull": "if-missing", "cpus": 1.0, "pids_limit": 64, "tmpfs_mb": 64,
                            "max_output_file_mb": 100, "max_output_total_mb": 500, "max_output_files": 2000}},
        "browser": {"enabled": True, "headless": True},
        "desktop_uia": {"enabled": False},
        # Pixel control drives a real mouse and keyboard. Only enable it inside
        # an isolated agent workspace VM, never on an employee laptop.
        "desktop_pixels": {
            "enabled": False,
            "dry_run": False,
            "max_long_edge": 2576,
            # "toolset" = Anthropic computer_toolset_20260801 (best). "custom" = the same
            # actions as an ordinary tool, for gateways that block the toolset.
            "tool_mode": "toolset",
            # Input is refused unless the window in front matches one of these
            # titles (fnmatch, case-insensitive) or an allowed app.
            "allowed_window_titles": [],
        },
    },
    "limits": {
        "max_executor_turns": 25,
        "max_images_in_context": 6,
        "max_step_retries": 1,
        "max_replans": 1,
        "task_timeout_s": 3600,
    },
    "connectors": {"databases": {}},
    "audit": {"dir": "./workspace/audit"},
    # Web portal (python -m analyst_agent portal). See README "Portal".
    "portal": {
        "host": "127.0.0.1",
        "port": 8765,
        "session_ttl_s": 28800,
        "cookie_secure": False,  # set true when served over HTTPS
        "allowed_hosts": [],  # Host header names; empty = loopback names when bound to loopback
        "question_timeout_s": 900,
        "live_screenshots": 4,
        "state_dir": "portal_state",  # under workspace/: pending approvals and questions, one JSON file each
        "auth": {
            # "local" (users file), "trusted_header" (SSO reverse proxy) or "oidc".
            "mode": "local",
            "users_file": "portal_users.json",  # under workspace/
            "secret_file": "portal_secret.key",  # under workspace/, created on first run
            "trusted_header": {"header": "X-Forwarded-User", "groups_header": None, "proxy_ips": [], "user_roles": {}, "group_roles": {}, "default_role": "analyst"},
            "oidc": {"issuer": "", "client_id": "", "client_secret_env": "PORTAL_OIDC_CLIENT_SECRET", "redirect_uri": "", "scopes": "openid profile email",
                     "username_claim": "preferred_username", "groups_claim": "groups", "user_roles": {}, "group_roles": {}, "default_role": "analyst"},
        },
    },
    # Credential vault (vault.py). backend: "dpapi" (Windows, current user), "env" (read-only), "keyring" (if installed),
    # "hashicorp" (KV v2) or "azure_keyvault" (central stores, see vault_remote.py).
    "vault": {"backend": "dpapi", "path": "./workspace/vault", "env_prefix": "AGENT_SECRET_", "entropy_env": "",
              # Central stores (vault_remote.py). Credentials come from the named env vars, never from this file.
              "hashicorp": {"url": "", "mount": "secret", "path_prefix": "analyst_agent/", "namespace": "", "token_env": "VAULT_TOKEN",
                            "role_id_env": "VAULT_ROLE_ID", "secret_id_env": "VAULT_SECRET_ID", "approle_mount": "approle",
                            "ca_bundle": "", "verify_tls": True, "timeout_s": 10, "cache_ttl_s": 60},
              "azure_keyvault": {"vault_url": "", "auth": "auto", "tenant_id": "", "client_id": "", "client_secret_env": "AZURE_CLIENT_SECRET",
                                 "authority_host": "https://login.microsoftonline.com", "imds_endpoint": "http://169.254.169.254/metadata/identity/oauth2/token",
                                 "managed_identity_client_id": "", "api_version": "7.4", "ca_bundle": "", "verify_tls": True, "timeout_s": 10, "cache_ttl_s": 60}},
    # Scheduled unattended runs (scheduler.py): definitions file and run state/history folder.
    "schedules": {"path": "./config/schedules.json", "state_dir": "./workspace/schedules", "lock_stale_s": 7200},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


@dataclass
class Settings:
    data: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULTS))
    base_dir: Path = field(default_factory=Path.cwd)

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def path(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else (self.base_dir / p).resolve()

    @property
    def workspace_root(self) -> Path:
        return self.path(self.data["workspace"]["root"])

    @property
    def output_dir(self) -> Path:
        return self.path(self.data["workspace"]["output_dir"])

    @property
    def input_dirs(self) -> list[Path]:
        return [self.path(p) for p in self.data["workspace"]["input_dirs"]]

    @property
    def audit_dir(self) -> Path:
        return self.path(self.data["audit"]["dir"])

    def gateway_token(self) -> str | None:
        return os.environ.get(self.data["gateway"]["token_env"])


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a local .env file. Values already in the environment win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_settings(config_path: str | os.PathLike | None = None, overrides: dict | None = None) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    base_dir = Path.cwd()
    if config_path:
        p = Path(config_path).resolve()
        data = _deep_merge(data, json.loads(p.read_text(encoding="utf-8")))
        base_dir = p.parent.parent if p.parent.name == "config" else p.parent
        load_dotenv(base_dir / ".env")
    env_base = os.environ.get("AGENT_GATEWAY_URL")
    if env_base:
        data["gateway"]["base_url"] = env_base
    env_backend = os.environ.get("AGENT_MODEL_BACKEND")
    if env_backend:
        data["gateway"]["backend"] = env_backend
    if overrides:
        data = _deep_merge(data, overrides)
    return Settings(data=data, base_dir=base_dir)
