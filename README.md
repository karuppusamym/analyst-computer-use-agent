# Analyst Computer-Use Agent — Phase 1 prototype

This is the harness from the design doc *Analyst Computer-Use Agent — Product Design*. It has:
- **Model roles:** a planner, an executor and a verifier.
- **Tool tiers:** a router that picks the most reliable of five tiers: connectors, then Python code, then the browser (by page element), then Windows UI Automation, then screen pixels.
- **Playbooks** with scripted and guided replay.
- **Safety and recovery:** approval gates, allowlists, an append-only audit log, checkpoints with resume, and a kill switch.
- **Evaluation:** an eval runner that measures the pilot metrics.

## Works without any SDK

The core needs **only Python 3.10+ and its standard library**:

| Part | Needs | If it's missing |
| --- | --- | --- |
| Model calls | nothing: stdlib `urllib` streams the native `/v1/messages` API (default `backend: "http"`) | — |
| Connectors (files, SQLite, email drafts), Python code tier, checks, playbooks, audit, evals | nothing | — |
| Desktop pixel tier (computer use) | nothing on Windows: screenshots via GDI, input via `SendInput` (`ctypes`) | — |
| Browser tier | `playwright` + Chromium | tier reports *unavailable*; router skips it |
| Windows UI Automation tier | `pywinauto` | tier reports *unavailable* |
| Reading `.xlsx` | `openpyxl` | ask for CSV, or use the code tier |
| YAML playbooks | `pyyaml` | use `.json` playbooks (the default) |
| `anthropic` SDK | optional `backend: "sdk"` | use `http` |

This was tested by running the whole suite with all of those packages blocked from importing. It passes, and only the browser tests skip.

## Point it at your gateway

Edit `config/default.json`:

```json
"gateway": {
  "base_url": "https://your-internal-gateway.example.com",
  "token_env": "ANTHROPIC_API_KEY",
  "auth_style": "x-api-key",
  "backend": "http"
}
```

- Set `auth_style` to `"bearer"` if the gateway expects `Authorization: Bearer`.
- Put the token in the environment variable that `token_env` names. Never put it in the file.
- Set `"fallbacks": null` if the gateway rejects the server-side refusal fallback.

Then run the week-1 gateway test from design-doc Risk 1. It costs a few cents:

```powershell
python -m analyst_agent gateway-check
```

## Commands

```powershell
python -m analyst_agent status
```
```powershell
python -m analyst_agent playbooks
```
```powershell
python -m analyst_agent run "Reconcile October" --playbook erp-crm-reconciliation --param period=2026-10
```
```powershell
python -m analyst_agent run "Revenue and churn by region for Q3 2026"
```
```powershell
python -m analyst_agent eval
```
```powershell
python -m analyst_agent stop <session-id>
```

- `run` without `--playbook` either matches a playbook from the request or has the planner build the steps. The planner needs the model.
- `--unattended` declines every approval and reports it. Nothing is ever auto-approved.
- `--resume <session>` continues from the last checkpoint.
- Each run writes its audit log, screenshots, checkpoint and a "what I checked" report to `workspace/audit/<session>/`. Outputs go to `workspace/output/`.

## Portal

A small web portal (standard library `http.server`, no CDN, works in light and dark mode) replaces the console for day-to-day use:

```powershell
python -m analyst_agent portal-user add alice --role admin
```
```powershell
python -m analyst_agent portal --host 127.0.0.1 --port 8765
```

- **Task chat** (`/`): submit a request, optionally with a playbook and `name=value` parameters. Runs execute in background threads through the normal orchestrator. Clarifying questions from the planner appear in the chat; the run waits until they are answered or `portal.question_timeout_s` passes.
- **Sessions** (`/sessions`): every session folder under `workspace/audit/`, with step statuses, approvals, outputs, the full audit log, the "what I checked" report and a **kill switch** button. The button writes the same `STOP` file as `python -m analyst_agent stop <session>`.
- **Live view** (`/sessions/<id>/live`): the latest screenshots from the session's audit folder and a tail of audit events, refreshed by polling. It stands in for Guacamole/noVNC for now.
- **Approval inbox** (`/approvals`): `WebApprover` queues every approval request, including the plan. A reviewer sees the full preview and approves or rejects. The run waits until someone decides or `policy.approval_timeout_s` passes; a timeout is a decline. The decision and who made it go into the session's audit log and `workspace/portal_audit/`.
- **Playbook review** (`/playbooks`): lists playbooks with steps, parameters, owner and version. Drafts (`playbooks/drafts/*.json`, or `"status": "draft"`) never run. A reviewer approves a draft, which validates it and moves it into `playbooks/`, or rejects it, which moves it to `playbooks/drafts/rejected/`. The author of a draft cannot approve it unless they are an admin.

**Roles:** `analyst` runs tasks and uses the kill switch. `reviewer` can also approve requests and playbooks. `admin` can do everything, including answering questions on anyone's run.

**Sign-in** (`portal.auth.mode` in the config):

| Mode | How it works |
| --- | --- |
| `local` (default) | Users and roles live in `workspace/portal_users.json`. Passwords are PBKDF2-SHA256 hashes (600,000 iterations). Manage them with `portal-user add/remove/list`. |
| `trusted_header` | Behind an SSO reverse proxy. The user comes from `trusted_header.header` (default `X-Forwarded-User`), and groups optionally come from `groups_header`. Both are accepted **only** from the addresses in `proxy_ips`. Roles come from `user_roles` / `group_roles` / `default_role`. |
| `oidc` | Authorization-code flow with PKCE against `oidc.issuer`, using stdlib `urllib`. The ID token's RS256 signature is checked against the issuer's JWKS in pure Python, then `iss`, `aud`, `exp` and `nonce`. The client secret, if any, is read from the env var `client_secret_env`. |

- Sessions are HMAC-signed `HttpOnly; SameSite=Strict` cookies. The key is generated into `workspace/portal_secret.key` on first run. Set `portal.cookie_secure: true` when serving over HTTPS.
- Every POST needs a CSRF token and a same-origin `Origin`.
- Responses carry a strict CSP. Files are served only from inside the session folder or `workspace/output/`, and path traversal is refused.
- The Host header is checked, which guards against DNS rebinding.
- The portal **refuses to start** when no auth is configured (for example, `local` mode with no users). `--dev-no-auth` makes everyone admin with no sign-in and only binds to loopback (127.0.0.1).
- The portal binds to `127.0.0.1` by default. To expose it, put it behind the SSO proxy or use `oidc` with HTTPS.

Run `python samples/make_samples.py` to regenerate the sample ERP/CRM exports and `warehouse.sqlite`.

## Testing on this PC without a VM

Windows 11 Home has no Windows Sandbox, so the tests use local targets that are safe to drive:

- `test_targets/portal.py`: a localhost web portal with report downloads, a submit form for approval tests, and a prompt-injection page.
- `test_targets/legacy_app.py`: the "Legacy Ledger - TEST" tkinter window for the pixel tier.
- **Pixel tier guard:** every click or keystroke is refused unless the window in front matches `allowed_window_titles` or an allowed app. It can only act on the test app, and refusals are logged. `--dry-run-desktop` logs actions without sending them.
- **Mock model:** a scripted model client tests the planner, executor and verifier loop without a gateway.

```powershell
python -m unittest discover -s tests -t . -v
```

To include the live desktop tests, set the variable first. They move the mouse for about 5 seconds, so don't touch it while they run:

```powershell
$env:RUN_DESKTOP_TESTS = "1"
```

Current result: **77 tests** (55 core + 22 portal). Here 74 pass, and the 3 live desktop tests skip unless `RUN_DESKTOP_TESTS=1`. Those include the live desktop end-to-end test. That test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code, browser, desktop_uia, computer (+ screen_win ctypes)
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
  portal/       web portal: server, views, auth (local / SSO header / OIDC), WebApprover inbox, runs, playbook review
playbooks/      4 pilot playbooks (reconciliation, warehouse question, portal download, legacy entry)
evals/tasks.json  eval set with graders, tune/holdout split
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not tested against a real model.** No gateway token was available here, so every model call is mocked. Run `gateway-check` first, then `eval`, on your gateway.
- **Portal is a first version.** Task chat, sessions, approval inbox, playbook review, SSO (trusted header / OIDC) and a polling live view are in place (see Portal). Still missing:
  - Pending approvals and questions live in memory, so a portal restart declines them.
  - The live view shows screenshots, not an interactive remote desktop.
  - Every signed-in user can see every session.
- **Later-phase features:** teach mode recording, schedules, the credential vault and a Guacamole/noVNC interactive desktop are Phase 3 items in the design.
- **Two eval tasks per workflow** for two workflows. The design calls for five per workflow across all ten.
- **The code tier is not a sandbox on its own.** Production needs the disposable per-task VM or container from the design.
