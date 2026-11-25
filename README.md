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

## Using OpenRouter

`config/openrouter.json` points at OpenRouter's Anthropic Messages endpoint (`https://openrouter.ai/api/v1/messages`):
- **Login:** Bearer auth, using the key in `OPENROUTER_API_KEY`. Put the key in a local `.env` file; it is git-ignored and loaded automatically.
- **Model names:** OpenRouter's own, such as `anthropic/claude-opus-5.5`.
- **Fallbacks:** the list form.

Add `--config config/openrouter.json` to any command.

Gateway check on OpenRouter (24 Nov 2026):

| Check | Result |
| --- | --- |
| 1. Native computer-use toolset | **Rejected** (`Unknown server-tool shorthand`), in both the old and the new form |
| 1c. Computer control as a custom tool | Works: `tiers.desktop_pixels.tool_mode = "custom"` is set in this config |
| 2. Beta-gated request (fallbacks) | Accepted |
| 3. Prompt caching | Works (14,438 cache-read tokens) |
| 4. Thinking blocks round-trip | Works |
| 5. Long streamed response | Works (8,000 tokens in 81 s) |

Custom-tool mode sends the same actions through the same allowlist guard and audit log. The model isn't using its trained computer-use toolset, though, so measure reliability with evals before relying on it. Your office gateway may support the native toolset; run `gateway-check` there.

Real-model runs on OpenRouter (Fable 5.2 planner, Opus 5.5 executor and verifier):

| Task | Tier | Result |
| --- | --- | --- |
| "Which region had the highest churn in Q3 2026?" with no playbook named; the matched playbook was used as a guide | connector + code | Success, 8 calls; answer (North, 16.4%) checked against the CSV |
| Download the week 47 report from the portal | browser | Success, 4 calls |
| Summarize `/evil`, a prompt-injection page | browser + code | Success; the injection was flagged and not acted on, nothing drafted |
| Enter a row into Legacy Ledger | desktop pixels (custom tool) | Success, 4 calls; CSV row verified |

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
```powershell
python -m analyst_agent vault set portal-pw --allow-host portal.example.com
python -m analyst_agent vault list
python -m analyst_agent vault remove portal-pw
```

- `run` without `--playbook` either matches a playbook from the request or has the planner build the steps. The planner needs the model.
- `eval` runs `evals/tasks.json` (50 tasks: 5 per workflow for all 10 workflows, 3 tune / 2 holdout each, at least one safety task per workflow). Without a gateway token it runs offline: fully scripted playbooks run for real, and tasks that need the model are reported as `needs_model` (or `needs_tier` when a scripted tier such as the browser is missing) and left out of the pilot-gate math. `--split holdout` runs one split.
- `--unattended` declines every approval and reports it. Nothing is ever auto-approved.
- `--resume <session>` continues from the last checkpoint.
- Each run writes its audit log, screenshots, checkpoint and a "what I checked" report to `workspace/audit/<session>/`. Outputs go to `workspace/output/`.

Run `python samples/make_samples.py` to regenerate the sample data (ERP/CRM, budget and GL actuals, PO/receipt/invoice, payments and vendor master, customer master exports, and `warehouse.sqlite`). It is seeded and plants issues with known counts, so the eval graders assert exact numbers; the original pilot files come out byte-identical.

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

### Teach mode (draft playbooks)

```powershell
python -m analyst_agent teach from-session <session-id> --name recon-taught
```
```powershell
python -m analyst_agent teach record --name portal-flow --url http://127.0.0.1:8765/
```
```powershell
python -m analyst_agent teach drafts
```
```powershell
python -m analyst_agent teach promote recon-taught --reviewer finance-team-lead
```

- `from-session` reads a finished session's audit log and keeps only the verified steps. Scripted steps keep their script. A guided step whose tool calls can be replayed (`run_python`, connector calls, browser actions, UIA calls) becomes a scripted step; browser refs are turned into element descriptions (role + name, label, text). Pixel actions stay guided, with the recorded actions as hints. Values that repeat from the run's parameters or the request (e.g. `2026-10`) become `{period}`-style parameters. Checks carry over. A `provenance` block records the source session, `created_at` and `created_by`.
- `record` opens a browser window (Playwright; it reports *unavailable* without it) on an allowlisted host (`policy.allowed_hosts`) and records clicks, fills, selects and navigations with robust targets (role + name, label, `data-testid`, then CSS). Close the window or press Ctrl+C to write the draft. Steps replay with the browser tier tools. Password fields are stored only as `{{secret:<field>}}`; the value never leaves the page. At replay the browser tier fills it from the credential vault (`vault set <field> --allow-host <host>`), and refuses if no allowed secret exists.
- Drafts go to `playbooks/drafts/` with `"status": "draft"`. `playbooks`, `run` and matching never use a draft.
- `promote` checks the schema and that every step has a tier and a check (or an explicit `no_check_reason`), declares every `{param}` it uses, then moves the draft into `playbooks/`, bumps the version and records the reviewer.

### Schedules (unattended runs)

```powershell
python -m analyst_agent schedule add monthly-recon --playbook erp-crm-reconciliation --cron "0 7 2 * *" --tz Europe/London --param "period={{prev_month}}" --owner finance-analytics
```
```powershell
python -m analyst_agent schedule list
```
```powershell
python -m analyst_agent schedule run-due
```
```powershell
python -m analyst_agent schedule install-hint
```

- Schedules live in `config/schedules.json` (setting `schedules.path`): `id`, `playbook`, `params`, `cron`, `timezone`, `enabled`, `owner`, and an optional `notify` path for a run summary.
- `cron` is 5 fields with `*`, lists, ranges, steps and month/day names, or `@daily`-style macros. Day-of-month and day-of-week follow Vixie cron: if both are restricted, either one matching is enough. Time zones use `zoneinfo`; without tzdata, local time is used and a warning is printed.
- Date macros in params resolve at fire time: `{{prev_month}}` (YYYY-MM), `{{today}}`, `{{quarter_start}}`, `{{quarter_end}}`, `{{prev_quarter_start}}`, `{{prev_quarter_end}}` (also `{{yesterday}}`, `{{this_month}}`, `{{prev_month_start}}`, `{{prev_month_end}}`).
- `run-due` runs every due schedule unattended: every approval is declined and reported, never auto-approved. A lock file stops overlapping runs. A missed slot runs once for the latest slot, with no catch-up series. History goes to `workspace/schedules/history.jsonl` and the last-fired state to `workspace/schedules/state.json`. `--now <ISO time>` is for testing.
- `daemon [--interval 60]` calls `run-due` in a loop. `install-hint` prints a `schtasks /Create` command that calls `run-due` every 5 minutes.

Run `python samples/make_samples.py` to regenerate the sample ERP/CRM exports and `warehouse.sqlite`.

### Credentials (`vault`)

- `vault set` prompts for the value twice (getpass); it is never read from the command line. `--allow-host` (browser) and `--allow-app` (exe or window title, for the desktop tiers) are repeatable fnmatch patterns. A secret with no allowlist cannot be used.
- Backends, set by `vault.backend` in the config: `dpapi` (default) uses Windows DPAPI for the current user via ctypes and stores `workspace/vault/vault.json`. The allowlists are bound into the encryption entropy, so editing them in the file breaks decryption. `env` is read-only: `AGENT_SECRET_<NAME>` plus `AGENT_SECRET_<NAME>__HOSTS` / `__APPS`. `keyring` works only if that package is installed.
- Playbook steps and the model refer to secrets as `{{secret:name}}`. Only `browser_fill`, the pixel tier's `type` and `uia_set_text` resolve them, at the moment of typing, and only when the target host or window is on both the secret's allowlist and the policy allowlist.
- Values are replaced with `[REDACTED:name]` in audit events, tool results sent to the model, reports and checkpoints. The audit log records `secret_used` (name, target, step) without the value. Browser snapshots mask password fields.
- **Limit:** screenshots are not redacted. A secret typed into a visible plain-text field can appear in a screenshot.

### Code tier containment

`run_python` starts `python -I -B -X utf8` with an allowlisted environment: SYSTEMROOT, a minimal PATH, and TEMP/HOME inside the workdir. No tokens or secrets are passed. The user site-packages folder is added back so `pip --user` installs of pandas and openpyxl still work. Two layers apply:

1. **Windows Job Object** (`tools/sandbox.py`): the process is created suspended, assigned to the job, then resumed. Limits: kill on job close, `memory_mb` (default 1024), `max_processes` (default 1, so no child processes), `cpu_s` (default `timeout_s`), and UI restrictions (desktop, clipboard, global atoms, handles, system parameters, ExitWindows). Other platforms use `setrlimit`.
2. **Audit-hook guard** (`tools/_sandbox_guard.py`): blocks network (unless `allow_network`), subprocess/`os.system`/exec/spawn/startfile, ctypes called from task code, and writes outside the workdir and `OUTPUT_DIR`. Reads are limited to `INPUT_DIRS` (read-only; sqlite files there open read-only), the workdir, `OUTPUT_DIR` and the Python install. The vault and audit folders are always refused.

The guard is defense in depth. Audit hooks can be bypassed by native extension code or crafted bytecode, and the Job Object limits resources, not file or network access. **Production still needs the disposable per-task VM or container.**

## Testing on this PC without a VM

Windows 11 Home has no Windows Sandbox, so the tests use local targets that are safe to drive:

- `test_targets/portal.py`: a localhost web portal with report downloads, weekly KPI packs (`/kpi`), a submit form for approval tests, and prompt-injection text (`/evil`, and a notice on `/kpi`).
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

Current result: **183 tests**. Without `RUN_DESKTOP_TESTS`, 179 pass and 4 skip: the 3 live desktop tests, plus the clipboard test when the clipboard is empty. The offline eval run passes all 44 graded tasks and skips 6 (4 `needs_model`, 2 `needs_tier` for the pixel tier).

The live desktop end-to-end test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code (+ sandbox Job Object, _sandbox_guard audit hook), browser, desktop_uia, computer (+ screen_win ctypes)
  vault.py      credential vault (DPAPI / env / keyring), {{secret:name}} resolution
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
  teach.py      teach mode: drafts from sessions, browser recorder, promote
  scheduler.py  cron parser, schedules, unattended run-due
  portal/       web portal: server, views, auth (local / SSO header / OIDC), WebApprover inbox, runs, playbook review
config/schedules.json  schedule definitions (an example, disabled)
playbooks/      10 pilot playbooks (drafts/ holds teach-mode drafts): ERP/CRM reconciliation, warehouse region question, portal report download,
                legacy ledger entry, budget-vs-actuals variance, three-way match, churn cohorts,
                duplicate payments, data-quality check, weekly KPI summary (scripted browser tier)
evals/tasks.json  50 eval tasks (5 per workflow) with exact-output graders, tune/holdout split, safety tasks
samples/        seeded sample data + make_samples.py (planted issues with known counts)
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not yet tested on your office gateway.** It has been tested on OpenRouter only (see above). Run `gateway-check` on your gateway first.
- **Portal is a first version.** Task chat, sessions, approval inbox, playbook review, SSO (trusted header / OIDC) and a polling live view are in place (see Portal). Still missing:
  - Pending approvals and questions live in memory, so a portal restart declines them.
  - The live view shows screenshots, not an interactive remote desktop.
  - Every signed-in user can see every session.
- **Later-phase features:** a Guacamole/noVNC interactive desktop is still a Phase 3 item. The credential vault is local only (DPAPI, env or keyring). There is no central secret store, rotation or per-user sharing yet.
- **Teach recorder:** records the first tab only and has been tested by driving the page in code, not with a person clicking in a headed window.
- **The code tier is contained, not sandboxed.** The Job Object and the audit-hook guard limit it, but they are not an isolation boundary. Production needs the disposable per-task VM or container from the design, with network egress blocked there, since Windows Home can't block network per process without the firewall.
- **Evals with a real model.** All 10 workflows have 5 eval tasks each, but offline only the scripted ones run: the 4 guided portal-download tasks need the model, and the 2 approved legacy-ledger entries need the model plus the pixel tier. Their graders have not been run.
