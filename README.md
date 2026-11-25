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

Full eval set on OpenRouter (25 Nov 2026, `python -m analyst_agent --config config/openrouter.json eval`):

- **First run:** 44 of 48 graded tasks passed, with 0 unapproved outbound actions. The 2 legacy-ledger entry tasks were skipped because the pixel tier is off on this PC.
- **The run found a real safety gap.** In `region-sql-injection` the scripted step refused an injected `end_date`, but the model's guided retry guessed the intended date and reported success. Parameters now declare a `format` (`date`, `month`, `week`, `number`, `email`, `url`, `identifier`), an `enum` or a `pattern`. A value that doesn't fit is dropped before any step runs, logged as `params_invalid`, and the agent asks for a valid one. The model is never allowed to guess.
- **The other 3 failures were the grader, not the agent.** The real model words its questions naturally ("which date range?") instead of naming `start_date`. The grader now also accepts the parameters the orchestrator recorded as missing (`params_missing`).
- **After the fixes:** all 4 re-run tasks pass, so all 48 graded tasks pass. Cost was about $0.01 per successful task.

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
python -m analyst_agent vault check
python -m analyst_agent vault rotate portal-pw
python -m analyst_agent vault remove portal-pw
```

- `run` without `--playbook` either matches a playbook from the request or has the planner build the steps. The planner needs the model.
- `eval` runs `evals/tasks.json` (50 tasks: 5 per workflow for all 10 workflows, 3 tune / 2 holdout each, at least one safety task per workflow). Without a gateway token it runs offline: fully scripted playbooks run for real, and tasks that need the model are reported as `needs_model` (or `needs_tier` when a scripted tier such as the browser is missing) and left out of the pilot-gate math. `--split holdout` runs one split.
- **Eval history.** Every `eval` run appends one row to `workspace/evals/history.jsonl`: run id, UTC timestamp, git commit (with a dirty flag), config name (the `--config` file's stem, else `default`), the model id for each role from the settings, each task's status, grade (`pass`/`fail`/`skip`), cost and seconds (plus the failing grader lines), and the pilot metrics. It also writes a self-contained HTML report to `workspace/evals/<run-id>.html` (inline CSS, light and dark mode, no scripts and no CDN).

```powershell
python -m analyst_agent eval history --last 10
```
```powershell
python -m analyst_agent eval compare -2 -1
```

- `eval history` prints a trend table: pass/fail/skip counts, success rate and its change from the run before, unapproved outbound actions, cost per success and the pilot gate.
- `eval compare <A> <B>` lists tasks that **regressed** (pass to fail) or **improved** (fail to pass), tasks newly skipped or newly graded, status changes, changed models and changed pilot metrics. Name a run by its id, a unique prefix of it, or a negative index (`-1` is the latest). It exits with 1 when anything regressed, so CI can gate on it.
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
- **Sessions** (`/sessions`): the session folders under `workspace/audit/` that you may see (see **Who sees which session** below), with step statuses, approvals, outputs, the full audit log, the "what I checked" report and a **kill switch** button. The button writes the same `STOP` file as `python -m analyst_agent stop <session>`.
- **Resume** (session page): a session that has a `checkpoint.json`, is not running, did not end in `success` and has no `STOP` file gets a **Resume from checkpoint** button. It calls `Orchestrator.run(..., session_id=<id>, resume=True)` in a background thread, the same as `run --resume <id>`: verified steps are skipped, and the plan goes to the approval inbox again. The original owner stays the owner. Each resume is recorded in `portal_meta.json` and as `run_resumed` in `workspace/portal_audit/`.
- **Live view** (`/sessions/<id>/live`): the latest screenshots from the session's audit folder and a tail of audit events, refreshed by polling, plus **Take over** / **Hand back** (see **Human takeover** below). For the pilot this replaces Guacamole/noVNC.
- **Approval inbox** (`/approvals`): `WebApprover` queues every approval request, including the plan. A reviewer sees the full preview and approves or rejects. The run waits until someone decides or `policy.approval_timeout_s` passes; a timeout is a decline. The decision and who made it go into the session's audit log and `workspace/portal_audit/`.
- **Playbook review** (`/playbooks`): lists playbooks with steps, parameters, owner and version. Drafts (`playbooks/drafts/*.json`, or `"status": "draft"`) never run. A reviewer approves a draft, which validates it and moves it into `playbooks/`, or rejects it, which moves it to `playbooks/drafts/rejected/`. The author of a draft cannot approve it unless they are an admin.

**Roles:** `analyst` runs tasks and uses the kill switch. `reviewer` can also approve requests and playbooks (limited by teams, below). `admin` can do everything, including answering questions on anyone's run.

**Who sees which session.** When the portal starts a run, it writes the owner (the signed-in user) to `workspace/audit/<session>/portal_meta.json` before the run begins.

| Role | Sees |
| --- | --- |
| `analyst` | Their own sessions, sessions shared with them, and sessions owned by someone in one of their teams. |
| `reviewer` | The same, plus sessions with an approval waiting that they may decide, and sessions with no owner. |
| `admin` | Every session. |

- Sessions with no `portal_meta.json` (started from the CLI or a schedule, or from a portal older than this change) count as having no owner, so only reviewers and admins see them.
- The person holding a takeover keeps the session until they hand back.
- The rule covers the session list, task chat, detail, live view, report, files, the polling APIs, the kill switch, Resume, answering questions, takeover, sharing, and the approval inbox and history.
- A session you can't see returns **404**, the same page as a session that doesn't exist, and is logged as `session_hidden`.

**Teams** (`portal.teams` in the config):

```json
"teams": {
  "finance": {
    "members": ["alice", "bob"],
    "reviewers": ["rita", {"name": "rob", "action_classes": ["plan", "submit"], "max_amount": 5000}],
    "playbooks": ["erp-crm-reconciliation", "budget-*", "vendor-*"],
    "sso_groups": ["fin-analysts"],
    "sso_reviewer_groups": ["fin-approvers"],
    "reviewer_limits": {"action_classes": ["plan"], "max_amount": 1000}
  },
  "audit": {"members": [], "reviewers": ["rhea"], "playbooks": ["*"]}
}
```

- Members and reviewers of a team are all in the team, and each sees the sessions the others own.
- With teams configured, a reviewer may decide an approval only if the session's playbook matches (fnmatch) a `playbooks` entry of a team that lists them under `reviewers`. `"*"` means any playbook, including planner-built sessions with no playbook; nothing else matches those. A reviewer listed in no team's `reviewers` decides nothing. Admins are not limited.
- Approvals a reviewer may not decide don't make the session visible to them. If they can see it anyway (team, share), the inbox shows the request with disabled buttons, and a POST gets **403** and is logged as `approval_forbidden`.
- With no teams configured, every reviewer may decide every approval, as before.

*Teams from SSO groups* (`trusted_header` and `oidc` sign-in only):

- A user is a member of a team if the config lists them under `members`, **or** one of their SSO groups is in the team's `sso_groups`. They are a reviewer of the team if listed under `reviewers` or one of their groups is in `sso_reviewer_groups`. Deciding still needs the `reviewer` role (from `group_roles` / `user_roles`).
- OIDC: groups come from the ID token claim `oidc.groups_claim` (default `groups`), are read once at sign-in, and are kept in the signed session cookie. Only groups that the team config mentions are kept, at most 100. A changed group takes effect at the next sign-in.
- Trusted header: groups come from `trusted_header.groups_header` (for example `X-Forwarded-Groups`, comma- or semicolon-separated) on every request, and only from the addresses in `proxy_ips`. There is no default header; make sure the proxy strips any client-sent copy.
- Groups are never read from a form, a query string or a JSON body.
- To find the teams of *another* user (for example the owner of a session), the portal uses that user's groups as last seen at their sign-in or proxied request, stored in `workspace/portal_sso_groups.json`. A change is logged as `sso_groups_seen`.
- Local (PBKDF2) users keep config-only membership. `sso_groups` and `sso_reviewer_groups` are ignored, with a start-up warning.

*Reviewer limits by approval type and amount:*

- A reviewer entry can be a name or a dict: `{"name": ..., "action_classes": [...], "max_amount": ...}`. Plain names and reviewers who come in through `sso_reviewer_groups` get the team's `reviewer_limits`. A dict entry overrides the team's limits key by key. No limits means unlimited, as before.
- `action_classes` lists the approval types the reviewer may **approve**: the request's `action_class`, which is `plan` for the plan, a step's `action_class` (`send`, `submit`, `delete`, `upload_external`, ...; `approval` when the step has none), or `submit` / `upload` for in-step browser and desktop prompts. A reviewer without `plan` in their list can't approve plans.
- `max_amount` applies to requests that carry an amount. A playbook step declares one with `"approval_amount": "{amount}"` (any parameter placeholder). The value is put on the step's approval request and on the in-step tool approvals of that step, shown in the plan preview and the inbox, and saved in `portal_state` and the audit logs. It is compared as an absolute value. `12,500.00` and `12 500` are read as numbers. An amount that isn't a number is refused for any reviewer with an amount limit. Requests with no amount are not limited by `max_amount`.
- A reviewer may decide in any team that covers the playbook. If their limits allow the request in one of those teams, they may approve it.
- These limits are enforced on the server when the decision is POSTed. A reviewer outside their limits gets **403** for Approve, but can still Reject. The inbox shows the reason and disables only the Approve button. Every refusal is logged as `approval_forbidden` (who, the decision, the action class, the amount and the reason), both in `workspace/portal_audit/` and in the session's audit log.
- A limit that is invalid in the config (for example a `max_amount` that is not a number) approves nothing and gives a start-up warning. Admins are not limited by teams or limits.

*Checking the config against the user store:* with `local` sign-in, the portal warns on start-up, logging `teams_config_warning`, about every team member or reviewer who is not in `workspace/portal_users.json`, and it starts anyway. `python -m analyst_agent portal-user teams` prints each team, its reviewers with their limits and its SSO groups, plus the same warnings. It exits 0 even when there are warnings. With SSO, user names are not checked, because they come from the IdP.

**Share** (session page, owner or admin only): adds or removes individual viewers by user name. They are stored as `viewers` in `portal_meta.json` and logged as `session_shared` / `session_unshared` in the session's audit log and `workspace/portal_audit/`. Viewers get the same access as a team member: they can see the session and use its kill switch and Resume, but they cannot share it further or decide approvals unless their role and team allow it.

**Human takeover** (live view):

- **Who:** admins on any session they see; reviewers on any session they see; the session owner when they are an analyst, if `portal.takeover.owner_analysts` is true (the default; set it to false so only reviewers and admins can take over). The run must be alive in this portal, and nobody else may hold it. Only the holder sends input; the holder or an admin can hand back.
- **Take over** writes `workspace/audit/<session>/PAUSE` (who and when) and logs `takeover_started` with `actor: "human:<user>"`. The orchestrator checks the file before each step, the executor before each model turn and before each tool call in a batch, and a scripted tool sequence before each call. The run logs `takeover_paused` and waits. A hand-made `PAUSE` file works the same way.
- **While paused**, the holder (and any admin, read-only) sees the screen refreshed every `frame_interval_ms` (default 1000 ms), as a PNG at the agent's screenshot scale reduced to `frame_max_width` (default 1280). Frames are captured on request and never saved. Click on the image (left, double, right, move; optional shift/ctrl/alt), use the wheel to scroll, type text, or press keys (`ctrl+s`, `Return`, …). The browser maps the click to the image's own pixels, and the server scales that back to the agent's coordinate space and then to the screen.
- **Every input is a `ComputerTier` action**, so it uses the same foreground-window allowlist guard (`allowed_window_titles` or an allowed app) and `dry_run` as the agent. Allowed input is logged as `human_action`; refused input is not sent and is logged as `human_action_refused` (also in `workspace/portal_audit/`). Both carry `actor: "human:<user>"` and the foreground window. A person may not type `{{secret:...}}` placeholders or press Windows-key combinations. Input requests need the CSRF token and a same-origin `Origin`, like every POST.
- **Hand back** logs `takeover_ended` and removes `PAUSE`. The run logs `takeover_resumed` with the human action counts. The executor's next turn gets a note listing what the person did (actions, coordinates and windows; typed text only as a character count) and must take a screenshot before its next desktop action. Any other desktop action is refused until it does. A scripted sequence interrupted by a takeover fails that attempt, and the guided retry gets the note. The step's checks still decide whether it passed.
- **Kill switch while paused:** the run stops at once. If nobody hands back within `limits.takeover_timeout_s` (default 1800), the run stops as blocked; the `PAUSE` file stays until someone hands back. The task time-out (`limits.task_timeout_s`) keeps running during a takeover. A session with a `PAUSE` file is not resumed from the portal.
- Screen and input need `tiers.desktop_pixels.enabled` on Windows. Without it, taking over still pauses the agent, and the panel says remote control is unavailable. Turn the feature off with `portal.takeover.enabled: false`.
- Files in the shared `workspace/output/` (`/out/...`) are served only if a session you can see lists them as an output. Admins can get any file there. Two sessions that write the same file name share that file.

**Pending requests survive a restart.** Each pending approval and each set of clarifying questions is saved as one JSON file in `workspace/portal_state/` (setting `portal.state_dir`).

- Files are written atomically (temp file, fsync, `os.replace`). A request is saved before it appears in the inbox, and the decision (approved, declined, timeout or answered, with who and when) is saved before the waiting run thread continues. If the decision can't be saved, the run keeps waiting.
- Answers to questions go into the run's parameters and audit log, not into `portal_state`.
- Each portal process has its own instance id. On start, the portal checks for requests still pending from an earlier instance. Their run thread no longer exists, so each one is closed as declined by `portal-restart`, never approved. This is logged as `approval_orphaned` or `question_orphaned` in the session's audit log and in `workspace/portal_audit/`.
- The session page then shows **Orphaned — run was interrupted**, with status `interrupted` and the Resume button if there is a checkpoint.
- Earlier decisions stay in the inbox's "Recent decisions". Closed records beyond the newest 500 are pruned at start-up.

**Sign-in** (`portal.auth.mode` in the config):

| Mode | How it works |
| --- | --- |
| `local` (default) | Users and roles live in `workspace/portal_users.json`. Passwords are PBKDF2-SHA256 hashes (600,000 iterations). Manage them with `portal-user add/remove/list`; `portal-user teams` checks `portal.teams` against them. |
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
- **Tabs and popups.** The recorder follows every page in the browser context, including popups opened by `window.open` or `target=_blank`. Each event carries its tab (0 = first tab, then in open order) and each popup its opener. The click that opened a popup is replayed with `expect_popup: true`: `browser_click` waits for the new tab and makes it current. An action in another tab first gets a `browser_switch_tab` step (`tab`, or `url_contains`, waiting up to `wait_s`). A tab opened by a page script with no click becomes a `browser_switch_tab` that waits for it. A popup on a host off the allowlist is closed, at recording and at replay. `provenance.tabs` counts the tabs used.
- **Downloads and uploads.** A download in any tab turns the click that started it into a `browser_download` step with a `file_exists` check on `output/downloads/<name>`. Choosing a file for a file input becomes a `browser_upload` step whose path is a required `{<field>_path}` parameter. Only the file's base name is recorded (in the parameter's description), never its content or a local path. At replay `browser_upload` only takes a file the policy lets the agent read (input folders, workspace, output) and **always asks for approval** before setting it, because it sends a local file to a website. The approved upload is logged as an `outbound_action`.
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

#### Central stores

`vault.backend: "hashicorp"` or `"azure_keyvault"` keeps secrets in a central store instead of on the machine. Both use stdlib `urllib` (no SDK). Credentials come only from environment variables named in the config, never from the config file. Base URLs must be `https://`, except loopback hosts. `ca_bundle` sets a CA file for a private CA. Values are cached in memory only, for `cache_ttl_s` (default 60 s, 0 turns it off), and never written to disk.

| Backend | Config (`vault.<backend>`) | Auth | Metadata | Versions |
|---|---|---|---|---|
| `hashicorp` | `url` (or `VAULT_ADDR`), `mount` (`secret`), `path_prefix` (`analyst_agent/`), `namespace` (or `VAULT_NAMESPACE`) | Token from `token_env` (`VAULT_TOKEN`), or AppRole: `role_id_env` / `secret_id_env` (`VAULT_ROLE_ID` / `VAULT_SECRET_ID`) at `approle_mount`. It logs in again when the lease runs out or a request gets 403. | KV v2 `custom_metadata` | KV v2 versions |
| `azure_keyvault` | `vault_url`, `tenant_id`, `client_id` (or `AZURE_TENANT_ID` / `AZURE_CLIENT_ID`), `api_version` (`7.4`) | `auth: client_secret` (client credentials against `login.microsoftonline.com/{tenant}`, scope `https://vault.azure.net/.default`, secret from `client_secret_env`), `managed_identity` (IMDS), or `auto` (client secret if its env var is set). It gets a new token when the old one expires or a request gets 401. | Tags. `_` and `.` in a name become `-` in Key Vault; tag `agent_name` keeps the real name and stops collisions. A native expiry set in Key Vault counts as `expires_at`. | Key Vault versions. `remove` is Key Vault's soft delete. |

The store's own access control decides who can read a value. The allowlists and sharing lists live in the store's metadata and this agent enforces them at use time, so anyone who can write a secret's metadata can widen them. Give metadata write access only to the secret's owners (a HashiCorp policy on `<mount>/metadata/...`, or Key Vault RBAC). On the `dpapi` backend these fields are bound into the encryption entropy instead, as the allowlists are.

#### Rotation

- `vault set` takes `--rotate-after-days N` and `--expires-at YYYY-MM-DD` (or `--expires-in-days N`). For the `env` backend, use `AGENT_SECRET_<NAME>__ROTATE_AFTER_DAYS`, `__EXPIRES_AT` and `__UPDATED` (the date the value was set).
- `vault list` shows each secret's age and status: `ok`, `rotate-soon` (a deadline within 7 days), `rotate-due` (older than `rotate_after_days`; still usable) or `expired`.
- An expired secret is refused when a tool tries to use it. The error says to rotate it, and the audit log records `secret_expired`.
- `vault check [--warn-days 7]` prints the secrets that are not `ok` and exits 1 if any are expired or due (or the store can't be reached). Run it from a daily scheduled task (`schtasks /Create /SC DAILY ...`, with full paths as in the command `schedule install-hint` prints).
- `vault rotate <name>` prompts twice (getpass) for the new value. It refuses the current value and keeps the allowlists, sharing and rotation period. It keeps the expiry unless you pass a new one, and clears an expiry that has passed. `hashicorp` and `azure_keyvault` keep earlier versions. `dpapi` keeps one previous value. `vault rollback <name>` restores the previous value as a new version. `keyring` keeps no previous value, and `env` is read-only.

#### Sharing

- `vault set --owner USER` (may use and manage) and `--user USER` (may use) are repeatable, case-insensitive fnmatch patterns such as `schedule:*`. If both lists are empty, any run user may use the secret, which is how secrets made before this feature behave.
- At use time the run's user must match. That user is the orchestrator's `user`: the portal login, `schedule:<owner>` for scheduled runs, or `analyst` for CLI runs. A `ToolContext.user`, if set, takes precedence. A refusal raises an error and is audited as `secret_denied` with the user.
- `vault rotate`, `rollback`, `remove` and overwriting `set` need the CLI user to be an owner when the secret has owners. The CLI user is `AGENT_USER` or the OS account name. This check is a guard against mistakes and is easy to bypass. The real control is the store's ACL.

### Code tier containment

`run_python` starts `python -I -B -X utf8` with an allowlisted environment: SYSTEMROOT, a minimal PATH, and TEMP/HOME inside the workdir. No tokens or secrets are passed. The user site-packages folder is added back so `pip --user` installs of pandas and openpyxl still work. Two layers apply:

1. **Windows Job Object** (`tools/sandbox.py`): the process is created suspended, assigned to the job, then resumed. Limits: kill on job close, `memory_mb` (default 1024), `max_processes` (default 1, so no child processes), `cpu_s` (default `timeout_s`), and UI restrictions (desktop, clipboard, global atoms, handles, system parameters, ExitWindows). Other platforms use `setrlimit`.
2. **Audit-hook guard** (`tools/_sandbox_guard.py`): blocks network (unless `allow_network`), subprocess/`os.system`/exec/spawn/startfile, ctypes called from task code, and writes outside the workdir and `OUTPUT_DIR`. Reads are limited to `INPUT_DIRS` (read-only; sqlite files there open read-only), the workdir, `OUTPUT_DIR` and the Python install. The vault and audit folders are always refused.

The guard is defense in depth. Audit hooks can be bypassed by native extension code or crafted bytecode, and the Job Object limits resources, not file or network access. **Production still needs the disposable per-task VM or container.**

#### Docker backend (`tiers.code.backend: "docker"`)

The default backend is `"local"` (the two layers above). With `"docker"`, each `run_python` step runs in its own disposable container, started through the docker CLI (`tools/docker_backend.py`, subprocess only, no SDK):

```
docker run --rm --name aa-code-<random> --network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 64 --memory 1024m --memory-swap 1024m --cpus 1
  --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --ulimit core=0 --pull never
  --workdir /work --env HOME=/tmp ... (a fixed allowlist, nothing from the agent's environment)
  --mount type=bind,source=<input 0>,target=/inputs/0,readonly   (one per input folder)
  --mount type=bind,source=<stage>/work,target=/work
  --mount type=bind,source=<stage>/output,target=/output
  python:3.13-slim python -I -B -X utf8 /work/_bootstrap.py
```

- **Paths.** `INPUT_DIRS` becomes `["/inputs/0", ...]` and `OUTPUT_DIR` becomes `/output` inside the container. The audit-hook guard still runs inside it (`python_guard`) as a second layer. On Windows, mount sources are written as `C:/dir/sub`. UNC/network paths, relative paths, and paths containing `,` `"` `'` `=` or control characters are refused, and the step fails before anything runs. `docker.path_style` (`auto`/`windows`/`posix`) overrides the detection.
- **Outputs.** The real `OUTPUT_DIR` is never mounted. A fresh per-step stage folder under the workdir is seeded with copies of the current files in `OUTPUT_DIR`, so a step can read earlier outputs. After the container exits, new or changed files are copied back. Only regular files are copied. Symlinks and junctions/reparse points, special files, names that are unsafe on Windows (`CON`, `a:b`, trailing dots), and anything that would land on a link or outside `OUTPUT_DIR` are refused. Caps apply: `max_output_file_mb` (100), `max_output_total_mb` (500) and `max_output_files` (2000). Refused files are listed in the step result and the audit log. Files deleted inside the container are not deleted from `OUTPUT_DIR`.
- **Time-out.** At `timeout_s` the agent runs `docker kill <name>`. If the CLI still hasn't exited, it is killed and `docker rm -f` runs. Exit 137 without a time-out is reported as the memory limit.
- **Image.** The default is `docker.image: "python:3.13-slim"`. **Pin it by digest in production** (`"python:3.13-slim@sha256:<digest>"`, from `docker buildx imagetools inspect python:3.13-slim`) and bake in pandas/openpyxl if steps need them, since the container has no network to `pip install`. `docker.pull: "if-missing"` pulls a missing image before the step, outside the time-out. `"never"` fails closed when the image is missing. The run itself always uses `--pull never`.
- **Fail closed.** If the CLI is missing, the daemon is unreachable, or the image is missing and can't be pulled, the step fails with an error that says why, and nothing runs. It falls back to the local backend only when `tiers.code.fallback_to_local: true`, and records `code_backend_fallback` in the audit log when it does.
- **Settings:** `tiers.code.docker_cli` (a path or an argv prefix, default `docker`), `memory_mb` (shared with local), and under `tiers.code.docker`: `image`, `pull`, `cpus`, `pids_limit`, `tmpfs_mb`, the output caps, `control_timeout_s`, `pull_timeout_s`.
- `python -m analyst_agent status` prints a `code backend:` line: CLI found, daemon reachable, image present.

**Limitations:**
- Network is always `none`. `allow_network` is ignored, and an egress allowlist is out of scope.
- `--user 65534` needs the input folders to be readable by that user on Linux hosts. Docker Desktop's bind mounts don't enforce this.
- Bind mounts name host paths, so `DOCKER_HOST` must point at a daemon on this machine (Docker Desktop or a local engine), not a remote one.
- On Docker Desktop the container runs in its Linux VM. That isolates it from the Windows host, but it is not a per-task VM. The kernel is shared with other containers in that VM.
- The live container tests (`tests/test_docker_backend.py`, `Live*`) skip unless `docker info` succeeds, and they have not been run here yet.

## Testing on this PC without a VM

Windows 11 Home has no Windows Sandbox, so the tests use local targets that are safe to drive:

- `test_targets/portal.py`: a localhost web portal with report downloads, weekly KPI packs (`/kpi`), a submit form for approval tests, prompt-injection text (`/evil`, and a notice on `/kpi`), and a teach-recorder page (`/tabs`: a `target=_blank` popup with a download, a `window.open` popup, and a file upload form that keeps only each upload's name, size and SHA-256).
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

Current result: **297 tests**. Without `RUN_DESKTOP_TESTS` and without a running Docker daemon, 287 pass and 10 skip: the live desktop tests (including live takeover), the 6 live container tests, and the clipboard test when the clipboard is empty. Offline, the eval run passes all 44 graded tasks and skips 6 (4 `needs_model`, 2 `needs_tier`). On OpenRouter all 48 graded tasks pass. CI (`.github/workflows/tests.yml`) runs the suite on Windows with and without the optional packages.

The live desktop end-to-end test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code (+ sandbox Job Object, _sandbox_guard audit hook, docker_backend container per step), browser, desktop_uia, computer (+ screen_win ctypes)
  vault.py      credential vault (DPAPI / env / keyring), rotation, sharing, {{secret:name}} resolution
  vault_remote.py  central vault backends: HashiCorp Vault KV v2, Azure Key Vault (stdlib urllib)
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
  eval_history.py  eval history.jsonl rows, `eval history` / `eval compare`, per-run HTML report
  teach.py      teach mode: drafts from sessions, browser recorder, promote
  scheduler.py  cron parser, schedules, unattended run-due
  takeover.py   human takeover: PAUSE file, hand-back note for the executor
  portal/       web portal: server, views, auth (local / SSO header / OIDC), WebApprover inbox, runs, playbook review, takeover, teams
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
- **Portal is a first version.** Task chat, sessions, approval inbox, playbook review, SSO (trusted header / OIDC), a polling live view with human takeover, pending requests that survive a restart (with Resume), team and per-owner session visibility, sharing, teams from SSO groups, and reviewers limited by playbook, approval type and amount are in place (see Portal). Still missing or limited:
  - Takeover is polled PNG frames plus single inputs, not a streaming remote desktop. Expect about a second of lag, and no drag, key-hold or clipboard. The screen is the primary monitor of the machine the portal runs on, so the portal and the agent must share a desktop. Frames and typed text are not redacted; don't type secrets during a takeover.
  - A takeover holds only within one portal process. After a restart the run thread is gone, a leftover `PAUSE` file blocks Resume until someone hands back, and the task time-out keeps running while a person holds the session.
  - A restart can't reconnect a waiting run. Its pending requests are declined as orphaned, and the session has to be resumed from its last checkpoint. The plan is approved again, and an unverified step that was in progress runs again.
  - SSO team membership is only as current as the last sign-in. OIDC groups are fixed at sign-in, and other users' groups are used as last seen, so a session owner removed from a group still counts as a member until they sign in again. Group overage claims (for example Azure AD `_claim_names` when a user has too many groups) are not resolved; put the groups in the token or use the proxy header. With `local` sign-in, a team member who is missing from the user store gets a warning, not an error.
  - Amount limits cover only amounts a playbook step declares (`approval_amount`). Planner-built steps carry no amount, because a model-chosen amount can't be trusted, and nothing reads amounts off the screen. A step that declares an amount needs `approval: "required"` (or an action class the policy gates) to be reviewed at all. Admins have no limits. Reviewer limits exist only inside `portal.teams`. With no teams configured, every reviewer is unlimited, as before.
- **Later-phase features:** a Guacamole/noVNC desktop with streaming video is still a Phase 3 item, for VMs the portal does not run on. The central vault backends (HashiCorp Vault, Azure Key Vault) have been tested only against local fake servers that mimic their APIs, not against a real Vault or Key Vault. Rotation is manual (`vault rotate`). Nothing changes the password on the target system itself. Sharing is per user, not per portal group or team.
- **Teach recorder:** has been tested by driving the page in code (`tests/test_teach.py`, against the `/tabs` page of the test portal), not with a person clicking in a headed window. Still limited:
  - A link that downloads straight into a new tab (`target=_blank` on an attachment) is reported as a warning, not replayed, because the download belongs to a tab that closes itself.
  - Tabs are matched by open order. If a site opens its tabs in a different order at replay, the `browser_switch_tab` steps need `url_contains` instead of `tab`, by hand.
  - Closing a tab is not recorded. Replay leaves popups open and switches back by index.
  - A multi-file upload replays one path only (with a warning). Drag-and-drop uploads are not recorded.
  - Actions inside iframes are recorded, but replay looks for their targets in the main frame only, so those steps fail.
- **The code tier container backend is built but not yet run live.** `tiers.code.backend: "docker"` runs each step in a disposable, network-less, read-only, unprivileged container (see Docker backend). Its unit tests use a fake docker CLI. The live container tests skip until a docker daemon is reachable, and they have not run on this PC. The default `local` backend is still contained, not sandboxed: the Job Object and the audit-hook guard are not an isolation boundary. There is no network egress allowlist (the container network is always `none`), and a per-task VM, as opposed to a container, is not built.
- **Pixel-tier evals.** The 2 approved legacy-ledger entry tasks need the pixel tier, which moves the real mouse, so they have not run with a real model here. Run them on the isolated agent VM with `tiers.desktop_pixels.enabled`.

## License

MIT. See [LICENSE](LICENSE).
