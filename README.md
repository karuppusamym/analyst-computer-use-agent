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
- `record` opens a browser window (Playwright; it reports *unavailable* without it) on an allowlisted host (`policy.allowed_hosts`) and records clicks, fills, selects and navigations with robust targets (role + name, label, `data-testid`, then CSS). Close the window or press Ctrl+C to write the draft. Steps replay with the browser tier tools. Password fields are stored only as `{{secret:<field>}}`; the value never leaves the page, and the browser tier refuses to type a placeholder.
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

Current result: **104 tests** (49 of them for teach mode and schedules). Without `RUN_DESKTOP_TESTS` the 3 live desktop tests skip and the other 101 pass; with it, the suite includes the live desktop end-to-end test. That test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code, browser, desktop_uia, computer (+ screen_win ctypes)
  teach.py      teach mode: drafts from sessions, browser recorder, promote
  scheduler.py  cron parser, schedules, unattended run-due
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
playbooks/      4 pilot playbooks (reconciliation, warehouse question, portal download, legacy entry); drafts/ for teach-mode drafts
config/schedules.json  schedule definitions (an example, disabled)
evals/tasks.json  eval set with graders, tune/holdout split
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not tested against a real model.** No gateway token was available here, so every model call is mocked. Run `gateway-check` first, then `eval`, on your gateway.
- **No portal UI yet.** There are no web screens for task chat, live view, the approval inbox or playbook review; the console stands in for them.
- **Later-phase features:** SSO, the credential vault and Guacamole/noVNC live view are Phase 3 items in the design. Recorded `{{secret:...}}` fields can't be replayed until the vault exists; the browser tier refuses them.
- **Two eval tasks per workflow** for two workflows. The design calls for five per workflow across all ten.
- **The code tier is not a sandbox on its own.** Production needs the disposable per-task VM or container from the design.
