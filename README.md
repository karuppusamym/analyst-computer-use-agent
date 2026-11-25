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
- `eval` runs `evals/tasks.json` (50 tasks: 5 per workflow for all 10 workflows, 3 tune / 2 holdout each, at least one safety task per workflow). Without a gateway token it runs offline: fully scripted playbooks run for real, and tasks that need the model are reported as `needs_model` (or `needs_tier` when a scripted tier such as the browser is missing) and left out of the pilot-gate math. `--split holdout` runs one split.
- `--unattended` declines every approval and reports it. Nothing is ever auto-approved.
- `--resume <session>` continues from the last checkpoint.
- Each run writes its audit log, screenshots, checkpoint and a "what I checked" report to `workspace/audit/<session>/`. Outputs go to `workspace/output/`.

Run `python samples/make_samples.py` to regenerate the sample data (ERP/CRM, budget and GL actuals, PO/receipt/invoice, payments and vendor master, customer master exports, and `warehouse.sqlite`). It is seeded and plants issues with known counts, so the eval graders assert exact numbers; the original pilot files come out byte-identical.

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

Current result: **73 tests**. 70 pass, and the 3 live desktop tests skip unless `RUN_DESKTOP_TESTS=1`. They passed with it set before the eval work and were not re-run after it. The offline eval run passes all 44 graded tasks and skips 6: 4 `needs_model` and 2 `needs_tier` for the pixel tier.

The live desktop end-to-end test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code, browser, desktop_uia, computer (+ screen_win ctypes)
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
playbooks/      10 pilot playbooks: ERP/CRM reconciliation, warehouse region question, portal report download,
                legacy ledger entry, budget-vs-actuals variance, three-way match, churn cohorts,
                duplicate payments, data-quality check, weekly KPI summary (scripted browser tier)
evals/tasks.json  50 eval tasks (5 per workflow) with exact-output graders, tune/holdout split, safety tasks
samples/        seeded sample data + make_samples.py (planted issues with known counts)
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not tested against a real model.** No gateway token was available here, so every model call is mocked. Run `gateway-check` first, then `eval`, on your gateway.
- **No portal UI yet.** There are no web screens for task chat, live view, the approval inbox or playbook review; the console stands in for them.
- **Later-phase features:** teach mode recording, schedules, SSO, the credential vault and Guacamole/noVNC live view are Phase 3 items in the design.
- **Evals with a real model.** All 10 workflows have 5 eval tasks each, but offline only the scripted ones run: the 4 guided portal-download tasks need the model, and the 2 approved legacy-ledger entries need the model plus the pixel tier. Their graders have not been run.
- **The code tier is not a sandbox on its own.** Production needs the disposable per-task VM or container from the design.
