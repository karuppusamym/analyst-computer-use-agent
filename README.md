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

- `run` without `--playbook` either matches a playbook from the request or has the planner build the steps. The planner needs the model.
- `--unattended` declines every approval and reports it. Nothing is ever auto-approved.
- `--resume <session>` continues from the last checkpoint.
- Each run writes its audit log, screenshots, checkpoint and a "what I checked" report to `workspace/audit/<session>/`. Outputs go to `workspace/output/`.

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

Current result: **57 tests pass**, including the live desktop end-to-end test. That test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

## Layout

```
analyst_agent/
  model/        ModelClient + HTTP (stdlib) / SDK / mock backends, SSE parser
  agents.py     planner, executor (computer batch rules, act-then-look, context resets), verifier
  orchestrator.py  clarify → plan → approve → steps → verify → checkpoint → recover → report
  router.py     tier selection and fallbacks
  tools/        connectors, code, browser, desktop_uia, computer (+ screen_win ctypes)
  playbook.py checks.py policy.py audit.py checkpoint.py report.py evals.py gateway_check.py
playbooks/      4 pilot playbooks (reconciliation, warehouse question, portal download, legacy entry)
evals/tasks.json  eval set with graders, tune/holdout split
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not yet tested on your office gateway.** It has been tested on OpenRouter only (see above). Run `gateway-check` on your gateway first.
- **The code tier can reach the network when there is no VM.** The prompts forbid it and every script is audited, but nothing blocks it. Web access is meant to go through the browser tier, which enforces the site allowlist.
- **No portal UI yet.** There are no web screens for task chat, live view, the approval inbox or playbook review; the console stands in for them.
- **Later-phase features:** teach mode recording, schedules, SSO, the credential vault and Guacamole/noVNC live view are Phase 3 items in the design.
- **Two eval tasks per workflow** for two workflows. The design calls for five per workflow across all ten.
- **The code tier is not a sandbox on its own.** Production needs the disposable per-task VM or container from the design.
