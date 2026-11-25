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
```powershell
python -m analyst_agent vault set portal-pw --allow-host portal.example.com
python -m analyst_agent vault list
python -m analyst_agent vault remove portal-pw
```

- `run` without `--playbook` either matches a playbook from the request or has the planner build the steps. The planner needs the model.
- `--unattended` declines every approval and reports it. Nothing is ever auto-approved.
- `--resume <session>` continues from the last checkpoint.
- Each run writes its audit log, screenshots, checkpoint and a "what I checked" report to `workspace/audit/<session>/`. Outputs go to `workspace/output/`.

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

Current result: **92 tests**. Without `RUN_DESKTOP_TESTS`, 88 pass and 4 skip: the 3 live desktop tests, plus the clipboard test when the clipboard is empty. The baseline's 55 tests passed with the live desktop end-to-end test included. That test runs playbook → approval → router → executor → real pixel tier → test app → verifier.

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
playbooks/      4 pilot playbooks (reconciliation, warehouse question, portal download, legacy entry)
evals/tasks.json  eval set with graders, tune/holdout split
knowledge/      team knowledge injected into the planner
test_targets/   local portal + Legacy Ledger test app
tests/          unit, integration and live desktop tests
```

## Not done yet

- **Not tested against a real model.** No gateway token was available here, so every model call is mocked. Run `gateway-check` first, then `eval`, on your gateway.
- **No portal UI yet.** There are no web screens for task chat, live view, the approval inbox or playbook review; the console stands in for them.
- **Later-phase features:** teach mode recording, schedules, SSO and Guacamole/noVNC live view are Phase 3 items in the design. The credential vault is local only (DPAPI, env or keyring). There is no central secret store, rotation or per-user sharing yet.
- **Two eval tasks per workflow** for two workflows. The design calls for five per workflow across all ten.
- **The code tier is contained, not sandboxed.** The Job Object and the audit-hook guard limit it, but they are not an isolation boundary. Production needs the disposable per-task VM or container from the design, with network egress blocked there, since Windows Home can't block network per process without the firewall.
