"""Tier 2 - code: run Python in the task workspace, contained.

Each run is a fresh interpreter started as
`python -I -B -X utf8 -c <guard> script.py`:
- `-I` isolated mode: no PYTHON* variables, no script folder on sys.path, no
  user site (the user site-packages folder is added back explicitly so
  pandas/openpyxl installed with `pip --user` keep working)
- an allowlisted environment (SYSTEMROOT, WINDIR, minimal PATH, TEMP/TMP and
  HOME inside the workdir, PYTHONIOENCODING); tokens and vault secrets in the
  agent's environment never reach the child
- resource limits from sandbox.py: on Windows a Job Object (memory, process
  count, CPU time, UI restrictions, kill on close) assigned while the process
  is still suspended; elsewhere setrlimit
- an audit-hook guard (_sandbox_guard.py) that blocks network, child
  processes, ctypes from task code, and file access outside INPUT_DIRS
  (read-only), the workdir and OUTPUT_DIR

The guard is defense in depth, not a security boundary on its own: in
production the whole agent workspace is a disposable VM or container (design
doc, Security). Set tiers.code.python_guard to false only for debugging.

Excel note (Risk 11): editing .xlsx with openpyxl does not recalculate
formulas or refresh pivots. Steps that need fresh numbers must recalculate in
real Excel (desktop tier) or LibreOffice before the verifier runs.
"""

from __future__ import annotations

import site
import sys
import uuid
from pathlib import Path

from .base import Tier, Tool, ToolContext, ToolOutput, schema
from .sandbox import IS_WINDOWS, Limits, SandboxError, minimal_env, run_limited

_GUARD_SRC = (Path(__file__).with_name("_sandbox_guard.py")).read_text(encoding="utf-8")


def _site_dirs() -> list[str]:
    """User site-packages, which -I would otherwise drop."""
    dirs: list[str] = []
    try:
        if site.ENABLE_USER_SITE:
            user = site.getusersitepackages()
            if user and Path(user).is_dir():
                dirs.append(user)
    except Exception:
        pass
    return dirs


def _limits(cfg: dict, timeout: float) -> Limits:
    procs = int(cfg.get("max_processes", 1) or 1)
    # A venv python.exe on Windows is a launcher that starts the real interpreter as a child.
    if IS_WINDOWS and getattr(sys, "_base_executable", sys.executable) != sys.executable:
        procs = max(procs, 2)
    return Limits(
        memory_mb=int(cfg.get("memory_mb", 1024) or 0),
        max_processes=procs,
        cpu_s=float(cfg.get("cpu_s") or timeout),
        ui_restrictions=bool(cfg.get("ui_restrictions", True)),
    )


def build_command(script: Path, ctx: ToolContext) -> list[str]:
    s = ctx.settings
    cfg = s["tiers"]["code"]
    from ..vault import vault_dir

    work = ctx.workdir.resolve()
    guard_cfg = {
        "guard": bool(cfg.get("python_guard", True)),
        "script": str(script),
        "input_dirs": [str(p) for p in s.input_dirs],
        "output_dir": str(s.output_dir),
        "params": ctx.params,
        "read": [str(p) for p in s.input_dirs],
        "write": [str(work), str(s.output_dir)],
        "deny": [str(vault_dir(s)), str(s.audit_dir)],
        "site_dirs": _site_dirs(),
        "allow_network": bool(cfg.get("allow_network", False)),
    }
    bootstrap = _GUARD_SRC + f"\n_run({guard_cfg!r})\n"
    return [sys.executable, "-I", "-B", "-X", "utf8", "-c", bootstrap]


def run_python(code: str, ctx: ToolContext, timeout: int | None = None) -> ToolOutput:
    cfg = ctx.settings["tiers"]["code"]
    work = ctx.workdir
    work.mkdir(parents=True, exist_ok=True)
    script = (work / f"_step_{ctx.step_id or 'code'}_{uuid.uuid4().hex[:6]}.py").resolve()
    script.write_text(code, encoding="utf-8")
    limit = timeout or cfg["timeout_s"]
    limits = _limits(cfg, limit)
    ctx.audit.event("code_run", step=ctx.step_id, script=str(script), code=code[:20000], memory_mb=limits.memory_mb, max_processes=limits.max_processes, cpu_s=limits.cpu_s, guard=bool(cfg.get("python_guard", True)), network=bool(cfg.get("allow_network", False)))
    try:
        res = run_limited(build_command(script, ctx), work, minimal_env(work.resolve()), limit, limits, require=bool(cfg.get("require_job", True)))
    except SandboxError as e:
        ctx.audit.event("code_result", step=ctx.step_id, error=f"sandbox setup failed: {e}")
        return ToolOutput(f"Error: the code sandbox could not be set up ({e}); nothing was run", is_error=True)
    if res.timed_out:
        ctx.audit.event("code_result", step=ctx.step_id, timed_out=True, peak_memory_mb=res.peak_memory_mb)
        return ToolOutput(f"Error: code ran longer than {limit}s and was stopped", is_error=True)
    out = res.stdout[-15000:]
    err = res.stderr[-8000:]
    notes = list(res.notes)
    if res.returncode != 0 and "MemoryError" in err:
        notes.append(f"the script hit the code tier memory limit ({limits.memory_mb} MB)")
    cpu_codes = (0xC0000044,) if IS_WINDOWS else (-24, -9)  # STATUS_QUOTA_EXCEEDED / SIGXCPU, SIGKILL
    if res.returncode in cpu_codes:
        notes.append(f"the script hit the code tier CPU time limit ({limits.cpu_s:g}s) and was stopped")
    if res.returncode != 0 and "sandbox:" in err:
        notes.append("the code tier sandbox blocked an action (see stderr); do not try to work around it")
    text = f"exit code {res.returncode}\n--- stdout ---\n{out}" + (f"\n--- stderr ---\n{err}" if err else "") + "".join(f"\nnote: {n}" for n in notes)
    ctx.audit.event("code_result", step=ctx.step_id, exit_code=res.returncode, stdout=out[-4000:], stderr=err[-4000:], peak_memory_mb=res.peak_memory_mb, contained=res.contained)
    return ToolOutput(text, is_error=res.returncode != 0)


def _run_python(inp: dict, ctx: ToolContext) -> ToolOutput:
    return run_python(inp["code"], ctx)


class CodeTier(Tier):
    name = "code"
    rank = 2

    def available(self) -> tuple[bool, str]:
        return bool(self.settings["tiers"]["code"]["enabled"]), "ok"

    def tools(self) -> list[Tool]:
        return [
            Tool(
                "run_python",
                "Run a Python script in the task workspace and return stdout/stderr. "
                "Predefined variables: INPUT_DIRS (list of input folders, read-only), OUTPUT_DIR (write results here), PARAMS (task parameters). "
                "Use the csv module or pandas if installed. The script runs contained: no network, no child processes, "
                "no files outside INPUT_DIRS, OUTPUT_DIR and the workdir. Print a short summary of what you produced.",
                schema({"code": {"type": "string"}}),
                _run_python,
                self.name,
            )
        ]
