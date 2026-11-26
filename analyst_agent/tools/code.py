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

tiers.code.backend "docker" instead runs each step in a disposable,
network-less, read-only container (docker_backend.py), with the same guard
inside it. It fails closed when docker is unavailable unless
tiers.code.fallback_to_local is true.

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
    backend = str(cfg.get("backend") or "local").lower()
    fallback_note = ""
    if backend == "docker":
        from .docker_backend import DockerUnavailable

        try:
            return run_python_docker(code, ctx, timeout)
        except DockerUnavailable as e:
            if not cfg.get("fallback_to_local"):
                ctx.audit.event("code_result", step=ctx.step_id, backend="docker", error=f"docker backend unavailable: {e}")
                return ToolOutput(f"Error: the code tier docker backend is unavailable ({e}); nothing was run. "
                                  "Tell the user the code sandbox is down; do not try to work around it.", is_error=True)
            ctx.audit.event("code_backend_fallback", step=ctx.step_id, backend="docker", to="local", reason=str(e))
            fallback_note = f"\nnote: docker backend unavailable ({e}); ran on the local backend (tiers.code.fallback_to_local)"
    elif backend != "local":
        return ToolOutput(f"Error: unknown tiers.code.backend {backend!r} (use 'local' or 'docker'); nothing was run", is_error=True)
    out = _run_python_local(code, ctx, timeout)
    return ToolOutput(out.text + fallback_note, is_error=out.is_error) if fallback_note else out


def _run_python_local(code: str, ctx: ToolContext, timeout: int | None = None) -> ToolOutput:
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


def run_python_docker(code: str, ctx: ToolContext, timeout: int | None = None) -> ToolOutput:
    """The docker backend (docker_backend.py): one disposable container per step.
    Raises DockerUnavailable (before anything runs) when the CLI, daemon or image is missing."""
    from . import docker_backend as db

    s = ctx.settings
    cfg = s["tiers"]["code"]
    limit = timeout or cfg["timeout_s"]
    try:
        dcfg = db.DockerConfig.from_settings(cfg)
    except SandboxError as e:
        raise db.DockerUnavailable(f"misconfigured: {e}") from e
    db.ensure_ready(dcfg)
    work = ctx.workdir
    work.mkdir(parents=True, exist_ok=True)
    inputs = [p.resolve() for p in s.input_dirs]
    missing = [str(p) for p in inputs if not p.is_dir()]
    if missing:
        return ToolOutput(f"Error: input folder(s) not found, nothing was run: {missing}", is_error=True)
    guard_cfg = db.guard_config(bool(cfg.get("python_guard", True)), f"_step_{ctx.step_id or 'code'}.py", len(inputs), ctx.params)
    files = db.prepare_stage(work.resolve(), ctx.step_id or "code", code, _GUARD_SRC + f"\n_run({guard_cfg!r})\n")
    out_dir = s.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    seeded, notes = db.seed_stage(out_dir, files.output, dcfg)
    name = db.new_name()
    try:
        argv = db.run_argv(dcfg, name, inputs, files.work, files.output, files.bootstrap_name)
    except SandboxError as e:
        ctx.audit.event("code_result", step=ctx.step_id, backend="docker", error=f"mount refused: {e}")
        return ToolOutput(f"Error: the code sandbox could not be set up ({e}); nothing was run", is_error=True)
    ctx.audit.event("code_run", step=ctx.step_id, backend="docker", container=name, image=dcfg.image, argv=argv, script=str(files.work / files.script_name), code=code[:20000],
                    memory_mb=dcfg.memory_mb, cpus=dcfg.cpus, pids_limit=dcfg.pids_limit, guard=guard_cfg["guard"], network="none")
    if cfg.get("allow_network"):
        notes.append("tiers.code.allow_network is ignored by the docker backend: the container network is always none")
    res = db.run_container(dcfg, argv, name, files.stage, limit)
    rep = db.copy_back(files.output, out_dir, dcfg, seeded)
    notes += res.notes + rep.notes()
    if res.timed_out:
        ctx.audit.event("code_result", step=ctx.step_id, backend="docker", container=name, timed_out=True, copied=rep.copied, rejected=rep.rejected)
        return ToolOutput(f"Error: code ran longer than {limit}s and the container was stopped" + "".join(f"\nnote: {n}" for n in notes), is_error=True)
    out = res.stdout[-15000:]
    err = res.stderr[-8000:]
    if res.returncode != 0 and "sandbox:" in err:
        notes.append("the code tier sandbox blocked an action (see stderr); do not try to work around it")
    if rep.copied:
        notes.append(f"copied to OUTPUT_DIR: {', '.join(rep.copied[:20])}" + (" ..." if len(rep.copied) > 20 else ""))
    text = f"exit code {res.returncode}\n--- stdout ---\n{out}" + (f"\n--- stderr ---\n{err}" if err else "") + "".join(f"\nnote: {n}" for n in notes)
    ctx.audit.event("code_result", step=ctx.step_id, backend="docker", container=name, exit_code=res.returncode, stdout=out[-4000:], stderr=err[-4000:], copied=rep.copied, rejected=rep.rejected, contained=True)
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
