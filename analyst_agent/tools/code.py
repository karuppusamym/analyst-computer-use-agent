"""Tier 2 - code: run Python in the task workspace.

Runs a separate interpreter process with a time-out, the workspace as its
current folder and the gateway token removed from its environment. This is
not a security sandbox by itself: in production the whole agent workspace is
a disposable VM or container (design doc, Security).

Excel note (Risk 11): editing .xlsx with openpyxl does not recalculate
formulas or refresh pivots. Steps that need fresh numbers must recalculate in
real Excel (desktop tier) or LibreOffice before the verifier runs.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid

from .base import Tier, Tool, ToolContext, ToolOutput, schema


def run_python(code: str, ctx: ToolContext, timeout: int | None = None) -> ToolOutput:
    work = ctx.workdir
    work.mkdir(parents=True, exist_ok=True)
    script = work / f"_step_{ctx.step_id or 'code'}_{uuid.uuid4().hex[:6]}.py"
    preamble = (
        "import os, sys\n"
        f"INPUT_DIRS = {[str(p) for p in ctx.settings.input_dirs]!r}\n"
        f"OUTPUT_DIR = {str(ctx.settings.output_dir)!r}\n"
        f"PARAMS = {ctx.params!r}\n"
        "os.makedirs(OUTPUT_DIR, exist_ok=True)\n"
    )
    script.write_text(preamble + code, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}
    env["PYTHONIOENCODING"] = "utf-8"
    limit = timeout or ctx.settings["tiers"]["code"]["timeout_s"]
    ctx.audit.event("code_run", step=ctx.step_id, script=str(script), code=code[:20000])
    try:
        proc = subprocess.run([sys.executable, "-E", str(script)], cwd=work, env=env, capture_output=True, text=True, timeout=limit, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return ToolOutput(f"Error: code ran longer than {limit}s and was stopped", is_error=True)
    out = proc.stdout[-15000:]
    err = proc.stderr[-8000:]
    text = f"exit code {proc.returncode}\n--- stdout ---\n{out}" + (f"\n--- stderr ---\n{err}" if err else "")
    ctx.audit.event("code_result", step=ctx.step_id, exit_code=proc.returncode, stdout=out[-4000:], stderr=err[-4000:])
    return ToolOutput(text, is_error=proc.returncode != 0)


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
                "Predefined variables: INPUT_DIRS (list of input folders), OUTPUT_DIR (write results here), PARAMS (task parameters). "
                "Use the csv module or pandas if installed. Never modify files in INPUT_DIRS. Print a short summary of what you produced.",
                schema({"code": {"type": "string"}}),
                _run_python,
                self.name,
            )
        ]
