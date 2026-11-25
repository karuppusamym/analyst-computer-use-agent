"""The "what I checked" report that comes with every result."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .audit import AuditLog
    from .config import Settings
    from .orchestrator import TaskResult

_ICON = {"verified": "OK", "failed": "FAILED", "skipped": "SKIPPED", "rejected": "DECLINED", "blocked": "BLOCKED", "pending": "NOT RUN"}


def write_report(result: "TaskResult", request: str, settings: "Settings", audit: "AuditLog") -> Path:
    lines = [
        "# Task report",
        "",
        f"- Request: {request}",
        f"- Status: **{result.status.upper()}**",
        f"- Session: {result.session_id} (audit log: {audit.path})",
        f"- Model calls: {result.usage.get('calls', 0)}, tokens in/out: {result.usage.get('input_tokens', 0)}/{result.usage.get('output_tokens', 0)}",
        "",
        "## Steps",
        "",
        "| # | Step | Tier | Result | Attempts |",
        "| --- | --- | --- | --- | --- |",
    ]
    for i, r in enumerate(result.records, 1):
        tier = r.tier_used or r.step.tier
        if r.route_note:
            tier += " (fallback)"
        lines.append(f"| {i} | {r.step.intent} | {tier} | {_ICON.get(r.status, r.status)} | {r.attempts} |")
    lines += ["", "## What I checked", ""]
    for r in result.records:
        if not r.verdict:
            continue
        lines.append(f"**{r.step.intent}**")
        for o in r.verdict.outcomes:
            lines.append(f"- [{'PASS' if o.passed else 'FAIL'}] {o.name} - {o.detail}" + (" (judged by verifier model)" if o.kind == "model" else ""))
        if r.verdict.problems:
            lines.append(f"- Verifier notes: {r.verdict.problems}")
        lines.append("")
    if result.final:
        lines.append("**Final output**")
        for o in result.final.outcomes:
            lines.append(f"- [{'PASS' if o.passed else 'FAIL'}] {o.name} - {o.detail}")
        lines.append("")
    if result.approvals:
        lines += ["## Approvals", ""] + [f"- {a['step']}: {a['action']} - {'approved' if a['approved'] else 'declined'} by {a['by']}" for a in result.approvals] + [""]
    files = sorted({f for r in result.records for f in r.files})
    if files:
        lines += ["## Files produced", ""] + [f"- {f}" for f in files] + [""]
    not_done = [r for r in result.records if r.status != "verified"]
    if not_done:
        lines += ["## Not done", ""] + [f"- {r.step.intent}: {r.summary[:400] or r.status}" for r in not_done] + [""]
    if result.questions:
        lines += ["## Questions for you", ""] + [f"- {q}" for q in result.questions] + [""]
    from .audit import redact

    text = redact("\n".join(lines), audit)  # vault values -> [REDACTED:name]
    path = audit.dir / "report.md"
    path.write_text(text, encoding="utf-8")
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    (settings.output_dir / f"report-{result.session_id}.md").write_text(text, encoding="utf-8")
    return path
