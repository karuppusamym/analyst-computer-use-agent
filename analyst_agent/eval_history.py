"""Eval history: one summary row per `eval` run, trend and compare views, and an HTML report.

  python -m analyst_agent eval                      runs the set, appends a row, writes the report
  python -m analyst_agent eval history [--last N]   trend table of recent runs
  python -m analyst_agent eval compare <A> <B>      tasks that regressed / improved from run A to run B

Rows go to workspace/evals/history.jsonl (one JSON object per line, append-only).
A run is named by its run id, a unique prefix of it, or a negative index
(-1 = latest, -2 = the one before). Each run also gets a self-contained HTML
report at workspace/evals/<run-id>.html (inline CSS, light and dark, no CDN).
"""

from __future__ import annotations

import html
import json
import os
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings

PILOT_KEYS = (
    "tasks", "graded_tasks", "skipped_tasks", "task_success_rate", "safety_task_success_rate",
    "verified_wrong_rate", "unapproved_outbound_actions", "human_interventions_per_task",
    "cost_per_successful_task_usd", "manual_minutes_covered", "pilot_gate_met",
)


def evals_dir(settings: Settings) -> Path:
    return settings.workspace_root / "evals"


def history_path(settings: Settings) -> Path:
    return evals_dir(settings) / "history.jsonl"


def git_info(root: str | Path) -> tuple[str, bool]:
    """(short commit, dirty) of the checkout at root; ("", False) without git."""
    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=str(root), capture_output=True, text=True, timeout=10, check=True).stdout.strip()

    try:
        commit = git("rev-parse", "--short=12", "HEAD")
    except (OSError, subprocess.SubprocessError):
        return "", False
    try:
        dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    except (OSError, subprocess.SubprocessError):
        dirty = False
    return commit, dirty


def _graded(o) -> str:
    return "skip" if not o.ran else "pass" if o.graded_pass else "fail"


def make_row(settings: Settings, outcomes: list, summary: dict, config_name: str = "default", root: str | Path | None = None,
             split: str | None = None, workflow: str | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    commit, dirty = git_info(root) if root else ("", False)
    run_id = now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)
    models = {role: (spec or {}).get("model", "") for role, spec in (settings.data.get("models") or {}).items()}
    return {
        "run_id": run_id,
        "timestamp": now.isoformat(timespec="seconds"),
        "git_commit": commit,
        "git_dirty": dirty,
        "config": config_name,
        "models": models,
        "split": split or "all",
        "workflow": workflow or "",
        "tasks": [
            {"id": o.task_id, "workflow": o.workflow, "split": o.split, "status": o.status, "graded": _graded(o),
             "cost_usd": round(o.cost_usd, 6), "seconds": round(o.seconds, 2), "safety": o.safety,
             **({"skipped": o.skipped} if o.skipped else {}),
             **({"failures": [d for d in o.grader_details if d.startswith("[FAIL")][:10]} if o.ran and not o.graded_pass else {})}
            for o in outcomes
        ],
        "pilot": {k: summary.get(k) for k in PILOT_KEYS},
        "by_workflow": summary.get("by_workflow", {}),
    }


def append_history(settings: Settings, row: dict) -> Path:
    path = history_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return path


def load_history(settings: Settings) -> list[dict]:
    path = history_path(settings)
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue  # a torn last line from a crash is skipped, not fatal
        if isinstance(row, dict) and row.get("run_id"):
            rows.append(row)
    return rows


def find_run(rows: list[dict], ref: str) -> dict:
    """By run id, unique prefix, or negative index (-1 = latest)."""
    if not rows:
        raise LookupError("no eval history yet; run `python -m analyst_agent eval` first")
    try:
        n = int(ref)
        if n < 0:
            return rows[n]
    except ValueError:
        pass
    except IndexError:
        raise LookupError(f"only {len(rows)} runs in the history") from None
    exact = [r for r in rows if r["run_id"] == ref]
    if exact:
        return exact[-1]
    hits = [r for r in rows if r["run_id"].startswith(ref)]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise LookupError(f"no run {ref!r} in the history")
    raise LookupError(f"{ref!r} matches {len(hits)} runs; give more of the id")


def _pct(v: Any) -> str:
    return "-" if v is None else f"{v * 100:.0f}%"


def _money(v: Any) -> str:
    return "-" if v is None else f"${v:.4f}"


def _counts(row: dict) -> dict[str, int]:
    c = {"pass": 0, "fail": 0, "skip": 0}
    for t in row.get("tasks", []):
        c[t.get("graded", "skip")] = c.get(t.get("graded", "skip"), 0) + 1
    return c


def format_history(rows: list[dict], last: int = 10) -> str:
    if not rows:
        return "no eval history yet; run `python -m analyst_agent eval` first"
    shown = rows[-last:] if last and last > 0 else rows
    head = f"{'run':<26} {'when (UTC)':<17} {'commit':<14} {'config':<12} {'split':<8} {'pass':>4} {'fail':>4} {'skip':>4} {'success':>8} {'unappr':>6} {'$/success':>10} {'gate':<4}  {'change':<8}"
    lines = [head, "-" * len(head)]
    prev_rate = None
    start = len(rows) - len(shown)
    if start > 0:
        prev_rate = rows[start - 1].get("pilot", {}).get("task_success_rate")
    for r in shown:
        p, c = r.get("pilot", {}), _counts(r)
        rate = p.get("task_success_rate")
        change = "" if prev_rate is None or rate is None else ("=" if abs(rate - prev_rate) < 1e-9 else f"{(rate - prev_rate) * 100:+.0f}pt")
        prev_rate = rate if rate is not None else prev_rate
        commit = (r.get("git_commit") or "-") + ("*" if r.get("git_dirty") else "")
        lines.append(
            f"{r['run_id']:<26} {r.get('timestamp', '')[:16].replace('T', ' '):<17} {commit:<14} {str(r.get('config', ''))[:12]:<12} {str(r.get('split', ''))[:8]:<8} "
            f"{c['pass']:>4} {c['fail']:>4} {c['skip']:>4} {_pct(rate):>8} {p.get('unapproved_outbound_actions', 0) or 0:>6} "
            f"{_money(p.get('cost_per_successful_task_usd')):>10} {'yes' if p.get('pilot_gate_met') else 'no':<4}  {change:<8}"
        )
    lines.append(f"\n{len(shown)} of {len(rows)} runs shown; * = uncommitted changes at run time")
    return "\n".join(lines)


def compare(a: dict, b: dict) -> dict:
    """Task-level differences from run a to run b."""
    ta = {t["id"]: t for t in a.get("tasks", [])}
    tb = {t["id"]: t for t in b.get("tasks", [])}
    out: dict[str, list] = {"regressed": [], "improved": [], "newly_skipped": [], "newly_graded": [], "status_changed": [], "only_in_a": [], "only_in_b": []}
    for tid in sorted(set(ta) | set(tb)):
        x, y = ta.get(tid), tb.get(tid)
        if x is None:
            out["only_in_b"].append(tid)
            continue
        if y is None:
            out["only_in_a"].append(tid)
            continue
        gx, gy = x.get("graded"), y.get("graded")
        item = {"id": tid, "workflow": y.get("workflow", ""), "a": gx, "b": gy, "a_status": x.get("status"), "b_status": y.get("status"),
                "cost_delta_usd": round((y.get("cost_usd") or 0) - (x.get("cost_usd") or 0), 6)}
        if gx == "pass" and gy == "fail":
            out["regressed"].append(item | ({"failures": y["failures"]} if y.get("failures") else {}))
        elif gx == "fail" and gy == "pass":
            out["improved"].append(item)
        elif gx != "skip" and gy == "skip":
            out["newly_skipped"].append(item)
        elif gx == "skip" and gy != "skip":
            out["newly_graded"].append(item)
        elif x.get("status") != y.get("status"):
            out["status_changed"].append(item)
    pa, pb = a.get("pilot", {}), b.get("pilot", {})
    out["pilot"] = {k: {"a": pa.get(k), "b": pb.get(k)} for k in PILOT_KEYS if pa.get(k) != pb.get(k)}
    return out


def format_compare(a: dict, b: dict, diff: dict) -> str:
    lines = [f"A: {a['run_id']}  commit {a.get('git_commit') or '-'}  config {a.get('config')}",
             f"B: {b['run_id']}  commit {b.get('git_commit') or '-'}  config {b.get('config')}", ""]
    if a.get("models") != b.get("models"):
        changed = {k: f"{(a.get('models') or {}).get(k)} -> {(b.get('models') or {}).get(k)}" for k in sorted(set(a.get("models") or {}) | set(b.get("models") or {})) if (a.get("models") or {}).get(k) != (b.get("models") or {}).get(k)}
        lines.append("models changed: " + ", ".join(f"{k}: {v}" for k, v in changed.items()))
        lines.append("")
    labels = [("regressed", "REGRESSED (pass -> fail)"), ("improved", "IMPROVED (fail -> pass)"), ("newly_skipped", "newly skipped"),
              ("newly_graded", "newly graded"), ("status_changed", "status changed, same grade")]
    for key, title in labels:
        items = diff[key]
        lines.append(f"{title}: {len(items)}")
        for it in items:
            lines.append(f"  {it['id']:<34} {it['a']:<4} -> {it['b']:<4}  status {it['a_status']} -> {it['b_status']}")
            lines += [f"      {f}" for f in it.get("failures", [])[:3]]
    for key, title in (("only_in_a", "only in A"), ("only_in_b", "only in B")):
        if diff[key]:
            lines.append(f"{title}: {', '.join(diff[key])}")
    if diff["pilot"]:
        lines.append("")
        lines.append("pilot metrics:")
        for k, v in diff["pilot"].items():
            lines.append(f"  {k:<32} {v['a']} -> {v['b']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- HTML report
_CSS = """
:root { --bg: #ffffff; --fg: #1d1f23; --muted: #5d6470; --line: #dde1e7; --card: #f5f7fa;
        --pass: #1a7f37; --pass-bg: #e6f4ea; --fail: #b42318; --fail-bg: #fdecea; --skip: #6b6f76; --skip-bg: #eef0f3; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #15171b; --fg: #e6e8eb; --muted: #9aa1ac; --line: #2c3038; --card: #1d2026;
          --pass: #5fd07a; --pass-bg: #173322; --fail: #ff8a80; --fail-bg: #3a1c1a; --skip: #a2a7ae; --skip-bg: #262a31; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 28px 0 8px; }
.meta { color: var(--muted); margin: 0 0 16px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.card b { display: block; font-size: 20px; } .card span { color: var(--muted); font-size: 12px; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.pass { color: var(--pass); background: var(--pass-bg); } .fail { color: var(--fail); background: var(--fail-bg); } .skip { color: var(--skip); background: var(--skip-bg); }
.detail { color: var(--muted); font-size: 12px; white-space: pre-wrap; word-break: break-word; }
"""


def render_html(row: dict) -> str:
    e = html.escape
    p, c = row.get("pilot", {}), _counts(row)
    cards = [
        ("task success", _pct(p.get("task_success_rate"))),
        ("graded / skipped", f"{p.get('graded_tasks', 0)} / {p.get('skipped_tasks', 0)}"),
        ("passed / failed", f"{c['pass']} / {c['fail']}"),
        ("safety task success", _pct(p.get("safety_task_success_rate"))),
        ("verified-wrong rate", _pct(p.get("verified_wrong_rate"))),
        ("unapproved outbound", str(p.get("unapproved_outbound_actions", 0))),
        ("interventions / task", f"{(p.get('human_interventions_per_task') or 0):.2f}"),
        ("cost / success", _money(p.get("cost_per_successful_task_usd"))),
        ("manual minutes covered", f"{p.get('manual_minutes_covered') or 0:g}"),
        ("pilot gate", "met" if p.get("pilot_gate_met") else "not met"),
    ]
    rows_html = []
    for t in row.get("tasks", []):
        g = t.get("graded", "skip")
        detail = t.get("skipped") or "\n".join(t.get("failures", []))
        badge = " <span class='pill skip'>safety</span>" if t.get("safety") else ""
        rows_html.append(
            f"<tr><td>{e(t['id'])}{badge}</td><td>{e(t.get('workflow', ''))}</td><td>{e(t.get('split', ''))}</td>"
            f"<td>{e(str(t.get('status', '')))}</td><td><span class='pill {e(g)}'>{e(g.upper())}</span></td>"
            f"<td class='num'>{t.get('seconds', 0):.1f}</td><td class='num'>{t.get('cost_usd', 0):.4f}</td>"
            f"<td class='detail'>{e(detail)}</td></tr>"
        )
    wf = "".join(f"<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>" for k, v in (row.get("by_workflow") or {}).items())
    models = ", ".join(f"{e(k)}: {e(str(v))}" for k, v in (row.get("models") or {}).items())
    commit = e(row.get("git_commit") or "no git") + (" (uncommitted changes)" if row.get("git_dirty") else "")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'>"
        f"<title>Eval run {e(row['run_id'])}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>Eval run {e(row['run_id'])}</h1>"
        f"<p class='meta'>{e(row.get('timestamp', ''))} &middot; commit {commit} &middot; config {e(str(row.get('config', '')))} &middot; split {e(str(row.get('split', '')))}"
        f"{(' &middot; workflow ' + e(row['workflow'])) if row.get('workflow') else ''}<br>models: {models}</p>"
        "<div class='cards'>" + "".join(f"<div class='card'><b>{e(v)}</b><span>{e(k)}</span></div>" for k, v in cards) + "</div>"
        "<h2>By workflow</h2><div class='wrap'><table><thead><tr><th>workflow</th><th>result</th></tr></thead><tbody>" + wf + "</tbody></table></div>"
        "<h2>Tasks</h2><div class='wrap'><table><thead><tr><th>task</th><th>workflow</th><th>split</th><th>status</th><th>graded</th><th>sec</th><th>cost $</th><th>details</th></tr></thead><tbody>"
        + "".join(rows_html) + "</tbody></table></div></main></body></html>\n"
    )


def write_html(settings: Settings, row: dict) -> Path:
    path = evals_dir(settings) / f"{row['run_id']}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".html.tmp")
    tmp.write_text(render_html(row), encoding="utf-8")
    os.replace(tmp, path)
    return path


def record_run(settings: Settings, outcomes: list, summary: dict, config_name: str = "default", root: str | Path | None = None,
               split: str | None = None, workflow: str | None = None) -> tuple[dict, Path, Path]:
    """Append the run to the history and write its HTML report. Returns (row, history path, report path)."""
    row = make_row(settings, outcomes, summary, config_name=config_name, root=root, split=split, workflow=workflow)
    return row, append_history(settings, row), write_html(settings, row)


def cli(args, settings: Settings) -> int:
    rows = load_history(settings)
    if args.action == "history":
        print(format_history(rows, last=args.last))
        return 0
    if args.action == "compare":
        if len(args.runs) != 2:
            print("usage: eval compare <runA> <runB>   (run id, unique prefix, or -1 for the latest)")
            return 2
        try:
            a, b = find_run(rows, args.runs[0]), find_run(rows, args.runs[1])
        except LookupError as e:
            print(f"error: {e}")
            return 2
        diff = compare(a, b)
        print(format_compare(a, b, diff))
        return 1 if diff["regressed"] else 0
    return 2
