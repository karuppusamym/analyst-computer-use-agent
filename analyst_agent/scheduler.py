"""Schedules: run playbooks unattended on a cron timetable.

  schedule list | add | remove | run-due [--now ISO] | daemon [--interval 60] | install-hint

Definitions live in config/schedules.json (settings `schedules.path`):

  {"schedules": [{"id": "monthly-recon", "playbook": "erp-crm-reconciliation",
                  "params": {"period": "{{prev_month}}"}, "cron": "0 7 2 * *",
                  "timezone": "Europe/London", "enabled": true, "owner": "finance-analytics",
                  "notify": "workspace/output/schedule-notes/monthly-recon.md"}]}

run-due fires every schedule whose next time has passed, UNATTENDED: approvals are
declined and reported (UnattendedApprover; nothing is auto-approved). A lock file
stops overlapping runs. A missed slot runs once, never a catch-up series.
State and history live in workspace/schedules/ (state.json, history.jsonl).

The cron parser is our own (stdlib only): 5 fields, `*`, lists, ranges, steps,
month/day names, @hourly/@daily/@weekly/@monthly/@yearly, and Vixie-cron
day-of-month/day-of-week OR semantics (if both fields are restricted, a day
matches when EITHER matches; if either starts with `*`, both must match).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable

from .config import Settings

# --------------------------------------------------------------------------- cron


class CronError(ValueError):
    pass


_MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
_DAYS = {d: i for i, d in enumerate(["sun", "mon", "tue", "wed", "thu", "fri", "sat"])}
_MACROS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}
# name, low, high, names
_FIELDS = [("minute", 0, 59, {}), ("hour", 0, 23, {}), ("day of month", 1, 31, {}), ("month", 1, 12, _MONTHS), ("day of week", 0, 7, _DAYS)]


def _value(token: str, fname: str, lo: int, hi: int, names: dict) -> int:
    t = token.strip().lower()
    if t in names:
        return names[t]
    if not t.isdigit():
        raise CronError(f"{fname}: {token!r} is not a number" + (f" or a name ({', '.join(names)})" if names else ""))
    v = int(t)
    if not lo <= v <= hi:
        raise CronError(f"{fname}: {v} is out of range {lo}-{hi}")
    return v


def parse_field(text: str, fname: str, lo: int, hi: int, names: dict | None = None) -> set[int]:
    names = names or {}
    if not text:
        raise CronError(f"{fname}: empty field")
    out: set[int] = set()
    for item in text.split(","):
        if not item:
            raise CronError(f"{fname}: empty list item in {text!r}")
        rng, _, step_s = item.partition("/")
        if _:
            if not step_s.isdigit() or int(step_s) < 1:
                raise CronError(f"{fname}: step {step_s!r} must be a positive number")
            step = int(step_s)
        else:
            step = 1
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            a_s, b_s = rng.split("-", 1)
            a, b = _value(a_s, fname, lo, hi, names), _value(b_s, fname, lo, hi, names)
            if a > b:
                raise CronError(f"{fname}: range {rng!r} goes backwards")
        else:
            a = _value(rng, fname, lo, hi, names)
            b = hi if _ else a  # "5/15" means 5-max every 15 (Vixie)
        out.update(range(a, b + 1, step))
    return out


@dataclass
class CronExpr:
    expr: str
    minutes: set[int] = field(default_factory=set)
    hours: set[int] = field(default_factory=set)
    doms: set[int] = field(default_factory=set)
    months: set[int] = field(default_factory=set)
    dows: set[int] = field(default_factory=set)
    dom_star: bool = True
    dow_star: bool = True

    @classmethod
    def parse(cls, expr: str) -> "CronExpr":
        if not isinstance(expr, str) or not expr.strip():
            raise CronError("empty cron expression")
        text = expr.strip()
        if text.startswith("@"):
            if text.lower() not in _MACROS:
                raise CronError(f"unsupported macro {text!r} (use {', '.join(_MACROS)})")
            text = _MACROS[text.lower()]
        parts = text.split()
        if len(parts) != 5:
            raise CronError(f"cron needs 5 fields (minute hour day-of-month month day-of-week), got {len(parts)}: {expr!r}")
        sets = [parse_field(p, n, lo, hi, names) for p, (n, lo, hi, names) in zip(parts, _FIELDS)]
        dows = {0 if d == 7 else d for d in sets[4]}
        c = cls(expr, sets[0], sets[1], sets[2], sets[3], dows, parts[2].startswith("*"), parts[4].startswith("*"))
        if not c._can_ever_fire():
            raise CronError(f"{expr!r} can never fire (no month has that day)")
        return c

    def _can_ever_fire(self) -> bool:
        if not (self.dom_star or self.dow_star) or self.dom_star:
            return True  # OR semantics, or only dow restricts: some day always exists
        longest = {1: 31, 2: 29, 3: 31, 4: 30, 5: 31, 6: 30, 7: 31, 8: 31, 9: 30, 10: 31, 11: 30, 12: 31}
        return any(min(self.doms) <= longest[m] for m in self.months)

    def day_matches(self, d: date) -> bool:
        dom_ok = d.day in self.doms
        dow_ok = (d.isoweekday() % 7) in self.dows
        if self.dom_star or self.dow_star:
            return dom_ok and dow_ok
        return dom_ok or dow_ok

    def matches(self, dt: datetime) -> bool:
        """Wall-clock match (dt's own fields)."""
        return dt.minute in self.minutes and dt.hour in self.hours and dt.month in self.months and self.day_matches(dt.date())

    def next_after(self, after: datetime, tz: tzinfo | None = None) -> datetime:
        """The first fire time strictly after `after`, as an aware datetime in `tz`.

        Wall-clock times in `tz`. A time that falls in a DST gap fires at the
        equivalent instant after the jump; a repeated hour fires once (first pass).
        """
        tz = tz or local_tz()
        if after.tzinfo is None:
            after = after.replace(tzinfo=tz)
        after_utc = after.astimezone(timezone.utc)
        cur = after.astimezone(tz).replace(tzinfo=None, second=0, microsecond=0) + timedelta(minutes=1)
        limit = cur.year + 10
        mins, hrs = sorted(self.minutes), sorted(self.hours)
        while cur.year <= limit:
            if cur.month not in self.months:
                cur = (cur.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self.day_matches(cur.date()):
                cur = cur.replace(hour=0, minute=0) + timedelta(days=1)
                continue
            if cur.hour not in self.hours:
                nh = next((h for h in hrs if h > cur.hour), None)
                cur = cur.replace(hour=nh, minute=0) if nh is not None else cur.replace(hour=0, minute=0) + timedelta(days=1)
                continue
            if cur.minute not in self.minutes:
                nm = next((m for m in mins if m > cur.minute), None)
                cur = cur.replace(minute=nm) if nm is not None else cur.replace(minute=0) + timedelta(hours=1)
                continue
            aware = cur.replace(tzinfo=tz).astimezone(timezone.utc)
            if aware > after_utc:
                return aware.astimezone(tz)
            cur += timedelta(minutes=1)
        raise CronError(f"{self.expr!r} does not fire within 10 years")

    def latest_at_or_before(self, now: datetime, tz: tzinfo, not_before: datetime) -> datetime | None:
        """The most recent fire time in (not_before, now], or None."""
        first = self.next_after(not_before, tz)
        if first > now:
            return None
        for window in (timedelta(hours=2), timedelta(days=2), timedelta(days=40), timedelta(days=400), timedelta(days=4000)):
            start = max(not_before, now - window)
            try:
                s = self.next_after(start, tz)
            except CronError:
                break
            if s <= now:
                last = s
                for _ in range(200000):
                    n = self.next_after(last, tz)
                    if n > now:
                        return last
                    last = n
                return last
        return first


# --------------------------------------------------------------------------- time zones and date macros


def local_tz() -> tzinfo:
    return datetime.now().astimezone().tzinfo or timezone.utc


_TZ_WARNED: set[str] = set()


def resolve_tz(name: str | None) -> tuple[tzinfo, str]:
    """(tzinfo, warning). Falls back to local time when tzdata is missing."""
    if not name or name.lower() == "local":
        return local_tz(), ""
    if name.upper() in ("UTC", "Z", "ETC/UTC", "GMT"):
        return timezone.utc, ""
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones
    except ImportError:  # pragma: no cover - py<3.9
        return local_tz(), f"zoneinfo unavailable; using local time for {name}"
    try:
        return ZoneInfo(name), ""
    except (ZoneInfoNotFoundError, ValueError, OSError):
        if available_timezones():
            raise ScheduleError(f"unknown time zone {name!r}")
        return local_tz(), f"time zone {name!r} unavailable (install tzdata: pip install tzdata); using local time"


def _quarter_bounds(d: date) -> tuple[date, date]:
    q0 = 3 * ((d.month - 1) // 3) + 1
    start = date(d.year, q0, 1)
    end = (date(d.year + 1, 1, 1) if q0 == 10 else date(d.year, q0 + 3, 1)) - timedelta(days=1)
    return start, end


def date_macros(ref: date) -> dict[str, str]:
    first = ref.replace(day=1)
    prev_end = first - timedelta(days=1)
    prev_start = prev_end.replace(day=1)
    qs, qe = _quarter_bounds(ref)
    pqs, pqe = _quarter_bounds(qs - timedelta(days=1))
    return {
        "today": ref.isoformat(),
        "yesterday": (ref - timedelta(days=1)).isoformat(),
        "this_month": ref.strftime("%Y-%m"),
        "prev_month": prev_start.strftime("%Y-%m"),
        "prev_month_start": prev_start.isoformat(),
        "prev_month_end": prev_end.isoformat(),
        "quarter_start": qs.isoformat(),
        "quarter_end": qe.isoformat(),
        "prev_quarter_start": pqs.isoformat(),
        "prev_quarter_end": pqe.isoformat(),
        "quarter": f"{qs.year}-Q{(qs.month - 1) // 3 + 1}",
        "prev_quarter": f"{pqs.year}-Q{(pqs.month - 1) // 3 + 1}",
    }


_MACRO_RE = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def resolve_params(params: dict[str, Any], ref: date) -> dict[str, Any]:
    macros = date_macros(ref)

    def sub(m: re.Match) -> str:
        if m.group(1) not in macros:
            raise ScheduleError(f"unknown date macro {{{{{m.group(1)}}}}} (known: {', '.join(sorted(macros))})")
        return macros[m.group(1)]

    return {k: _MACRO_RE.sub(sub, v) if isinstance(v, str) else v for k, v in (params or {}).items()}


# --------------------------------------------------------------------------- schedule definitions


class ScheduleError(ValueError):
    pass


@dataclass
class Schedule:
    id: str
    playbook: str
    cron: str
    params: dict = field(default_factory=dict)
    timezone: str = "local"
    enabled: bool = True
    owner: str = ""
    notify: str = ""
    request: str = ""
    created_at: str = ""

    @property
    def expr(self) -> CronExpr:
        return CronExpr.parse(self.cron)

    def to_dict(self) -> dict:
        d = {"id": self.id, "playbook": self.playbook, "params": self.params, "cron": self.cron, "timezone": self.timezone, "enabled": self.enabled, "owner": self.owner}
        for k in ("notify", "request", "created_at"):
            if getattr(self, k):
                d[k] = getattr(self, k)
        return d


_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}")


def schedule_from_dict(d: dict) -> Schedule:
    if not isinstance(d, dict):
        raise ScheduleError("schedule entry must be an object")
    for key in ("id", "playbook", "cron"):
        if not d.get(key):
            raise ScheduleError(f"schedule entry is missing '{key}': {d}")
    if not _ID_RE.fullmatch(str(d["id"])):
        raise ScheduleError(f"invalid schedule id {d['id']!r}")
    if not isinstance(d.get("params", {}), dict):
        raise ScheduleError(f"{d['id']}: params must be an object")
    s = Schedule(
        id=str(d["id"]), playbook=str(d["playbook"]), cron=str(d["cron"]), params=dict(d.get("params") or {}),
        timezone=str(d.get("timezone") or "local"), enabled=bool(d.get("enabled", True)), owner=str(d.get("owner", "")),
        notify=str(d.get("notify") or ""), request=str(d.get("request") or ""), created_at=str(d.get("created_at") or ""),
    )
    try:
        s.expr
    except CronError as e:
        raise ScheduleError(f"{s.id}: {e}") from e
    return s


def load_schedules(path: Path) -> list[Schedule]:
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8") or "{}")
    entries = raw.get("schedules", []) if isinstance(raw, dict) else raw
    out, seen = [], set()
    for d in entries:
        s = schedule_from_dict(d)
        if s.id in seen:
            raise ScheduleError(f"duplicate schedule id {s.id}")
        seen.add(s.id)
        out.append(s)
    return out


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_schedules(path: Path, schedules: list[Schedule]) -> None:
    _atomic_write(path, json.dumps({"schedules": [s.to_dict() for s in schedules]}, indent=2) + "\n")


# --------------------------------------------------------------------------- state, history, lock


class LockBusy(RuntimeError):
    pass


class RunLock:
    """Exclusive lock file. A lock older than `stale_s` (a crashed run) is broken."""

    def __init__(self, path: Path, stale_s: float = 7200):
        self.path = path
        self.stale_s = stale_s
        self.held = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age > self.stale_s:
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise LockBusy(f"another run-due holds {self.path} (for {int(age)}s)")
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"pid": os.getpid(), "since": datetime.now(timezone.utc).isoformat()}))
            self.held = True
            return
        raise LockBusy(f"could not take {self.path}")

    def release(self) -> None:
        if self.held:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self.held = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


class ScheduleStore:
    def __init__(self, settings: Settings):
        cfg = settings.data.get("schedules", {})
        self.settings = settings
        self.path = settings.path(cfg.get("path", "./config/schedules.json"))
        self.dir = settings.path(cfg.get("state_dir", "./workspace/schedules"))
        self.state_path = self.dir / "state.json"
        self.history_path = self.dir / "history.jsonl"
        self.lock = RunLock(self.dir / "run-due.lock", float(cfg.get("lock_stale_s", 7200)))

    def schedules(self) -> list[Schedule]:
        return load_schedules(self.path)

    def save(self, schedules: list[Schedule]) -> None:
        save_schedules(self.path, schedules)

    def state(self) -> dict:
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8")).get("schedules", {})
        except (json.JSONDecodeError, AttributeError):
            return {}

    def save_state(self, state: dict) -> None:
        _atomic_write(self.state_path, json.dumps({"schedules": state}, indent=2) + "\n")

    def append_history(self, record: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def history(self) -> list[dict]:
        if not self.history_path.exists():
            return []
        return [json.loads(x) for x in self.history_path.read_text(encoding="utf-8").splitlines() if x.strip()]


# --------------------------------------------------------------------------- running


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def parse_when(text: str) -> datetime:
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    dt = datetime.fromisoformat(t)
    return dt if dt.tzinfo else dt.astimezone()  # naive = local time


def default_runner(settings: Settings, playbooks_dir: Path, knowledge_dir: Path | None = None) -> Callable:
    """Runs one schedule with the real orchestrator, unattended."""

    def run(schedule: Schedule, playbook, params: dict):
        from .orchestrator import Orchestrator
        from .policy import UnattendedApprover

        orch = Orchestrator(settings, approver=UnattendedApprover(), user=f"schedule:{schedule.owner or schedule.id}", ask=None, knowledge_dir=knowledge_dir, require_plan_approval=False)
        try:
            return orch.run(schedule.request or f"Scheduled run '{schedule.id}' of {playbook.name}", playbook=playbook, params=params)
        finally:
            orch.router.close()

    return run


def _notify(settings: Settings, schedule: Schedule, record: dict, result) -> str:
    from .policy import PolicyEngine, PolicyViolation

    try:
        path = PolicyEngine(settings).check_path(schedule.notify, write=True)
    except PolicyViolation as e:
        return f"notify refused: {e}"
    lines = [
        f"# Scheduled run: {schedule.id}",
        "",
        f"- playbook: {schedule.playbook}",
        f"- scheduled for: {record['scheduled_for']}",
        f"- fired at: {record['fired_at']}",
        f"- status: {record['status']}",
        f"- session: {record.get('session_id') or '-'}",
        f"- params: {json.dumps(record.get('params', {}))}",
    ]
    if record.get("missed"):
        lines.append(f"- missed slots: ran once for the latest slot (first missed {record['first_missed']})")
    if record.get("error"):
        lines.append(f"- error: {record['error']}")
    if result is not None:
        if getattr(result, "report_path", ""):
            lines.append(f"- report: {result.report_path}")
        lines += ["", "Steps:"] + [f"- [{r.status}] {r.step.id}: {r.summary[:200]}" for r in getattr(result, "records", [])]
        if getattr(result, "approvals", None):
            lines += ["", "Approvals (unattended: never auto-approved):"] + [f"- {a['step']}: {'approved' if a['approved'] else 'declined'} by {a['by']}" for a in result.approvals]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def run_due(settings: Settings, playbooks_dir: Path, now: datetime | None = None, runner: Callable | None = None, knowledge_dir: Path | None = None, log: Callable[[str], None] = print) -> list[dict]:
    """Fire every enabled schedule that is due at `now`. Returns the history records written."""
    from .playbook import PlaybookError, PlaybookRegistry

    store = ScheduleStore(settings)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    runner = runner or default_runner(settings, playbooks_dir, knowledge_dir)
    records: list[dict] = []
    try:
        store.lock.acquire()
    except LockBusy as e:
        log(f"skipped: {e}")
        return records
    try:
        registry = PlaybookRegistry(playbooks_dir)  # drafts are never run
        state = store.state()
        for sch in store.schedules():
            if not sch.enabled:
                continue
            st = dict(state.get(sch.id, {}))
            try:
                tz, warn = resolve_tz(sch.timezone)
            except ScheduleError as e:
                log(f"{sch.id}: {e}")
                continue
            if warn and sch.timezone not in _TZ_WARNED:
                _TZ_WARNED.add(sch.timezone)
                log(f"{sch.id}: {warn}")
            base_s = st.get("last_slot") or sch.created_at
            if not base_s:
                st.update(last_slot=_iso(now), note="first seen; fires from the next slot")
                state[sch.id] = st
                store.save_state(state)
                continue
            try:
                base = parse_when(base_s)
                expr = sch.expr
                first = expr.next_after(base, tz)
                if first > now:
                    continue
                slot = expr.latest_at_or_before(now, tz, base) or first
            except (CronError, ValueError) as e:
                log(f"{sch.id}: cannot compute the next fire time: {e}")
                continue
            missed = slot != first
            # Record the slot BEFORE running: a crash never causes a repeat run.
            st.update(last_slot=_iso(slot), last_fired_at=_iso(now), last_status="running")
            state[sch.id] = st
            store.save_state(state)
            local_slot = slot.astimezone(tz)
            record: dict[str, Any] = {
                "schedule_id": sch.id, "playbook": sch.playbook, "owner": sch.owner,
                "scheduled_for": _iso(local_slot), "fired_at": _iso(now.astimezone(tz)),
                "missed": missed, "session_id": None, "status": "error",
            }
            if missed:
                record["first_missed"] = _iso(first.astimezone(tz))
            result = None
            try:
                params = resolve_params(sch.params, local_slot.date())
                record["params"] = params
                pb = registry.get(sch.playbook)
                pb.bind(params)  # missing parameters fail here; nobody is present to answer questions
                log(f"{sch.id}: firing {pb.name} for {record['scheduled_for']}" + (" (missed slots: running once)" if missed else ""))
                result = runner(sch, pb, params)
                record["session_id"] = result.session_id
                record["status"] = result.status
                record["steps"] = {r.step.id: r.status for r in result.records}
                if result.report_path:
                    record["report"] = result.report_path
            except (PlaybookError, ScheduleError) as e:
                record["status"] = "invalid"
                record["error"] = str(e)
            except Exception as e:  # a broken run is recorded, never retried in a loop
                record["error"] = f"{type(e).__name__}: {e}"
            if sch.notify:
                record["notify"] = _notify(settings, sch, record, result)
            store.append_history(record)
            records.append(record)
            st.update(last_status=record["status"], last_session=record["session_id"])
            state[sch.id] = st
            store.save_state(state)
            log(f"{sch.id}: {record['status']}" + (f" session {record['session_id']}" if record["session_id"] else "") + (f" - {record.get('error')}" if record.get("error") else ""))
    finally:
        store.lock.release()
    return records


def next_fires(settings: Settings, now: datetime | None = None) -> list[tuple[Schedule, datetime | None, str]]:
    now = now or datetime.now(timezone.utc)
    out = []
    for sch in ScheduleStore(settings).schedules():
        try:
            tz, warn = resolve_tz(sch.timezone)
            out.append((sch, sch.expr.next_after(now, tz), warn))
        except (ScheduleError, CronError) as e:
            out.append((sch, None, str(e)))
    return out


# --------------------------------------------------------------------------- CLI


def add_cli(sub) -> None:
    sp = sub.add_parser("schedule", help="scheduled unattended playbook runs")
    ss = sp.add_subparsers(dest="schedule_cmd", required=True)
    ss.add_parser("list", help="list schedules with their next fire time")
    a = ss.add_parser("add", help="add a schedule")
    a.add_argument("id")
    a.add_argument("--playbook", required=True)
    a.add_argument("--cron", required=True, help='5 fields, e.g. "0 7 2 * *" (07:00 on the 2nd)')
    a.add_argument("--tz", default="local", help="IANA time zone, e.g. Europe/London (default: local)")
    a.add_argument("--param", action="append", default=[], help="name=value; date macros like {{prev_month}} resolve at fire time")
    a.add_argument("--owner", default="")
    a.add_argument("--notify", default="", help="write a run summary to this workspace path")
    a.add_argument("--request", default="", help="task text recorded with each run")
    a.add_argument("--disabled", action="store_true")
    a.add_argument("--force", action="store_true", help="replace a schedule with the same id")
    r = ss.add_parser("remove", help="remove a schedule")
    r.add_argument("id")
    rd = ss.add_parser("run-due", help="run every due schedule once, unattended")
    rd.add_argument("--now", help="ISO time to treat as now (testing)")
    d = ss.add_parser("daemon", help="call run-due in a loop")
    d.add_argument("--interval", type=int, default=60, help="seconds between checks")
    ss.add_parser("install-hint", help="print a Windows Task Scheduler command that calls run-due every 5 minutes")


def install_hint(root: Path, python: str, config: str | None) -> str:
    """A schtasks command for cmd.exe. Everything after /TR sits inside ONE quoted
    string, so cmd passes `&&` and `>>` to the task instead of acting on them."""
    cfg = str(Path(config).resolve()) if config else ""
    log = root / "workspace" / "schedules" / "run-due.log"
    paths = [str(root), python, str(log)] + ([cfg] if cfg else [])
    if any(" " in x for x in paths):
        wrapper = root / "run-due.cmd"
        body = "\n".join([
            "@echo off",
            f'cd /d "{root}"',
            f'"{python}" -m analyst_agent' + (f' --config "{cfg}"' if cfg else "") + f' schedule run-due >> "{log}" 2>&1',
        ])
        return (
            f"A path contains spaces, so use a wrapper. Save this as {wrapper}:\n\n{body}\n\nthen run:\n"
            f'schtasks /Create /F /SC MINUTE /MO 5 /TN "AnalystAgent\\RunDueSchedules" /TR "\\"{wrapper}\\""'
        )
    run = f"cd /d {root} && {python} -m analyst_agent" + (f" --config {cfg}" if cfg else "") + f" schedule run-due >> {log} 2>&1"
    return f'schtasks /Create /F /SC MINUTE /MO 5 /TN "AnalystAgent\\RunDueSchedules" /TR "cmd /c {run}"'


def cli(args, settings: Settings, root: Path) -> int:
    from .playbook import PlaybookError, PlaybookRegistry

    store = ScheduleStore(settings)
    playbooks = root / "playbooks"
    cmd = args.schedule_cmd
    try:
        if cmd == "list":
            state = store.state()
            rows = next_fires(settings)
            if not rows:
                print(f"no schedules in {store.path}")
            for sch, nxt, note in rows:
                st = state.get(sch.id, {})
                print(f"{sch.id:<24} {'on ' if sch.enabled else 'off'} {sch.cron!r:<18} {sch.timezone:<16} {sch.playbook:<26} next={_iso(nxt) if nxt and sch.enabled else '-':<26} last={st.get('last_status', '-')} {st.get('last_fired_at', '')}")
                if note:
                    print(f"    note: {note}")
            return 0
        if cmd == "add":
            schedules = store.schedules()
            if any(s.id == args.id for s in schedules) and not args.force:
                print(f"error: schedule {args.id} exists (use --force to replace)")
                return 1
            try:
                PlaybookRegistry(playbooks).get(args.playbook)
            except PlaybookError as e:
                print(f"error: {e}")
                return 1
            tz, warn = resolve_tz(args.tz)
            params = dict(p.split("=", 1) for p in args.param)
            resolve_params(params, date.today())  # rejects unknown macros now, not at 7am
            sch = schedule_from_dict({"id": args.id, "playbook": args.playbook, "cron": args.cron, "timezone": args.tz, "params": params, "owner": args.owner, "notify": args.notify, "request": args.request, "enabled": not args.disabled, "created_at": _iso(datetime.now(timezone.utc))})
            store.save([s for s in schedules if s.id != args.id] + [sch])
            print(f"added {sch.id}: next fire {_iso(sch.expr.next_after(datetime.now(timezone.utc), tz))}" + (f"  ({warn})" if warn else ""))
            return 0
        if cmd == "remove":
            schedules = store.schedules()
            if not any(s.id == args.id for s in schedules):
                print(f"no schedule {args.id}")
                return 1
            store.save([s for s in schedules if s.id != args.id])
            state = store.state()
            if state.pop(args.id, None) is not None:
                store.save_state(state)
            print(f"removed {args.id}")
            return 0
        if cmd == "run-due":
            now = parse_when(args.now) if args.now else None
            recs = run_due(settings, playbooks, now=now, knowledge_dir=root / "knowledge")
            if not recs:
                print("nothing due")
            return 0 if all(r["status"] in ("success", "partial") for r in recs) else 1
        if cmd == "daemon":
            print(f"schedule daemon: checking every {args.interval}s (Ctrl+C to stop)")
            try:
                while True:
                    try:
                        run_due(settings, playbooks, knowledge_dir=root / "knowledge")
                    except Exception as e:  # keep the daemon alive; the error is printed
                        print(f"run-due failed: {type(e).__name__}: {e}")
                    time.sleep(max(5, args.interval))
            except KeyboardInterrupt:
                print("daemon stopped")
                return 0
        if cmd == "install-hint":
            print("Run this once in an elevated or normal cmd.exe prompt (it calls run-due every 5 minutes):\n")
            print(install_hint(root, sys.executable, getattr(args, "config", None)))
            print("\nAdd /RU <account> to run when nobody is logged on. Remove with: schtasks /Delete /TN \"AnalystAgent\\RunDueSchedules\" /F")
            return 0
    except (ScheduleError, CronError, json.JSONDecodeError) as e:
        print(f"error: {e}")
        return 1
    return 2
