"""Scheduler: cron parser, next-fire calculation (incl. DST and Vixie dom/dow OR),
date macros, and unattended run-due with lock, misfire handling and history."""

from __future__ import annotations

import contextlib
import io
import itertools
import json
import os
import random
import time
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from analyst_agent import scheduler


def _have_tzdata() -> bool:
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo("America/New_York")
        return True
    except Exception:  # Windows without the tzdata package has no IANA zones
        return False


HAVE_TZDATA = _have_tzdata()
needs_tzdata = unittest.skipUnless(HAVE_TZDATA, "no IANA time zones (pip install tzdata)")
from analyst_agent.__main__ import main
from analyst_agent.scheduler import (
    CronError,
    CronExpr,
    RunLock,
    LockBusy,
    ScheduleError,
    ScheduleStore,
    date_macros,
    install_hint,
    load_schedules,
    parse_field,
    parse_when,
    resolve_params,
    resolve_tz,
    run_due,
)
from analyst_agent.teach import write_draft

from .helpers import TempWorkspace

UTC = timezone.utc


def utc(*a) -> datetime:
    return datetime(*a, tzinfo=UTC)


class ParseTests(unittest.TestCase):
    def test_field_syntax(self):
        self.assertEqual(parse_field("*", "m", 0, 5), {0, 1, 2, 3, 4, 5})
        self.assertEqual(parse_field("1,3,5", "m", 0, 59), {1, 3, 5})
        self.assertEqual(parse_field("10-12", "m", 0, 59), {10, 11, 12})
        self.assertEqual(parse_field("*/20", "m", 0, 59), {0, 20, 40})
        self.assertEqual(parse_field("5-20/5", "m", 0, 59), {5, 10, 15, 20})
        self.assertEqual(parse_field("50/5", "m", 0, 59), {50, 55})  # a/n = a-max/n (Vixie)
        self.assertEqual(parse_field("1-3,7,9-10", "m", 0, 59), {1, 2, 3, 7, 9, 10})

    def test_names_and_sunday_7(self):
        c = CronExpr.parse("0 9 * jan,JUL mon-fri")
        self.assertEqual(c.months, {1, 7})
        self.assertEqual(c.dows, {1, 2, 3, 4, 5})
        self.assertEqual(CronExpr.parse("0 0 * * 7").dows, {0})
        self.assertEqual(CronExpr.parse("0 0 * * 5-7").dows, {5, 6, 0})
        self.assertEqual(CronExpr.parse("0 0 * * sun").dows, {0})

    def test_macros(self):
        self.assertEqual(CronExpr.parse("@hourly").minutes, {0})
        self.assertEqual(CronExpr.parse("@weekly").dows, {0})
        self.assertEqual(CronExpr.parse("@monthly").doms, {1})
        self.assertEqual(CronExpr.parse("@yearly").months, {1})
        self.assertEqual(CronExpr.parse("@DAILY").hours, {0})

    def test_errors(self):
        bad = [
            "", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *", "* * * 13 *", "* * * * 8",
            "5-1 * * * *", "*/0 * * * *", "*/x * * * *", "1,,2 * * * *", "a * * * *", "* * * foo *", "@reboot", "0 0 30 2 *", "0 0 31 4,6,9,11 *",
        ]
        for expr in bad:
            with self.assertRaises(CronError, msg=expr):
                CronExpr.parse(expr)

    def test_feb_29_is_valid(self):
        self.assertEqual(CronExpr.parse("0 0 29 2 *").next_after(utc(2026, 3, 1), UTC), utc(2028, 2, 29))
        self.assertEqual(CronExpr.parse("0 0 29 2 *").next_after(utc(2096, 3, 1), UTC), utc(2104, 2, 29))  # 2100 is not a leap year


class NextFireTests(unittest.TestCase):
    def nxt(self, expr, after, tz=UTC):
        return CronExpr.parse(expr).next_after(after, tz)

    def seq(self, expr, after, n, tz=UTC):
        c, out, t = CronExpr.parse(expr), [], after
        for _ in range(n):
            t = c.next_after(t, tz)
            out.append(t)
        return out

    def test_basic(self):
        self.assertEqual(self.nxt("*/15 * * * *", utc(2026, 11, 24, 10, 7, 30)), utc(2026, 11, 24, 10, 15))
        self.assertEqual(self.nxt("0 7 2 * *", utc(2026, 11, 24)), utc(2026, 12, 2, 7))
        self.assertEqual(self.nxt("0 0 1 1 *", utc(2026, 12, 31, 23, 59)), utc(2027, 1, 1))
        self.assertEqual(self.nxt("59 23 31 12 *", utc(2026, 1, 1)), utc(2026, 12, 31, 23, 59))
        self.assertEqual(self.nxt("0 */6 * * *", utc(2026, 11, 24, 18, 0)), utc(2026, 11, 25, 0, 0))

    def test_strictly_after(self):
        self.assertEqual(self.nxt("30 9 * * *", utc(2026, 11, 24, 9, 30)), utc(2026, 11, 25, 9, 30))
        self.assertEqual(self.nxt("30 9 * * *", utc(2026, 11, 24, 9, 29, 59)), utc(2026, 11, 24, 9, 30))

    def test_vixie_dom_dow_or(self):
        # Both restricted: the 13th OR any Friday.
        got = self.seq("0 0 13 * 5", utc(2026, 11, 1), 8)
        self.assertEqual([d.date() for d in got], [date(2026, 11, 6), date(2026, 11, 13), date(2026, 11, 20), date(2026, 11, 27), date(2026, 12, 4), date(2026, 12, 11), date(2026, 12, 13), date(2026, 12, 18)])
        # dom starts with '*': AND (odd days that are Mondays).
        got = self.seq("0 0 */2 * 1", utc(2026, 11, 1), 3)
        self.assertEqual([d.date() for d in got], [date(2026, 11, 9), date(2026, 11, 23), date(2026, 12, 7)])
        # dow '*' with restricted dom: just the dom.
        self.assertEqual([d.day for d in self.seq("0 0 1,15 * *", utc(2026, 11, 1), 3)], [15, 1, 15])
        # dow restricted only: weekdays.
        self.assertEqual([d.isoweekday() for d in self.seq("0 8 * * mon-fri", utc(2026, 11, 27, 9), 3)], [1, 2, 3])

    def test_matches_brute_force(self):
        """next_after agrees with a minute-by-minute scan for random expressions."""
        rng = random.Random(7)
        pools = [
            ["*", "0", "*/7", "5,35", "10-20/5", "59"],
            ["*", "0", "*/5", "9-17", "23"],
            ["*", "1", "13", "*/10", "28-31", "15"],
            ["*", "2", "1-3", "*/4", "dec"],
            ["*", "0", "5", "1-5", "sat,sun", "*/3"],
        ]
        for _ in range(40):
            expr = " ".join(rng.choice(p) for p in pools)
            try:
                c = CronExpr.parse(expr)
            except CronError:
                continue
            start = utc(2026, 1, 1) + timedelta(minutes=rng.randrange(0, 525600))
            t = start.replace(second=0) + timedelta(minutes=1)
            expected = None
            for _ in range(60 * 24 * 120):
                if c.matches(t):
                    expected = t
                    break
                t += timedelta(minutes=1)
            if expected is None:
                continue
            self.assertEqual(c.next_after(start, UTC), expected, expr)

    @needs_tzdata
    def test_timezone_wall_clock(self):
        from zoneinfo import ZoneInfo

        ny = ZoneInfo("America/New_York")
        got = self.nxt("0 7 2 * *", utc(2026, 11, 24), ny)
        self.assertEqual(got.utcoffset(), timedelta(hours=-5))
        self.assertEqual((got.hour, got.day, got.month), (7, 2, 12))
        self.assertEqual(got.astimezone(UTC), utc(2026, 12, 2, 12))

    @needs_tzdata
    def test_dst_gap_and_repeat(self):
        from zoneinfo import ZoneInfo

        lon = ZoneInfo("Europe/London")
        # 2027-03-28: 01:00 GMT jumps to 02:00 BST, so 01:30 does not exist; it fires at the same instant after the jump.
        got = self.nxt("30 1 * * *", utc(2027, 3, 27, 12), lon)
        self.assertEqual(got.astimezone(UTC), utc(2027, 3, 28, 1, 30))
        self.assertEqual(self.nxt("30 1 * * *", got, lon).astimezone(UTC), utc(2027, 3, 29, 0, 30))
        # 2026-10-25: 01:00-02:00 happens twice; a daily job fires once (the first pass).
        first = self.nxt("30 1 * * *", utc(2026, 10, 24, 12), lon)
        self.assertEqual(first.astimezone(UTC), utc(2026, 10, 25, 0, 30))
        self.assertEqual(self.nxt("30 1 * * *", first, lon).astimezone(UTC), utc(2026, 10, 26, 1, 30))
        # Times are strictly increasing through both transitions.
        for after in (utc(2027, 3, 27, 23), utc(2026, 10, 24, 23)):
            ts = self.seq("*/20 * * * *", after, 12, lon)
            self.assertEqual(ts, sorted(set(ts)))

    def test_latest_slot_for_misfires(self):
        c = CronExpr.parse("0 7 2 * *")
        self.assertEqual(c.latest_at_or_before(utc(2027, 2, 10), UTC, utc(2026, 11, 3)), utc(2027, 2, 2, 7))
        self.assertIsNone(c.latest_at_or_before(utc(2026, 11, 30), UTC, utc(2026, 11, 3)))
        every = CronExpr.parse("* * * * *")
        self.assertEqual(every.latest_at_or_before(utc(2026, 11, 24, 10, 0, 30), UTC, utc(2026, 1, 1)), utc(2026, 11, 24, 10, 0))


class MacroAndZoneTests(unittest.TestCase):
    def test_date_macros(self):
        m = date_macros(date(2026, 11, 24))
        self.assertEqual(m["prev_month"], "2026-10")
        self.assertEqual(m["today"], "2026-11-24")
        self.assertEqual((m["quarter_start"], m["quarter_end"]), ("2026-10-01", "2026-12-31"))
        self.assertEqual((m["prev_quarter_start"], m["prev_quarter_end"]), ("2026-07-01", "2026-09-30"))
        m = date_macros(date(2026, 1, 15))
        self.assertEqual(m["prev_month"], "2025-12")
        self.assertEqual((m["quarter_start"], m["quarter_end"]), ("2026-01-01", "2026-03-31"))
        self.assertEqual((m["prev_quarter_start"], m["prev_quarter_end"]), ("2025-10-01", "2025-12-31"))
        self.assertEqual((m["prev_month_start"], m["prev_month_end"]), ("2025-12-01", "2025-12-31"))
        m = date_macros(date(2028, 3, 1))
        self.assertEqual((m["prev_month_end"], m["yesterday"]), ("2028-02-29", "2028-02-29"))

    def test_resolve_params(self):
        out = resolve_params({"period": "{{prev_month}}", "range": "{{ quarter_start }}..{{quarter_end}}", "n": 3, "plain": "x"}, date(2026, 11, 2))
        self.assertEqual(out, {"period": "2026-10", "range": "2026-10-01..2026-12-31", "n": 3, "plain": "x"})
        with self.assertRaisesRegex(ScheduleError, "unknown date macro"):
            resolve_params({"p": "{{next_year}}"}, date(2026, 1, 1))

    @needs_tzdata
    def test_resolve_tz(self):
        self.assertEqual(resolve_tz("UTC")[0], UTC)
        self.assertEqual(resolve_tz("local")[1], "")
        self.assertEqual(str(resolve_tz("Europe/London")[0]), "Europe/London")
        with self.assertRaises(ScheduleError):
            resolve_tz("Mars/Olympus")

    def test_tz_falls_back_to_local_without_tzdata(self):
        import zoneinfo

        with mock.patch.object(zoneinfo, "ZoneInfo", side_effect=zoneinfo.ZoneInfoNotFoundError("x")), mock.patch.object(zoneinfo, "available_timezones", return_value=set()):
            tz, warn = resolve_tz("Europe/London")
        self.assertIn("tzdata", warn)
        self.assertEqual(tz.utcoffset(None), scheduler.local_tz().utcoffset(None))

    def test_parse_when(self):
        self.assertEqual(parse_when("2026-11-02T07:03:00Z"), utc(2026, 11, 2, 7, 3))
        self.assertIsNotNone(parse_when("2026-11-02T07:03").tzinfo)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()

    def tearDown(self):
        self.ws.cleanup()

    def test_load_validates(self):
        p = self.ws.root / "s.json"
        p.write_text(json.dumps({"schedules": [{"id": "a", "playbook": "x", "cron": "0 0 * * *"}, {"id": "a", "playbook": "y", "cron": "0 0 * * *"}]}))
        with self.assertRaisesRegex(ScheduleError, "duplicate"):
            load_schedules(p)
        p.write_text(json.dumps({"schedules": [{"id": "a", "playbook": "x", "cron": "0 0 31 2 *"}]}))
        with self.assertRaisesRegex(ScheduleError, "never fire"):
            load_schedules(p)
        p.write_text(json.dumps([{"id": "a", "playbook": "x", "cron": "@daily", "params": {"k": "v"}}]))
        s = load_schedules(p)[0]
        self.assertEqual((s.enabled, s.timezone, s.params), (True, "local", {"k": "v"}))
        self.assertEqual(load_schedules(self.ws.root / "missing.json"), [])

    def test_lock_excludes_and_breaks_stale(self):
        path = self.ws.root / "w" / "run.lock"
        a, b = RunLock(path, stale_s=60), RunLock(path, stale_s=60)
        a.acquire()
        with self.assertRaises(LockBusy):
            b.acquire()
        old = time.time() - 120
        os.utime(path, (old, old))
        b.acquire()  # a's lock is stale (a crashed run)
        self.assertTrue(b.held)
        b.release()
        self.assertFalse(path.exists())


class RunDueTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        self.s = self.ws.settings
        self.s.data["schedules"] = {"path": str(self.ws.root / "config" / "schedules.json"), "state_dir": str(self.ws.root / "workspace" / "schedules"), "lock_stale_s": 7200}
        self.store = ScheduleStore(self.s)
        self.pbdir = self.ws.root / "playbooks"
        self.logs: list[str] = []
        self.fired: list[tuple[str, dict]] = []

    def tearDown(self):
        self.ws.cleanup()

    def write(self, *entries):
        p = self.store.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"schedules": list(entries)}), encoding="utf-8")

    def entry(self, **kw):
        e = {"id": "recon", "playbook": "erp-crm-reconciliation", "params": {"period": "{{prev_month}}"}, "cron": "0 7 2 * *", "timezone": "UTC", "enabled": True, "owner": "finance", "created_at": "2026-11-01T00:00:00+00:00"}
        e.update(kw)
        return e

    def fake_runner(self, sch, pb, params):
        self.fired.append((sch.id, params))
        return SimpleNamespace(session_id=f"sess-{len(self.fired)}", status="success", records=[], report_path="", approvals=[])

    def due(self, now, runner=None):
        return run_due(self.s, self.pbdir, now=now, runner=runner or self.fake_runner, log=self.logs.append)

    def test_real_unattended_run_declines_approval_and_writes_history(self):
        self.write(self.entry(notify="workspace/output/notes/recon.md"))
        self.assertEqual(self.due(utc(2026, 11, 2, 6, 59)), [])
        recs = run_due(self.s, self.pbdir, now=utc(2026, 11, 2, 7, 3), log=self.logs.append)  # the real orchestrator
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["status"], "partial")  # the email step needs approval; unattended declines it
        self.assertEqual(rec["params"], {"period": "2026-10"})
        self.assertEqual(rec["scheduled_for"], "2026-11-02T07:00:00+00:00")
        self.assertEqual(rec["steps"]["draft-email"], "rejected")
        self.assertTrue((self.s.output_dir / "mismatches_2026-10.csv").exists())
        self.assertFalse((self.s.output_dir / "outbox").exists())
        self.assertTrue((self.s.audit_dir / rec["session_id"] / "events.jsonl").exists())
        events = [json.loads(x) for x in (self.s.audit_dir / rec["session_id"] / "events.jsonl").read_text().splitlines()]
        decided = [e for e in events if e["kind"] == "approval_decided"]
        self.assertEqual([(e["approved"], e["by"]) for e in decided], [(False, "unattended")])
        note = (self.ws.root / "workspace" / "output" / "notes" / "recon.md").read_text()
        self.assertIn("declined by unattended", note)
        self.assertEqual(self.store.history(), recs)
        state = self.store.state()["recon"]
        self.assertEqual((state["last_slot"], state["last_status"], state["last_session"]), ("2026-11-02T07:00:00+00:00", "partial", rec["session_id"]))
        # Never twice for the same slot.
        self.assertEqual(self.due(utc(2026, 11, 2, 7, 8)), [])
        self.assertEqual(len(self.store.history()), 1)

    def test_misfire_runs_once_for_latest_slot(self):
        self.write(self.entry())
        recs = self.due(utc(2027, 2, 10, 12))  # Dec 2, Jan 2 and Feb 2 were all missed
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0]["missed"])
        self.assertEqual(recs[0]["first_missed"], "2026-11-02T07:00:00+00:00")
        self.assertEqual(recs[0]["scheduled_for"], "2027-02-02T07:00:00+00:00")
        self.assertEqual(self.fired, [("recon", {"period": "2027-01"})])
        self.assertEqual(self.due(utc(2027, 2, 10, 12, 5)), [])
        self.assertEqual(len(self.due(utc(2027, 3, 2, 7))), 1)
        self.assertEqual(self.fired[-1], ("recon", {"period": "2027-02"}))

    @needs_tzdata
    def test_timezone_of_schedule_is_used(self):
        self.write(self.entry(timezone="America/New_York"))
        self.assertEqual(self.due(utc(2026, 11, 2, 7, 30)), [])  # 07:00 New York is 12:00 UTC
        recs = self.due(utc(2026, 11, 2, 12, 1))
        self.assertEqual(recs[0]["scheduled_for"], "2026-11-02T07:00:00-05:00")

    def test_disabled_first_seen_and_drafts(self):
        write_draft(self.pbdir, {"name": "draft-only", "status": "draft", "owner": "x", "steps": [{"id": "a", "tier": "code", "script": {"kind": "python", "code": "print(1)"}, "no_check_reason": "x"}]})
        self.write(
            self.entry(id="off", enabled=False),
            self.entry(id="new", created_at=""),
            self.entry(id="draft", playbook="draft-only", params={}),
        )
        recs = self.due(utc(2026, 11, 2, 7, 1))
        self.assertEqual([(r["schedule_id"], r["status"]) for r in recs], [("draft", "invalid")])
        self.assertIn("promote it first", recs[0]["error"])
        self.assertNotIn("off", self.store.state())
        self.assertEqual(self.store.state()["new"]["note"], "first seen; fires from the next slot")
        recs = self.due(utc(2026, 12, 2, 7, 1))
        self.assertEqual(sorted(r["schedule_id"] for r in recs), ["draft", "new"])
        self.assertEqual(self.fired, [("new", {"period": "2026-11"})])

    def test_missing_params_and_runner_errors_are_recorded_not_retried(self):
        self.write(self.entry(id="nop", playbook="warehouse-region-revenue", params={}), self.entry(id="boom"))

        def boom(sch, pb, params):
            raise RuntimeError("gateway down")

        recs = self.due(utc(2026, 11, 2, 7, 1), runner=boom)
        by = {r["schedule_id"]: r for r in recs}
        self.assertEqual(by["nop"]["status"], "invalid")
        self.assertIn("missing parameters", by["nop"]["error"])
        self.assertEqual((by["boom"]["status"], by["boom"]["error"]), ("error", "RuntimeError: gateway down"))
        self.assertEqual(self.due(utc(2026, 11, 2, 7, 6), runner=boom), [])

    def test_lock_prevents_double_run(self):
        self.write(self.entry())
        self.store.lock.acquire()
        try:
            self.assertEqual(self.due(utc(2026, 11, 2, 7, 1)), [])
            self.assertTrue(any("another run-due" in x for x in self.logs))
        finally:
            self.store.lock.release()
        self.assertEqual(len(self.due(utc(2026, 11, 2, 7, 1))), 1)
        self.assertFalse(self.store.lock.path.exists())

    def test_notify_outside_workspace_is_refused(self):
        self.write(self.entry(notify=str(Path(self.ws.root).parent / "elsewhere.md")))
        rec = self.due(utc(2026, 11, 2, 7, 1))[0]
        self.assertIn("notify refused", rec["notify"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace()
        cfg = {"workspace": {"root": "./workspace", "input_dirs": ["./samples"], "output_dir": "./workspace/output"}, "audit": {"dir": "./workspace/audit"}, "gateway": {"backend": "mock"}}
        (self.ws.root / "config").mkdir()
        self.cfg = self.ws.root / "config" / "test.json"
        self.cfg.write_text(json.dumps(cfg))

    def tearDown(self):
        self.ws.cleanup()

    def run_cli(self, *args) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["--config", str(self.cfg), *args])
        return code, buf.getvalue()

    def test_add_list_remove(self):
        code, out = self.run_cli("schedule", "add", "monthly", "--playbook", "erp-crm-reconciliation", "--cron", "0 7 2 * *", "--tz", "Europe/London", "--param", "period={{prev_month}}", "--owner", "fin")
        self.assertEqual(code, 0, out)
        saved = json.loads((self.ws.root / "config" / "schedules.json").read_text())["schedules"][0]
        self.assertEqual((saved["id"], saved["params"], saved["timezone"]), ("monthly", {"period": "{{prev_month}}"}, "Europe/London"))
        self.assertTrue(saved["created_at"])
        code, out = self.run_cli("schedule", "add", "monthly", "--playbook", "erp-crm-reconciliation", "--cron", "0 7 2 * *")
        self.assertEqual(code, 1)
        self.assertIn("exists", out)
        bads = [["--cron", "0 7 31 2 *"], ["--cron", "@daily", "--param", "p={{nope}}"]]
        if HAVE_TZDATA:  # without zone data an unknown zone can't be told apart; it warns and uses local time
            bads.append(["--cron", "@daily", "--tz", "Mars/Base"])
        for bad in bads:
            code, out = self.run_cli("schedule", "add", "x", "--playbook", "erp-crm-reconciliation", *bad)
            self.assertEqual(code, 1, out)
        code, out = self.run_cli("schedule", "add", "x", "--playbook", "no-such-playbook", "--cron", "@daily")
        self.assertEqual(code, 1)
        code, out = self.run_cli("schedule", "list")
        self.assertIn("monthly", out)
        self.assertIn("next=", out)
        code, out = self.run_cli("schedule", "run-due", "--now", "2026-11-24T10:00:00Z")
        self.assertEqual((code, out.strip()), (0, "nothing due"))
        code, out = self.run_cli("schedule", "remove", "monthly")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((self.ws.root / "config" / "schedules.json").read_text())["schedules"], [])

    def test_install_hint(self):
        code, out = self.run_cli("schedule", "install-hint")
        self.assertEqual(code, 0)
        self.assertIn("schtasks /Create", out)
        self.assertIn("/SC MINUTE /MO 5", out)
        self.assertIn("schedule run-due", out)
        hint = install_hint(Path(r"C:\Program Files\agent"), r"C:\Python\python.exe", None)
        self.assertIn("run-due.cmd", hint)


if __name__ == "__main__":
    unittest.main()
