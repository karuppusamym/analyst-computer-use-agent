"""Code tier containment: Job Object limits + audit-hook guard."""

import importlib.util
import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.audit import AuditLog  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.tools.base import ToolContext  # noqa: E402
from analyst_agent.tools.code import run_python  # noqa: E402
from analyst_agent.tools.sandbox import IS_WINDOWS, Limits, minimal_env, run_limited  # noqa: E402
from analyst_agent.vault import vault_dir  # noqa: E402
from tests.helpers import TempWorkspace  # noqa: E402


class SandboxBase(unittest.TestCase):
    extra: dict = {}

    def setUp(self):
        self.ws = TempWorkspace(self.extra)
        self.s = self.ws.settings
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, ScriptedApprover([]), step_id="t", workdir=self.audit.dir / "scratch", params={"period": "2026-10"})

    def tearDown(self):
        self.ws.cleanup()

    def run_code(self, code: str, timeout: int = 60):
        return run_python(code, self.ctx, timeout=timeout)

    def assertBlocked(self, out, what: str = "sandbox:"):
        self.assertTrue(out.is_error, out.text)
        self.assertIn(what, out.text)


class GuardTests(SandboxBase):
    def test_network_blocked(self):
        out = self.run_code("import socket\nsocket.create_connection(('127.0.0.1', 9), timeout=2)")
        self.assertBlocked(out, "network access is not allowed")
        out = self.run_code("import urllib.request\nurllib.request.urlopen('http://127.0.0.1:9/')")
        self.assertBlocked(out, "network access is not allowed")

    def test_subprocess_and_system_blocked(self):
        for code in ("import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'print(1)'])", "import os\nos.system('echo hi')", "import os, sys\nos.spawnl(os.P_WAIT, sys.executable, 'python', '-c', 'pass')"):
            with self.subTest(code=code):
                self.assertBlocked(self.run_code(code), "processes is not allowed")

    def test_ctypes_blocked_in_task_code(self):
        out = self.run_code("import ctypes\nprint(ctypes.CDLL('kernel32' if __import__('os').name == 'nt' else None))")
        self.assertTrue(out.is_error, out.text)
        self.assertIn("ctypes", out.text)

    def test_write_outside_workdir_and_output_blocked(self):
        target = self.ws.root / "outside.txt"
        out = self.run_code(f"open({str(target)!r}, 'w').write('x')")
        self.assertBlocked(out, "write only inside")
        self.assertFalse(target.exists())
        # input dirs are read-only
        out = self.run_code("open(INPUT_DIRS[0] + '/evil.csv', 'a').write('x')")
        self.assertBlocked(out, "write only inside")
        out = self.run_code("import os\nos.remove(os.path.join(INPUT_DIRS[0], 'erp_export_2026-10.csv'))")
        self.assertBlocked(out, "write only inside")
        self.assertTrue((self.ws.root / "samples" / "erp_export_2026-10.csv").exists())
        out = self.run_code("import shutil\nshutil.copyfile(INPUT_DIRS[0] + '/erp_export_2026-10.csv', " + repr(str(self.ws.root / "copy.csv")) + ")")
        self.assertBlocked(out)

    def test_forbidden_reads_blocked(self):
        secret_file = self.ws.root / "not_an_input.txt"
        secret_file.write_text("private")
        out = self.run_code(f"print(open({str(secret_file)!r}).read())")
        self.assertBlocked(out, "read only INPUT_DIRS")
        self.assertNotIn("private", out.text.split("--- stderr ---")[0])
        vd = vault_dir(self.s)
        vd.mkdir(parents=True, exist_ok=True)
        (vd / "vault.json").write_text("{}")
        out = self.run_code(f"print(open({str(vd / 'vault.json')!r}).read())")
        self.assertBlocked(out, "protected agent folder")
        out = self.run_code(f"import os\nprint(os.listdir({str(self.s.audit_dir)!r}))")
        self.assertBlocked(out, "protected agent folder")

    def test_isolated_mode_and_minimal_env(self):
        os.environ["AGENT_SECRET_SANDBOX_PROBE"] = "do-not-leak-1234"
        os.environ["SOME_API_TOKEN"] = "tok-should-not-leak"
        try:
            out = self.run_code("import os, sys\nprint(sys.flags.isolated, sorted(os.environ))\nprint(os.environ.get('TEMP'))")
        finally:
            del os.environ["AGENT_SECRET_SANDBOX_PROBE"], os.environ["SOME_API_TOKEN"]
        self.assertFalse(out.is_error, out.text)
        self.assertIn("\n1 [", out.text)
        self.assertNotIn("do-not-leak", out.text)
        self.assertNotIn("AGENT_SECRET_SANDBOX_PROBE", out.text)
        self.assertNotIn("SOME_API_TOKEN", out.text)
        self.assertIn(str(self.ctx.workdir.resolve()), out.text)  # TEMP points into the workdir

    def test_legit_csv_and_sqlite_script(self):
        code = (
            "import csv, json, os, sqlite3, tempfile\n"
            "rows = list(csv.DictReader(open(os.path.join(INPUT_DIRS[0], f\"erp_export_{PARAMS['period']}.csv\"), newline='', encoding='utf-8-sig')))\n"
            "con = sqlite3.connect(os.path.join(INPUT_DIRS[0], 'warehouse.sqlite'))\n"
            "tables = [r[0] for r in con.execute(\"select name from sqlite_master where type='table'\")]\n"
            "try:\n    con.execute('create table hacked(x)'); wrote = True\nexcept sqlite3.OperationalError:\n    wrote = False\n"
            "out = sqlite3.connect(os.path.join(OUTPUT_DIR, 'scratch.sqlite')); out.execute('create table t(x)'); out.commit()\n"
            "with tempfile.NamedTemporaryFile('w', delete=False) as f: f.write('tmp')\n"
            "json.dump({'rows': len(rows), 'tables': tables, 'wrote_input': wrote}, open(os.path.join(OUTPUT_DIR, 'legit.json'), 'w'))\n"
            "print('rows', len(rows), 'tables', tables, 'wrote_input', wrote)\n"
        )
        out = self.run_code(code)
        self.assertFalse(out.is_error, out.text)
        self.assertIn("wrote_input False", out.text)
        self.assertTrue((self.s.output_dir / "legit.json").exists())
        self.assertTrue((self.s.output_dir / "scratch.sqlite").exists())

    def test_sqlite_attach_outside_blocked(self):
        target = str(self.ws.root / "attached.db").replace("\\", "/")
        out = self.run_code(f"import sqlite3\ncon = sqlite3.connect(':memory:')\ncon.execute(\"attach '{target}' as x\")")
        self.assertTrue(out.is_error, out.text)
        self.assertIn("not authorized", out.text)
        self.assertFalse(Path(target).exists())

    def test_imports_openpyxl_and_sqlite3(self):
        mods = ["sqlite3", "csv", "json", "decimal", "datetime", "statistics"]
        for m in ("openpyxl", "pandas"):
            if importlib.util.find_spec(m):
                mods.append(m)
        out = self.run_code("import importlib\n" + "".join(f"importlib.import_module({m!r})\n" for m in mods) + "print('imported', len(" + repr(mods) + "))")
        self.assertFalse(out.is_error, out.text)
        if "openpyxl" in mods:
            out = self.run_code("import openpyxl, os\nwb = openpyxl.Workbook(); wb.active['A1'] = 42\np = os.path.join(OUTPUT_DIR, 'x.xlsx'); wb.save(p)\nprint(openpyxl.load_workbook(p).active['A1'].value)")
            self.assertFalse(out.is_error, out.text)
            self.assertIn("42", out.text)

    def test_timeout_works(self):
        t = time.time()
        out = self.run_code("while True:\n    pass", timeout=2)
        self.assertTrue(out.is_error)
        self.assertIn("longer than 2s", out.text)
        self.assertLess(time.time() - t, 20)

    def test_tamper_helpers_blocked(self):
        self.assertBlocked(self.run_code("import sys\nsys.settrace(lambda *a: None)"), "sys.settrace")
        self.assertBlocked(self.run_code("import gc\ngc.get_objects()"), "gc.get_objects")


class MemoryLimitTests(SandboxBase):
    extra = {"tiers": {"code": {"memory_mb": 256}}}

    def test_memory_hog_killed(self):
        out = self.run_code("x = bytearray(700 * 1024 * 1024)\nprint('allocated', len(x))")
        self.assertTrue(out.is_error, out.text)
        self.assertNotIn("allocated", out.text)
        if IS_WINDOWS:
            self.assertIn("memory limit", out.text)


class GuardOffTests(SandboxBase):
    extra = {"tiers": {"code": {"python_guard": False}}}

    @unittest.skipUnless(IS_WINDOWS, "Job Object test")
    def test_process_limit_enforced_by_job_even_without_guard(self):
        out = self.run_code("import subprocess, sys\nprint('child exit', subprocess.run([sys.executable, '-c', 'print(1)']).returncode)")
        self.assertTrue(out.is_error, out.text)
        self.assertIn("1816", out.text)  # ERROR_NOT_ENOUGH_QUOTA: active-process limit of the job


@unittest.skipUnless(IS_WINDOWS, "Job Object tests need Windows")
class JobObjectTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.env = minimal_env(self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def test_active_process_limit(self):
        code = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'pass'])"
        r = run_limited([sys.executable, "-c", code], self.work, self.env, 30, Limits(max_processes=1))
        self.assertTrue(r.contained)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1816", r.stderr)
        r = run_limited([sys.executable, "-c", code], self.work, self.env, 30, Limits(max_processes=3))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_cpu_time_limit(self):
        r = run_limited([sys.executable, "-c", "while True: pass"], self.work, self.env, 30, Limits(cpu_s=1))
        self.assertFalse(r.timed_out)
        self.assertEqual(r.returncode, 0xC0000044)  # STATUS_QUOTA_EXCEEDED

    def test_clipboard_read_restricted(self):
        code = "import ctypes\nu = ctypes.windll.user32\nu.OpenClipboard(None)\nprint('data', bool(u.GetClipboardData(13)))"
        free = run_limited([sys.executable, "-c", code], self.work, self.env, 30, Limits(ui_restrictions=False))
        if "data True" not in free.stdout:
            self.skipTest("clipboard has no text to compare against")
        r = run_limited([sys.executable, "-c", code], self.work, self.env, 30, Limits())
        self.assertIn("data False", r.stdout, r.stderr)

    def test_kill_on_close_and_timeout(self):
        t = time.time()
        r = run_limited([sys.executable, "-c", "import time\ntime.sleep(60)"], self.work, self.env, 1, Limits())
        self.assertTrue(r.timed_out)
        self.assertLess(time.time() - t, 15)


if __name__ == "__main__":
    unittest.main()
