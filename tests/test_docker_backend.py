"""Code tier docker backend: argv, path translation, copy-back, fail-closed (fake docker CLI),
plus live container tests that run only when `docker info` succeeds."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyst_agent.audit import AuditLog  # noqa: E402
from analyst_agent.policy import PolicyEngine, ScriptedApprover  # noqa: E402
from analyst_agent.tools import docker_backend as db  # noqa: E402
from analyst_agent.tools.base import ToolContext  # noqa: E402
from analyst_agent.tools.code import run_python  # noqa: E402
from analyst_agent.tools.sandbox import IS_WINDOWS, SandboxError  # noqa: E402
from tests.helpers import TempWorkspace  # noqa: E402

FAKE = Path(__file__).with_name("fake_docker.py")


def _cfg(**docker) -> db.DockerConfig:
    return db.DockerConfig.from_settings({"memory_mb": 512, "docker_cli": [sys.executable, str(FAKE)], "docker": docker})


def _pair(argv, flag):
    """Values that follow each occurrence of flag."""
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


class ArgvTests(unittest.TestCase):
    def test_exact_hardening_flags(self):
        cfg = _cfg(cpus=1.5, pids_limit=32, tmpfs_mb=16, path_style="posix", image="python:3.13-slim@sha256:" + "a" * 64)
        P = PurePosixPath
        argv = db.run_argv(cfg, "aa-code-x", [P("/data/in0"), P("/data/in1")], P("/stage/work"), P("/stage/output"), "_bootstrap.py")
        self.assertEqual(argv[:2], cfg.cli)
        rest = argv[2:]
        self.assertEqual(rest[:4], ["run", "--rm", "--name", "aa-code-x"])
        for flag, value in [("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"), ("--pids-limit", "32"),
                            ("--memory", "512m"), ("--memory-swap", "512m"), ("--cpus", "1.5"), ("--user", "65534:65534"),
                            ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m"), ("--pull", "never"), ("--workdir", "/work"), ("--ulimit", "core=0")]:
            with self.subTest(flag=flag):
                self.assertEqual(_pair(rest, flag), [value])
        self.assertIn("--read-only", rest)
        self.assertEqual(_pair(rest, "--mount"), [
            "type=bind,source=/data/in0,target=/inputs/0,readonly",
            "type=bind,source=/data/in1,target=/inputs/1,readonly",
            "type=bind,source=/stage/work,target=/work",
            "type=bind,source=/stage/output,target=/output",
        ])
        envs = dict(e.split("=", 1) for e in _pair(rest, "--env"))
        self.assertEqual(set(envs), {"HOME", "TMPDIR", "MPLCONFIGDIR", "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE", "LANG"})
        self.assertEqual(rest[-7:], [cfg.image, "python", "-I", "-B", "-X", "utf8", "/work/_bootstrap.py"])
        for bad in ("--privileged", "-v", "--volume", "--network=host", "host", "--cap-add", "--env-file", "-e"):
            self.assertNotIn(bad, rest)

    def test_windows_mount_syntax(self):
        cfg = _cfg(path_style="windows")
        argv = db.run_argv(cfg, "n", [Path(r"C:\Users\Analyst\Data")], Path(r"c:\stage\work"), Path(r"c:\stage\output"), "b.py")
        self.assertEqual(_pair(argv, "--mount"), [
            "type=bind,source=C:/Users/Analyst/Data,target=/inputs/0,readonly",
            "type=bind,source=C:/stage/work,target=/work",
            "type=bind,source=C:/stage/output,target=/output",
        ])

    def test_guard_config_uses_container_paths(self):
        g = db.guard_config(True, "_step_s1.py", 2, {"period": "2026-10"})
        self.assertEqual(g["input_dirs"], ["/inputs/0", "/inputs/1"])
        self.assertEqual(g["output_dir"], "/output")
        self.assertEqual(g["script"], "/work/_step_s1.py")
        self.assertEqual(g["read"], ["/inputs/0", "/inputs/1"])
        self.assertEqual(g["write"], ["/work", "/output", "/tmp"])
        self.assertFalse(g["allow_network"])
        self.assertEqual(g["params"], {"period": "2026-10"})

    def test_bad_config_rejected(self):
        with self.assertRaises(SandboxError):
            _cfg(pull="always")
        with self.assertRaises(SandboxError):
            _cfg(path_style="wsl")


class PathTranslationTests(unittest.TestCase):
    def test_windows(self):
        w = lambda p: db.host_mount_path(p, "windows")  # noqa: E731
        self.assertEqual(w(r"C:\Users\a b\x"), "C:/Users/a b/x")
        self.assertEqual(w(r"d:\data"), "D:/data")
        self.assertEqual(w("C:/already/forward"), "C:/already/forward")
        self.assertEqual(w("\\\\?\\C:\\long\\path"), "C:/long/path")
        self.assertEqual(w("C:\\"), "C:/")
        for bad in (r"\\server\share\x", "\\\\?\\UNC\\server\\share", "relative\\x", r"C:relative", r"\no\drive", r"C:\a,b", 'C:\\a"b', r"C:\a=b", "C:\\a\nb"):
            with self.subTest(bad=bad):
                with self.assertRaises(SandboxError):
                    w(bad)

    def test_posix(self):
        self.assertEqual(db.host_mount_path("/home/u/data", "posix"), "/home/u/data")
        for bad in ("rel/x", "/a,b", "/a/../b"):
            with self.subTest(bad=bad):
                with self.assertRaises(SandboxError):
                    db.host_mount_path(bad, "posix")

    def test_safe_names(self):
        for ok in ("report.csv", "a b.xlsx", ".hidden", "x.tar.gz"):
            self.assertTrue(db._safe_name(ok), ok)
        for bad in ("CON", "con.txt", "aux", "COM1.log", "a:b", "a|b", "trail.", "trail ", "a\\b", "..", "x\x01"):
            self.assertFalse(db._safe_name(bad), bad)


def _make_link(link: Path, target: Path, is_dir: bool):
    """A symlink, or on Windows without the symlink privilege a junction (directories only)."""
    try:
        os.symlink(target, link, target_is_directory=is_dir)
        return "symlink"
    except OSError:
        if IS_WINDOWS and is_dir:
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
            return "junction"
        raise unittest.SkipTest("cannot create symlinks here")


class CopyBackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.stage, self.out, self.outside = base / "stage", base / "out", base / "outside"
        for d in (self.stage, self.out, self.outside):
            d.mkdir()
        self.cfg = _cfg(max_output_file_mb=0.001, max_output_total_mb=0.003, max_output_files=5)  # 1 KiB / ~3 KiB / 5 files

    def tearDown(self):
        self.tmp.cleanup()

    def test_regular_files_copied_nested(self):
        (self.stage / "a.csv").write_text("x,y\n1,2\n")
        (self.stage / "sub" / "deep").mkdir(parents=True)
        (self.stage / "sub" / "deep" / "b.txt").write_text("b")
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertEqual(sorted(rep.copied), ["a.csv", "sub/deep/b.txt"])
        self.assertEqual(rep.rejected, [])
        self.assertEqual((self.out / "sub" / "deep" / "b.txt").read_text(), "b")
        self.assertEqual([p.name for p in self.out.rglob("*.part")], [])

    def test_oversize_and_caps(self):
        (self.stage / "big.bin").write_bytes(b"x" * 2000)
        for i in range(4):
            (self.stage / f"f{i}.txt").write_bytes(b"y" * 900)
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertFalse((self.out / "big.bin").exists())
        self.assertTrue(any(r.startswith("big.bin:") and "per-file cap" in r for r in rep.rejected), rep.rejected)
        self.assertEqual(len(rep.copied), 3)  # 3 x 900 fits in ~3 KiB, the 4th does not
        self.assertTrue(any("total output cap" in r for r in rep.rejected), rep.rejected)

    def test_file_count_cap(self):
        for i in range(7):
            (self.stage / f"n{i}.txt").write_text("1")
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertEqual(len(rep.copied), 5)
        self.assertEqual(sum("file-count cap" in r for r in rep.rejected), 2)

    def test_symlinked_file_rejected(self):
        secret = self.outside / "secret.txt"
        secret.write_text("host secret")
        try:
            os.symlink(secret, self.stage / "leak.txt")
        except OSError:
            self.skipTest("file symlinks need a privilege on this machine")
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertFalse((self.out / "leak.txt").exists())
        self.assertIn("leak.txt: symlink or reparse point", rep.rejected)

    def test_linked_folder_in_stage_rejected(self):
        (self.outside / "host.txt").write_text("host file")
        _make_link(self.stage / "linkdir", self.outside, True)
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertEqual(rep.copied, [])
        self.assertIn("linkdir: symlink or reparse point", rep.rejected)
        self.assertFalse((self.out / "linkdir").exists())

    def test_link_inside_output_dir_not_followed(self):
        _make_link(self.out / "reports", self.outside, True)
        (self.stage / "reports").mkdir()
        (self.stage / "reports" / "r.txt").write_text("would escape")
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertEqual(rep.copied, [])
        self.assertFalse((self.outside / "r.txt").exists())
        self.assertTrue(any(r.startswith("reports/r.txt:") for r in rep.rejected), rep.rejected)

    def test_existing_file_symlink_target_not_overwritten(self):
        victim = self.outside / "victim.txt"
        victim.write_text("keep")
        try:
            os.symlink(victim, self.out / "result.txt")
        except OSError:
            self.skipTest("file symlinks need a privilege on this machine")
        (self.stage / "result.txt").write_text("overwrite")
        rep = db.copy_back(self.stage, self.out, self.cfg)
        self.assertEqual(victim.read_text(), "keep")
        self.assertEqual(rep.copied, [])

    def test_seeded_unchanged_files_skipped_changed_copied(self):
        (self.out / "keep.csv").write_text("old")
        (self.out / "edit.csv").write_text("old")
        seeded, notes = db.seed_stage(self.out, self.stage, self.cfg)
        self.assertEqual(sorted(seeded), ["edit.csv", "keep.csv"])
        self.assertEqual(notes, [])
        time.sleep(0.02)
        (self.stage / "edit.csv").write_text("new value")
        (self.stage / "fresh.csv").write_text("n")
        rep = db.copy_back(self.stage, self.out, self.cfg, seeded)
        self.assertEqual(sorted(rep.copied), ["edit.csv", "fresh.csv"])
        self.assertEqual((self.out / "edit.csv").read_text(), "new value")
        self.assertEqual((self.out / "keep.csv").read_text(), "old")


class FakeDockerBase(unittest.TestCase):
    """run_python with tiers.code.backend=docker against tests/fake_docker.py, placed on PATH as `docker`."""

    extra: dict = {}
    mode = "ok"

    def setUp(self):
        self.ws = TempWorkspace(self._merge({"tiers": {"code": {"backend": "docker", "docker_cli": "docker", "docker": {"pull": "if-missing"}}}}, self.extra))
        self.s = self.ws.settings
        self.state = self.ws.root / "fake_state"
        self.state.mkdir()
        self.bin = self.ws.root / "fakebin"
        self.bin.mkdir()
        if IS_WINDOWS:
            (self.bin / "docker.cmd").write_text(f'@"{sys.executable}" "{FAKE}" %*\r\n', encoding="utf-8")
        else:
            shim = self.bin / "docker"
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
            shim.chmod(0o755)
        self._env = {k: os.environ.get(k) for k in ("PATH", "FAKE_DOCKER_STATE", "FAKE_DOCKER_MODE", "FAKE_DOCKER_RUN_SCRIPT")}
        os.environ["PATH"] = str(self.bin) + os.pathsep + os.environ.get("PATH", "")
        os.environ["FAKE_DOCKER_STATE"] = str(self.state)
        os.environ["FAKE_DOCKER_MODE"] = self.mode
        os.environ.pop("FAKE_DOCKER_RUN_SCRIPT", None)
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, ScriptedApprover([]), step_id="s1", workdir=self.audit.dir / "scratch", params={"period": "2026-10"})

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.ws.cleanup()

    @staticmethod
    def _merge(a, b):
        from analyst_agent.config import _deep_merge

        return _deep_merge(a, b)

    def scenario(self, code: str):
        p = self.ws.root / "scenario.py"
        p.write_text(code, encoding="utf-8")
        os.environ["FAKE_DOCKER_RUN_SCRIPT"] = str(p)

    def calls(self) -> list[list[str]]:
        f = self.state / "calls.jsonl"
        return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines()] if f.exists() else []

    def run_calls(self):
        return [c for c in self.calls() if c and c[0] == "run"]


class FakeDockerRunTests(FakeDockerBase):
    def test_fake_resolved_from_path(self):
        cfg = db.DockerConfig.from_settings(self.s["tiers"]["code"])
        self.assertEqual(Path(cfg.cli[0]).parent, self.bin)
        self.assertTrue(db.check(cfg).ok)

    def test_step_runs_in_container_and_outputs_copied_back(self):
        (self.s.output_dir).mkdir(parents=True, exist_ok=True)
        (self.s.output_dir / "earlier.csv").write_text("from step 0")
        self.scenario(
            "import os, pathlib\n"
            "out = pathlib.Path(mounts['/output']); work = pathlib.Path(mounts['/work'])\n"
            "boot = (work / '_bootstrap.py').read_text(encoding='utf-8')\n"
            "print('script', (work / '_step_s1.py').read_text(encoding='utf-8').strip())\n"
            "print('seeded', (out / 'earlier.csv').read_text())\n"
            "print('cfg', \"'output_dir': '/output'\" in boot, \"'input_dirs': ['/inputs/0']\" in boot, \"'allow_network': False\" in boot)\n"
            "(out / 'result.csv').write_text('a,b\\n1,2\\n')\n"
            "(out / 'sub').mkdir(); (out / 'sub' / 'n.txt').write_text('nested')\n"
            "print('inputs', sorted(k for k in mounts if k.startswith('/inputs/')))\n"
        )
        out = run_python("print('hello')", self.ctx)
        self.assertFalse(out.is_error, out.text)
        self.assertIn("script print('hello')", out.text)
        self.assertIn("seeded from step 0", out.text)
        self.assertIn("cfg True True True", out.text)
        self.assertIn("inputs ['/inputs/0']", out.text)
        self.assertEqual((self.s.output_dir / "result.csv").read_text(), "a,b\n1,2\n")
        self.assertEqual((self.s.output_dir / "sub" / "n.txt").read_text(), "nested")
        self.assertIn("copied to OUTPUT_DIR: result.csv, sub/n.txt", out.text)
        run = self.run_calls()
        self.assertEqual(len(run), 1)
        mounts = _pair(run[0], "--mount")
        src = db.host_mount_path(self.ws.root.resolve() / "samples", "windows" if IS_WINDOWS else "posix")
        self.assertIn(f"type=bind,source={src},target=/inputs/0,readonly", mounts)
        self.assertFalse(any(str(self.s.output_dir.resolve()).replace("\\", "/") in m for m in mounts), "real OUTPUT_DIR must not be mounted")
        for flag in ("--network", "--user", "--cap-drop", "--security-opt", "--pids-limit", "--memory"):
            self.assertTrue(_pair(run[0], flag), flag)
        runs = [e for e in self.audit.events() if e.get("kind") == "code_run" or e.get("argv")]
        self.assertTrue(any(e.get("backend") == "docker" and e.get("argv", [])[-len(run[0]):] == run[0] for e in runs), runs)

    def test_rejected_outputs_reported(self):
        self.scenario(
            "import pathlib\nout = pathlib.Path(mounts['/output'])\n"
            "(out / 'ok.txt').write_text('fine')\n"
            "(out / 'huge.bin').write_bytes(b'x' * 3000)\n"
        )
        self.s.data["tiers"]["code"]["docker"]["max_output_file_mb"] = 0.002
        out = run_python("pass", self.ctx)
        self.assertFalse(out.is_error, out.text)
        self.assertTrue((self.s.output_dir / "ok.txt").exists())
        self.assertFalse((self.s.output_dir / "huge.bin").exists())
        self.assertIn("were not copied to OUTPUT_DIR: huge.bin", out.text)

    def test_nonzero_exit_and_oom_note(self):
        self.scenario("import sys\nsys.stderr.write('Killed\\n')\nraise SystemExit(137)\n")
        out = run_python("x = bytearray(10**10)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("exit code 137", out.text)
        self.assertIn("memory limit", out.text)

    def test_timeout_kills_named_container(self):
        self.scenario("import os, time\n(state / f'{name}.pid').write_text(str(os.getpid()))\ntime.sleep(60)\n")
        t = time.time()
        out = run_python("while True: pass", self.ctx, timeout=2)
        self.assertLess(time.time() - t, 30)
        self.assertTrue(out.is_error)
        self.assertIn("longer than 2s", out.text)
        name = _pair(self.run_calls()[0], "--name")[0]
        self.assertTrue(name.startswith("aa-code-"))
        self.assertIn(["kill", name], self.calls())
        self.assertEqual((self.state / "killed").read_text(), name)

    def test_unsafe_mount_path_refused_before_run(self):
        bad = self.ws.root / "in,put"
        bad.mkdir()
        self.s.data["workspace"]["input_dirs"] = [str(bad)]
        out = run_python("pass", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("nothing was run", out.text)
        self.assertEqual(self.run_calls(), [])


class FailClosedTests(FakeDockerBase):
    mode = "down"

    def test_daemon_down_fails_closed(self):
        out = run_python("open(OUTPUT_DIR + '/x.txt', 'w').write('x')", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("docker backend is unavailable", out.text)
        self.assertIn("daemon not reachable", out.text)
        self.assertIn("nothing was run", out.text)
        self.assertEqual(self.run_calls(), [])
        self.assertFalse((self.s.output_dir / "x.txt").exists())

    def test_windows_containers_daemon_fails_closed(self):
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"FAKE_DOCKER_MODE": "windows"}):
            out = run_python("print(1)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("Linux-containers daemon", out.text)
        self.assertIn("nothing was run", out.text)
        self.assertEqual(self.run_calls(), [])

    def test_cli_missing_fails_closed(self):
        self.s.data["tiers"]["code"]["docker_cli"] = str(self.ws.root / "no" / "docker.exe")
        out = run_python("print(1)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("docker CLI not found", out.text)
        self.assertEqual(self.calls(), [])

    def test_fallback_to_local_only_when_configured(self):
        self.s.data["tiers"]["code"]["fallback_to_local"] = True
        out = run_python("print('ran', 6 * 7)", self.ctx)
        self.assertFalse(out.is_error, out.text)
        self.assertIn("ran 42", out.text)
        self.assertIn("ran on the local backend", out.text)
        self.assertEqual(self.run_calls(), [])

    def test_status_line(self):
        line = db.status_line(self.s["tiers"]["code"])
        self.assertIn("code backend: docker", line)
        self.assertIn("daemon unreachable", line)
        self.assertIn("fail closed", line)

    def test_unknown_backend_refused(self):
        self.s.data["tiers"]["code"]["backend"] = "vm"
        out = run_python("print(1)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("unknown tiers.code.backend", out.text)


class ImagePolicyTests(FakeDockerBase):
    mode = "noimage"

    def test_pull_never_fails_closed(self):
        self.s.data["tiers"]["code"]["docker"]["pull"] = "never"
        out = run_python("print(1)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("is not present", out.text)
        self.assertFalse(any(c[0] == "pull" for c in self.calls()))
        self.assertEqual(self.run_calls(), [])

    def test_if_missing_pulls_then_runs(self):
        out = run_python("print(1)", self.ctx)
        self.assertFalse(out.is_error, out.text)
        names = [c[0] for c in self.calls()]
        self.assertLess(names.index("pull"), names.index("run"))
        self.assertIn("present", db.status_line(self.s["tiers"]["code"]))

    def test_status_reports_missing_image(self):
        line = db.status_line(self.s["tiers"]["code"])
        self.assertIn("daemon reachable (28.5.2)", line)
        self.assertIn("missing", line)


class PullFailTests(FakeDockerBase):
    mode = "pullfail"

    def test_pull_failure_fails_closed(self):
        out = run_python("print(1)", self.ctx)
        self.assertTrue(out.is_error)
        self.assertIn("docker pull", out.text)
        self.assertEqual(self.run_calls(), [])


# --------------------------------------------------------------------------- live


def _docker_up() -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        r = subprocess.run([exe, "version", "--format", "{{.Server.Os}}"], capture_output=True, text=True, timeout=30)
        # GitHub's windows runners have a Windows-containers daemon; the Linux image can't run there.
        return r.returncode == 0 and r.stdout.strip().lower() == "linux"
    except Exception:
        return False


LIVE = _docker_up()


@unittest.skipUnless(LIVE, "no Linux-containers docker daemon reachable")
class LiveDockerTests(unittest.TestCase):
    extra: dict = {}

    def setUp(self):
        from analyst_agent.config import _deep_merge

        self.ws = TempWorkspace(_deep_merge({"tiers": {"code": {"backend": "docker", "docker_cli": "docker", "memory_mb": 256}}}, self.extra))
        self.s = self.ws.settings
        self.audit = AuditLog(self.s.audit_dir)
        self.ctx = ToolContext(self.s, PolicyEngine(self.s), self.audit, ScriptedApprover([]), step_id="live", workdir=self.audit.dir / "scratch", params={"period": "2026-10"})

    def tearDown(self):
        self.ws.cleanup()

    def test_reads_inputs_writes_output(self):
        code = (
            "import csv, os, json\n"
            "rows = list(csv.DictReader(open(os.path.join(INPUT_DIRS[0], f\"erp_export_{PARAMS['period']}.csv\"), newline='', encoding='utf-8-sig')))\n"
            "json.dump({'rows': len(rows), 'uid': os.getuid(), 'out': OUTPUT_DIR}, open(os.path.join(OUTPUT_DIR, 'live.json'), 'w'))\n"
            "print('rows', len(rows), 'uid', os.getuid(), INPUT_DIRS, OUTPUT_DIR)\n"
        )
        out = run_python(code, self.ctx, timeout=120)
        self.assertFalse(out.is_error, out.text)
        self.assertIn("uid 65534 ['/inputs/0'] /output", out.text)
        self.assertEqual(json.loads((self.s.output_dir / "live.json").read_text())["uid"], 65534)

    def test_timeout_kills_container(self):
        t = time.time()
        out = run_python("while True: pass", self.ctx, timeout=5)
        self.assertTrue(out.is_error)
        self.assertIn("longer than 5s", out.text)
        self.assertLess(time.time() - t, 60)


@unittest.skipUnless(LIVE, "no Linux-containers docker daemon reachable")
class LiveDockerNoGuardTests(LiveDockerTests):
    """With the Python guard off, the container itself must still hold."""

    extra = {"tiers": {"code": {"python_guard": False}}}

    def test_container_boundary(self):
        code = (
            "import os, socket\n"
            "def tryit(label, fn):\n"
            "    try:\n        fn(); print(label, 'ALLOWED')\n"
            "    except Exception as e:\n        print(label, 'blocked', type(e).__name__)\n"
            "tryit('net', lambda: socket.create_connection(('1.1.1.1', 53), timeout=3))\n"
            "tryit('rootfs', lambda: open('/usr/evil', 'w'))\n"
            "tryit('input', lambda: open(os.path.join(INPUT_DIRS[0], 'evil.csv'), 'w'))\n"
            "tryit('tmp', lambda: open('/tmp/ok', 'w').write('x'))\n"
            "print('uid', os.getuid())\n"
        )
        out = run_python(code, self.ctx, timeout=120)
        self.assertFalse(out.is_error, out.text)
        for label in ("net", "rootfs", "input"):
            self.assertIn(f"{label} blocked", out.text)
        self.assertIn("tmp ALLOWED", out.text)
        self.assertFalse((self.ws.root / "samples" / "evil.csv").exists())

    def test_memory_limit(self):
        out = run_python("x = bytearray(700 * 1024 * 1024)\nprint('allocated', len(x))", self.ctx, timeout=120)
        self.assertTrue(out.is_error, out.text)
        self.assertNotIn("allocated", out.text.split("--- stderr ---")[0])


if __name__ == "__main__":
    unittest.main()
