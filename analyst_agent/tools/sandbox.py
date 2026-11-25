"""Process limits for the code tier (stdlib + ctypes only).

Windows: the child starts CREATE_SUSPENDED, is assigned to a Job Object, and
only then resumed (NtResumeProcess), so it never runs a single instruction
outside the job. The job has:
- KILL_ON_JOB_CLOSE: the parent closing the handle (or dying) kills every
  process in it, so nothing outlives the step
- a per-process and per-job committed-memory limit (tiers.code.memory_mb)
- an active-process limit (tiers.code.max_processes, default 1: no children,
  so no fork bombs)
- per-process and per-job user-mode CPU time limits (tiers.code.cpu_s)
- UI restrictions: no desktop switching, clipboard read/write, global atoms,
  USER handles of other processes, system parameter changes, display
  settings or ExitWindows
- DIE_ON_UNHANDLED_EXCEPTION (no error dialog waiting for a human)

Other platforms: resource.setrlimit in preexec_fn (address space, CPU time,
process count, no core files) and a new session so the whole group is killed
on time-out.

This limits *resources*; it does not hide files or the network from the
child. That is the job of the Python guard (defense in depth) and, in
production, of the disposable per-task VM or container.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"


@dataclass
class Limits:
    memory_mb: int = 1024
    max_processes: int = 1
    cpu_s: float = 300
    ui_restrictions: bool = True


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    contained: bool = False  # True when the job object / rlimits were applied
    notes: list[str] = field(default_factory=list)
    peak_memory_mb: float | None = None


class SandboxError(RuntimeError):
    pass


# --------------------------------------------------------------------------- Windows job object

if IS_WINDOWS:
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
        _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.QueryInformationJobObject.restype = wintypes.BOOL
    _k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.TerminateJobObject.restype = wintypes.BOOL
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.restype = ctypes.c_long
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

CREATE_SUSPENDED = 0x00000004
JobObjectBasicUIRestrictions = 4
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_UILIMIT_ALL = 0xFF  # HANDLES|READCLIPBOARD|WRITECLIPBOARD|SYSTEMPARAMETERS|DISPLAYSETTINGS|GLOBALATOMS|DESKTOP|EXITWINDOWS
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class JobObject:
    """A Windows Job Object with the code-tier limits. Closing it kills its processes."""

    def __init__(self, limits: Limits):
        if not IS_WINDOWS:
            raise SandboxError("job objects need Windows")
        self.handle = _k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise SandboxError(f"CreateJobObject failed: {ctypes.get_last_error()}")
        self.limits = limits
        try:
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            b = info.BasicLimitInformation
            b.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            if limits.memory_mb:
                mem = int(limits.memory_mb) * 1024 * 1024
                info.ProcessMemoryLimit = mem
                info.JobMemoryLimit = mem
                b.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
            if limits.max_processes:
                b.ActiveProcessLimit = int(limits.max_processes)
                b.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            if limits.cpu_s:
                ticks = int(float(limits.cpu_s) * 10_000_000)  # 100 ns units
                b.PerProcessUserTimeLimit = ticks
                b.PerJobUserTimeLimit = ticks
                b.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME
            if not _k32.SetInformationJobObject(self.handle, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
                raise SandboxError(f"SetInformationJobObject(limits) failed: {ctypes.get_last_error()}")
            if limits.ui_restrictions:
                ui = JOBOBJECT_BASIC_UI_RESTRICTIONS(JOB_OBJECT_UILIMIT_ALL)
                if not _k32.SetInformationJobObject(self.handle, JobObjectBasicUIRestrictions, ctypes.byref(ui), ctypes.sizeof(ui)):
                    raise SandboxError(f"SetInformationJobObject(UI) failed: {ctypes.get_last_error()}")
        except Exception:
            self.close()
            raise

    def assign_and_resume(self, pid: int) -> None:
        h = _k32.OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            raise SandboxError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
        try:
            if not _k32.AssignProcessToJobObject(self.handle, h):
                raise SandboxError(f"AssignProcessToJobObject failed: {ctypes.get_last_error()}")
            status = _ntdll.NtResumeProcess(h)
            if status < 0:
                raise SandboxError(f"NtResumeProcess failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
        finally:
            _k32.CloseHandle(h)

    def peak_memory_mb(self) -> float | None:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        if _k32.QueryInformationJobObject(self.handle, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info), None):
            return round(info.PeakJobMemoryUsed / (1024 * 1024), 1)
        return None

    def terminate(self, code: int = 1) -> None:
        if self.handle:
            _k32.TerminateJobObject(self.handle, code)

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)  # KILL_ON_JOB_CLOSE ends anything left
            self.handle = None


# --------------------------------------------------------------------------- POSIX rlimits


def _posix_preexec(limits: Limits):  # pragma: no cover - non-Windows
    def apply():
        import resource

        if limits.memory_mb:
            mem = int(limits.memory_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        if limits.cpu_s:
            cpu = max(1, int(limits.cpu_s))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        if limits.max_processes and hasattr(resource, "RLIMIT_NPROC"):
            # RLIMIT_NPROC counts all of the user's processes, so a small value means "no fork".
            n = int(limits.max_processes)
            resource.setrlimit(resource.RLIMIT_NPROC, (n, n))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


# --------------------------------------------------------------------------- environment


def minimal_env(workdir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """An allowlisted environment: nothing from the agent's own environment
    (tokens, vault env secrets, proxies) reaches the child."""
    tmp = workdir / "tmp"
    home = workdir / "home"
    tmp.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    env: dict[str, str] = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(tmp),
        "TMP": str(tmp),
        "TMPDIR": str(tmp),
        "HOME": str(home),
        "MPLCONFIGDIR": str(home),
    }
    exe_dir = os.path.dirname(sys.executable)
    if IS_WINDOWS:
        sysroot = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
        env.update(
            SYSTEMROOT=sysroot,
            WINDIR=os.environ.get("WINDIR", sysroot),
            PATH=os.pathsep.join([exe_dir, os.path.join(sysroot, "System32")]),
            PATHEXT=".COM;.EXE;.BAT;.CMD",
            USERPROFILE=str(home),
            APPDATA=str(home),
            LOCALAPPDATA=str(home),
        )
        for k in ("NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "SYSTEMDRIVE"):
            if os.environ.get(k):
                env[k] = os.environ[k]
    else:
        env["PATH"] = os.pathsep.join([exe_dir, "/usr/bin", "/bin"])
        env["LANG"] = "C.UTF-8"
    env.update(extra or {})
    return env


# --------------------------------------------------------------------------- run


def run_limited(argv: list[str], cwd: Path, env: dict[str, str], timeout: float, limits: Limits, require: bool = True) -> RunResult:
    """Run argv with the resource limits. `require=True` fails closed when the
    limits cannot be applied."""
    notes: list[str] = []
    job: JobObject | None = None
    kwargs: dict = dict(cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    if IS_WINDOWS:
        try:
            job = JobObject(limits)
        except SandboxError as e:
            if require:
                raise
            notes.append(f"job object unavailable: {e}")
        kwargs["creationflags"] = CREATE_SUSPENDED if job else 0
    else:  # pragma: no cover - non-Windows
        kwargs["preexec_fn"] = _posix_preexec(limits)
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv, **kwargs)
    except Exception:
        if job:
            job.close()
        raise
    contained = not IS_WINDOWS
    try:
        if job:
            try:
                job.assign_and_resume(proc.pid)
                contained = True
            except SandboxError:
                proc.kill()
                proc.communicate()
                raise
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if job:
                job.terminate(1)
            elif not IS_WINDOWS:  # pragma: no cover
                import signal

                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
            else:
                proc.kill()
            out, err = proc.communicate()
        peak = job.peak_memory_mb() if job else None
    finally:
        if job:
            job.close()
    return RunResult(proc.returncode, out or "", err or "", timed_out, contained, notes, peak)
