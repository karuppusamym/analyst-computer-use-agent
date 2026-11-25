"""Code tier backend "docker": one disposable container per step (docker CLI, no SDK).

Selected with `tiers.code.backend: "docker"` (default "local": Job Object +
audit-hook guard, see code.py / sandbox.py). Each run_python step becomes

    docker run --rm --name aa-code-<random> --network none --read-only
        --cap-drop ALL --security-opt no-new-privileges --pids-limit N
        --memory Mm --memory-swap Mm --cpus C --user 65534:65534
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=Tm --ulimit core=0
        --pull never --workdir /work --env ...
        --mount type=bind,source=<input n>,target=/inputs/<n>,readonly ...
        --mount type=bind,source=<stage>/work,target=/work
        --mount type=bind,source=<stage>/output,target=/output
        <image> python -I -B -X utf8 /work/_bootstrap.py

- The script, and the audit-hook guard as defense in depth (python_guard),
  run inside the container with INPUT_DIRS = /inputs/<n>, OUTPUT_DIR = /output.
- The real OUTPUT_DIR is never mounted. A fresh per-step stage folder is
  seeded with copies of the current regular files in OUTPUT_DIR, mounted at
  /output, and after the container has exited, new or changed files are
  copied back by `copy_back`: regular files only, no symlinks or reparse
  points, names that are valid on Windows, inside OUTPUT_DIR, per-file,
  total and count caps. Deletions inside the container are not propagated.
- The time-out is enforced with `docker kill <name>`; the container is
  `--rm`, so nothing is left behind.
- Network is always `none`. An egress allowlist is out of scope.
- The image is not pulled during the step: `pull: "if-missing"` pulls it
  (outside the time-out) before the run, `pull: "never"` fails closed when
  it is missing. Pin it by digest, e.g. "python:3.13-slim@sha256:<digest>".

When the CLI, the daemon or the image is unavailable the step fails closed
(DockerUnavailable). code.py falls back to the local backend only when
`tiers.code.fallback_to_local` is true.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from .sandbox import IS_WINDOWS, RunResult, SandboxError

CONTAINER_WORK = "/work"
CONTAINER_OUTPUT = "/output"
CONTAINER_INPUTS = "/inputs"
CONTAINER_TMP = "/tmp"
NOBODY = "65534:65534"

DOCKER_DEFAULTS = {
    "image": "python:3.13-slim",
    "pull": "if-missing",  # "never" | "if-missing"
    "cpus": 1.0,
    "pids_limit": 64,
    "tmpfs_mb": 64,
    "path_style": "auto",  # "auto" | "windows" | "posix": how host paths are written in --mount
    "control_timeout_s": 20,  # docker version / image inspect / kill
    "pull_timeout_s": 900,
    "max_output_file_mb": 100,
    "max_output_total_mb": 500,
    "max_output_files": 2000,
}


class DockerUnavailable(SandboxError):
    """The docker backend cannot run this step (CLI, daemon or image missing)."""


@dataclass
class DockerConfig:
    cli: list[str]
    image: str
    pull: str
    memory_mb: int
    cpus: float
    pids_limit: int
    tmpfs_mb: int
    path_style: str
    control_timeout_s: float
    pull_timeout_s: float
    max_file_bytes: int
    max_total_bytes: int
    max_files: int

    @classmethod
    def from_settings(cls, code_cfg: dict) -> "DockerConfig":
        d = dict(DOCKER_DEFAULTS)
        d.update({k: v for k, v in (code_cfg.get("docker") or {}).items() if v is not None})
        cli = code_cfg.get("docker_cli") or "docker"
        cli = [str(x) for x in cli] if isinstance(cli, (list, tuple)) else [str(cli)]
        if cli and not os.path.dirname(cli[0]):
            # Resolve through PATH/PATHEXT here: CreateProcess alone would only find docker.exe, not a docker.cmd shim.
            cli[0] = shutil.which(cli[0]) or cli[0]
        pull = str(d["pull"]).lower()
        if pull not in ("never", "if-missing"):
            raise SandboxError(f"tiers.code.docker.pull must be 'never' or 'if-missing', not {d['pull']!r}")
        style = str(d["path_style"]).lower()
        if style == "auto":
            style = "windows" if IS_WINDOWS else "posix"
        if style not in ("windows", "posix"):
            raise SandboxError(f"tiers.code.docker.path_style must be auto, windows or posix, not {d['path_style']!r}")
        mb = 1024 * 1024
        return cls(
            cli=cli,
            image=str(d["image"]),
            pull=pull,
            memory_mb=int(code_cfg.get("memory_mb", 1024) or 1024),
            cpus=float(d["cpus"]),
            pids_limit=int(d["pids_limit"]),
            tmpfs_mb=int(d["tmpfs_mb"]),
            path_style=style,
            control_timeout_s=float(d["control_timeout_s"]),
            pull_timeout_s=float(d["pull_timeout_s"]),
            max_file_bytes=int(float(d["max_output_file_mb"]) * mb),
            max_total_bytes=int(float(d["max_output_total_mb"]) * mb),
            max_files=int(d["max_output_files"]),
        )


# --------------------------------------------------------------------------- paths


_MOUNT_UNSAFE = re.compile(r'[,"\'\n\r\t=]')


def host_mount_path(path: str | os.PathLike, style: str) -> str:
    """A host path as the docker CLI's --mount source.

    windows: drive-letter paths only, written C:/dir/sub (Docker Desktop
    accepts this form); \\\\?\\ prefixes are stripped; UNC/network paths and
    relative paths are refused. posix: absolute paths as they are.
    Characters that would break --mount's comma-separated syntax are refused
    rather than quoted."""
    raw = os.fspath(path)
    if style == "windows":
        if raw.startswith("\\\\?\\UNC\\"):
            raise SandboxError(f"network (UNC) paths cannot be mounted into the container: {raw}")
        if raw.startswith("\\\\?\\") or raw.startswith("//?/"):
            raw = raw[4:]
        p = PureWindowsPath(raw)
        if p.drive.startswith("\\\\") or raw.startswith("//") or raw.startswith("\\\\"):
            raise SandboxError(f"network (UNC) paths cannot be mounted into the container: {raw}")
        if not (len(p.drive) == 2 and p.drive[1] == ":" and p.drive[0].isalpha()) or not p.root:
            raise SandboxError(f"only absolute drive-letter paths can be mounted into the container: {raw}")
        out = p.drive.upper() + "/" + "/".join(p.parts[1:])
    elif style == "posix":
        if not raw.startswith("/"):
            raise SandboxError(f"only absolute paths can be mounted into the container: {raw}")
        out = raw
    else:
        raise SandboxError(f"unknown path style {style!r}")
    if _MOUNT_UNSAFE.search(out) or ".." in out.replace("\\", "/").split("/"):
        raise SandboxError(f"path cannot be mounted safely (contains , \" ' = .. or a control character): {raw}")
    return out


def mount_arg(source: Path, target: str, style: str, readonly: bool) -> str:
    return f"type=bind,source={host_mount_path(source, style)},target={target}" + (",readonly" if readonly else "")


def container_inputs(n: int) -> list[str]:
    return [f"{CONTAINER_INPUTS}/{i}" for i in range(n)]


# --------------------------------------------------------------------------- argv


def run_argv(cfg: DockerConfig, name: str, input_dirs: list[Path], work: Path, output: Path, bootstrap_name: str) -> list[str]:
    """The exact `docker run` command line for one step."""
    argv = list(cfg.cli) + [
        "run", "--rm", "--name", name,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(cfg.pids_limit),
        "--memory", f"{cfg.memory_mb}m",
        "--memory-swap", f"{cfg.memory_mb}m",
        "--cpus", f"{cfg.cpus:g}",
        "--user", NOBODY,
        "--tmpfs", f"{CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={cfg.tmpfs_mb}m",
        "--ulimit", "core=0",
        "--pull", "never",
        "--label", "analyst_agent=code",
        "--workdir", CONTAINER_WORK,
    ]
    for k, v in container_env().items():
        argv += ["--env", f"{k}={v}"]
    for src, target in zip(input_dirs, container_inputs(len(input_dirs))):
        argv += ["--mount", mount_arg(src, target, cfg.path_style, readonly=True)]
    argv += ["--mount", mount_arg(work, CONTAINER_WORK, cfg.path_style, readonly=False)]
    argv += ["--mount", mount_arg(output, CONTAINER_OUTPUT, cfg.path_style, readonly=False)]
    argv += [cfg.image, "python", "-I", "-B", "-X", "utf8", f"{CONTAINER_WORK}/{bootstrap_name}"]
    return argv


def container_env() -> dict[str, str]:
    """The only environment the container gets (nothing from the agent's)."""
    return {
        "HOME": CONTAINER_TMP,
        "TMPDIR": CONTAINER_TMP,
        "MPLCONFIGDIR": CONTAINER_TMP,
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }


def guard_config(guard: bool, script_name: str, n_inputs: int, params: dict) -> dict:
    """The _sandbox_guard config with container paths (INPUT_DIRS/OUTPUT_DIR rewritten)."""
    ins = container_inputs(n_inputs)
    return {
        "guard": guard,
        "script": f"{CONTAINER_WORK}/{script_name}",
        "input_dirs": ins,
        "output_dir": CONTAINER_OUTPUT,
        "params": params,
        "read": list(ins),
        "write": [CONTAINER_WORK, CONTAINER_OUTPUT, CONTAINER_TMP],
        "deny": [],  # the vault and audit folders are not mounted at all
        "site_dirs": [],
        "allow_network": False,  # network is always none in the container
    }


# --------------------------------------------------------------------------- availability


def _control(cfg: DockerConfig, args: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(cfg.cli) + args, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout or cfg.control_timeout_s)


def _cli_present(cfg: DockerConfig) -> str | None:
    exe = cfg.cli[0]
    if os.path.dirname(exe):
        return exe if os.path.isfile(exe) else None
    return shutil.which(exe)


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")[:300]


@dataclass
class DockerStatus:
    cli: str | None = None
    daemon: str | None = None  # server version when reachable
    image_present: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.cli and self.daemon and self.image_present)


def check(cfg: DockerConfig, check_image: bool = True) -> DockerStatus:
    st = DockerStatus()
    st.cli = _cli_present(cfg)
    if not st.cli:
        st.errors.append(f"docker CLI not found ({cfg.cli[0]!r}; set tiers.code.docker_cli)")
        return st
    try:
        r = _control(cfg, ["version", "--format", "{{.Server.Version}}"])
    except (OSError, subprocess.TimeoutExpired) as e:
        st.errors.append(f"docker daemon not reachable: {e}")
        return st
    if r.returncode != 0 or not r.stdout.strip():
        st.errors.append(f"docker daemon not reachable: {_first_line(r.stderr) or f'exit code {r.returncode}'}")
        return st
    st.daemon = r.stdout.strip()
    if check_image:
        try:
            r = _control(cfg, ["image", "inspect", "--format", "{{.Id}}", cfg.image])
            st.image_present = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as e:
            st.errors.append(f"image inspect failed: {e}")
        if not st.image_present:
            st.errors.append(f"image {cfg.image} is not present (pull policy: {cfg.pull})")
    return st


def status_line(code_cfg: dict) -> str:
    """One line for `python -m analyst_agent status`."""
    backend = str(code_cfg.get("backend", "local"))
    try:
        cfg = DockerConfig.from_settings(code_cfg)
    except SandboxError as e:
        return f"code backend: {backend}   docker: misconfigured ({e})"
    st = check(cfg)
    parts = [f"cli {'found' if st.cli else 'missing'}", f"daemon {'reachable (' + st.daemon + ')' if st.daemon else 'unreachable'}"]
    if st.daemon:
        parts.append(f"image {cfg.image} {'present' if st.image_present else 'missing'}")
    verdict = "available" if st.ok else ("available after pull" if st.daemon and cfg.pull == "if-missing" else "unavailable")
    line = f"code backend: {backend}   docker: {verdict} ({', '.join(parts)})"
    if backend == "docker" and not st.ok and st.errors:
        fb = "falls back to local" if code_cfg.get("fallback_to_local") else "code steps fail closed"
        line += f"\n  {st.errors[0]}; {fb}"
    return line


def ensure_ready(cfg: DockerConfig) -> DockerStatus:
    """Fail closed unless the CLI, the daemon and the image are there (pulling if allowed)."""
    st = check(cfg)
    if st.ok:
        return st
    if not st.cli or not st.daemon:
        raise DockerUnavailable("; ".join(st.errors))
    if cfg.pull != "if-missing":
        raise DockerUnavailable(f"image {cfg.image} is not present and tiers.code.docker.pull is 'never'")
    try:
        r = _control(cfg, ["pull", cfg.image], timeout=cfg.pull_timeout_s)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DockerUnavailable(f"docker pull {cfg.image} failed: {e}") from e
    if r.returncode != 0:
        raise DockerUnavailable(f"docker pull {cfg.image} failed: {_first_line(r.stderr) or r.returncode}")
    st.image_present = True
    return st


# --------------------------------------------------------------------------- output staging

_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_BAD_NAME = re.compile(r'[<>:"|?*\\\x00-\x1f]')


def _safe_name(part: str) -> bool:
    if part in ("", ".", "..") or _BAD_NAME.search(part) or part[-1] in " .":
        return False
    return part.split(".")[0].upper() not in _WIN_RESERVED


def _is_link(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


@dataclass
class CopyReport:
    copied: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)  # "path: reason"

    def notes(self) -> list[str]:
        out = []
        if self.rejected:
            shown = "; ".join(self.rejected[:10]) + (" ..." if len(self.rejected) > 10 else "")
            out.append(f"{len(self.rejected)} output file(s) from the container were not copied to OUTPUT_DIR: {shown}")
        return out


def _walk(root: Path, report: CopyReport):
    """Yield (relative posix path, lstat) for regular files under root; record everything else."""
    stack = [(root, "")]
    while stack:
        d, rel = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as e:
            report.rejected.append(f"{rel or '.'}: cannot list ({e.strerror})")
            continue
        for e in entries:
            r = f"{rel}/{e.name}" if rel else e.name
            try:
                st = os.lstat(e.path)
            except OSError as ex:
                report.rejected.append(f"{r}: {ex.strerror}")
                continue
            if not _safe_name(e.name):
                report.rejected.append(f"{r}: unsafe file name")
            elif _is_link(st):
                report.rejected.append(f"{r}: symlink or reparse point")
            elif stat.S_ISDIR(st.st_mode):
                stack.append((Path(e.path), r))
            elif stat.S_ISREG(st.st_mode):
                yield r, st
            else:
                report.rejected.append(f"{r}: not a regular file")


def seed_stage(output_dir: Path, stage: Path, cfg: DockerConfig) -> tuple[dict[str, tuple[int, int]], list[str]]:
    """Copy the current regular files of OUTPUT_DIR into the stage folder, so
    scripts can read (and append to) earlier outputs. Returns the
    {relpath: (size, mtime_ns)} of what was seeded, plus notes."""
    seeded: dict[str, tuple[int, int]] = {}
    notes: list[str] = []
    if not output_dir.is_dir():
        return seeded, notes
    rep = CopyReport()
    total = 0
    for rel, st in _walk(output_dir, rep):
        if len(seeded) >= cfg.max_files or st.st_size > cfg.max_file_bytes or total + st.st_size > cfg.max_total_bytes:
            notes.append("OUTPUT_DIR is larger than the container output caps; only part of it is visible at /output")
            break
        dst = stage.joinpath(*rel.split("/"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(output_dir.joinpath(*rel.split("/")), dst, follow_symlinks=False)
        _open_perms(dst, 0o666)
        s2 = os.lstat(dst)
        seeded[rel] = (s2.st_size, s2.st_mtime_ns)
        total += st.st_size
    for p in sorted({p for p in stage.rglob("*") if p.is_dir()}):
        _open_perms(p, 0o777)
    return seeded, notes


def copy_back(stage: Path, output_dir: Path, cfg: DockerConfig, seeded: dict[str, tuple[int, int]] | None = None) -> CopyReport:
    """Copy new or changed regular files from the stage folder into OUTPUT_DIR.

    Rejected: symlinks/reparse points (files and folders), anything that is
    not a regular file, names that are unsafe on Windows, paths that would
    land outside OUTPUT_DIR or on a symlink there, files over the per-file
    cap, and everything past the total size or file-count caps."""
    seeded = seeded or {}
    rep = CopyReport()
    out_root = output_dir.resolve()
    total = 0
    count = 0
    for rel, st in _walk(stage, rep):
        if seeded.get(rel) == (st.st_size, st.st_mtime_ns):
            continue  # unchanged copy of an existing output
        if st.st_size > cfg.max_file_bytes:
            rep.rejected.append(f"{rel}: {st.st_size} bytes is over the per-file cap ({cfg.max_file_bytes})")
            continue
        if total + st.st_size > cfg.max_total_bytes:
            rep.rejected.append(f"{rel}: total output cap ({cfg.max_total_bytes} bytes) reached")
            continue
        if count >= cfg.max_files:
            rep.rejected.append(f"{rel}: file-count cap ({cfg.max_files}) reached")
            continue
        dst = out_root.joinpath(*rel.split("/"))
        if not _inside(dst, out_root):
            rep.rejected.append(f"{rel}: outside OUTPUT_DIR")
            continue
        bad = _link_on_path(dst, out_root)
        if bad:
            rep.rejected.append(f"{rel}: {bad} in OUTPUT_DIR is a symlink or not a folder")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not _inside(dst.parent.resolve(), out_root):
            rep.rejected.append(f"{rel}: outside OUTPUT_DIR")
            continue
        tmp = dst.with_name(f".{dst.name}.{secrets.token_hex(4)}.part")
        shutil.copyfile(stage.joinpath(*rel.split("/")), tmp, follow_symlinks=False)
        os.replace(tmp, dst)
        rep.copied.append(rel)
        total += st.st_size
        count += 1
    return rep


def _inside(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _link_on_path(dst: Path, root: Path) -> str | None:
    """The first existing component between root and dst that is a link (or a non-folder parent)."""
    cur = root
    parts = dst.relative_to(root).parts
    for i, part in enumerate(parts):
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return None
        if _is_link(st) or (i < len(parts) - 1 and not stat.S_ISDIR(st.st_mode)):
            return cur.relative_to(root).as_posix()
    return None


def _open_perms(p: Path, mode: int) -> None:
    """The container runs as nobody (65534); on POSIX hosts the stage must be writable for it."""
    if not IS_WINDOWS:
        try:
            os.chmod(p, mode)
        except OSError:
            pass


# --------------------------------------------------------------------------- run


@dataclass
class StepFiles:
    stage: Path
    work: Path
    output: Path
    script_name: str
    bootstrap_name: str


def prepare_stage(workdir: Path, step: str, code: str, bootstrap: str) -> StepFiles:
    stage = workdir / f"_ctr_{step}_{secrets.token_hex(4)}"
    work, output = stage / "work", stage / "output"
    work.mkdir(parents=True)
    output.mkdir()
    for d in (stage, work, output):
        _open_perms(d, 0o777)
    script_name = f"_step_{step}.py"
    (work / script_name).write_text(code, encoding="utf-8")
    (work / "_bootstrap.py").write_text(bootstrap, encoding="utf-8")
    return StepFiles(stage, work, output, script_name, "_bootstrap.py")


def new_name() -> str:
    return f"aa-code-{secrets.token_hex(6)}"


def run_container(cfg: DockerConfig, argv: list[str], name: str, cwd: Path, timeout: float) -> RunResult:
    """Run `docker run ...`; on time-out `docker kill <name>` (then kill the CLI as a last resort)."""
    notes: list[str] = []
    env = dict(os.environ)  # the docker CLI needs DOCKER_HOST/context/config; the container gets only --env
    try:
        proc = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    except OSError as e:
        raise DockerUnavailable(f"could not start the docker CLI: {e}") from e
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_container(cfg, name, notes)
        try:
            out, err = proc.communicate(timeout=cfg.control_timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            notes.append("docker CLI did not exit after docker kill and was killed")
        _best_effort(cfg, ["rm", "-f", name])
    rc = proc.returncode
    if not timed_out and rc == 137:
        notes.append(f"the container was killed (exit 137), most likely by the code tier memory limit ({cfg.memory_mb} MB)")
    if not timed_out and rc == 125:
        notes.append("docker could not start the container (exit 125, see stderr)")
    return RunResult(rc, out or "", err or "", timed_out, contained=True, notes=notes)


def kill_container(cfg: DockerConfig, name: str, notes: list[str]) -> None:
    try:
        r = _control(cfg, ["kill", name])
        if r.returncode != 0:
            notes.append(f"docker kill {name}: {_first_line(r.stderr) or r.returncode}")
    except (OSError, subprocess.TimeoutExpired) as e:
        notes.append(f"docker kill {name} failed: {e}")


def _best_effort(cfg: DockerConfig, args: list[str]) -> None:
    try:
        _control(cfg, args)
    except (OSError, subprocess.TimeoutExpired):
        pass
