"""In-process guard for the code tier (defense in depth, NOT the security boundary).

This file is never imported by the agent itself. Its source is passed to the
child interpreter with `python -I -B -X utf8 -c <source + _main(cfg)> script.py`.
`_main` installs a `sys.addaudithook` hook, then runs the user's script with
runpy so its line numbers stay unchanged.

What the hook blocks (raising PermissionError inside the offending call):
- network: socket connect/bind/getaddrinfo/sendto/..., urllib/http/smtp/ftp
  (unless cfg["allow_network"])
- processes: subprocess, os.system/exec*/spawn*/posix_spawn/fork/startfile/kill,
  every _winapi.* event
- ctypes when called from code outside the Python install (the user's script,
  exec'd strings): dlopen, dlsym, foreign calls, from_address, string_at, ...
  Library code in the stdlib/site-packages may still use ctypes (pandas'
  dateutil and `import ctypes` itself need it).
- file writes (open in w/a/x/+ modes, os.remove/rename/mkdir/rmdir/chmod/...,
  shutil.*, tempfile.*) outside the task workdir and OUTPUT_DIR
- file reads and directory listings outside INPUT_DIRS, workdir, OUTPUT_DIR and
  the Python install (prefix, stdlib, site-packages, user site-packages)
- the vault folder and the audit folder (except the workdir inside it)
- sqlite: connections to files outside the write roots are rewritten to
  read-only URIs when they are in a read root, refused otherwise; ATTACH is
  checked by an authorizer; extension loading is refused
- tampering helpers: sys.settrace/setprofile, sys.monitoring callbacks,
  gc.get_objects/get_referrers/get_referents, sys._current_frames, compile()
  with a filename inside the Python install, code.__new__/marshal.loads from
  user code, registry writes

Known gaps (why this is not a sandbox on its own): audit hooks only see what
CPython reports. Native code in an installed extension module, a custom import
loader that feeds crafted bytecode with a spoofed filename, or a CPython bug
can step around the hook. The Windows Job Object (memory, CPU, process count,
UI limits, kill on close) set up by the parent and, in production, the
disposable per-task VM/container are the real boundary.
"""


def _main(cfg):  # pragma: no cover - runs in the child interpreter
    import os
    import sys
    import _thread

    for p in cfg.get("site_dirs", []):
        if os.path.isdir(p):
            import site

            site.addsitedir(p)

    import sqlite3
    import sqlite3.dbapi2 as _dbapi
    from urllib.parse import quote, unquote

    fspath, fsdecode, realpath, normcase, sep = os.fspath, os.fsdecode, os.path.realpath, os.path.normcase, os.sep
    isabs, getcwd, dirname = os.path.isabs, os.getcwd, os.path.dirname

    def norm(p):
        if isinstance(p, bytes):
            p = fsdecode(p)
        return normcase(realpath(fspath(p)))

    def roots(items):
        out = []
        for x in items:
            if isinstance(x, str) and x and isabs(x):
                try:
                    out.append(norm(x).rstrip("\\/") or sep)
                except Exception:
                    pass
        return tuple(dict.fromkeys(out))

    def inside(p, rs):
        for r in rs:
            if p == r or p.startswith(r + sep):
                return True
        return False

    WRITE = roots(cfg["write"])
    PY = roots([sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, dirname(os.__file__)] + list(cfg.get("site_dirs", [])) + [p for p in sys.path if isinstance(p, str)])
    READ = roots(cfg["read"]) + PY
    DENY = roots(cfg["deny"])
    CTYPES_DIR = norm(os.path.join(dirname(os.__file__), "ctypes"))
    NET = bool(cfg.get("allow_network"))
    DEVNULL = norm(os.devnull)
    W_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    getframe = sys._getframe
    state = _thread._local()
    trusted_cache = {}

    class SandboxBlocked(PermissionError):
        pass

    def block(msg):
        raise SandboxBlocked("sandbox: " + msg)

    # ------------------------------------------------------------ files
    def check(path, write, what):
        if path is None:
            path = getcwd()
        if isinstance(path, int):
            return  # an already-open descriptor
        try:
            p = norm(path)
        except Exception:
            block(f"{what}: cannot resolve path {path!r}")
        if p == DEVNULL:
            return
        if inside(p, WRITE):
            return
        if inside(p, DENY):
            block(f"{what} {p} is not allowed (protected agent folder)")
        if not write and inside(p, READ):
            return
        if write:
            block(f"{what} {p} is not allowed; write only inside the task workdir or OUTPUT_DIR")
        block(f"{what} {p} is not allowed; read only INPUT_DIRS, the workdir, OUTPUT_DIR and the Python install")

    def sqlite_target(db):
        """(path or None, wants_write) for a sqlite3.connect / ATTACH argument."""
        if isinstance(db, bytes):
            db = fsdecode(db)
        if not isinstance(db, str):
            db = fspath(db)
        if db in ("", ":memory:"):
            return None, False
        if db.startswith("file:"):
            rest, _, query = db[5:].partition("?")
            rest = rest.split("#")[0]
            params = dict(kv.partition("=")[::2] for kv in query.split("&") if kv)
            if params.get("mode") == "memory" or rest in ("", ":memory:"):
                return None, False
            if rest.startswith("//"):
                host, _, tail = rest[2:].partition("/")
                if host not in ("", "localhost"):
                    block(f"sqlite URI host {host!r} is not allowed")
                rest = "/" + tail
            rest = unquote(rest)
            if os.name == "nt" and len(rest) >= 3 and rest[0] == "/" and rest[2] == ":":
                rest = rest[1:]
            return rest, params.get("mode") != "ro"
        return db, True

    def check_sqlite(db):
        path, wants_write = sqlite_target(db)
        if path is not None:
            check(path, wants_write, "sqlite open of")

    def authorizer(action, arg1, arg2, dbname, source):
        if action == sqlite3.SQLITE_ATTACH:
            try:
                check_sqlite(arg1 or "")
            except PermissionError:
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    _orig_connect = sqlite3.connect

    def connect(database, *args, **kwargs):
        """Open sqlite files from read-only roots (INPUT_DIRS) read-only."""
        if not kwargs.get("uri") and len(args) < 7 and isinstance(database, (str, bytes, os.PathLike)):
            db = fsdecode(database) if isinstance(database, bytes) else fspath(database)
            if db not in ("", ":memory:") and not db.startswith("file:"):
                p = norm(db)
                if not inside(p, WRITE) and not inside(p, DENY) and inside(p, READ):
                    url = p.replace("\\", "/")
                    database = "file://" + ("" if url.startswith("/") else "/") + quote(url, safe="/:") + "?mode=ro"
                    kwargs["uri"] = True
        state.sqlite_ok = True
        try:
            con = _orig_connect(database, *args, **kwargs)
        finally:
            state.sqlite_ok = False
        try:
            con.set_authorizer(authorizer)  # checks ATTACH targets
        except Exception:
            con.close()
            raise
        return con

    connect.__doc__ = _orig_connect.__doc__
    sqlite3.connect = _dbapi.connect = connect

    # ------------------------------------------------------------ caller trust
    def trusted_file(fn):
        hit = trusted_cache.get(fn)
        if hit is None:
            if fn.startswith("<frozen "):
                hit = True
            else:
                try:
                    hit = isabs(fn) and inside(norm(fn), PY)
                except Exception:
                    hit = False
            trusted_cache[fn] = hit
        return hit

    def caller_trusted(skip_ctypes=True):
        """True when the nearest frame outside ctypes/importlib is library code."""
        f = state.frame
        while f is not None:
            fn = f.f_code.co_filename
            if fn.startswith("<frozen importlib"):
                f = f.f_back
                continue
            if skip_ctypes:
                try:
                    if isabs(fn) and inside(norm(fn), (CTYPES_DIR,)):
                        f = f.f_back
                        continue
                except Exception:
                    pass
            return trusted_file(fn)
        return False

    def immediate_caller_is_importlib():
        f = state.frame
        return f is not None and f.f_code.co_filename.startswith("<frozen importlib")

    # ------------------------------------------------------------ event tables
    PROC = {
        "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.forkpty",
        "os.startfile", "os.kill", "os.killpg", "pty.spawn", "webbrowser.open", "os.popen",
    }
    NET_EVENTS = {
        "socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
        "socket.getnameinfo", "socket.sendto", "socket.sendmsg", "urllib.Request", "http.client.connect",
        "ftplib.connect", "smtplib.connect", "smtplib.send", "poplib.connect", "imaplib.open", "nntplib.connect",
        "telnetlib.open",
    }
    TAMPER = {
        "sys.settrace", "sys.setprofile", "sys._settraceallthreads", "sys._setprofileallthreads",
        "sys.monitoring.register_callback", "gc.get_objects", "gc.get_referrers", "gc.get_referents",
        "sys._current_frames", "sqlite3.enable_load_extension", "sqlite3.load_extension",
        "winreg.CreateKey", "winreg.DeleteKey", "winreg.DeleteValue", "winreg.SetValue", "winreg.SaveKey",
        "winreg.LoadKey", "winreg.DisableReflectionKey", "winreg.EnableReflectionKey",
    }
    CTYPES = {
        "ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle", "ctypes.call_function", "ctypes.cdata",
        "ctypes.cdata/buffer", "ctypes.string_at", "ctypes.wstring_at", "ctypes.PyObj_FromPtr",
        "ctypes.addressof", "ctypes.set_errno", "ctypes.set_last_error", "ctypes.get_errno", "ctypes.get_last_error",
        "ctypes.seh_exception", "ctypes.create_string_buffer", "ctypes.create_unicode_buffer",
    }
    CTYPES_HARMLESS = {"ctypes.create_string_buffer", "ctypes.create_unicode_buffer", "ctypes.addressof", "ctypes.get_errno", "ctypes.get_last_error", "ctypes.set_errno", "ctypes.set_last_error", "ctypes.seh_exception", "ctypes.cdata/buffer"}
    WRITE1 = {
        "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.utime", "os.truncate", "os.chflags",
        "os.lchflags", "os.lchmod", "os.setxattr", "os.removexattr", "os.mkfifo", "os.mknod", "shutil.rmtree",
        "tempfile.mkstemp", "tempfile.mkdtemp", "shutil.chown",
    }
    READ1 = {"os.listdir", "os.scandir", "os.listxattr", "os.getxattr", "os.chdir"}
    COPY = {"shutil.copyfile", "shutil.copymode", "shutil.copystat", "shutil.copytree"}

    def dispatch(event, args):
        if event == "open":
            path, mode, flags = (tuple(args) + (None, None, None))[:3]
            w = isinstance(mode, str) and any(c in mode for c in "wax+")
            if isinstance(flags, int) and flags & W_FLAGS:
                w = True
            check(path, w, "writing" if w else "reading")
        elif event in READ1:
            check(args[0] if args else None, False, "listing" if event != "os.chdir" else "changing into")
        elif event in WRITE1:
            check(args[0], True, event)
        elif event in ("os.rename", "os.link", "shutil.move"):
            check(args[0], True, event)
            check(args[1], True, event)
        elif event == "os.symlink":
            check(args[1], True, event)
        elif event in COPY:
            check(args[0], False, event)
            check(args[1], True, event)
        elif event == "shutil.make_archive":
            check(args[0], True, event)
            if len(args) > 2 and args[2] is not None:
                check(args[2], False, event)
        elif event == "shutil.unpack_archive":
            check(args[0], False, event)
            check(args[1], True, event)
        elif event == "sqlite3.connect":
            if not getattr(state, "sqlite_ok", False) and not caller_trusted(skip_ctypes=False):
                block("open sqlite databases with sqlite3.connect()")
            check_sqlite(args[0])
        elif event == "_winapi.CopyFile2":
            check(args[0], False, "copying")
            check(args[1], True, "copying to")
        elif event == "_winapi.CreateFile":
            check(args[0], True, "opening")
        elif event in PROC or event.startswith("_winapi."):
            block(f"starting or signalling processes is not allowed ({event})")
        elif event in NET_EVENTS:
            if not NET:
                block(f"network access is not allowed ({event}); set tiers.code.allow_network to enable it")
        elif event == "winreg.ConnectRegistry":
            if args and args[0]:
                block("remote registry access is not allowed")
        elif event in TAMPER:
            block(f"{event} is not allowed in the code tier")
        elif event.startswith("ctypes."):
            if event in CTYPES_HARMLESS:
                return
            if not caller_trusted():
                block(f"ctypes is not allowed in task code ({event})")
        elif event == "os.add_dll_directory":
            try:
                ok = inside(norm(args[0]), PY)
            except Exception:
                ok = False
            if not ok:
                block("os.add_dll_directory outside the Python install is not allowed")
        elif event == "compile":
            fn = args[1] if len(args) > 1 else None
            if isinstance(fn, (str, bytes)) and not immediate_caller_is_importlib():
                fn = fsdecode(fn) if isinstance(fn, bytes) else fn
                if isabs(fn) and trusted_file(fn) and not caller_trusted(skip_ctypes=False):
                    block("compile() with a filename inside the Python install is not allowed")
        elif event in ("code.__new__", "marshal.loads", "marshal.load"):
            if not immediate_caller_is_importlib() and not caller_trusted(skip_ctypes=False):
                block(f"{event} is not allowed in task code")

    def hook(event, args):
        if getattr(state, "busy", False):
            return
        state.busy = True
        try:
            try:
                state.frame = getframe(1)  # the frame whose action raised the event
            except ValueError:
                state.frame = None  # raised from C with no Python frame
            dispatch(event, args)
        finally:
            state.frame = None
            state.busy = False

    sys.addaudithook(hook)
    return SandboxBlocked


def _run(cfg):  # pragma: no cover - runs in the child interpreter
    import os
    import runpy
    import sys

    if cfg.get("guard", True):
        _main(cfg)
    script = cfg["script"]
    sys.argv = [script]
    os.makedirs(cfg["output_dir"], exist_ok=True)
    g = {"os": os, "sys": sys, "INPUT_DIRS": list(cfg["input_dirs"]), "OUTPUT_DIR": cfg["output_dir"], "PARAMS": cfg["params"]}
    runpy.run_path(script, init_globals=g, run_name="__main__")
