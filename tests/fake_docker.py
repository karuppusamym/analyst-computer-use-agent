"""A fake `docker` CLI for the docker-backend unit tests (not a test module).

Every call is appended to $FAKE_DOCKER_STATE/calls.jsonl. Behaviour:
- FAKE_DOCKER_MODE=down     `version` fails like an unreachable daemon
- FAKE_DOCKER_MODE=windows  the daemon runs Windows containers
- FAKE_DOCKER_MODE=noimage  `image inspect` fails until `pull` has run
- FAKE_DOCKER_MODE=pullfail `image inspect` and `pull` fail
- `run`: parses --name and --mount, then execs $FAKE_DOCKER_RUN_SCRIPT (if set)
  with `mounts` {target: host source}, `argv`, `name`, `state`; otherwise
  prints "fake run". The script's SystemExit code becomes the exit code.
- `kill NAME`: terminates the pid in $FAKE_DOCKER_STATE/NAME.pid.
"""

import json
import os
import sys
from pathlib import Path

state = Path(os.environ["FAKE_DOCKER_STATE"])
mode = os.environ.get("FAKE_DOCKER_MODE", "ok")
args = sys.argv[1:]
with open(state / "calls.jsonl", "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\n")

cmd = args[0] if args else ""
if cmd == "version":
    if mode == "down":
        sys.stderr.write("error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.\n")
        sys.exit(1)
    print("28.5.2 windows" if mode == "windows" else "28.5.2 linux")
elif cmd == "image":
    if mode == "pullfail" or (mode == "noimage" and not (state / "pulled").exists()):
        sys.stderr.write("Error: No such image\n")
        sys.exit(1)
    print("sha256:fake")
elif cmd == "pull":
    if mode == "pullfail":
        sys.stderr.write("pull access denied\n")
        sys.exit(1)
    (state / "pulled").write_text("1")
elif cmd == "kill":
    pidfile = state / f"{args[1]}.pid"
    if not pidfile.exists():
        sys.stderr.write(f"Error: No such container: {args[1]}\n")
        sys.exit(1)
    import signal

    os.kill(int(pidfile.read_text()), signal.SIGTERM)
    (state / "killed").write_text(args[1])
elif cmd == "rm":
    pass
elif cmd == "run":
    mounts, name, i = {}, None, 1
    while i < len(args):
        if args[i] == "--name":
            name = args[i + 1]
        if args[i] == "--mount":
            fields = dict(kv.split("=", 1) for kv in args[i + 1].split(",") if "=" in kv)
            mounts[fields["target"]] = fields["source"]
        i += 1
    script = os.environ.get("FAKE_DOCKER_RUN_SCRIPT")
    if script:
        g = {"mounts": mounts, "argv": args, "name": name, "state": state, "__name__": "__fake__"}
        exec(compile(Path(script).read_text(encoding="utf-8"), script, "exec"), g)
    else:
        print("fake run")
else:
    sys.stderr.write(f"fake docker: unknown command {cmd}\n")
    sys.exit(2)
