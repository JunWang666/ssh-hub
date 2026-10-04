"""Control agents in the target user's existing Herdr default session."""
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time

payload = json.loads(sys.argv[1])
request = payload["request"]
lock_id = payload["lock_id"]
deadline = time.monotonic() + payload["budget"]
action = request["action"]
agent_id = request.get("agent_id", "")
result = {}
# Noninteractive SSH often omits the usual user-local executable directories.
os.environ["PATH"] = os.pathsep.join([
    os.path.expanduser("~/.local/bin"), os.path.expanduser("~/.cargo/bin"),
    os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")])
for name in list(os.environ):
    if name.startswith("HERDR_") and name != "HERDR_CONFIG_PATH":
        del os.environ[name]
herdr = shutil.which("herdr")


class Failure(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def remaining():
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise Failure("timeout", "Controller timed out; inspect agent before retrying.")
    return seconds


def cli(args, raw=False):
    completed = subprocess.run([herdr] + args,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True,
                               encoding="utf-8", errors="replace", timeout=remaining())
    if raw and completed.returncode == 0:
        return completed.stdout
    try:
        response = json.loads(completed.stdout if completed.returncode == 0 else completed.stderr)
    except ValueError:
        if completed.returncode != 0:
            raise Failure("herdr_error", (completed.stderr or completed.stdout)[-2048:])
        raise Failure("invalid_response", "Herdr returned invalid JSON; check the installed version.")
    if completed.returncode != 0 or response.get("error"):
        error = response.get("error", response)
        if isinstance(error, dict):
            raise Failure(str(error.get("code", "herdr_error")), str(error.get("message", error))[:2048])
        raise Failure("herdr_error", str(error)[:2048])
    return response.get("result", response)


def summary(agent):
    output = {"agent_id": agent.get("name") or agent["pane_id"],
              "pane_id": agent["pane_id"], "kind": agent.get("agent"),
              "state": agent.get("agent_status", "unknown")}
    for key in ("interactive_ready", "launch_pending", "state_change_seq", "completion_seq"):
        if key in agent:
            output[key] = agent[key]
    cwd = agent.get("foreground_cwd") or agent.get("cwd")
    if cwd:
        output["cwd"] = cwd[:512]
    return output


def lookup():
    return cli(["agent", "get", agent_id])["agent"]


def acquire_start_lock():
    # Serialize server bootstrap and workspace creation, including across Hub
    # restarts. Other actions (especially interrupt during wait) remain usable.
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    directory = os.path.join(state, "ssh-hub", "locks")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    lock = open(os.path.join(directory, lock_id + ".lock"), "a")
    os.chmod(lock.name, 0o600)
    while True:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            time.sleep(min(0.1, remaining()))


def main():
    if not herdr:
        raise Failure("missing_dependency", "Install Herdr on the SSH host and put it on PATH; SSH Hub does not install software automatically.")
    if action == "start":
        cwd = request["cwd"]
        kind = request["kind"]
        if not os.path.isdir(cwd):
            raise Failure("invalid_cwd", "Remote cwd is not an existing directory.")
        if not shutil.which(kind):
            raise Failure("missing_dependency", "Install and authenticate the %s CLI for this SSH user." % kind)
        with acquire_start_lock():
            try:
                cli(["agent", "list"])
            except Failure as exc:
                raise Failure("default_session_unavailable", "Start the existing Herdr default session on the target first; SSH Hub will not create a Herdr session. " + str(exc))
            # A caller-specified name can recover a timed-out launch. Never
            # create a second workspace or resubmit a prompt with that name.
            existing = cli(["workspace", "list"])["workspaces"]
            if any(w.get("label") == agent_id for w in existing):
                raise Failure("already_exists", "Workspace exists for this name; use list/status/read before retrying.")
            created = cli(["workspace", "create", "--cwd", cwd, "--label", agent_id, "--no-focus"])
            pane_id = created["root_pane"]["pane_id"]
            result.update({"agent_id": agent_id, "pane_id": pane_id,
                           "workspace_id": created["workspace"]["id"] if "id" in created["workspace"] else created["workspace"]["workspace_id"],
                           "prompt_submitted": False})
            # Shell initialization can take a moment. Only retry observational
            # readiness checks; launching the agent is done exactly once.
            time.sleep(min(0.25, remaining()))
            timeout_ms = int((remaining() - 0.5) * 1000)
            if timeout_ms <= 3000:
                raise Failure("timeout", "Workspace created; insufficient startup budget. Inspect the pane.")
            started = cli(["agent", "start", agent_id, "--kind", kind, "--pane", pane_id,
                           "--timeout", str(timeout_ms)])
            result["agent"] = summary(started["agent"])
            if request.get("text"):
                result["prompt_submitted"] = "unknown"
                prompted = cli(["agent", "prompt", agent_id, request["text"]])
                result["agent"] = summary(prompted["agent"])
                result["prompt_submitted"] = True
        return
    if action == "list":
        agents = cli(["agent", "list"])["agents"]
        agents.sort(key=lambda a: a.get("name") or a["pane_id"])
        offset = request.get("offset", 0)
        result.update({"agents": [summary(a) for a in agents[offset:offset+50]], "total": len(agents)})
        if offset + 50 < len(agents):
            result["next_offset"] = offset + 50
        return
    if action == "status":
        result["agent"] = summary(lookup())
    elif action == "read":
        # Visible reads are passive and also work while an agent is blocked or
        # busy. Snapshots deliberately do not claim to be complete transcripts.
        text = cli(["agent", "read", agent_id, "--source", "visible", "--lines", str(request.get("lines") or 40)], raw=True)
        encoded = text.encode("utf-8")
        result.update({"agent_id": agent_id, "output": encoded[-16384:].decode("utf-8", "ignore"),
                       "snapshot": True, "truncated": len(encoded) > 16384})
    elif action == "prompt":
        result["prompt_submitted"] = "unknown"
        prompted = cli(["agent", "prompt", agent_id, request["text"]])
        result.update({"agent": summary(prompted["agent"]), "prompt_submitted": True})
    elif action == "keys" or action == "interrupt":
        keys = request["keys"] if action == "keys" else ["ctrl+c"]
        response = cli(["agent", "send-keys", agent_id] + keys)
        result.update({"agent_id": agent_id, "input_sent": True})
    elif action == "wait":
        args = ["agent", "wait", agent_id, "--timeout", str(max(1, int((remaining()-0.5)*1000)))]
        if request.get("until"):
            args += ["--until", request["until"]]
        try:
            waited = cli(args)
            result.update({"agent": summary(waited["agent"]), "timed_out": False})
        except Failure as exc:
            if exc.code != "timeout":
                raise
            result.update({"agent_id": agent_id, "timed_out": True})
    elif action == "stop":
        # Resolve as an agent first: never send input to a shell after it exits.
        agent = lookup()
        cli(["pane", "close", agent["pane_id"]])
        result.update({"agent_id": agent_id, "closed": True})


try:
    main()
except Failure as exc:
    result["error"] = {"code": exc.code, "message": str(exc)}
except subprocess.TimeoutExpired:
    result["error"] = {"code": "timeout", "message": "Control call timed out; input may already have been sent. Inspect before retrying."}
except Exception as exc:
    result["error"] = {"code": "controller_error", "message": str(exc)[:2048]}
print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
sys.exit(1 if "error" in result else 0)
