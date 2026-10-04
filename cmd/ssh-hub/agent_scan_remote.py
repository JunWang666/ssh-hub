"""Read summaries from currently running Herdr sessions; never reads transcripts."""
import json
import os
import shutil
import subprocess
import sys

os.environ["PATH"] = os.pathsep.join([
    os.path.expanduser("~/.local/bin"), os.path.expanduser("~/.cargo/bin"),
    os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")])
for name in list(os.environ):
    if name.startswith("HERDR_") and name != "HERDR_CONFIG_PATH":
        del os.environ[name]
herdr = shutil.which("herdr")


def run(args):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True,
                       encoding="utf-8", errors="replace", timeout=5)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "Herdr command failed")[-512:])
    response = json.loads(p.stdout)
    # Herdr CLI releases may emit the socket-style {"result": ...} envelope.
    return response.get("result", response) if isinstance(response, dict) else response


result = {"sessions": [], "error": ""}
try:
    if not herdr:
        raise RuntimeError("Herdr is not installed or missing from the SSH user's PATH")
    listing = run([herdr, "session", "list", "--json"])
    sessions = [s for s in listing.get("sessions", []) if s.get("running") is True]
    for session in sessions[:32]:
        name = session.get("name", "")
        if not isinstance(name, str) or not name or len(name) > 128 or "\x00" in name:
            continue
        args = [herdr]
        if name != "default":
            args += ["--session", name]
        args += ["agent", "list"]
        try:
            agents = run(args).get("agents", [])
            summary = []
            for agent in agents[:64]:
                if not isinstance(agent, dict) or not agent.get("pane_id"):
                    continue
                item = {"agentId": agent.get("name") or agent["pane_id"],
                        "paneId": agent["pane_id"], "kind": agent.get("agent") or "",
                        "state": agent.get("agent_status") or "unknown"}
                cwd = agent.get("foreground_cwd") or agent.get("cwd")
                if isinstance(cwd, str) and cwd:
                    item["cwd"] = cwd[:512]
                summary.append(item)
            result["sessions"].append({"name": name, "agents": summary})
        except Exception as exc:
            result["sessions"].append({"name": name, "agents": [], "error": str(exc)[:512]})
    if len(sessions) > 32:
        result["truncated"] = True
except Exception as exc:
    result["error"] = str(exc)[:512]

print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
sys.exit(1 if result["error"] else 0)
