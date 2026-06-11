#!/usr/bin/env python3
"""
gate-notifier — push an iPhone notification when a remediate run hits the
approval GATE, with one-tap Approve / Abort buttons (via ntfy actions).

A remediate run awaiting Ben's approval looks like:
    effectiveStatus == "blocked"  AND  assignmentName == "remediate"
(after root-cause + adversarial-review, 2/5 tasks done, before apply-fix).

Approval is documented in config/assignments/remediate/assignment.md as:
    ./bin/ar run --resume-run <id> "Approved. Continue."
…which is exactly  POST /api/runs/<id>/resume {"overrides":{"message":"Approved. Continue."}}.
The ntfy "Approve" button performs that POST against the phone board proxy
(reachable from the phone over Tailscale). "Abort" → POST /api/runs/<id>/abort.

Run once per invocation; schedule via launchd StartInterval (e.g. 60s).
First run BASELINES (records currently-blocked gates as already-seen, no push)
so a backlog of stuck gates doesn't storm the phone. Only NEW gates ping.

Internal disk only. Zero deps.
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
DAEMON = os.environ.get("AGENT_RUNNER_HTTP", "http://127.0.0.1:4773")
PHONE_BOARD = os.environ.get("PHONE_BOARD_URL", "https://127.0.0.1:4775")
PUSH_URL = os.environ.get("PUSH_BROADCAST_URL", "https://127.0.0.1:4775/push/broadcast")
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh")
TOPIC_FILE = Path(os.path.expanduser(os.environ.get("NTFY_TOPIC_FILE", "~/.pi/dashboard/.ntfy-topic")))
STATE_FILE = Path(os.environ.get("GATE_STATE_FILE", os.path.join(_HERE, ".gate-notified.json")))
ENABLED = os.environ.get("GATE_NOTIFY", "1") != "0"


def read_topic() -> str:
    t = os.environ.get("NTFY_TOPIC", "").strip()
    if t:
        return t
    try:
        return TOPIC_FILE.read_text().strip()
    except OSError:
        return ""


def get_runs() -> list:
    req = urllib.request.Request(DAEMON + "/api/runs", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read()).get("runs", [])


def is_gate(run: dict) -> bool:
    return run.get("effectiveStatus") == "blocked" and run.get("assignmentName") == "remediate"


def load_state() -> set:
    try:
        return set(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        return set()


def save_state(seen: set) -> None:
    try:
        STATE_FILE.write_text(json.dumps(sorted(seen)))
    except OSError as e:
        print(f"state write failed: {e}", file=sys.stderr)


def notify(topic: str, run: dict) -> bool:
    rid = run["runId"]
    name = run.get("name") or rid
    # name looks like: card=cpuhog-… detector=cpu stage=root-cause
    card = name.split("detector=")[0].replace("card=", "").strip() or rid
    payload = {
        "topic": topic,
        "title": f"🔧 Approve fix? {card}",
        "message": f"{name}\nA remediate run is waiting for your OK (2/5 done).",
        "tags": ["wrench"],
        "priority": 4,
        "click": f"{PHONE_BOARD}/runs/{rid}",  # tap = open the run on the phone board
        "actions": [
            {
                "action": "http",
                "label": "Approve",
                "url": f"{PHONE_BOARD}/api/runs/{rid}/resume",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"overrides": {"message": "Approved. Continue."}}),
                "clear": True,
            },
            {
                "action": "http",
                "label": "Abort",
                "url": f"{PHONE_BOARD}/api/runs/{rid}/abort",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "body": "{}",
                "clear": True,
            },
        ],
    }
    req = urllib.request.Request(
        NTFY_SERVER,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
        return True
    except (urllib.error.URLError, OSError) as e:
        print(f"notify failed run={rid}: {e}", file=sys.stderr)
        return False


def web_push(run: dict) -> bool:
    """App-opening web push (tap -> opens the PWA on this run). Best-effort; the spike
    owns the push keys, so we just trigger its localhost broadcast endpoint."""
    rid = run["runId"]
    name = run.get("name") or rid
    card = name.split("detector=")[0].replace("card=", "").strip() or rid
    payload = {"title": f"⛔ Approve fix? {card}",
               "body": f"{name}\nA remediate run is waiting for your OK (2/5 done).",
               "url": f"/runs/{rid}"}
    try:
        req = urllib.request.Request(PUSH_URL, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10, context=_SSL):
            pass
        return True
    except (urllib.error.URLError, OSError) as e:
        print(f"web push failed run={rid}: {e}", file=sys.stderr)
        return False


def main() -> int:
    if not ENABLED:
        return 0
    topic = read_topic()
    if not topic:
        print("no ntfy topic; nothing to do", file=sys.stderr)
        return 0
    try:
        runs = get_runs()
    except (urllib.error.URLError, OSError) as e:
        print(f"daemon unreachable: {e}", file=sys.stderr)
        return 0  # don't crash the launchd job on a transient blip

    gates = {r["runId"] for r in runs if is_gate(r)}

    # First ever run: baseline the current backlog silently so it doesn't storm.
    if not STATE_FILE.exists():
        save_state(gates)
        print(f"baselined {len(gates)} existing gate(s), no push")
        return 0

    seen = load_state()
    new = [r for r in runs if is_gate(r) and r["runId"] not in seen]
    for r in new:
        ok_ntfy = notify(topic, r)       # lock-screen Approve/Abort buttons
        ok_push = web_push(r)            # app-opening web push (tap = open the run)
        if ok_ntfy or ok_push:
            seen.add(r["runId"])
            print(f"NOTIFY gate run={r['runId']} ntfy={ok_ntfy} push={ok_push} {r.get('name','')}")
    # Drop runs that are no longer at the gate so a future re-block re-notifies.
    seen &= gates | {r["runId"] for r in new}
    save_state(seen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
