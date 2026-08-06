#!/usr/bin/env python3
"""Central Ops Mobile PWA — direct Pi RPC, no ACP or bb dependency.

This service provides a small mobile-first PWA with persistent threads. Each turn
runs in its own isolated ``pi --mode rpc`` process, streams events to the browser,
and is forcibly reaped after ``agent_settled``. Thread state lives in SQLite, so a
provider process cannot leave the UI permanently stuck in "working".
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import http.server
import json
import os
import queue
import secrets
import signal
import socketserver
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

APP_VERSION = "0.1.0"
DEFAULT_HOST = os.environ.get("CENTRAL_OPS_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("CENTRAL_OPS_PORT", "4785"))
DEFAULT_DATA_DIR = Path(os.path.expanduser(os.environ.get("CENTRAL_OPS_DATA_DIR", "~/.central-ops-pwa")))
DEFAULT_PROVIDER = os.environ.get("PI_PROVIDER", "commandcode")
DEFAULT_MODEL = os.environ.get("PI_MODEL", "deepseek/deepseek-v4-pro")
DEFAULT_PI_COMMAND = os.environ.get("PI_COMMAND", "pi")
DEFAULT_TIMEOUT = int(os.environ.get("PI_TURN_TIMEOUT_SECONDS", "900"))
DEFAULT_PROJECTS = [
    {
        "id": "central-ops",
        "name": "Central Ops",
        "path": os.path.expanduser(os.environ.get("CENTRAL_OPS_PROJECT_PATH", "~/.buzz/REPOS/central-ops")),
    }
]


def now_ms() -> int:
    return int(time.time() * 1000)


def json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def make_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(8).replace('-', '').replace('_', '')[:12]}"


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _init_schema(self) -> None:
        with contextlib.closing(self.connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS threads (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('idle','working','error')),
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
                    content TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS messages_thread_created_idx
                  ON messages(thread_id, created_at, id);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                    type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_thread_id_idx ON events(thread_id, id);
                """
            )

    def create_thread(self, *, title: str, project_id: str, project_path: str, provider: str, model: str) -> dict[str, Any]:
        thread_id = make_id("thr")
        ts = now_ms()
        with contextlib.closing(self.connect()) as db:
            db.execute(
                "INSERT INTO threads(id,title,project_id,project_path,provider,model,status,created_at,updated_at) VALUES(?,?,?,?,?,?, 'idle', ?, ?)",
                (thread_id, title.strip() or "New thread", project_id, project_path, provider, model, ts, ts),
            )
        self.add_event(thread_id, "thread.created", {"threadId": thread_id})
        return self.get_thread(thread_id)

    def list_threads(self) -> list[dict[str, Any]]:
        with contextlib.closing(self.connect()) as db:
            rows = db.execute("SELECT * FROM threads ORDER BY updated_at DESC, id DESC").fetchall()
        return [dict(row) for row in rows]

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        with contextlib.closing(self.connect()) as db:
            row = db.execute("SELECT * FROM threads WHERE id=?", (thread_id,)).fetchone()
        if row is None:
            raise KeyError(thread_id)
        return dict(row)

    def set_status(self, thread_id: str, status: str, error: str | None = None) -> None:
        ts = now_ms()
        with contextlib.closing(self.connect()) as db:
            db.execute(
                "UPDATE threads SET status=?, last_error=?, updated_at=? WHERE id=?",
                (status, error, ts, thread_id),
            )
        self.add_event(thread_id, "thread.status", {"status": status, "error": error})

    def add_message(self, thread_id: str, role: str, content: str) -> dict[str, Any]:
        message_id = make_id("msg")
        ts = now_ms()
        with contextlib.closing(self.connect()) as db:
            db.execute(
                "INSERT INTO messages(id,thread_id,role,content,created_at) VALUES(?,?,?,?,?)",
                (message_id, thread_id, role, content, ts),
            )
            db.execute("UPDATE threads SET updated_at=? WHERE id=?", (ts, thread_id))
        message = {"id": message_id, "thread_id": thread_id, "role": role, "content": content, "created_at": ts}
        self.add_event(thread_id, "message.created", message)
        return message

    def list_messages(self, thread_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with contextlib.closing(self.connect()) as db:
            rows = db.execute(
                "SELECT * FROM messages WHERE thread_id=? ORDER BY created_at ASC, id ASC LIMIT ?",
                (thread_id, max(1, min(limit, 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_event(self, thread_id: str, event_type: str, payload: dict[str, Any]) -> int:
        ts = now_ms()
        with contextlib.closing(self.connect()) as db:
            cur = db.execute(
                "INSERT INTO events(thread_id,type,payload_json,created_at) VALUES(?,?,?,?)",
                (thread_id, event_type, json_dumps(payload), ts),
            )
            return int(cur.lastrowid)

    def list_events_after(self, thread_id: str, after_id: int, limit: int = 200) -> list[dict[str, Any]]:
        with contextlib.closing(self.connect()) as db:
            rows = db.execute(
                "SELECT * FROM events WHERE thread_id=? AND id>? ORDER BY id ASC LIMIT ?",
                (thread_id, after_id, max(1, min(limit, 500))),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result


@dataclasses.dataclass
class RunningTurn:
    thread_id: str
    process: subprocess.Popen[str]
    started_at: int
    stop_requested: bool = False


class PiRunner:
    def __init__(
        self,
        store: Store,
        *,
        pi_command: str = DEFAULT_PI_COMMAND,
        timeout_seconds: int = DEFAULT_TIMEOUT,
        extra_args: Iterable[str] = (),
    ):
        self.store = store
        self.pi_command = pi_command
        self.timeout_seconds = timeout_seconds
        self.extra_args = list(extra_args)
        self._lock = threading.RLock()
        self._running: dict[str, RunningTurn] = {}

    def start_turn(self, thread_id: str, user_text: str) -> None:
        with self._lock:
            if thread_id in self._running:
                raise RuntimeError("A turn is already running for this thread")
            thread = self.store.get_thread(thread_id)
            self.store.add_message(thread_id, "user", user_text)
            self.store.set_status(thread_id, "working")
            worker = threading.Thread(target=self._run_turn, args=(thread, user_text), daemon=True)
            worker.start()

    def stop_turn(self, thread_id: str) -> bool:
        with self._lock:
            running = self._running.get(thread_id)
            if running is None:
                return False
            running.stop_requested = True
            self._terminate_process_group(running.process)
            return True

    def _build_prompt(self, thread: dict[str, Any], latest_user_text: str) -> str:
        messages = self.store.list_messages(thread["id"], limit=40)
        prior = messages[:-1]
        transcript = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in prior[-20:])
        context = (
            "You are working through the Central Ops mobile workspace.\n"
            f"Project directory: {thread['project_path']}\n"
            f"Conversation thread: {thread['id']}\n"
            "Give the user a direct final response. Use tools when necessary.\n"
        )
        if transcript:
            context += "\nPrior conversation:\n" + transcript + "\n"
        return context + "\nUSER: " + latest_user_text

    def _run_turn(self, thread: dict[str, Any], user_text: str) -> None:
        thread_id = thread["id"]
        cmd = [
            self.pi_command,
            "--mode",
            "rpc",
            "--no-session",
            "--provider",
            thread["provider"],
            "--model",
            thread["model"],
            *self.extra_args,
        ]
        project_path = os.path.expanduser(thread["project_path"])
        prompt = self._build_prompt(thread, user_text)
        assistant_chunks: list[str] = []
        settled = False
        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=project_path if os.path.isdir(project_path) else None,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
                env=os.environ.copy(),
            )
            with self._lock:
                self._running[thread_id] = RunningTurn(thread_id, proc, now_ms())
            self.store.add_event(thread_id, "pi.started", {"pid": proc.pid, "command": cmd, "cwd": project_path})
            assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
            proc.stdin.write(json_dumps({"type": "prompt", "message": prompt}) + "\n")
            proc.stdin.flush()

            stderr_queue: queue.Queue[str] = queue.Queue()

            def read_stderr() -> None:
                for line in proc.stderr:
                    stderr_queue.put(line.rstrip("\n"))

            threading.Thread(target=read_stderr, daemon=True).start()
            deadline = time.monotonic() + self.timeout_seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                line = proc.stdout.readline()
                while True:
                    try:
                        err_line = stderr_queue.get_nowait()
                    except queue.Empty:
                        break
                    self.store.add_event(thread_id, "pi.stderr", {"line": err_line[-4000:]})
                if not line:
                    time.sleep(0.05)
                    continue
                raw = line.rstrip("\n")
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    self.store.add_event(thread_id, "pi.raw", {"line": raw[-8000:]})
                    continue
                self.store.add_event(thread_id, "pi.event", event if isinstance(event, dict) else {"value": event})
                text = extract_text_delta(event)
                if text:
                    assistant_chunks.append(text)
                    self.store.add_event(thread_id, "assistant.delta", {"text": text})
                if isinstance(event, dict) and event.get("type") == "agent_settled":
                    settled = True
                    break

            if not settled:
                if proc.poll() is None:
                    raise TimeoutError(f"Pi turn did not settle within {self.timeout_seconds}s")
                raise RuntimeError(f"Pi exited before agent_settled (code {proc.returncode})")

            final_text = "".join(assistant_chunks).strip()
            if not final_text:
                final_text = "Pi completed the turn without emitting text."
            self.store.add_message(thread_id, "assistant", final_text)
            self.store.set_status(thread_id, "idle")
            self.store.add_event(thread_id, "turn.completed", {"status": "completed"})
        except Exception as exc:
            stopped = False
            with self._lock:
                current = self._running.get(thread_id)
                stopped = bool(current and current.stop_requested)
            message = "Stopped by user" if stopped else f"{type(exc).__name__}: {exc}"
            self.store.set_status(thread_id, "idle" if stopped else "error", None if stopped else message)
            self.store.add_event(
                thread_id,
                "turn.completed",
                {"status": "interrupted" if stopped else "failed", "error": message, "trace": traceback.format_exc(limit=8)},
            )
        finally:
            if proc is not None:
                self._terminate_process_group(proc)
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
                if proc.poll() is None:
                    self._kill_process_group(proc)
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=5)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        with contextlib.suppress(Exception):
                            stream.close()
                self.store.add_event(thread_id, "pi.reaped", {"pid": proc.pid, "returncode": proc.returncode})
            with self._lock:
                self._running.pop(thread_id, None)

    @staticmethod
    def _terminate_process_group(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)


def extract_text_delta(event: Any) -> str:
    if not isinstance(event, dict):
        return ""
    event_type = event.get("type")
    if event_type in {"text_delta", "assistant_text_delta", "message_delta"}:
        for key in ("text", "delta", "content"):
            value = event.get(key)
            if isinstance(value, str):
                return value
    for key in ("textDelta", "text_delta"):
        value = event.get(key)
        if isinstance(value, str):
            return value
    delta = event.get("delta")
    if isinstance(delta, dict):
        for key in ("text", "content"):
            value = delta.get(key)
            if isinstance(value, str):
                return value
    content = event.get("content")
    if isinstance(content, list):
        return "".join(
            str(item.get("text", "")) for item in content if isinstance(item, dict) and item.get("type") in {"text", "output_text"}
        )
    return ""


INDEX_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0d12"><link rel="manifest" href="/manifest.webmanifest"><title>Central Ops</title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui;background:#0b0d12;color:#eef1f8}*{box-sizing:border-box}body{margin:0;min-height:100dvh;background:linear-gradient(180deg,#10141d,#090b10)}button,input,textarea,select{font:inherit}.app{max-width:900px;margin:auto;min-height:100dvh;padding:env(safe-area-inset-top) 14px calc(80px + env(safe-area-inset-bottom))}.top{position:sticky;top:0;z-index:5;padding:14px 0 12px;background:linear-gradient(#0b0d12 75%,transparent);display:flex;align-items:center;justify-content:space-between}.brand{font-weight:800;font-size:20px}.muted{color:#8f98aa;font-size:13px}.btn{border:1px solid #2b3342;background:#171c26;color:#f4f6fb;border-radius:12px;padding:10px 14px}.btn.primary{background:#eef1f8;color:#0b0d12;border-color:#eef1f8;font-weight:700}.btn.danger{background:#27171a;border-color:#6a2f38;color:#ffb6bf}.cards{display:grid;gap:10px}.card{border:1px solid #242b38;background:rgba(20,25,35,.9);border-radius:16px;padding:14px;box-shadow:0 12px 40px rgba(0,0,0,.2)}.row{display:flex;gap:10px;align-items:center;justify-content:space-between}.status{font-size:12px;border-radius:999px;padding:5px 8px;background:#222a38}.status.working{background:#4b3e14;color:#ffe9a6}.status.error{background:#4a1f27;color:#ffc2ca}.title{font-weight:700}.messages{display:flex;flex-direction:column;gap:10px;padding:8px 0 120px}.msg{max-width:88%;padding:12px 13px;border-radius:16px;white-space:pre-wrap;line-height:1.42}.msg.user{align-self:flex-end;background:#3157d5}.msg.assistant{align-self:flex-start;background:#1b2230;border:1px solid #2a3446}.composer{position:fixed;left:0;right:0;bottom:0;padding:10px max(12px,calc((100vw - 900px)/2 + 14px)) calc(10px + env(safe-area-inset-bottom));background:linear-gradient(transparent,#090b10 20%);display:flex;gap:8px;align-items:flex-end}.composer textarea{flex:1;min-height:48px;max-height:150px;resize:none;border:1px solid #30394b;background:#121722;color:white;border-radius:14px;padding:12px}.hidden{display:none!important}.empty{padding:36px 12px;text-align:center;color:#8f98aa}.project{font-size:12px;color:#9ba6ba;margin-top:3px}.errorbox{border:1px solid #6a2f38;background:#2b171b;color:#ffc2ca;padding:10px;border-radius:12px;margin:8px 0}
</style></head><body><div class="app"><div class="top"><div><div class="brand">Central Ops</div><div id="subtitle" class="muted">Direct Pi workspace</div></div><button id="newBtn" class="btn primary">New</button></div><main id="listView"><div id="threadList" class="cards"></div></main><main id="threadView" class="hidden"><button id="backBtn" class="btn">← Threads</button><div class="row" style="margin-top:12px"><div><div id="threadTitle" class="title"></div><div id="threadMeta" class="muted"></div></div><span id="threadStatus" class="status"></span></div><div id="threadError" class="errorbox hidden"></div><div id="messages" class="messages"></div><div class="composer"><textarea id="composer" placeholder="Message Pi…"></textarea><button id="stopBtn" class="btn danger hidden">Stop</button><button id="sendBtn" class="btn primary">Send</button></div></main></div>
<script>
let current=null, es=null, deltaBubble=null;
const $=s=>document.querySelector(s); const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function token(){let t=localStorage.getItem('centralOpsToken')||''; if(!t){t=prompt('Central Ops token (leave blank if disabled)')||''; localStorage.setItem('centralOpsToken',t)} return t}
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'Content-Type':'application/json','X-Central-Ops-Token':token()};const r=await fetch(path,opt);if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()}
function fmt(ts){return new Date(ts).toLocaleString([], {month:'short',day:'numeric',hour:'numeric',minute:'2-digit'})}
async function loadThreads(){const d=await api('/api/threads');$('#threadList').innerHTML=d.threads.length?d.threads.map(t=>`<button class="card" style="text-align:left;color:inherit" onclick="openThread('${t.id}')"><div class="row"><div><div class="title">${esc(t.title)}</div><div class="project">${esc(t.project_id)} · ${esc(t.model)}</div></div><span class="status ${t.status}">${t.status}</span></div><div class="muted" style="margin-top:9px">${fmt(t.updated_at)}</div></button>`).join(''):'<div class="empty">No threads yet. Tap New.</div>'}
async function newThread(){const p=await api('/api/projects');const project=p.projects[0];const title=prompt('Thread title','New Pi task');if(title===null)return;const d=await api('/api/threads',{method:'POST',body:JSON.stringify({title,projectId:project.id,projectPath:project.path})});openThread(d.thread.id)}
async function openThread(id){current=id;$('#listView').classList.add('hidden');$('#threadView').classList.remove('hidden');$('#newBtn').classList.add('hidden');await refreshThread();connectEvents()}
async function refreshThread(){const d=await api('/api/threads/'+current);const t=d.thread;$('#threadTitle').textContent=t.title;$('#threadMeta').textContent=t.project_id+' · '+t.model;$('#threadStatus').textContent=t.status;$('#threadStatus').className='status '+t.status;$('#stopBtn').classList.toggle('hidden',t.status!=='working');$('#sendBtn').disabled=t.status==='working';$('#threadError').classList.toggle('hidden',!t.last_error);$('#threadError').textContent=t.last_error||'';$('#messages').innerHTML=d.messages.map(m=>`<div class="msg ${m.role}">${esc(m.content)}</div>`).join('');deltaBubble=null;window.scrollTo(0,document.body.scrollHeight)}
function connectEvents(){if(es)es.close();es=new EventSource('/api/threads/'+current+'/events?token='+encodeURIComponent(token()));es.onmessage=ev=>{const e=JSON.parse(ev.data);if(e.type==='assistant.delta'){if(!deltaBubble){deltaBubble=document.createElement('div');deltaBubble.className='msg assistant';$('#messages').appendChild(deltaBubble)}deltaBubble.textContent+=(e.payload.text||'');window.scrollTo(0,document.body.scrollHeight)}if(['thread.status','message.created','turn.completed'].includes(e.type))refreshThread()}}
async function send(){const text=$('#composer').value.trim();if(!text)return;$('#composer').value='';deltaBubble=null;try{await api('/api/threads/'+current+'/messages',{method:'POST',body:JSON.stringify({content:text})});await refreshThread()}catch(e){alert(e.message)}}
async function stop(){await api('/api/threads/'+current+'/stop',{method:'POST'});await refreshThread()}
$('#newBtn').onclick=newThread;$('#backBtn').onclick=()=>{if(es)es.close();current=null;$('#threadView').classList.add('hidden');$('#listView').classList.remove('hidden');$('#newBtn').classList.remove('hidden');loadThreads()};$('#sendBtn').onclick=send;$('#stopBtn').onclick=stop;$('#composer').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});if('serviceWorker'in navigator)navigator.serviceWorker.register('/sw.js');loadThreads();setInterval(()=>{if(!current)loadThreads()},5000);
</script></body></html>'''

MANIFEST = {
    "name": "Central Ops",
    "short_name": "Central Ops",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0b0d12",
    "theme_color": "#0b0d12",
    "icons": [],
}

SERVICE_WORKER = """const CACHE='central-ops-v1';self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/','/manifest.webmanifest']))));self.addEventListener('fetch',e=>{if(e.request.method==='GET'&&!e.request.url.includes('/api/'))e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))})"""


class App:
    def __init__(self, store: Store, runner: PiRunner, projects: list[dict[str, str]], token: str = ""):
        self.store = store
        self.runner = runner
        self.projects = projects
        self.token = token

    def authorized(self, handler: http.server.BaseHTTPRequestHandler, query: dict[str, list[str]]) -> bool:
        if not self.token:
            return True
        supplied = handler.headers.get("X-Central-Ops-Token", "") or (query.get("token", [""])[0])
        return secrets.compare_digest(supplied, self.token)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"CentralOps/{APP_VERSION}"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} {fmt % args}")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path.startswith("/api/") and not self.app.authorized(self, query):
            return self.send_json(401, {"error": "unauthorized"})
        try:
            if parsed.path == "/":
                return self.send_bytes(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            if parsed.path == "/manifest.webmanifest":
                return self.send_json(200, MANIFEST)
            if parsed.path == "/sw.js":
                return self.send_bytes(200, "application/javascript", SERVICE_WORKER.encode())
            if parsed.path == "/api/health":
                return self.send_json(200, {"ok": True, "version": APP_VERSION})
            if parsed.path == "/api/projects":
                return self.send_json(200, {"projects": self.app.projects})
            if parsed.path == "/api/threads":
                return self.send_json(200, {"threads": self.app.store.list_threads()})
            if parsed.path.startswith("/api/threads/") and parsed.path.endswith("/events"):
                thread_id = parsed.path.split("/")[3]
                return self.stream_events(thread_id, int(query.get("after", ["0"])[0] or 0))
            if parsed.path.startswith("/api/threads/"):
                thread_id = parsed.path.split("/")[3]
                return self.send_json(200, {"thread": self.app.store.get_thread(thread_id), "messages": self.app.store.list_messages(thread_id)})
            return self.send_json(404, {"error": "not found"})
        except KeyError:
            return self.send_json(404, {"error": "thread not found"})
        except Exception as exc:
            return self.send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path.startswith("/api/") and not self.app.authorized(self, query):
            return self.send_json(401, {"error": "unauthorized"})
        try:
            body = self.read_json()
            if parsed.path == "/api/threads":
                project_id = str(body.get("projectId") or self.app.projects[0]["id"])
                project = next((p for p in self.app.projects if p["id"] == project_id), None)
                if project is None:
                    return self.send_json(400, {"error": "unknown project"})
                thread = self.app.store.create_thread(
                    title=str(body.get("title") or "New thread"),
                    project_id=project_id,
                    project_path=str(body.get("projectPath") or project["path"]),
                    provider=str(body.get("provider") or DEFAULT_PROVIDER),
                    model=str(body.get("model") or DEFAULT_MODEL),
                )
                return self.send_json(201, {"thread": thread})
            if parsed.path.startswith("/api/threads/") and parsed.path.endswith("/messages"):
                thread_id = parsed.path.split("/")[3]
                content = str(body.get("content") or "").strip()
                if not content:
                    return self.send_json(400, {"error": "content is required"})
                self.app.runner.start_turn(thread_id, content)
                return self.send_json(202, {"ok": True})
            if parsed.path.startswith("/api/threads/") and parsed.path.endswith("/stop"):
                thread_id = parsed.path.split("/")[3]
                return self.send_json(200, {"stopped": self.app.runner.stop_turn(thread_id)})
            return self.send_json(404, {"error": "not found"})
        except KeyError:
            return self.send_json(404, {"error": "thread not found"})
        except RuntimeError as exc:
            return self.send_json(409, {"error": str(exc)})
        except Exception as exc:
            return self.send_json(500, {"error": str(exc)})

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def send_json(self, status: int, value: Any) -> None:
        self.send_bytes(status, "application/json", json_dumps(value).encode())

    def send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def stream_events(self, thread_id: str, after_id: int) -> None:
        self.app.store.get_thread(thread_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        cursor = after_id
        last_heartbeat = time.monotonic()
        try:
            while True:
                events = self.app.store.list_events_after(thread_id, cursor)
                for event in events:
                    cursor = event["id"]
                    payload = json_dumps(event)
                    self.wfile.write(f"id: {cursor}\ndata: {payload}\n\n".encode())
                    self.wfile.flush()
                if time.monotonic() - last_heartbeat > 15:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    last_heartbeat = time.monotonic()
                time.sleep(0.35)
        except (BrokenPipeError, ConnectionResetError):
            return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def load_projects(path: str | None) -> list[dict[str, str]]:
    if not path:
        return DEFAULT_PROJECTS
    with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
        value = json.load(f)
    projects = value.get("projects") if isinstance(value, dict) else value
    if not isinstance(projects, list) or not projects:
        raise ValueError("projects file must contain a non-empty list")
    result = []
    for project in projects:
        if not isinstance(project, dict):
            raise ValueError("project entries must be objects")
        result.append({"id": str(project["id"]), "name": str(project.get("name") or project["id"]), "path": os.path.expanduser(str(project["path"]))})
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    parser.add_argument("--projects", help="JSON file containing project definitions")
    parser.add_argument("--pi-command", default=DEFAULT_PI_COMMAND)
    parser.add_argument("--turn-timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--token", default=os.environ.get("CENTRAL_OPS_TOKEN", ""))
    args = parser.parse_args(argv)

    data_dir = Path(os.path.expanduser(args.data_dir))
    store = Store(data_dir / "central-ops-pwa.db")
    runner = PiRunner(store, pi_command=args.pi_command, timeout_seconds=args.turn_timeout)
    app = App(store, runner, load_projects(args.projects), token=args.token)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.app = app  # type: ignore[attr-defined]
    print(f"Central Ops PWA {APP_VERSION} listening on http://{args.host}:{args.port}")
    print(f"Data: {store.db_path}")
    print("Expose privately with Tailscale Serve for HTTPS/PWA installation.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
