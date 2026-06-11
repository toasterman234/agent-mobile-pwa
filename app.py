#!/usr/bin/env python3
"""
Agent Mobile PWA — a one-file mobile PWA: board + chat over an agent-runner daemon.

A phone-friendly front-end on the daemon's EXISTING /api, served as an installable
web app over HTTPS.

What it does:
  - Serves a mobile board at /  (your real runs grouped into status columns)
  - Tap a run -> CHAT/SESSION view (its attempts = the conversation,
    live-streamed via SSE when the run is active)
  - Reply box: idle/terminal run -> RESUME with your message; running run ->
    QUEUE a follow-up. Both are REAL governed agent work, gated by a confirm dialog.
  - Proxies /api/*  ->  http://127.0.0.1:4773/api/*  (streaming, so SSE works;
    forwards GET/POST/DELETE so writes go through)
  - Serves HTTPS using the Tailscale cert so the phone connects with a green lock

Run:   python3 app.py
Phone: https://<your-host>:4775   (e.g. over Tailscale, with a cert for that host)

Note: sending a reply triggers real agent work + spend on your backend.

Config is via environment variables (all have localhost-friendly defaults):
  PI_DAEMON        agent-runner daemon base URL   (default http://127.0.0.1:4773)
  AX_SERVER        AX engine base URL             (default http://127.0.0.1:8810)
  PI_BOARD_PORT    port to serve on               (default 4775)
  PI_BOARD_HOST    bind address                   (default 0.0.0.0)
  PI_BOARD_TLS     path prefix to your TLS cert   (expects <prefix>.crt / <prefix>.key)
  PI_BOARD_PUBLIC_HOST  hostname shown in the phone URL / printed banner
Runtime data + keys are written next to this script (see .gitignore).
"""
import http.server
import socketserver
import ssl
import urllib.request
import urllib.error
import os
import sys
import json
import time
import threading
import base64
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

_HERE = os.path.dirname(os.path.abspath(__file__))

DAEMON = os.environ.get("PI_DAEMON", "http://127.0.0.1:4773")   # agent-runner (pi) daemon -> /api/*
AX = os.environ.get("AX_SERVER", "http://127.0.0.1:8810")       # AX sandbox engine        -> /ax/*
PORT = int(os.environ.get("PI_BOARD_PORT", "4775"))
HOST = os.environ.get("PI_BOARD_HOST", "0.0.0.0")
PUBLIC_HOST = os.environ.get("PI_BOARD_PUBLIC_HOST", "localhost")
# Path PREFIX to a TLS cert/key pair for HTTPS (the phone needs a trusted cert for a
# green lock). Defaults to ./tls/cert(.crt/.key) next to this script. A Tailscale cert
# works well: `tailscale cert <your-host>` then point PI_BOARD_TLS at it.
TS = os.path.expanduser(os.environ.get("PI_BOARD_TLS", os.path.join(_HERE, "tls", "cert")))
CERT, KEY = TS + ".crt", TS + ".key"
NTFY_TOPIC_FILE = os.path.expanduser(os.environ.get("NTFY_TOPIC_FILE", "~/.pi/dashboard/.ntfy-topic"))
PHONE_URL = "https://%s:%d" % (PUBLIC_HOST, PORT)


# ---- server-side AX answer store ----------------------------------------------
# The phone's chat history lives in localStorage, but iOS suspends the page's JS the
# moment the app is closed — so an answer that arrives after you leave never gets saved
# on the phone. We mirror every AX answer here, keyed by a turnId the page generates,
# so when you reopen the app it can fetch the answer it missed and fill the bubble.
ANSWERS_FILE = os.path.join(_HERE, ".ax-answers.json")
_answers_lock = threading.Lock()


def _load_answers():
    try:
        with open(ANSWERS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


ANSWERS = _load_answers()


def store_answer(turn_id, answer):
    if not turn_id or not answer:
        return
    with _answers_lock:
        ANSWERS[turn_id] = {"answer": answer, "ts": time.time()}
        if len(ANSWERS) > 200:   # prune oldest, keep it small
            for k in sorted(ANSWERS, key=lambda k: ANSWERS[k].get("ts", 0))[:len(ANSWERS) - 200]:
                ANSWERS.pop(k, None)
        try:
            with open(ANSWERS_FILE, "w") as f:
                json.dump(ANSWERS, f)
        except Exception:
            pass


def get_answer(turn_id):
    with _answers_lock:
        return ANSWERS.get(turn_id)


def _ntfy_topic():
    t = os.environ.get("NTFY_TOPIC", "").strip()
    if t:
        return t
    try:
        with open(NTFY_TOPIC_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def push_ax_reply(answer):
    """Push AX's reply to the phone via ntfy. Called ONLY when the phone dropped the
    stream (app closed/backgrounded) before the answer finished. Never raises."""
    answer = (answer or "").strip()
    topic = _ntfy_topic()
    if not answer or not topic:
        return
    body = answer if len(answer) <= 240 else (answer[:237].rstrip() + "…")
    payload = {
        "topic": topic,
        "title": "✦ AX replied",
        "message": body,
        "tags": ["speech_balloon"],
        "priority": 3,
        "click": PHONE_URL + "/?tab=ax",   # tap opens the app on the AX tab
    }
    try:
        req = urllib.request.Request(
            "https://ntfy.sh",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass


# ---- Web Push (so a tapped notification opens the installed PWA, not a browser) -----
# iOS only opens the PWA when the notification comes from the PWA's own service worker
# via Web Push. We do the VAPID + RFC8291 (aes128gcm) crypto here with `cryptography`
# (already installed) — no third-party push library.
VAPID_KEY_FILE = os.path.join(_HERE, ".vapid.pem")
SUBS_FILE = os.path.join(_HERE, ".push-subs.json")
VAPID_SUB = os.environ.get("VAPID_SUB", "mailto:you@example.com")
_subs_lock = threading.Lock()


def _b64u_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_vapid():
    try:
        with open(VAPID_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        pk = ec.generate_private_key(ec.SECP256R1())
        try:
            with open(VAPID_KEY_FILE, "wb") as f:
                f.write(pk.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))
            os.chmod(VAPID_KEY_FILE, 0o600)
        except Exception:
            pass
        return pk


VAPID_PRIV = _load_vapid()
VAPID_PUBLIC_B64 = _b64u_encode(VAPID_PRIV.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def _load_subs():
    try:
        with open(SUBS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


SUBS = _load_subs()


def _save_subs():
    try:
        with open(SUBS_FILE, "w") as f:
            json.dump(SUBS, f)
    except Exception:
        pass


def add_subscription(sub):
    global SUBS
    ep = (sub or {}).get("endpoint")
    if not ep:
        return
    with _subs_lock:
        SUBS = [s for s in SUBS if s.get("endpoint") != ep]
        SUBS.append(sub)
        _save_subs()


def remove_subscription(ep):
    global SUBS
    with _subs_lock:
        SUBS = [s for s in SUBS if s.get("endpoint") != ep]
        _save_subs()


def _vapid_jwt(aud):
    hdr = _b64u_encode(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    pl = _b64u_encode(json.dumps({"aud": aud, "exp": int(time.time()) + 12 * 3600,
                                  "sub": VAPID_SUB}, separators=(",", ":")).encode())
    der = VAPID_PRIV.sign((hdr + "." + pl).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = _b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return hdr + "." + pl + "." + sig


def _encrypt_payload(p256dh_b64, auth_b64, plaintext):
    ua_pub_raw = _b64u_decode(p256dh_b64)
    auth = _b64u_decode(auth_b64)
    ua_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub_raw)
    as_priv = ec.generate_private_key(ec.SECP256R1())
    as_pub_raw = as_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = as_priv.exchange(ec.ECDH(), ua_pub)
    salt = os.urandom(16)
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth,
               info=b"WebPush: info\x00" + ua_pub_raw + as_pub_raw).derive(shared)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
               info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt,
                 info=b"Content-Encoding: nonce\x00").derive(ikm)
    ct = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + (4096).to_bytes(4, "big") + bytes([len(as_pub_raw)]) + as_pub_raw
    return header + ct


def webpush_send(sub, data):
    try:
        endpoint = sub["endpoint"]
        keys = sub["keys"]
        body = _encrypt_payload(keys["p256dh"], keys["auth"], json.dumps(data).encode())
        aud = "{u.scheme}://{u.netloc}".format(u=urlparse(endpoint))
        headers = {
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": "3600",
            "Authorization": "vapid t=%s,k=%s" % (_vapid_jwt(aud), VAPID_PUBLIC_B64),
        }
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):                      # subscription expired — drop it
            remove_subscription(sub.get("endpoint", ""))
        return e.code
    except Exception:
        return None


def notify_ax_reply(answer):
    """Push AX's reply when Ben is away. Web Push if he has subscribed (tap opens the
    PWA); otherwise fall back to ntfy so he still gets it before enabling push."""
    answer = (answer or "").strip()
    if not answer:
        return
    body = answer if len(answer) <= 240 else (answer[:237].rstrip() + "…")
    with _subs_lock:
        targets = list(SUBS)
    if targets:
        for s in targets:
            webpush_send(s, {"title": "✦ AX replied", "body": body, "url": "/?tab=ax"})
    else:
        push_ax_reply(answer)


def webpush_all(title, body, url):
    """Send one web push (opens the PWA) to every subscribed phone. Used by local
    watchers (e.g. gate-notifier) via POST /push/broadcast. Returns # delivered."""
    with _subs_lock:
        targets = list(SUBS)
    sent = 0
    for s in targets:
        if webpush_send(s, {"title": title, "body": body, "url": url or "/"}) in (200, 201, 202):
            sent += 1
    return sent


# ---- notify coordinator ---------------------------------------------------------
# A TCP write to a backgrounded phone often "succeeds" into the kernel buffer, so the
# socket can't tell us the user left. Instead the app beacons "I'm leaving" the moment
# iOS backgrounds it (visibilitychange→hidden); the server notifies based on THAT.
_notify_lock = threading.Lock()
WANT_NOTIFY = set()   # turnIds whose user has left and wants the reply pushed
NOTIFIED = set()      # turnIds already pushed (dedupe)
CANCELLED = set()     # turnIds the user came back to — never push these


def maybe_notify(turn_id, answer=None):
    if not turn_id:
        return
    with _notify_lock:
        if turn_id in NOTIFIED:
            return
        NOTIFIED.add(turn_id)
        if len(NOTIFIED) > 500:
            NOTIFIED.clear()
        WANT_NOTIFY.discard(turn_id)
    if answer is None:
        rec = get_answer(turn_id)
        answer = rec.get("answer") if rec else None
    if answer:
        notify_ax_reply(answer)


def request_notify(turn_id):
    """App says 'I left' for this turn. Notify now if the answer is already done,
    else mark it so the streaming completion notifies when it finishes."""
    if not turn_id:
        return
    with _notify_lock:
        WANT_NOTIFY.add(turn_id)
    rec = get_answer(turn_id)
    if rec and rec.get("answer"):
        maybe_notify(turn_id, rec["answer"])


def cancel_notify(turn_id):
    if not turn_id:
        return
    with _notify_lock:
        WANT_NOTIFY.discard(turn_id)
        CANCELLED.add(turn_id)
        if len(CANCELLED) > 500:
            CANCELLED.clear()


SW_JS = """
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'AX', {
    body: d.body || '', tag: 'ax-reply', data: { url: d.url || '/?tab=ax' }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/?tab=ax';
  e.waitUntil((async () => {
    const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) { if ('focus' in c) { try { await c.navigate(url); } catch (_) {} return c.focus(); } }
    if (clients.openWindow) return clients.openWindow(url);
  })());
});
"""

MANIFEST = json.dumps({
    "name": "pi runs", "short_name": "pi runs", "start_url": "/",
    "scope": "/", "display": "standalone",
    "background_color": "#0d1117", "theme_color": "#0d1117",
})


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#0d1117">
<link rel="manifest" href="/manifest.webmanifest">
<title>pi runs</title>
<style>
  :root{ --bg:#0d1117; --surface:#161b22; --surface2:#1c232c; --border:#2a3340;
         --fg:#e6edf3; --dim:#8b949e; --accent:#58a6ff; }
  *{ box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
  html,body{ height:100%; }
  body{ margin:0; background:var(--bg); color:var(--fg);
        font-family:-apple-system,BlinkMacSystemFont,"DM Sans","Segoe UI",sans-serif;
        font-size:15px; display:flex; flex-direction:column; }
  header{ flex:none; z-index:10; background:var(--bg);
          padding:calc(10px + env(safe-area-inset-top)) 16px 8px; border-bottom:1px solid var(--border); }
  .topline{ display:flex; align-items:center; gap:10px; }
  header h1{ font-size:17px; margin:0; font-weight:600; }
  header .meta{ color:var(--dim); font-size:12px; margin-left:auto; }
  button.refresh{ background:var(--surface2); color:var(--fg); border:1px solid var(--border);
        border-radius:8px; padding:6px 12px; font-size:13px; }
  .tabnav{ flex:none; z-index:10; display:flex; background:var(--surface);
        border-top:1px solid var(--border);
        padding:6px 8px calc(6px + env(safe-area-inset-bottom)); }
  .tabnav button{ flex:1; background:none; color:var(--dim); border:none;
        display:flex; flex-direction:column; align-items:center; gap:3px;
        padding:6px 4px; font-size:11px; font-weight:600; }
  .tabnav button .ico{ font-size:19px; line-height:1; }
  .tabnav button.on{ color:var(--accent); }
  #main{ flex:1; min-height:0; position:relative; }
  .view{ display:none; height:100%; overflow-y:auto; }
  .view.on{ display:block; }
  .view.chat{ overflow:hidden; }
  .view.chat.on{ display:flex; flex-direction:column; }
  .wrap{ padding:8px 12px 40px; }
  .filterbars{ position:sticky; top:0; z-index:6; background:var(--bg); border-bottom:1px solid var(--border); }
  .filterbar{ display:flex; gap:6px; align-items:center; overflow-x:auto; padding:7px 12px;
        -webkit-overflow-scrolling:touch; }
  .filterbar::-webkit-scrollbar{ display:none; }
  .typebar{ border-top:1px solid var(--border); }
  .fbar-tag{ flex:none; font-size:10px; color:var(--dim); font-weight:700; letter-spacing:.04em;
        text-transform:uppercase; margin-right:2px; min-width:34px; }
  .fpill.sortbtn{ margin-left:auto; color:var(--accent); border-color:var(--accent); }
  .fpill{ flex:none; display:flex; align-items:center; gap:6px; background:var(--surface);
        border:1px solid var(--border); color:var(--dim); border-radius:20px; padding:6px 12px;
        font-size:13px; font-weight:600; white-space:nowrap; }
  .fpill.on{ color:var(--fg); background:var(--surface2); border-color:var(--accent); }
  .fpill .fdot{ width:8px; height:8px; border-radius:50%; flex:none; }
  .fpill .fcount{ color:var(--dim); font-weight:400; }
  .fpill.zero{ opacity:.4; }
  .col{ margin:14px 0 6px; }
  .col-head{ display:flex; align-items:center; gap:8px; padding:6px 4px; font-weight:600;
        position:sticky; top:0; background:var(--bg); z-index:5; }
  .dot{ width:10px; height:10px; border-radius:50%; flex:none; }
  .count{ color:var(--dim); font-weight:400; font-size:13px; }
  .card{ background:var(--surface); border:1px solid var(--border); border-radius:12px;
        padding:11px 13px; margin:8px 0; }
  .card:active{ background:var(--surface2); }
  .card .name{ font-size:14px; line-height:1.35; word-break:break-word; }
  .card .row{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; align-items:center; }
  .chip{ font-size:11px; color:var(--dim); background:var(--surface2);
        border:1px solid var(--border); border-radius:6px; padding:2px 7px; }
  .chip.agent{ color:var(--accent); }
  .pin{ color:#d29922; }
  .prog{ font-size:11px; color:var(--dim); }
  .when{ color:var(--dim); font-size:11px; margin-left:auto; }
  .empty{ color:var(--dim); text-align:center; padding:40px 0; }

  /* chat / session sheet */
  .sheet{ position:fixed; inset:0; z-index:50; background:var(--bg);
        transform:translateY(100%); transition:transform .22s ease;
        display:flex; flex-direction:column; }
  .sheet.open{ transform:translateY(0); }
  .sheet-head{ padding:calc(10px + env(safe-area-inset-top)) 14px 10px; border-bottom:1px solid var(--border);
        display:flex; align-items:flex-start; gap:10px; background:var(--surface); }
  .sheet-head .x{ font-size:22px; line-height:1; color:var(--dim); background:none; border:none; padding:2px 6px; }
  .sheet-head .h-name{ font-size:14px; font-weight:600; word-break:break-word; }
  .sheet-head .h-sub{ color:var(--dim); font-size:12px; margin-top:3px;
        display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
  .sheet-body{ flex:1; overflow-y:auto; padding:14px; }
  .att{ margin:0 0 18px; }
  .att-label{ color:var(--dim); font-size:11px; margin:0 0 6px; display:flex; gap:8px; align-items:center; }
  .att-role{ color:var(--dim); font-size:10px; letter-spacing:.05em; text-transform:uppercase; margin:9px 0 4px; }
  .att-empty{ color:var(--dim); font-size:12px; font-style:italic; padding:7px 2px; }
  .clip{ max-height:66px; overflow:hidden; -webkit-mask-image:linear-gradient(#000 58%, transparent); }
  .bubble{ background:var(--surface); border:1px solid var(--border); border-radius:12px;
        padding:10px 12px; font-size:13px; line-height:1.5; white-space:pre-wrap; word-break:break-word; }
  .prompt-toggle{ color:var(--accent); font-size:11px; margin:6px 0 0; }
  .prompt-body{ display:none; margin-top:6px; padding:8px 10px; background:#0b0f14;
        border:1px dashed var(--border); border-radius:8px; font-size:11px; color:var(--dim);
        white-space:pre-wrap; max-height:240px; overflow:auto; }
  .prompt-body.open{ display:block; }
  .live-pill{ font-size:10px; color:#3fb950; border:1px solid #2ea043; border-radius:20px; padding:1px 7px; }
  .sent{ background:#13212e; border:1px solid #1f4f6b; border-radius:12px; padding:10px 12px;
        font-size:13px; line-height:1.5; white-space:pre-wrap; word-break:break-word; }
  .sent-label{ color:var(--accent); font-size:11px; margin:0 0 6px; }
  .composer{ border-top:1px solid var(--border);
        padding:10px 12px calc(10px + env(safe-area-inset-bottom));
        background:var(--surface); display:flex; gap:8px; align-items:flex-end; }
  .composer textarea{ flex:1; resize:none; background:var(--bg); color:var(--fg);
        border:1px solid var(--border); border-radius:10px; padding:9px 11px; font-size:16px;
        font-family:inherit; line-height:1.4; max-height:120px; }
  .composer button{ background:var(--accent); color:#06121f; border:none; border-radius:10px;
        padding:9px 15px; font-size:14px; font-weight:600; flex:none; }
  .composer button:disabled{ opacity:.5; }
  .composer .hint{ position:absolute; }

  /* AX chat tab */
  .msgs{ flex:1; overflow-y:auto; padding:14px; }
  .msg{ margin:0 0 12px; max-width:88%; }
  .msg.you{ margin-left:auto; }
  .msg .who{ font-size:11px; color:var(--dim); margin:0 0 4px; }
  .msg.you .who{ text-align:right; color:var(--accent); }
  .msg .b{ border:1px solid var(--border); border-radius:12px; padding:10px 12px;
        font-size:14px; line-height:1.5; white-space:pre-wrap; word-break:break-word; background:var(--surface); }
  .msg.you .b{ background:#13212e; border-color:#1f4f6b; }
  .msg .b.think{ color:var(--dim); }
  /* AX live trace */
  .trace{ margin:0 0 8px; max-width:88%; border:1px solid var(--border); border-radius:10px;
        background:#0b0f14; overflow:hidden; }
  .trace-head{ display:flex; align-items:center; gap:7px; padding:7px 10px;
        font-size:11px; color:var(--dim); font-weight:600; }
  .trace-head .caret{ font-size:9px; transition:transform .15s; }
  .trace:not(.open) .trace-head .caret{ transform:rotate(-90deg); }
  .trace-steps{ display:none; padding:1px 10px 9px; }
  .trace.open .trace-steps{ display:block; }
  .tstep{ font-size:11px; color:var(--dim); margin:5px 0; line-height:1.4; }
  .tstep-line{ display:flex; gap:6px; align-items:flex-start; }
  .tstep-line .tk{ flex:none; }
  .tstep.has-detail .tstep-line{ color:var(--accent); }
  .tstep-detail{ display:none; margin:5px 0 2px; padding:7px 9px; background:#0d1117;
        border:1px dashed var(--border); border-radius:7px; white-space:pre-wrap;
        font-family:ui-monospace,Menlo,monospace; font-size:10.5px; color:var(--dim);
        max-height:220px; overflow:auto; }
  .tstep.show .tstep-detail{ display:block; }
  .live-dot{ width:7px; height:7px; border-radius:50%; background:#3fb950; flex:none;
        display:inline-block; animation:pulse 1s infinite; }
  @keyframes pulse{ 0%,100%{opacity:1} 50%{opacity:.25} }
  /* AX sessions: list + chat sub-views */
  .ax-list{ display:none; flex-direction:column; flex:1; min-height:0; }
  .ax-list.on{ display:flex; }
  #ax-list-items{ flex:1; min-height:0; overflow-y:auto; padding:12px; }
  .ax-new{ background:var(--accent); color:#06121f; border:none; border-radius:10px; padding:12px;
        font-size:15px; font-weight:600; flex:none; margin:0 12px;
        margin-bottom:calc(12px + env(safe-area-inset-bottom)); }
  .ax-notify{ background:var(--surface2); color:var(--accent); border:1px solid var(--accent);
        border-radius:10px; padding:11px; font-size:13px; font-weight:600; flex:none; margin:12px 12px 0; }
  .ax-item{ background:var(--surface); border:1px solid var(--border); border-radius:11px;
        padding:11px 13px; margin-bottom:8px; display:flex; align-items:flex-start; gap:8px; }
  .ax-item:active{ background:var(--surface2); }
  .ax-item .t{ font-size:14px; font-weight:600; word-break:break-word; }
  .ax-item .prev{ color:var(--dim); font-size:12px; margin-top:3px;
        overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .ax-item .s{ color:var(--dim); font-size:11px; margin-top:4px; }
  .ax-item .unread{ display:inline-block; width:8px; height:8px; border-radius:50%;
        background:var(--accent); margin-right:6px; vertical-align:middle; flex:none; }
  .ax-item .del{ color:var(--dim); font-size:18px; background:none; border:none; padding:0 4px; margin-left:auto; flex:none; }
  .ax-chatwrap{ display:none; flex-direction:column; flex:1; min-height:0; }
  .ax-chatwrap.on{ display:flex; }
  .ax-bar{ display:flex; align-items:center; gap:10px; padding:8px 12px; flex:none;
        border-bottom:1px solid var(--border); background:var(--surface); }
  .ax-back{ background:var(--surface2); color:var(--fg); border:1px solid var(--border);
        border-radius:8px; padding:5px 10px; font-size:13px; flex:none; }
  .ax-title{ font-size:13px; color:var(--dim); font-weight:600; overflow:hidden;
        text-overflow:ellipsis; white-space:nowrap; }

  /* New-session form */
  .form{ padding:16px 14px 40px; }
  .form label{ display:block; font-size:12px; color:var(--dim); margin:14px 0 5px; }
  .form select, .form textarea{ width:100%; background:var(--surface); color:var(--fg);
        border:1px solid var(--border); border-radius:10px; padding:10px 11px; font-size:16px;
        font-family:inherit; line-height:1.4; }
  .form textarea{ resize:vertical; min-height:90px; }
  .form .go{ width:100%; margin-top:18px; background:var(--accent); color:#06121f; border:none;
        border-radius:10px; padding:12px; font-size:15px; font-weight:600; }
  .form .go:disabled{ opacity:.5; }
  .form .warn{ font-size:12px; color:#d29922; margin-top:14px; line-height:1.5; }
</style>
</head>
<body>
<header>
  <div class="topline">
    <h1 id="title">pi runs</h1>
    <span class="meta" id="meta">loading…</span>
    <button class="refresh" id="refreshBtn" onclick="refresh()">↻</button>
  </div>
</header>
<div id="main">
  <div class="view on" id="v-board">
    <div class="filterbars">
      <div class="filterbar" id="filterbar"></div>
      <div class="filterbar typebar" id="typebar"></div>
      <div class="filterbar typebar" id="whenbar"></div>
    </div>
    <div class="wrap" id="board"><div class="empty">loading your runs…</div></div>
  </div>

  <div class="view chat" id="v-ax">
    <div class="ax-list" id="ax-list">
      <button class="ax-notify" id="notifyBtn" onclick="enableNotifications()" style="display:none">🔔 Turn on reply notifications</button>
      <div id="ax-list-items"></div>
      <button class="ax-new" onclick="axNew()">＋ New chat</button>
    </div>
    <div class="ax-chatwrap" id="ax-chatwrap">
      <div class="ax-bar">
        <button class="ax-back" onclick="axShowList()">‹ Chats</button>
        <span class="ax-title" id="ax-title"></span>
      </div>
      <div class="msgs" id="ax-msgs"></div>
      <div class="composer">
        <textarea id="ax-input" rows="1" placeholder="Message AX…" oninput="grow(this)"></textarea>
        <button id="ax-send" onclick="axSend()">Send</button>
      </div>
    </div>
  </div>

  <div class="view" id="v-flows">
    <div class="wrap" id="flows"><div class="empty">loading flows…</div></div>
  </div>

  <div class="view" id="v-new">
    <div class="form">
      <label for="nw-agent">Agent</label>
      <select id="nw-agent"><option>loading…</option></select>
      <label for="nw-assign">Assignment (optional)</label>
      <select id="nw-assign"><option value="">— none —</option></select>
      <label for="nw-msg">First message</label>
      <textarea id="nw-msg" placeholder="What should this agent do?"></textarea>
      <button class="go" id="nw-go" onclick="createSession()">Start run</button>
      <div class="warn">⚠️ This starts a <b>real governed run</b> — real agent work and spend.</div>
    </div>
  </div>
</div>

<nav class="tabnav">
  <button id="tab-board" class="on" onclick="showTab('board')"><span class="ico">▦</span>Board</button>
  <button id="tab-ax" onclick="showTab('ax')"><span class="ico">✦</span>AX</button>
  <button id="tab-flows" onclick="showTab('flows')"><span class="ico">⛓</span>Flows</button>
  <button id="tab-new" onclick="showTab('new')"><span class="ico">＋</span>New</button>
</nav>

<div class="sheet" id="sheet">
  <div class="sheet-head">
    <button class="x" onclick="closeRun()">✕</button>
    <div style="flex:1">
      <div class="h-name" id="sh-name"></div>
      <div class="h-sub" id="sh-sub"></div>
    </div>
  </div>
  <div class="sheet-body" id="sh-body"></div>
  <div class="composer">
    <textarea id="msg" rows="1" placeholder="Reply… (sends real agent work)"
              oninput="grow(this)"></textarea>
    <button id="send" onclick="sendReply()">Send</button>
  </div>
</div>

<div class="sheet" id="flowsheet">
  <div class="sheet-head">
    <button class="x" onclick="closeFlow()">✕</button>
    <div style="flex:1">
      <div class="h-name" id="fl-name"></div>
      <div class="h-sub" id="fl-sub"></div>
    </div>
  </div>
  <div class="sheet-body" id="fl-body"></div>
</div>

<script>
const COLS = [
  ["ready",     "Ready",     "#3fb950"],
  ["running",   "Running",   "#58a6ff"],
  ["initialized","Initialized","#8b949e"],
  ["blocked",   "Blocked",   "#d29922"],
  ["exhausted", "Exhausted", "#f85149"],
  ["success",   "Success",   "#2ea043"],
];
const KNOWN = new Set(COLS.map(c=>c[0]));
let sse = null;

function ago(ts){
  if(!ts) return "";
  const s = Math.max(0,(Date.now()-new Date(ts).getTime())/1000);
  if(s<60) return Math.floor(s)+"s";
  if(s<3600) return Math.floor(s/60)+"m";
  if(s<86400) return Math.floor(s/3600)+"h";
  return Math.floor(s/86400)+"d";
}
function esc(x){ return (x==null?"":String(x)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function card(r){
  const tasks = (r.tasksTotal>0) ? `${r.tasksCompleted||0}/${r.tasksTotal}` : "";
  const sched = r.schedule ? "⏱" : "";
  const td = TYPES.find(t=>t[0]===typeOf(r));
  const d = document.createElement("div");
  d.className = "card";
  d.innerHTML = `
    <div class="name">${r.pinned?'<span class="pin">★ </span>':''}${esc(r.name||r.assignmentName||r.runId)}</div>
    <div class="row">
      <span class="chip ty" style="color:${td?td[2]:'#8b949e'};border-color:${td?td[2]:'var(--border)'}">${td?td[1]:'Other'}</span>
      <span class="chip agent">${esc(r.agentName||"")}</span>
      ${r.runGroupId?`<span class="chip">${esc(r.runGroupId)}</span>`:""}
      ${tasks?`<span class="prog">✓ ${tasks}</span>`:""}
      ${sched?`<span class="prog">${sched}</span>`:""}
      <span class="when">${ago(r.updatedAt)}</span>
    </div>`;
  d.onclick = ()=> openRun(r);
  return d;
}

let lastRuns = [];
let activeFilter = localStorage.getItem("board-filter") || "all";        // status facet
let activeType = localStorage.getItem("board-type-filter") || "all";     // type facet
let activeWhen = localStorage.getItem("board-when") || "any";            // time-window facet
let sortNewest = localStorage.getItem("board-sort") !== "old";          // sort direction

// Run "type" is derived (the daemon has no type field) from assignment/group/agent/model.
// First match wins — reorder if a bucket grabs the wrong runs.
const TYPES = [
  ["fix",      "Fix",      "#d29922"],
  ["research", "Research", "#a371f7"],
  ["build",    "Build",    "#58a6ff"],
  ["cards",    "Cards",    "#8b949e"],
  ["resource", "Resource", "#2ea043"],
  ["assistant","Assistant","#db61a2"],
  ["github",   "GitHub",   "#6e7681"],
];
function statusOf(r){ const k=r.effectiveStatus||r.status||"other"; return KNOWN.has(k)?k:"other"; }
function typeOf(r){
  const a=r.assignmentName||"", g=r.runGroupId||"", ag=r.agentName||"", m=r.model||"";
  if(a.indexOf("remediate")===0 || ag==="remediate-skeptic" || g==="remediate") return "fix";
  if(a==="research-handoff" || a==="discover-what-to-build" || /research/i.test(g)) return "research";
  if(a==="build-product") return "build";
  if(a==="do-card") return "cards";
  if(a==="guardian-investigate" || g==="guardian") return "resource";
  if(ag==="pi-pa") return "assistant";
  if(ag==="pi-github") return "github";
  if(/cod(e|ing)|codex/i.test(m)) return "build";
  return "other";
}
function setFilter(k){ activeFilter=k; localStorage.setItem("board-filter",k); render(lastRuns); }
function setType(k){ activeType=k; localStorage.setItem("board-type-filter",k); render(lastRuns); }
function setWhen(k){ activeWhen=k; localStorage.setItem("board-when",k); render(lastRuns); }
function toggleSort(){ sortNewest=!sortNewest; localStorage.setItem("board-sort", sortNewest?"new":"old"); render(lastRuns); }
function passStatus(r){ return activeFilter==="all" || statusOf(r)===activeFilter; }
function passType(r){ return activeType==="all" || typeOf(r)===activeType; }
function inWindow(r, key){
  if(key==="any") return true;
  const t=new Date(r.updatedAt||r.startedAt||0).getTime(), now=Date.now();
  if(key==="1h") return t>=now-3600e3;
  if(key==="week") return t>=now-7*864e5;
  if(key==="today"){ const d=new Date(); d.setHours(0,0,0,0); return t>=d.getTime(); }
  return true;
}
function passWhen(r){ return inWindow(r, activeWhen); }
function countBy(runs, fn){ const c={}; for(const r of runs){ const k=fn(r); c[k]=(c[k]||0)+1; } return c; }

function renderWhenBar(counts){
  const bar=document.getElementById("whenbar");
  const defs=[["any","Any"],["1h","1h"],["today","Today"],["week","Week"]];
  bar.innerHTML=`<span class="fbar-tag">When</span>`+
    defs.map(([k,l])=>{
      const n=counts[k]||0, on=activeWhen===k?" on":"", zero=(k!=="any"&&!n)?" zero":"";
      return `<button class="fpill${on}${zero}" onclick="setWhen('${k}')">${l}<span class="fcount">${n}</span></button>`;
    }).join("")+
    `<button class="fpill sortbtn" onclick="toggleSort()">⇅ ${sortNewest?"Newest":"Oldest"}</button>`;
}

function renderPills(barId, label, defs, activeKey, counts, total, setFn){
  const bar=document.getElementById(barId);
  bar.innerHTML=`<span class="fbar-tag">${label}</span>`+
    [["all","All","var(--accent)"], ...defs].map(([key,lbl,color])=>{
      const n = key==="all" ? total : (counts[key]||0);
      const on = activeKey===key ? " on" : "";
      const zero = (key!=="all" && !n) ? " zero" : "";
      return `<button class="fpill${on}${zero}" onclick="${setFn}('${key}')">`+
             `<span class="fdot" style="background:${color}"></span>${lbl}`+
             `<span class="fcount">${n}</span></button>`;
    }).join("");
}

function render(runs){
  const board=document.getElementById("board");
  // each facet's counts respect the OTHER facets' current selections
  const forStatus = runs.filter(r=>passType(r)&&passWhen(r));
  const forType   = runs.filter(r=>passStatus(r)&&passWhen(r));
  const forWhen   = runs.filter(r=>passStatus(r)&&passType(r));
  const sCounts = countBy(forStatus, statusOf);
  const sDefs = [...COLS, ...(sCounts["other"] ? [["other","Other","#8b949e"]] : [])];
  renderPills("filterbar","Status", sDefs, activeFilter, sCounts, forStatus.length, "setFilter");
  const tCounts = countBy(forType, typeOf);
  const tDefs = TYPES.filter(t => runs.some(r=>typeOf(r)===t[0]) || t[0]===activeType);
  if(tCounts["other"]) tDefs.push(["other","Other","#8b949e"]);
  renderPills("typebar","Type", tDefs, activeType, tCounts, forType.length, "setType");
  const wCounts={any:forWhen.length}; for(const k of ["1h","today","week"]) wCounts[k]=forWhen.filter(r=>inWindow(r,k)).length;
  renderWhenBar(wCounts);

  const visible = runs.filter(r=>passStatus(r)&&passType(r)&&passWhen(r));
  const cmp = sortNewest ? (a,b)=>new Date(b.updatedAt)-new Date(a.updatedAt)
                         : (a,b)=>new Date(a.updatedAt)-new Date(b.updatedAt);
  const g={};
  for(const r of visible){ const k=statusOf(r); (g[k]=g[k]||[]).push(r); }
  for(const k in g) g[k].sort((a,b)=>(b.pinned-a.pinned)|| cmp(a,b));
  board.innerHTML="";
  let any=false;
  const cols = activeFilter==="all" ? [...COLS,["other","Other","#8b949e"]]
             : [...COLS,["other","Other","#8b949e"]].filter(c=>c[0]===activeFilter);
  for(const [key,label,color] of cols){
    const list=g[key]; if(!list||!list.length) continue; any=true;
    const col=document.createElement("div"); col.className="col";
    if(activeFilter==="all"){
      const h=document.createElement("div"); h.className="col-head";
      h.innerHTML=`<span class="dot" style="background:${color}"></span>${label}<span class="count">${list.length}</span>`;
      col.appendChild(h);
    }
    for(const r of list) col.appendChild(card(r));
    board.appendChild(col);
  }
  if(!any) board.innerHTML='<div class="empty">'+
    ((activeFilter==="all"&&activeType==="all"&&activeWhen==="any")?"no active runs":"nothing matches")+'</div>';
}

async function load(){
  const board = document.getElementById("board");
  try{
    const res = await fetch("/api/runs", {headers:{accept:"application/json"}});
    const runs = ((await res.json()).runs||[]).filter(r=>!r.archivedAt);
    document.getElementById("meta").textContent = runs.length+" runs · "+new Date().toLocaleTimeString();
    lastRuns = runs;
    render(runs);
  }catch(e){
    board.innerHTML='<div class="empty">could not reach daemon<br><small>'+esc(e)+'</small></div>';
  }
}

// ---- chat / session view ----
function attemptBlock(a, ask){
  const div=document.createElement("div"); div.className="att";
  const when = a.startedAt ? new Date(a.startedAt).toLocaleString() : "";
  const durMs = (a.startedAt&&a.endedAt) ? (new Date(a.endedAt)-new Date(a.startedAt)) : null;
  const dur = durMs==null ? "" : (durMs<1000 ? durMs+"ms" : (durMs/1000).toFixed(1)+"s");
  const meta = ["attempt "+(a.attemptNumber ?? "?"), when, dur,
                a.timedOut?"⏱ timed out":"", a.exitCode!=null?"exit "+a.exitCode:""]
               .filter(Boolean).join(" · ");
  ask=(ask||"").trim(); const prompt=(a.prompt||"").trim(); const transcript=(a.transcript||"").trim();
  const reqText = ask || prompt;                 // prefer the real message; fall back to full prompt
  let html=`<div class="att-label">${esc(meta)}</div>`;
  if(reqText){
    const long = reqText.length>220;
    html+=`<div class="att-role">request</div>`+
          `<div class="sent${long?' clip':''}" onclick="this.classList.toggle('clip')">${esc(reqText)}</div>`;
  }
  // full composed prompt (incl. the agent's system preamble) tucked behind a toggle
  if(ask && prompt && prompt!==ask){
    html+=`<div class="prompt-toggle" onclick="this.nextElementSibling.classList.toggle('open')">show full prompt ▾</div>`+
          `<div class="prompt-body">${esc(prompt)}</div>`;
  }
  if(transcript){
    html+=`<div class="att-role">response</div><div class="bubble">${esc(transcript)}</div>`;
  }else{
    const ok = a.exitCode===0 && !a.timedOut;
    html+=`<div class="att-empty">${ok?"✓ finished":"△ ended"} — no transcript saved for this run`+
          `${dur?" · "+esc(dur):""}</div>`;
  }
  div.innerHTML=html;
  return div;
}

let curRun=null;

function isActive(r){ return ["running","ready","initialized"].includes(r.effectiveStatus||r.status); }

async function openRun(r){
  curRun=r;
  document.getElementById("msg").value="";
  document.getElementById("sheet").classList.add("open");
  history.pushState({sheet:1},"");
  await loadConversation();
}

async function loadConversation(){
  const r=curRun; if(!r) return;
  document.getElementById("sh-name").textContent = r.name || r.assignmentName || r.runId;
  document.getElementById("sh-sub").innerHTML =
    `<span class="chip agent">${esc(r.agentName||"")}</span>`+
    `<span class="chip">${esc(r.backend||"")}</span>`+
    `<span class="chip">${esc(r.model||"")}</span>`+
    `<span>${esc(r.effectiveStatus||r.status||"")}</span>`+
    (r.tasksTotal>0?`<span>✓ ${r.tasksCompleted||0}/${r.tasksTotal}</span>`:"")+
    `<span id="sh-live"></span>`;
  const body=document.getElementById("sh-body");
  body.innerHTML='<div class="empty">loading conversation…</div>';

  try{
    const res=await fetch(`/api/runs/${encodeURIComponent(r.runId)}/timeline`,{headers:{accept:"application/json"}});
    const h=(await res.json()).history||{};
    const att=h.attempts||[];
    // the list-card lacks `sessions`; fetch the full run so we can map attempt -> message
    let runObj=r;
    try{ const j=await (await fetch(`/api/runs/${encodeURIComponent(r.runId)}`,{headers:{accept:"application/json"}})).json();
         runObj=j.run||j; }catch(_){}
    const askFor=(n)=>{
      const hit=(runObj.sessions||[]).find(s=>n>=s.firstAttemptNumber && n<=s.lastAttemptNumber);
      return hit ? hit.message : (runObj.message||"");
    };
    body.innerHTML="";
    if(!att.length){ body.innerHTML='<div class="empty">no conversation yet</div>'; }
    for(const a of att) body.appendChild(attemptBlock(a, askFor(a.attemptNumber)));
    body.scrollTop=body.scrollHeight;
  }catch(e){
    body.innerHTML='<div class="empty">could not load conversation<br><small>'+esc(e)+'</small></div>';
  }

  // live stream only for active runs (terminal runs won't change)
  if(sse){ sse.close(); sse=null; }
  if(isActive(r)){
    document.getElementById("sh-live").innerHTML='<span class="live-pill">● live</span>';
    sse=new EventSource(`/api/runs/${encodeURIComponent(r.runId)}/events/timeline`);
    sse.onmessage=ev=>{
      try{
        const d=JSON.parse(ev.data);
        const note=document.createElement("div");
        note.className="att-label";
        note.textContent="· "+(d.event?.type||"update");
        document.getElementById("sh-body").appendChild(note);
        document.getElementById("sh-body").scrollTop=1e9;
      }catch(_){}
    };
    sse.onerror=()=>{ /* keep quiet; terminal/idle */ };
  }
}

function grow(ta){ ta.style.height="auto"; ta.style.height=Math.min(120,ta.scrollHeight)+"px"; }

function appendSent(text, queued){
  const body=document.getElementById("sh-body");
  const e=body.querySelector(".empty"); if(e) e.remove();
  const d=document.createElement("div"); d.className="att";
  d.innerHTML=`<div class="sent-label">you · ${queued?"queued":"sent"} ↑</div>`+
              `<div class="sent">${esc(text)}</div>`;
  body.appendChild(d); body.scrollTop=1e9;
}

async function sendReply(){
  if(!curRun) return;
  const ta=document.getElementById("msg");
  const text=ta.value.trim();
  if(!text) return;
  const queued=isActive(curRun) && (curRun.effectiveStatus||curRun.status)==="running";
  const verb = queued ? "QUEUE a follow-up message for" : "RESUME";
  const ok=confirm(`This will ${verb} a real run — real agent work and spend.\n\n`+
                   `Run: ${curRun.name||curRun.assignmentName||curRun.runId}\n\nProceed?`);
  if(!ok) return;
  const send=document.getElementById("send");
  send.disabled=true; send.textContent="…";
  try{
    let url, payload;
    if(queued){
      url=`/api/runs/${encodeURIComponent(curRun.runId)}/queued-resume-messages`;
      payload={message:text};
    }else{
      url=`/api/runs/${encodeURIComponent(curRun.runId)}/resume`;
      payload={overrides:{message:text}};
    }
    const res=await fetch(url,{method:"POST",
      headers:{"content-type":"application/json",accept:"application/json"},
      body:JSON.stringify(payload)});
    if(!res.ok){ throw new Error("HTTP "+res.status+" — "+(await res.text()).slice(0,200)); }
    ta.value=""; grow(ta);
    appendSent(text, queued);
    // resuming flips the run to running -> reflect so SSE opens on refresh
    if(!queued) curRun.effectiveStatus="running";
    // give the daemon a beat to register the new attempt, then refresh the timeline
    setTimeout(loadConversation, 800);
  }catch(err){
    alert("Send failed:\n"+err);
  }finally{
    send.disabled=false; send.textContent="Send";
  }
}

function closeRun(){
  curRun=null;
  document.getElementById("sheet").classList.remove("open");
  if(sse){ sse.close(); sse=null; }
}
window.addEventListener("popstate",()=>{ // phone back button closes whichever sheet is open
  if(document.getElementById("sheet").classList.contains("open")) closeRun();
  else if(document.getElementById("flowsheet").classList.contains("open")) closeFlow();
});

// ---- tabs ----
let tab="board";
const TITLES={board:"pi runs", ax:"AX chat", flows:"AX flows", new:"new session"};
function showTab(t){
  tab=t;
  for(const k of ["board","ax","flows","new"]){
    document.getElementById("v-"+k).classList.toggle("on", k===t);
    document.getElementById("tab-"+k).classList.toggle("on", k===t);
  }
  document.getElementById("title").textContent=TITLES[t];
  const showMeta = (t==="board"||t==="flows");
  document.getElementById("meta").style.display = showMeta?"":"none";
  document.getElementById("refreshBtn").style.display = showMeta?"":"none";
  if(t==="new" && !newLoaded) loadNewForm();
  if(t==="ax") axEnter();
  if(t==="flows") loadFlows();
}
// header refresh button: refresh whatever tab you're on
function refresh(){ if(tab==="flows") loadFlows(); else load(); }

// ---- AX chat (phone-local sessions; separate from AX Studio) ----
const AX_KEY="ax-sessions", AX_LAST="ax-last";
const AX_HIST_TURNS=16, AX_HIST_CHARS=6000;  // how much thread we re-send for memory
let axSessions=[], axCur=null;

function axStore(){ try{ localStorage.setItem(AX_KEY, JSON.stringify(axSessions)); }catch(_){} }
function axLoad(){
  try{ axSessions=JSON.parse(localStorage.getItem(AX_KEY)||"[]"); }catch(_){ axSessions=[]; }
  if(!Array.isArray(axSessions)) axSessions=[];
}
function axFind(id){ return axSessions.find(s=>s.id===id); }
function axId(){ return "s"+Date.now().toString(36)+Math.random().toString(36).slice(2,6); }

function axEnter(){
  axLoad();
  const last=localStorage.getItem(AX_LAST);
  if(last && axFind(last)) axOpen(last); else axShowList();
  axReconcile();
  updateNotifyBtn();
}
// Recover any AX reply that landed while the app was closed (JS was suspended, so it
// never got saved phone-side). For every chat whose last message is an unanswered
// "you" turn, ask the server for that turnId's answer and fill it in.
let axReconciling=false, axPendingTurn=null;
async function axReconcile(){
  if(axReconciling) return; axReconciling=true;
  try{
    axLoad(); let changed=false;
    for(const s of axSessions){
      const pend=s.messages.find(m=>m.role==="ax" && m.pending && m.turnId);
      if(!pend) continue;
      try{
        const j=await (await fetch("/ax/answer?turnId="+encodeURIComponent(pend.turnId))).json();
        if(j && j.answer){
          pend.text=j.answer; pend.pending=false;
          s.updatedAt=Date.now(); changed=true;
          if(axCur===s.id) axOpen(s.id);   // open — re-render the chat with the recovered reply
          else s.unread=true;              // not open — flag it new in the list
        }
      }catch(_){}
    }
    if(changed){
      axStore();
      if(document.getElementById("ax-list").classList.contains("on")) axShowList();
    }
  } finally { axReconciling=false; }
}
// On background, beacon "I left" so the server pushes this turn's reply. On return, cancel
// that (we're back) and recover anything we missed.
document.addEventListener("visibilitychange",()=>{
  if(document.hidden){
    if(axPendingTurn && navigator.sendBeacon){
      try{ navigator.sendBeacon("/ax/notify-on-done",
        new Blob([JSON.stringify({turnId:axPendingTurn})],{type:"application/json"})); }catch(_){}
    }
  }else{
    if(axPendingTurn){
      fetch("/ax/notify-on-done",{method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({turnId:axPendingTurn, cancel:true})}).catch(()=>{});
    }
    axReconcile();
  }
});

// ---- Web Push: notifications that open THIS app (not a browser) ----
let swReg=null;
async function initPush(){
  if(!("serviceWorker" in navigator)) return;
  try{ swReg=await navigator.serviceWorker.register("/sw.js"); }catch(_){}
  updateNotifyBtn();
}
function updateNotifyBtn(){
  const b=document.getElementById("notifyBtn"); if(!b) return;
  const granted=("Notification" in window) && Notification.permission==="granted";
  b.style.display=granted ? "none" : "";
}
function urlB64ToU8(s){
  const pad="=".repeat((4-s.length%4)%4);
  const raw=atob((s+pad).replace(/-/g,"+").replace(/_/g,"/"));
  const a=new Uint8Array(raw.length); for(let i=0;i<raw.length;i++) a[i]=raw.charCodeAt(i); return a;
}
async function enableNotifications(){
  try{
    if(!("Notification" in window) || !("serviceWorker" in navigator)){
      alert("Open the app from your home screen icon (not Safari) to turn on notifications."); return; }
    const perm=await Notification.requestPermission();
    if(perm!=="granted"){ alert("Notifications weren’t allowed."); return; }
    if(!swReg) swReg=await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
    const key=(await (await fetch("/push/key")).json()).key;
    const sub=await swReg.pushManager.subscribe({userVisibleOnly:true, applicationServerKey:urlB64ToU8(key)});
    const r=await fetch("/push/subscribe",{method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify(sub)});
    if(!r.ok) throw new Error("HTTP "+r.status);
    updateNotifyBtn();
    alert("Done — AX will notify this app when you’re away, and tapping it opens here.");
  }catch(e){ alert("Couldn’t enable notifications:\n"+e); }
}
function axShowList(){
  axCur=null;
  document.getElementById("ax-chatwrap").classList.remove("on");
  document.getElementById("ax-list").classList.add("on");
  const wrap=document.getElementById("ax-list-items");
  if(!axSessions.length){ wrap.innerHTML='<div class="empty">No chats yet.<br><small>Tap “New chat” to start.</small></div>'; return; }
  const sorted=[...axSessions].sort((a,b)=>(b.updatedAt||0)-(a.updatedAt||0));
  wrap.innerHTML="";
  for(const s of sorted){
    const d=document.createElement("div"); d.className="ax-item";
    const lastMsg=s.messages.length ? s.messages[s.messages.length-1] : null;
    let prev="";
    if(lastMsg){
      const who=lastMsg.role==="you" ? "You: " : "AX: ";
      const body=(lastMsg.pending && !lastMsg.text) ? "…" : (lastMsg.text||"");
      prev=(who+body).replace(/\s+/g," ").trim();
      if(prev.length>70) prev=prev.slice(0,69)+"…";
    }
    d.innerHTML=`<div style="flex:1;min-width:0">
        <div class="t">${s.unread?'<span class="unread"></span>':''}${esc(s.title||"New chat")}</div>
        ${prev?`<div class="prev">${esc(prev)}</div>`:""}
        <div class="s">${s.messages.length} msg · ${ago(s.updatedAt)} ago</div>
      </div>
      <button class="del" title="delete">✕</button>`;
    d.querySelector(".t").parentElement.onclick=()=>axOpen(s.id);
    d.querySelector(".del").onclick=(e)=>{ e.stopPropagation(); axDelete(s.id); };
    wrap.appendChild(d);
  }
}
function axNew(){
  const s={id:axId(), title:"New chat", createdAt:Date.now(), updatedAt:Date.now(), messages:[]};
  axSessions.push(s); axStore(); axOpen(s.id);
}
function axDelete(id){
  if(!confirm("Delete this chat?")) return;
  axSessions=axSessions.filter(s=>s.id!==id); axStore();
  if(localStorage.getItem(AX_LAST)===id) localStorage.removeItem(AX_LAST);
  axShowList();
}
function axOpen(id){
  const s=axFind(id); if(!s){ axShowList(); return; }
  axCur=id; localStorage.setItem(AX_LAST, id);
  if(s.unread){ s.unread=false; axStore(); }
  document.getElementById("ax-list").classList.remove("on");
  document.getElementById("ax-chatwrap").classList.add("on");
  document.getElementById("ax-title").textContent=s.title||"New chat";
  const m=document.getElementById("ax-msgs"); m.innerHTML="";
  if(!s.messages.length){ m.innerHTML='<div class="empty">Say something to AX.<br><small>This chat remembers itself.</small></div>'; }
  for(const msg of s.messages){
    if(msg.role==="ax" && msg.pending && !msg.text) axBubble("ax","…","think");
    else axBubble(msg.role, msg.text);
  }
}
function axBubble(who, text, cls){
  const m=document.getElementById("ax-msgs");
  const e=m.querySelector(".empty"); if(e) e.remove();
  const d=document.createElement("div"); d.className="msg "+who;
  d.innerHTML=`<div class="who">${who==="you"?"you":"AX"}</div>`+
              `<div class="b ${cls||""}">${esc(text)}</div>`;
  m.appendChild(d); m.scrollTop=1e9;
  return d.querySelector(".b");
}
// An AX reply slot = a live trace panel (steps appear as the engine works) + the answer bubble.
function axAssistantSlot(){
  const m=document.getElementById("ax-msgs");
  const e=m.querySelector(".empty"); if(e) e.remove();
  const d=document.createElement("div"); d.className="msg ax";
  d.innerHTML=`<div class="who">AX</div>`+
    `<div class="trace open"><div class="trace-head" onclick="this.parentNode.classList.toggle('open')">`+
      `<span class="caret">▾</span><span class="tstat"><span class="live-dot"></span>working…</span></div>`+
      `<div class="trace-steps"></div></div>`+
    `<div class="b think">…</div>`;
  m.appendChild(d); m.scrollTop=1e9;
  return { trace:d.querySelector(".trace"), steps:d.querySelector(".trace-steps"),
           stat:d.querySelector(".tstat"), answer:d.querySelector(".b") };
}
function axStep(stepsEl, icon, label, detail){
  const s=document.createElement("div"); s.className="tstep"+(detail?" has-detail":"");
  let html=`<div class="tstep-line"><span class="tk">${icon}</span><span>${esc(label)}</span></div>`;
  if(detail) html+=`<div class="tstep-detail">${esc(detail)}</div>`;
  s.innerHTML=html;
  if(detail) s.querySelector(".tstep-line").onclick=()=>s.classList.toggle("show");
  stepsEl.appendChild(s);
  document.getElementById("ax-msgs").scrollTop=1e9;
}
// Build the query the way AX Studio does: prepend recent turns so AX remembers.
function axCompose(sess, latest){
  const prior=sess.messages;  // does NOT yet include `latest`
  if(!prior.length) return latest;
  let lines=[];
  for(let i=prior.length-1; i>=0 && lines.length<AX_HIST_TURNS; i--){
    const m=prior[i];
    lines.unshift((m.role==="you"?"Ben":"You (AX)")+": "+m.text);
  }
  let transcript=lines.join("\n");
  if(transcript.length>AX_HIST_CHARS) transcript=transcript.slice(-AX_HIST_CHARS);
  return `Conversation so far (for context — do not answer these again):\n${transcript}\n\nBen's latest message:\n${latest}`;
}
async function axSend(){
  const ta=document.getElementById("ax-input");
  const text=ta.value.trim(); if(!text) return;
  if(!axCur) axNew();
  const sess=axFind(axCur); if(!sess) return;
  const btn=document.getElementById("ax-send");

  const query=axCompose(sess, text);          // compose BEFORE adding the new turn
  const turnId=(crypto.randomUUID?crypto.randomUUID():Date.now()+"-"+Math.random().toString(16).slice(2));
  axBubble("you", text);
  sess.messages.push({role:"you", text, turnId});   // turnId lets us recover the reply if the app closes
  const axMsg={role:"ax", text:"", turnId, pending:true};   // persistent slot; recovery fills it
  sess.messages.push(axMsg);
  if(sess.title==="New chat" || !sess.title){
    sess.title=text.slice(0,48); document.getElementById("ax-title").textContent=sess.title;
  }
  sess.updatedAt=Date.now(); axStore();
  ta.value=""; grow(ta);
  axPendingTurn=turnId;                              // so a background beacon can ask for a push
  const slot=axAssistantSlot(); const out=slot.answer;
  btn.disabled=true;
  let acc="", got=false, failed=false;
  let turns=0, lastModel="", totLat=0, stepsAdded=0;
  function finishTrace(){
    if(!stepsAdded){ slot.trace.remove(); return; }
    slot.trace.classList.remove("open");
    const n=turns, parts=[];
    parts.push(n? n+" step"+(n!=1?"s":"") : "trace");
    if(lastModel) parts.push(lastModel);
    if(totLat) parts.push(totLat.toFixed(1)+"s");
    slot.stat.textContent=parts.join(" · ");
  }
  try{
    const res=await fetch("/ax/dispatcher?stream=1&turnId="+encodeURIComponent(turnId),{method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({query})});
    if(!res.ok || !res.body){ throw new Error("HTTP "+res.status); }
    const reader=res.body.getReader(); const dec=new TextDecoder();
    let buf="";
    while(true){
      const {value,done}=await reader.read(); if(done) break;
      buf+=dec.decode(value,{stream:true});
      let i;
      while((i=buf.indexOf("\n\n"))>=0){
        const evt=buf.slice(0,i); buf=buf.slice(i+2);
        const line=evt.split("\n").find(l=>l.startsWith("data:"));
        if(!line) continue;
        const data=line.slice(5).trim();
        if(data==="[DONE]") continue;
        try{
          const o=JSON.parse(data);
          if(o.delta){
            if(!got){ out.textContent=""; out.classList.remove("think"); got=true; finishTrace(); }
            acc+=o.delta; out.textContent=acc;
          }
          else if(o.error){ out.classList.remove("think"); acc="[error] "+o.error; out.textContent=acc; failed=true; }
          else if(o.type==="status" && o.text){ axStep(slot.steps,"·",o.text); stepsAdded++; }
          else if(o.type==="route-decision"){
            axStep(slot.steps,"🧭","route: "+(o.route||"?"), o.rationale||""); stepsAdded++; }
          else if(o.type==="turn"){
            turns++; stepsAdded++; if(o.model) lastModel=o.model; if(o.latencySec) totLat+=o.latencySec;
            const lbl=(o.stage||"step")+(o.model?" · "+o.model:"")+(o.latencySec?" · "+o.latencySec.toFixed(1)+"s":"");
            axStep(slot.steps,"⚙️",lbl, o.code||o.modelOutput||""); }
        }catch(_){}
        document.getElementById("ax-msgs").scrollTop=1e9;
      }
    }
    if(!got && !failed){ out.classList.remove("think"); out.textContent="…"; }
  }catch(err){
    // Network interrupted (e.g. iOS suspended the app). Do NOT save a failure over the
    // turn — the answer is still being produced server-side and we'll recover it.
    out.classList.remove("think");
    if(!got) out.innerHTML='<span style="color:var(--dim)">…interrupted — your reply will appear when you reopen</span>';
  }finally{
    finishTrace();
    btn.disabled=false;
    if(got || failed){ axMsg.text=acc; axMsg.pending=false; }   // terminal: keep what we have
    else if(acc){ axMsg.text=acc; }                             // partial: keep, stay pending
    sess.updatedAt=Date.now(); axStore();
    if(axPendingTurn===turnId) axPendingTurn=null;
    if(axMsg.pending) axReconcile();                            // grab it if it already finished
  }
}

// ---- new session ----
let newLoaded=false;
async function loadNewForm(){
  newLoaded=true;
  try{
    const [ar,asr]=await Promise.all([
      fetch("/api/agents",{headers:{accept:"application/json"}}).then(r=>r.json()),
      fetch("/api/assignments",{headers:{accept:"application/json"}}).then(r=>r.json()),
    ]);
    const agents=(ar.agents?.entries||[]).map(e=>e.name).sort();
    const assigns=(asr.assignments?.entries||[]).map(e=>e.name).sort();
    const ag=document.getElementById("nw-agent");
    ag.innerHTML=agents.map(a=>`<option${a==="pi-pa"?" selected":""}>${esc(a)}</option>`).join("")
                 || '<option value="">(none found)</option>';
    const as=document.getElementById("nw-assign");
    as.innerHTML='<option value="">— none —</option>'+assigns.map(a=>`<option>${esc(a)}</option>`).join("");
  }catch(e){
    document.getElementById("nw-agent").innerHTML='<option value="">load failed</option>';
  }
}
async function createSession(){
  const agent=document.getElementById("nw-agent").value;
  const assignment=document.getElementById("nw-assign").value;
  const msg=document.getElementById("nw-msg").value.trim();
  if(!agent){ alert("Pick an agent."); return; }
  if(!msg){ alert("Type a first message."); return; }
  const ok=confirm(`Start a REAL run — real agent work and spend.\n\n`+
                   `Agent: ${agent}${assignment?"\nAssignment: "+assignment:""}\n\nProceed?`);
  if(!ok) return;
  const go=document.getElementById("nw-go");
  go.disabled=true; go.textContent="starting…";
  try{
    const body={agent, webVars:{}, overrides:{message:msg}};
    if(assignment) body.assignment=assignment;
    const res=await fetch("/api/runs",{method:"POST",
      headers:{"content-type":"application/json",accept:"application/json"},
      body:JSON.stringify(body)});
    const j=await res.json();
    if(!res.ok || !j.runId){ throw new Error(j.error?.message || ("HTTP "+res.status)); }
    document.getElementById("nw-msg").value="";
    // open the fresh run in the chat sheet (status will be running -> live SSE)
    showTab("board");
    load();
    openRun({runId:j.runId, name:msg.slice(0,60), agentName:agent,
             assignmentName:assignment||"", effectiveStatus:"running"});
  }catch(err){
    alert("Could not start run:\n"+err);
  }finally{
    go.disabled=false; go.textContent="Start run";
  }
}

// deep link: /runs/<id> (e.g. tapped from a phone notification) opens that run
async function openRunById(id){
  try{
    const runs=((await (await fetch("/api/runs",{headers:{accept:"application/json"}})).json()).runs)||[];
    const r=runs.find(x=>x.runId===id);
    openRun(r || {runId:id, name:id, effectiveStatus:"blocked"});
  }catch(_){ openRun({runId:id, name:id, effectiveStatus:"blocked"}); }
}

// ---- AX flows (read-only history of flow runs from the AX engine) ----
// Every flow run AX Studio (or CLI/n8n) finishes is persisted by the engine to
// runs.jsonl and served at /runs. We proxy /ax/runs -> :8810/runs, so this is a
// pure read of the SAME store Studio's Flows page shows. No new backend.
function flowInput(s){
  if(s==null) return "";
  if(typeof s!=="string") return JSON.stringify(s);
  try{ const o=JSON.parse(s); if(o && typeof o==="object"){
    const v=Object.values(o).find(x=>typeof x==="string"); if(v) return v; } }catch(_){}
  return s;
}
function flowCard(r){
  const d=document.createElement("div"); d.className="ax-item";
  const okc=r.ok?"#3fb950":"#f85149";
  const inp=flowInput(r.input);
  d.innerHTML=`<div style="flex:1;min-width:0">
      <div class="t"><span class="fdot" style="background:${okc};display:inline-block;margin-right:7px;vertical-align:middle"></span>${esc(r.flowId||"flow")}</div>
      ${inp?`<div class="prev">${esc(inp)}</div>`:""}
      <div class="s">${r.ok?"✓":"✗"}${r.latencySec?" · "+r.latencySec.toFixed(1)+"s":""} · ${ago(r.ts)} ago</div>
    </div>`;
  d.onclick=()=>openFlow(r.id);
  return d;
}
async function loadFlows(){
  const el=document.getElementById("flows");
  try{
    const res=await fetch("/ax/runs?limit=40",{headers:{accept:"application/json"}});
    const runs=((await res.json()).runs)||[];
    if(tab==="flows") document.getElementById("meta").textContent=runs.length+" flow runs";
    el.innerHTML="";
    if(!runs.length){ el.innerHTML='<div class="empty">No flow runs yet.<br><small>Run a flow in AX Studio and it appears here.</small></div>'; return; }
    for(const r of runs) el.appendChild(flowCard(r));
  }catch(e){
    el.innerHTML='<div class="empty">could not reach AX engine<br><small>'+esc(e)+'</small></div>';
  }
}
function nodeDetail(v){
  if(v==null) return "";
  return typeof v==="string" ? v : JSON.stringify(v, null, 2);
}
async function openFlow(id){
  document.getElementById("flowsheet").classList.add("open");
  history.pushState({flowsheet:1},"");
  const body=document.getElementById("fl-body");
  document.getElementById("fl-name").textContent="loading…";
  document.getElementById("fl-sub").innerHTML="";
  body.innerHTML='<div class="empty">loading flow…</div>';
  try{
    const d=await (await fetch("/ax/runs/"+encodeURIComponent(id),{headers:{accept:"application/json"}})).json();
    document.getElementById("fl-name").textContent=d.flowId||id;
    document.getElementById("fl-sub").innerHTML=
      `<span class="chip" style="color:${d.ok?'#3fb950':'#f85149'};border-color:${d.ok?'#2ea043':'#f85149'}">${d.ok?'✓ ok':'✗ failed'}</span>`+
      (d.latencySec?`<span class="chip">${d.latencySec.toFixed(1)}s</span>`:"")+
      `<span>${esc(new Date(d.ts).toLocaleString())}</span>`;
    let html="";
    const inp=flowInput(d.input);
    if(inp) html+=`<div class="att"><div class="att-role">input</div><div class="sent">${esc(inp)}</div></div>`;
    if(d.output) html+=`<div class="att"><div class="att-role">final output</div><div class="bubble">${esc(d.output)}</div></div>`;
    const nodes=d.nodes||[];
    if(nodes.length){
      html+=`<div class="att-role" style="margin-top:16px">${nodes.length} step${nodes.length!=1?'s':''} · tap to expand</div>`;
      nodes.forEach((n,i)=>{
        const meta=[n.nodeId||("step "+(i+1)), n.model, n.tokens?(n.tokens+" tok"):""].filter(Boolean).join(" · ");
        const ni=nodeDetail(n.input), no=nodeDetail(n.output);
        html+=`<div class="trace"><div class="trace-head" onclick="this.parentNode.classList.toggle('open')">`+
                `<span class="caret">▾</span><span>${esc(meta)}</span></div>`+
              `<div class="trace-steps">`+
                (ni?`<div class="att-role">in</div><div class="tstep-detail" style="display:block">${esc(ni)}</div>`:"")+
                (no?`<div class="att-role">out</div><div class="tstep-detail" style="display:block">${esc(no)}</div>`:"")+
              `</div></div>`;
      });
    }
    body.innerHTML=html||'<div class="empty">no detail saved for this run</div>';
    body.scrollTop=0;
  }catch(e){
    body.innerHTML='<div class="empty">could not load flow<br><small>'+esc(e)+'</small></div>';
  }
}
function closeFlow(){ document.getElementById("flowsheet").classList.remove("open"); }

load();
initPush();
(function(){
  const m=location.pathname.match(/^\/runs\/([^\/]+)/);
  if(m){ openRunById(decodeURIComponent(m[1])); return; }
  if(/[?&]tab=ax\b/.test(location.search)) showTab('ax');   // tapped from an "AX replied" push
})();
setInterval(()=>{
  if(tab==="board" && !document.getElementById("sheet").classList.contains("open")) load();
}, 10000);
</script>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        # "/" and deep links like /runs/<id> both serve the app (JS reads the path).
        path = self.path.split("?", 1)[0]
        if path == "/" or path.startswith("/index") or path.startswith("/runs/"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/sw.js":
            self._send_bytes(SW_JS.encode(), "application/javascript",
                             extra={"Service-Worker-Allowed": "/"})
            return
        if path == "/manifest.webmanifest":
            self._send_bytes(MANIFEST.encode(), "application/manifest+json")
            return
        if path == "/push/key":
            self._send_bytes(json.dumps({"key": VAPID_PUBLIC_B64}).encode(), "application/json")
            return
        # answer recovery: phone fetches an AX reply it missed while closed
        if path == "/ax/answer":
            tid = (parse_qs(urlparse(self.path).query).get("turnId") or [""])[0]
            rec = get_answer(tid)
            out = json.dumps({"answer": rec["answer"]} if rec else {}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(out)
            return
        if self._is_proxy():
            self._proxy("GET")
            return
        self.send_error(404)

    def _send_bytes(self, body, ctype, status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/push/broadcast":
            # local watchers only (not the phone) — send a web push to all subscriptions
            if self.client_address[0] not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                self._send_bytes(b'{"error":"forbidden"}', "application/json", status=403)
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                d = json.loads(raw.decode("utf-8")) if raw else {}
                sent = webpush_all(d.get("title", "pi"), d.get("body", ""), d.get("url", "/"))
                self._send_bytes(json.dumps({"sent": sent}).encode(), "application/json")
            except Exception as e:
                self._send_bytes(('{"error":"%s"}' % e).encode(), "application/json", status=400)
            return
        if path == "/ax/notify-on-done":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                d = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                d = {}
            tid = d.get("turnId")
            cancel_notify(tid) if d.get("cancel") else request_notify(tid)
            self._send_bytes(b'{"ok":true}', "application/json")
            return
        if path == "/push/subscribe":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                add_subscription(json.loads(raw.decode("utf-8")))
                self._send_bytes(b'{"ok":true}', "application/json")
            except Exception as e:
                self._send_bytes(('{"error":"%s"}' % e).encode(), "application/json", status=400)
            return
        if self._is_proxy():
            self._proxy("POST")
            return
        self.send_error(404)

    def do_DELETE(self):
        if self._is_proxy():
            self._proxy("DELETE")
            return
        self.send_error(404)

    def _stream_ax_with_notify(self, up):
        """Forward the AX SSE to the phone, accumulating the answer. If the phone
        disconnects (app closed/backgrounded) before the turn finishes, keep reading
        upstream to completion and push the answer via ntfy — so Ben gets the reply
        only when he is NOT looking at the app. If the phone stays connected, it sees
        the answer live and nothing is pushed. Either way we mirror the answer to the
        server store (keyed by turnId) so a reopened app can recover what it missed."""
        turn_id = (parse_qs(urlparse(self.path).query).get("turnId") or [""])[0]
        buf = ""
        parts = []
        client_alive = True
        while True:
            raw = up.read(1024)
            if not raw:
                break
            if client_alive:
                try:
                    self.wfile.write(raw)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    client_alive = False   # phone went away — keep reading, notify at the end
            buf += raw.decode("utf-8", "replace")
            while "\n\n" in buf:
                evt, buf = buf.split("\n\n", 1)
                for line in evt.split("\n"):
                    if not line.startswith("data:"):
                        continue
                    d = line[5:].strip()
                    if not d or d == "[DONE]":
                        continue
                    try:
                        o = json.loads(d)
                    except Exception:
                        continue
                    if isinstance(o, dict) and o.get("delta"):
                        parts.append(o["delta"])
        answer = "".join(parts)
        store_answer(turn_id, answer)
        with _notify_lock:
            wants = turn_id in WANT_NOTIFY
            cancelled = turn_id in CANCELLED
        # Notify if the user explicitly left (beacon), or — as a crash fallback — if the
        # socket died and they didn't explicitly come back.
        if answer and (wants or (not client_alive and not cancelled)):
            maybe_notify(turn_id, answer)

    def _is_proxy(self):
        return self.path.startswith("/api/") or self.path.startswith("/ax/")

    def _upstream(self):
        # /ax/dispatcher -> AX root (/dispatcher); /api/* stays on the pi daemon.
        if self.path.startswith("/ax/"):
            return AX + self.path[len("/ax"):]
        return DAEMON + self.path

    def _proxy(self, method):
        url = self._upstream()
        is_sse = "/events/" in self.path or "stream=1" in self.path
        body = None
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
        try:
            headers = {"Accept": "text/event-stream" if is_sse else "application/json"}
            ct = self.headers.get("Content-Type")
            if ct:
                headers["Content-Type"] = ct
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            up = urllib.request.urlopen(req, timeout=None if is_sse else 30)
            self.send_response(up.status)
            ct = up.headers.get("Content-Type", "application/json")
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            # stream the body in chunks (so SSE flows; also fine for JSON)
            if self.path.startswith("/ax/dispatcher") and is_sse:
                self._stream_ax_with_notify(up)
            else:
                while True:
                    chunk = up.read(2048)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.HTTPError as e:
            body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                msg = ('{"error":"%s"}' % str(e)).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
            except Exception:
                pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print("missing TLS cert:", CERT, file=sys.stderr)
        sys.exit(1)
    httpd = Server((HOST, PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"agent-mobile-pwa serving https://{HOST}:{PORT}  (proxy -> {DAEMON})")
    print(f"phone: {PHONE_URL}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
