# Agent Mobile PWA

> Source file: `pi-board-spike.py` (the project began as a "pi board" spike).

A **one-file mobile PWA** — a phone-friendly board + agent chat that runs on top of an
[agent-runner](https://github.com/) daemon's existing HTTP API. No app store, no build
step: a single Python file serves an HTTPS web app you add to your iPhone/Android home
screen, with live streaming and push notifications.

> **Heads up — this is a "spike" (a working prototype).** It was built to prove one idea:
> *you can put a good mobile front-end on a local agent daemon's existing `/api` with
> nothing but the standard library + a push-crypto dependency.* It's hardcoded to that
> daemon's API shape and shared here as a reference/recipe, not a turnkey product. Expect
> to adapt the API calls to your own backend.

## What it does

- **Board** — your agent runs grouped into status columns, with filters (status / type /
  time window) and sort, all remembered in `localStorage`.
- **Run chat** — tap a run to see its attempts as a conversation, live-streamed over SSE
  while the run is active. Reply to **resume** an idle run or **queue** a follow-up on a
  running one — real governed work, behind a confirm dialog.
- **Agent chat tab** — a separate chat with rejoinable sessions and a live per-turn trace.
- **iPhone push** — Web Push notifications (run finished, gate awaiting approval, reply
  landed) that open the app, implemented with the standard-library crypto only (VAPID +
  AES-GCM), plus a companion `gate-notifier.py` for one-tap Approve/Abort via
  [ntfy](https://ntfy.sh).

## Why it's interesting

- **Single file, ~1.5k lines, near-zero deps** — only `cryptography` (for Web Push).
- **Proxies, doesn't reimplement** — it forwards `/api/*` to the daemon (streaming intact),
  so the phone uses the exact same governed API as everything else.
- **Real Web Push from scratch** — VAPID signing and payload encryption with no push SDK.

## Configuration

Everything is environment variables with localhost defaults — nothing required to start:

| Variable | Default | Purpose |
|---|---|---|
| `PI_DAEMON` | `http://127.0.0.1:4773` | the agent-runner daemon it proxies to |
| `AX_SERVER` | `http://127.0.0.1:8810` | optional agent-chat engine |
| `PI_BOARD_PORT` | `4775` | port to serve on |
| `PI_BOARD_HOST` | `0.0.0.0` | bind address |
| `PI_BOARD_PUBLIC_HOST` | `localhost` | hostname shown in the phone URL |
| `PI_BOARD_TLS` | `./tls/cert` | path prefix to your `*.crt` / `*.key` |
| `VAPID_SUB` | `mailto:you@example.com` | contact for Web Push |

### HTTPS for the phone
Phones require a trusted cert for service workers + push. Easiest path is a
[Tailscale](https://tailscale.com) cert:

```bash
tailscale cert your-host.your-tailnet.ts.net
PI_BOARD_TLS=/path/to/your-host.your-tailnet.ts.net \
PI_BOARD_PUBLIC_HOST=your-host.your-tailnet.ts.net \
python3 pi-board-spike.py
```

Then open `https://your-host…:4775` on the phone and "Add to Home Screen."

## Run

```bash
pip install cryptography
python3 pi-board-spike.py
```

> ⚠️ Sending a reply triggers **real agent work and spend** on your backend.

## License

MIT — see [LICENSE](./LICENSE).
