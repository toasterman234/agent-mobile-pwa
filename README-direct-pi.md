# Central Ops PWA — direct Pi RPC

This is the replacement path for the bb/ACP experiment. It talks directly to `pi --mode rpc` and deliberately avoids ACP.

## Why

The bb custom ACP path can run Command Code, but thread settlement and provider-session recovery are currently unreliable in this setup. This app uses a simpler contract:

- SQLite owns threads, messages, and status.
- Every user turn starts one isolated Pi RPC process.
- Output streams to the PWA through SSE.
- `agent_settled` is the success boundary.
- The entire Pi process group is terminated and reaped after each turn.
- Any timeout or provider exit moves the thread to `error`; it cannot remain permanently `working`.

The tradeoff is that recent conversation history is included in each new turn instead of depending on a long-lived ACP session.

## Run

```bash
cd ~/.buzz/REPOS/agent-mobile-pwa
python3 central_ops.py \
  --host 127.0.0.1 \
  --port 4785 \
  --data-dir ~/.central-ops-pwa
```

Defaults:

- provider: `commandcode`
- model: `deepseek/deepseek-v4-pro`
- project: `~/.buzz/REPOS/central-ops`

Override with `PI_PROVIDER`, `PI_MODEL`, `PI_COMMAND`, or a projects JSON file:

```json
{
  "projects": [
    {"id": "central-ops", "name": "Central Ops", "path": "/Users/bencharney/.buzz/REPOS/central-ops"},
    {"id": "eval-tracking", "name": "Eval Tracking", "path": "/Users/bencharney/.buzz/REPOS/eval-tracking"}
  ]
}
```

```bash
python3 central_ops.py --projects ~/.central-ops-pwa/projects.json
```

## Private iPhone access

Keep the app bound to loopback and expose it privately with Tailscale Serve:

```bash
tailscale serve --bg --https=4785 http://127.0.0.1:4785
```

Open the resulting HTTPS URL in Safari and choose **Add to Home Screen**.

Set a token before exposing it:

```bash
export CENTRAL_OPS_TOKEN="$(openssl rand -hex 24)"
python3 central_ops.py
```

The PWA asks for the token once and stores it in local storage.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test harness uses a fake Pi RPC executable and verifies both success and provider-exit settlement.

## MVP limitations

- No file browser or diff viewer yet.
- No Dagu panel yet.
- No push notifications yet.
- Conversation context is replayed into each turn and currently capped to the latest 20 messages.
- The event parser supports common Pi RPC text-delta shapes but should be verified against the exact Pi 0.83.0 event stream on Ben's Mac.
