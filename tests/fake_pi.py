#!/usr/bin/env python3
import json
import os
import sys
import time

for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("type") != "prompt":
        continue
    mode = os.environ.get("FAKE_PI_MODE", "success")
    if mode == "hang":
        time.sleep(60)
    elif mode == "fail":
        print(json.dumps({"type": "error", "message": "fake failure"}), flush=True)
        sys.exit(7)
    else:
        print(json.dumps({"type": "text_delta", "text": "hello "}), flush=True)
        print(json.dumps({"type": "text_delta", "text": "from pi"}), flush=True)
        print(json.dumps({"type": "agent_settled"}), flush=True)
        time.sleep(60)
