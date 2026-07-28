#!/usr/bin/env python3
"""End-to-end smoke test for a running Honmoon sync server.

    python3 scripts/smoke_test.py [base_url]     # default http://localhost:8080

Checks the three things that make the server useful at all: it answers
/health, it issues a token, and it actually relays a message from one device
to another. CI runs this against the freshly built image; run it by hand
against a self-hosted box (including through a Tailscale Funnel URL) to see
whether the thing is really reachable.

Requires the `websockets` package: pip install websockets
"""

import asyncio
import json
import random
import sys
import urllib.request
import uuid

try:
    import websockets
except ImportError:
    sys.exit("missing dependency — pip install websockets")

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
WS_BASE = BASE.replace("https://", "wss://").replace("http://", "ws://")

# Invite-code alphabet: 0/O/1/I/L are left out so they can't be misread.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

TIMEOUT = 15


def get_token(household_id, invite_code, device_id, member_id):
    body = json.dumps(
        {
            "household_id": household_id,
            "invite_code": invite_code,
            "device_id": device_id,
            "member_id": member_id,
        }
    ).encode()
    request = urllib.request.Request(
        f"{BASE}/api/v1/auth/token",
        data=body,
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response)["token"]


async def main():
    with urllib.request.urlopen(f"{BASE}/health", timeout=TIMEOUT) as response:
        health = json.load(response)
    assert health.get("status") == "ok", f"unhealthy: {health}"
    print(f"health ok (build {health.get('build')})")

    household_id = str(uuid.uuid4())
    invite_code = "".join(random.choice(ALPHABET) for _ in range(6))
    sender_token = get_token(household_id, invite_code, "smoke-sender", str(uuid.uuid4()))
    receiver_token = get_token(household_id, invite_code, "smoke-receiver", str(uuid.uuid4()))
    print("tokens issued")

    payload = f"smoke-{uuid.uuid4()}"
    async with websockets.connect(f"{WS_BASE}/ws?token={receiver_token}") as receiver:
        async with websockets.connect(f"{WS_BASE}/ws?token={sender_token}") as sender:
            await sender.send(
                json.dumps(
                    {
                        "type": "sync",
                        "payload": payload,
                        "correlation_id": str(uuid.uuid4()),
                    }
                )
            )
            # Presence and queued frames arrive on the same socket, so read
            # until the relayed payload shows up or the deadline runs out.
            deadline = asyncio.get_event_loop().time() + TIMEOUT
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                assert remaining > 0, "message was never relayed"
                frame = json.loads(await asyncio.wait_for(receiver.recv(), remaining))
                if frame.get("type") == "sync" and frame.get("payload") == payload:
                    break
    print("message relayed — smoke test passed")


asyncio.run(main())
