from __future__ import annotations

import json
import sys


for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    params = message.get("params", {})
    arguments = params.get("arguments", {})
    response = {
        "jsonrpc": "2.0",
        "id": message["id"],
        "result": {
            "status": "accepted",
            "tool": params.get("name"),
            "symbol": arguments.get("symbol"),
            "notional_usd": arguments.get("notional_usd"),
        },
    }
    print(json.dumps(response, sort_keys=True), flush=True)