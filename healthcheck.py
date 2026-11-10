#!/usr/bin/env python
"""Docker HEALTHCHECK probe.

Queries the in-container readiness endpoint and exits 0 only when Shield is
connected to Discord *and* PostgreSQL. Any other outcome exits 1, which Docker
reports as unhealthy.

It is a standalone script with no third-party imports on purpose: it runs inside
the container every 30 seconds, so it must start fast and must not fail because
an application dependency is mid-upgrade.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 4.0


def main() -> int:
    if os.environ.get("HEALTH_SERVER_ENABLED", "true").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
        "n",
        "f",
    }:
        # Nothing to probe; treat the container as healthy rather than flapping.
        return 0

    port = os.environ.get("HEALTH_PORT", "8080").strip() or "8080"
    url = f"http://127.0.0.1:{port}/ready"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            body = json.loads(response.read() or b"{}")
            if response.status == 200 and body.get("status") == "ready":
                return 0
            print(f"not ready: {body}", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as error:
        try:
            print(f"not ready ({error.code}): {error.read().decode()[:300]}", file=sys.stderr)
        except Exception:  # noqa: BLE001
            print(f"not ready ({error.code})", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001
        print(f"health probe failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
