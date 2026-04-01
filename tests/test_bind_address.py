#!/usr/bin/env python3
"""E2E test: --address binds the proxy to the specified address.

When BIND_ADDRESS=127.0.0.1, the proxy should NOT be reachable from
other containers via the Docker network.  The proxy's internal
healthcheck (running inside its container) confirms it's alive.

This test verifies issue #19: IPv6 auto-detection was overriding
the --address option, causing the listener to bind to [::] instead
of the specified IPv4 address.

Environment variables:
    TELEPROXY_HOST       Proxy hostname (default: teleproxy)
    TELEPROXY_PORT       Proxy port (default: 8443)
    TELEPROXY_STATS_PORT Stats port (default: 8888)
"""

import os
import socket
import sys


def test_port_not_reachable(host, port, label):
    """Verify that a TCP port on host is NOT reachable from this container."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, port))
        s.close()
        print(f"  FAIL: connected to {host}:{port} ({label}) "
              "-- proxy is NOT bound to 127.0.0.1")
        return False
    except (ConnectionRefusedError, OSError) as e:
        print(f"  OK: {host}:{port} ({label}) correctly refused ({e})")
        return True
    finally:
        s.close()


def main():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    stats_port = int(os.environ.get("TELEPROXY_STATS_PORT", "8888"))

    print("=== Bind Address Tests ===\n")
    print("Proxy is healthy (Docker healthcheck passed inside container)")
    print(f"Verifying {host} ports are NOT reachable from this container...\n")

    ok = True
    ok &= test_port_not_reachable(host, port, "MTProto")
    ok &= test_port_not_reachable(host, stats_port, "stats")

    print(f"\n=== Result: {'PASS' if ok else 'FAIL'} ===")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
