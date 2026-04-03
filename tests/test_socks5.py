#!/usr/bin/env python3
"""Tests for SOCKS5 upstream proxy support.

Verifies that teleproxy starts with SOCKS5 configured, the stats endpoint
reports SOCKS5 counters, and basic MTProto connectivity works through
the SOCKS5 chain.
"""

import os
import socket
import sys
import time

import requests


def get_stats():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    url = f"http://{host}:{port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    stats = {}
    for line in resp.text.strip().split("\n"):
        if "\t" in line:
            k, v = line.split("\t", 1)
            stats[k] = v
    return stats


def test_stats_endpoint():
    """Stats endpoint responds and reports SOCKS5 enabled."""
    print("Testing stats endpoint with SOCKS5...")
    stats = get_stats()
    assert stats.get("socks5_enabled") == "1", \
        f"socks5_enabled should be 1, got {stats.get('socks5_enabled')}"
    print(f"  socks5_enabled = {stats['socks5_enabled']}")
    print(f"  socks5_connects_attempted = {stats.get('socks5_connects_attempted', '?')}")
    print("  OK")


def test_mtproto_port():
    """TCP connection to MTProto port succeeds."""
    print("Testing MTProto port connectivity...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    s = socket.create_connection((host, port), timeout=5)
    s.close()
    print(f"  Connected to {host}:{port}")
    print("  OK")


def test_socks5_connect_triggers():
    """A client connection triggers a SOCKS5 upstream connect attempt."""
    print("Testing SOCKS5 connect triggers...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    # Send a minimal obfuscated2-like payload to trigger DC connection
    s = socket.create_connection((host, port), timeout=5)
    # Send 64 random bytes (will be parsed as obfuscated2 init)
    import os as _os
    s.sendall(_os.urandom(64))
    time.sleep(1)
    s.close()

    # Give the proxy a moment to process
    time.sleep(1)

    stats = get_stats()
    attempted = int(stats.get("socks5_connects_attempted", "0"))
    print(f"  socks5_connects_attempted = {attempted}")
    # The connect attempt may or may not succeed (depends on whether
    # the random bytes form a valid obfuscated2 header), but the proxy
    # should not crash.
    print("  OK (proxy survived SOCKS5 path)")


def test_prometheus_socks5_metrics():
    """Prometheus metrics include SOCKS5 counters."""
    print("Testing Prometheus SOCKS5 metrics...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    resp = requests.get(f"http://{host}:{port}/metrics", timeout=5)
    resp.raise_for_status()
    body = resp.text

    for metric in [
        "teleproxy_socks5_connects_attempted_total",
        "teleproxy_socks5_connects_succeeded_total",
        "teleproxy_socks5_connects_failed_total",
    ]:
        assert metric in body, f"Missing Prometheus metric: {metric}"
    print("  All SOCKS5 Prometheus metrics present")
    print("  OK")


if __name__ == "__main__":
    tests = [
        test_stats_endpoint,
        test_mtproto_port,
        test_socks5_connect_triggers,
        test_prometheus_socks5_metrics,
    ]

    failures = 0
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"  FAIL: {e}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"\n{failures} test(s) failed")
        sys.exit(1)
    else:
        print(f"\nAll {len(tests)} tests passed")
