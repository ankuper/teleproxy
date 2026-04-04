#!/usr/bin/env python3
"""E2E tests for per-IP rate limiting configuration and metrics.

Verifies that:
- Stats and Prometheus metrics expose rate_limit config and rate_limited counter
- An unlimited secret still works normally at the handshake level
"""
import os
import sys
import time

import requests

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def _get_stats(host, stats_port):
    """Fetch plain-text stats from the proxy."""
    url = f"http://{host}:{stats_port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def _get_metrics(host, stats_port):
    """Fetch Prometheus metrics from the proxy."""
    url = f"http://{host}:{stats_port}/metrics"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_rate_limit_in_plain_stats():
    """Verify per-secret rate_limit and rate_limited counter in /stats."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    stats = _get_stats(host, stats_port)

    assert "secret_limited_rate_limit\t1048576" in stats, (
        f"Expected 'secret_limited_rate_limit\\t1048576' in stats:\n{stats}"
    )
    assert "secret_limited_rate_limited\t" in stats, (
        f"Expected 'secret_limited_rate_limited' in stats:\n{stats}"
    )
    # Unlimited secret should NOT have a rate_limit line
    assert "secret_unlimited_rate_limit" not in stats, (
        f"Unlimited secret should not have a rate_limit line:\n{stats}"
    )
    # But should still have a rate_limited counter
    assert "secret_unlimited_rate_limited\t" in stats, (
        f"Expected 'secret_unlimited_rate_limited' in stats:\n{stats}"
    )
    print("  Plain stats: rate_limit and rate_limited fields present")


def test_rate_limit_in_prometheus_metrics():
    """Verify per-secret rate_limit metrics in /metrics."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)

    assert 'teleproxy_secret_rate_limit_bytes{secret="limited"} 1048576' in metrics, (
        f"Expected rate_limit_bytes=1048576 for 'limited' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rate_limit_bytes{secret="unlimited"} 0' in metrics, (
        f"Expected rate_limit_bytes=0 for 'unlimited' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rate_limited_total{secret="limited"}' in metrics, (
        f"Expected rate_limited_total for 'limited' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rate_limited_total{secret="unlimited"}' in metrics, (
        f"Expected rate_limited_total for 'unlimited' in metrics:\n{metrics}"
    )
    print("  Prometheus metrics: rate_limit and rate_limited fields present")


def test_unlimited_secret_still_works():
    """Verify unlimited secret still accepts connections normally."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_2", "")
    assert secret_hex, "TELEPROXY_SECRET_2 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Unlimited secret: handshake OK")


def test_rate_limited_secret_still_works():
    """Verify rate-limited secret still accepts connections normally."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_1", "")
    assert secret_hex, "TELEPROXY_SECRET_1 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Rate-limited secret: handshake OK")


def main():
    tests = [
        ("test_rate_limit_in_plain_stats", test_rate_limit_in_plain_stats),
        ("test_rate_limit_in_prometheus_metrics", test_rate_limit_in_prometheus_metrics),
        ("test_unlimited_secret_still_works", test_unlimited_secret_still_works),
        ("test_rate_limited_secret_still_works", test_rate_limited_secret_still_works),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting rate limit tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    # Brief delay for stats endpoint to be ready
    time.sleep(2)

    passed = 0
    failed = 0
    errors = []

    for name, fn in tests:
        try:
            print(f"[RUN]  {name}")
            fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
