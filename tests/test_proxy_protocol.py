#!/usr/bin/env python3
"""PROXY protocol v1/v2 integration tests.

Verifies that teleproxy correctly parses PROXY protocol headers,
extracts real client IPs, applies IP ACLs to the reported address,
and rejects connections without a valid PROXY header when the
feature is enabled.
"""

import os
import socket
import struct
import sys
import time

import requests

HOST = os.environ.get("TELEPROXY_HOST", "teleproxy")
PORT = int(os.environ.get("TELEPROXY_PORT", 8443))
STATS_PORT = os.environ.get("TELEPROXY_STATS_PORT", "8888")

# PROXY protocol v2 12-byte signature
PP2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"


def build_proxy_v2_header(src_ip, src_port, dst_ip, dst_port):
    """Build a PROXY protocol v2 header for IPv4 PROXY command."""
    ver_cmd = 0x21  # version=2, command=PROXY
    fam_proto = 0x11  # AF_INET(1), STREAM(1)
    addr_len = 12  # 4+4+2+2
    header = PP2_SIGNATURE + bytes([ver_cmd, fam_proto]) + struct.pack(">H", addr_len)
    addrs = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack(">HH", src_port, dst_port)
    )
    return header + addrs


def build_proxy_v2_local():
    """Build a PROXY protocol v2 LOCAL header (health check)."""
    ver_cmd = 0x20  # version=2, command=LOCAL
    fam_proto = 0x00  # AF_UNSPEC, UNSPEC
    addr_len = 0
    return PP2_SIGNATURE + bytes([ver_cmd, fam_proto]) + struct.pack(">H", addr_len)


def connect_with_proxy_header(header, expect_open=True):
    """Connect to proxy, send header, return whether connection stayed open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((HOST, PORT))
        s.sendall(header)
        time.sleep(0.5)

        # Try to detect if the connection is still alive
        s.settimeout(1)
        try:
            data = s.recv(1)
            if not data:
                return False  # server closed
            return True  # got data (unexpected but still open)
        except socket.timeout:
            return True  # no data, connection still open
        except (ConnectionResetError, BrokenPipeError, OSError):
            return False
    except (ConnectionResetError, ConnectionRefusedError):
        return False
    finally:
        s.close()


def get_stats():
    url = f"http://{HOST}:{STATS_PORT}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    stats = {}
    for line in resp.text.strip().split("\n"):
        if "\t" in line:
            k, v = line.split("\t", 1)
            stats[k] = v
    return stats


def test_proxy_v1_accepted():
    """PROXY v1 header with allowed IP keeps connection open."""
    print("Test: PROXY v1 accepted (allowed IP)...")
    header = b"PROXY TCP4 10.0.0.1 172.0.0.1 12345 8443\r\n"
    alive = connect_with_proxy_header(header, expect_open=True)
    assert alive, "Connection should stay open after valid PROXY v1 header"
    print("  PASS")


def test_proxy_v2_accepted():
    """PROXY v2 header with allowed IP keeps connection open."""
    print("Test: PROXY v2 accepted (allowed IP)...")
    header = build_proxy_v2_header("10.0.0.2", 54321, "172.0.0.1", 8443)
    alive = connect_with_proxy_header(header, expect_open=True)
    assert alive, "Connection should stay open after valid PROXY v2 header"
    print("  PASS")


def test_proxy_v2_local():
    """PROXY v2 LOCAL command (health check) keeps connection open."""
    print("Test: PROXY v2 LOCAL accepted...")
    header = build_proxy_v2_local()
    alive = connect_with_proxy_header(header, expect_open=True)
    assert alive, "Connection should stay open after PROXY v2 LOCAL header"
    print("  PASS")


def test_proxy_v1_acl_blocked():
    """PROXY v1 header with blocked IP (192.0.2.x) gets rejected."""
    print("Test: PROXY v1 ACL blocked...")
    header = b"PROXY TCP4 192.0.2.1 172.0.0.1 12345 8443\r\n"

    rejected = 0
    attempts = 3
    for i in range(attempts):
        alive = connect_with_proxy_header(header, expect_open=False)
        if not alive:
            rejected += 1
            print(f"  Attempt {i+1}: rejected (expected)")
        else:
            print(f"  Attempt {i+1}: still open (unexpected)")

    assert rejected >= attempts, (
        f"Expected all {attempts} connections rejected, got {rejected}"
    )
    print("  PASS")


def test_no_proxy_header_rejected():
    """Sending raw data without PROXY header gets rejected."""
    print("Test: no PROXY header rejected...")
    # Send bytes that don't match any PROXY protocol signature
    # 0xAA doesn't match "PROXY " (0x50) or v2 signature (0x0d)
    raw_data = b"\xaa" * 64

    rejected = 0
    attempts = 3
    for i in range(attempts):
        alive = connect_with_proxy_header(raw_data, expect_open=False)
        if not alive:
            rejected += 1
            print(f"  Attempt {i+1}: rejected (expected)")
        else:
            print(f"  Attempt {i+1}: still open (unexpected)")

    assert rejected >= attempts, (
        f"Expected all {attempts} connections rejected, got {rejected}"
    )
    print("  PASS")


def test_stats_proxy_protocol():
    """Stats and Prometheus endpoints report proxy_protocol metrics."""
    print("Test: stats proxy_protocol metrics...")

    # Trigger a connection to ensure counters are non-zero
    header = b"PROXY TCP4 10.0.0.3 172.0.0.1 11111 8443\r\n"
    connect_with_proxy_header(header, expect_open=True)
    time.sleep(0.5)

    stats = get_stats()
    val = stats.get("proxy_protocol_enabled", "?")
    assert val == "1", f"proxy_protocol_enabled should be 1, got {val}"
    print(f"  proxy_protocol_enabled = {val}")

    conns = stats.get("proxy_protocol_connections", "?")
    print(f"  proxy_protocol_connections = {conns}")
    assert conns != "?" and int(conns) > 0, (
        f"proxy_protocol_connections should be > 0, got {conns}"
    )

    # Check Prometheus endpoint
    resp = requests.get(f"http://{HOST}:{STATS_PORT}/metrics", timeout=5)
    resp.raise_for_status()
    body = resp.text

    for metric in [
        "teleproxy_proxy_protocol_enabled",
        "teleproxy_proxy_protocol_connections_total",
        "teleproxy_proxy_protocol_errors_total",
    ]:
        assert metric in body, f"Missing Prometheus metric: {metric}"

    print("  All proxy_protocol Prometheus metrics present")
    print("  PASS")


if __name__ == "__main__":
    tests = [
        test_proxy_v1_accepted,
        test_proxy_v2_accepted,
        test_proxy_v2_local,
        test_proxy_v1_acl_blocked,
        test_no_proxy_header_rejected,
        test_stats_proxy_protocol,
    ]

    print(f"Starting PROXY protocol tests against {HOST}:{PORT}...", flush=True)
    time.sleep(1)

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
