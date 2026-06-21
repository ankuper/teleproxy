#!/usr/bin/env python3
"""
test_socks5_tunnel_httpstream.py — ATDD RED-phase scaffold for story 9.4.

teleproxy — SOCKS5 tunnel dispatch on the HTTP-stream path (server side).

Drives teleproxy's calls SOCKS5 tunnel over the **Type3 HTTP-stream** transport
using a self-contained Python client (`_t3_httpstream_client.py`, the inverse of
libteleproto3's 9.2 server mock) — no prebuilt shim binary needed (Step-02 dec. A).

RED PHASE (teleproxy harness has no pytest — red marker is an env gate):
  the suite SKIPS (exit 0) unless ATDD_9_4_ACTIVATE=1. It asserts the EXPECTED
  post-9.4 behaviour and FAILS once activated, until the server is implemented:
    AC1 — 0x5353 dispatched to the tunnel on the HTTP-stream decode path
          (mtproto-proxy-http.c / forward_mtproto_packet), tag-agnostic. Today
          the handoff is WS-path-only (net-tcp-rpc-ext-server.c:2114).
    AC2 — tunnel speaks length-delimited padded-intermediate, not WS frames
          (net-socks5-tunnel.c ws_read_decrypt/ws_write_encrypt swapped).
    AC3 — image built T3_SERVER_SOCKS5_CONNECT=1; socks5_connect_tunnels_*
          counters increment (/stats). Prod default 0 (Dockerfile:38).
    AC4 — SSRF block-list, concurrent cap, WS-path regression.

ACTIVATION (green-phase, per task — see atdd-checklist-9-4-*):
  1. Implement AC1 dispatch + AC2 codec; bring up tests/docker-compose.socks5-tunnel-test.yml
     (teleproxy built T3_SERVER_SOCKS5_CONNECT=1) and set ATDD_9_4_ACTIVATE=1.
  2. Confirm transport (TLS vs plaintext / port / request path) in _t3_httpstream_client.py.
  3. Wire `socks5-tunnel-test` into .github/workflows/test.yml.

Plain-python harness style (mirrors tests/test_socks5.py): assertions raise; the
__main__ runner counts failures and exits non-zero. Requires: requests,
cryptography (added to requirements.txt).
"""

import os
import socket
import sys

try:
    import requests
    from _t3_httpstream_client import HttpStreamTunnelClient, parse_secret_hex
    HAVE_DEPS = True
except ImportError as _e:
    HAVE_DEPS = False
    _IMPORT_ERR = _e

# --- environment (provided by docker-compose.socks5-tunnel-test.yml) ----------
HOST = os.environ.get("TELEPROXY_HOST", "teleproxy")
HTTP_PORT = int(os.environ.get("TELEPROXY_HTTP_PORT", "8443"))   # HTTP-stream port
STATS_PORT = os.environ.get("TELEPROXY_STATS_PORT", "8888")
SECRET_HEX = os.environ.get("TELEPROXY_SECRET_HEX", "ff" + bytes(range(16)).hex() + "127.0.0.1")
USE_TLS = os.environ.get("TELEPROXY_HTTP_TLS", "0") == "1"
TARGET_HOST = os.environ.get("TARGET_HOST", "echo")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "9000"))
TUNNEL_CAP = int(os.environ.get("SOCKS5_TUNNEL_CAP", "32"))   # confirm at activation


def _stats():
    resp = requests.get(f"http://{HOST}:{STATS_PORT}/stats", timeout=5)
    resp.raise_for_status()
    out = {}
    for line in resp.text.strip().split("\n"):
        if "\t" in line:
            k, v = line.split("\t", 1)
            out[k] = v
    return out


def _client():
    return HttpStreamTunnelClient(HOST, HTTP_PORT, parse_secret_hex(SECRET_HEX), use_tls=USE_TLS)


def _target_v4():
    return socket.inet_aton(socket.gethostbyname(TARGET_HOST))


# AC1 ----------------------------------------------------------------------
def test_dispatch_connect_over_http_stream():
    """[P0][AT-9.4-I1] obfs2 init with 0x5353 over HTTP-stream -> tunnel -> CONNECT
    to the echo target succeeds (REP=0x00) and bytes round-trip."""
    c = _client()
    try:
        c.open()
        rep = c.socks5_connect(0x01, _target_v4(), TARGET_PORT)
        assert rep[0] == 0x05 and rep[1] == 0x00, f"CONNECT rejected: {rep!r}"
        probe = b"TYPE3-9.4-" + bytes(range(16))
        c.send_msg(probe)
        assert probe in c.recv_msg(), "echo payload did not round-trip through the tunnel"
    finally:
        c.close()
    print("  OK AT-9.4-I1 dispatch+CONNECT over HTTP-stream")


def test_dispatch_is_tag_agnostic():
    """[P1][AT-9.4-I2] dispatch triggers on the 0x5353 sentinel alone, with 9.2's
    canonical tag 0xdddddddd at [56] (the client always stamps that tag)."""
    c = _client()
    try:
        c.open()
        rep = c.socks5_connect(0x01, _target_v4(), TARGET_PORT)
        assert rep[1] == 0x00, "canonical-tag tunnel must dispatch (tag-agnostic)"
    finally:
        c.close()
    print("  OK AT-9.4-I2 tag-agnostic dispatch")


# AC2 ----------------------------------------------------------------------
def test_length_delimited_roundtrip():
    """[P0][AT-9.4-I3] multi-message SOCKS5 byte stream survives intact as
    length-delimited padded-intermediate frames (not WS frames)."""
    c = _client()
    try:
        c.open()
        assert c.socks5_connect(0x01, _target_v4(), TARGET_PORT)[1] == 0x00
        for n in (1, 200, 1500):
            payload = bytes((i * 7) & 0xFF for i in range(n))
            c.send_msg(payload)
            assert payload in c.recv_msg(), f"{n}-byte frame corrupted in round-trip"
    finally:
        c.close()
    print("  OK AT-9.4-I3 length-delimited round-trip")


def test_server_speaks_http_stream_not_ws():
    """[P1][AT-9.4-I4] server accepts the HTTP-stream POST (HTTP 200, NOT a 101
    WS upgrade) -> tunnel codec is length-delimited, not RFC 6455. The client
    never sends an Upgrade header; .open() raises if the server demanded WS."""
    c = _client()
    try:
        c.open()
        assert c.socks5_connect(0x01, _target_v4(), TARGET_PORT)[1] == 0x00
    finally:
        c.close()
    print("  OK AT-9.4-I4 server speaks HTTP-stream (no WS)")


# AC4 — SSRF ---------------------------------------------------------------
def test_ssrf_blocklist_rejects():
    """[P0][AT-9.4-I5] CONNECT through the tunnel to loopback / RFC1918 /
    link-local is rejected (REP != 0x00) and bumps socks5_connect_tunnels_rejected
    — the v4_blocked/sockaddr_blocked guard holds on the new HTTP-stream path."""
    targets = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1"]
    before = int(_stats().get("socks5_connect_tunnels_rejected", "0"))
    for addr in targets:
        c = _client()
        try:
            c.open()
            rep = c.socks5_connect(0x01, socket.inet_aton(addr), 80)
            assert rep[1] != 0x00, f"SSRF target {addr} must be rejected, got REP={rep[1]:#x}"
        finally:
            c.close()
    assert int(_stats().get("socks5_connect_tunnels_rejected", "0")) > before, \
        "rejected counter must increment on SSRF blocks"
    print("  OK AT-9.4-I5 SSRF block-list rejects loopback/RFC1918/link-local")


# AC4 — cap ----------------------------------------------------------------
def test_concurrent_tunnel_cap():
    """[P1][AT-9.4-I6] the (cap+1)-th concurrent tunnel is refused; the rejected
    counter increments."""
    clients = []
    try:
        for _ in range(TUNNEL_CAP):
            c = _client(); c.open()
            assert c.socks5_connect(0x01, _target_v4(), TARGET_PORT)[1] == 0x00
            clients.append(c)
        before = int(_stats().get("socks5_connect_tunnels_rejected", "0"))
        over = _client(); over.open()
        rep = over.socks5_connect(0x01, _target_v4(), TARGET_PORT)
        over.close()
        assert rep[1] != 0x00, "over-cap tunnel must be refused"
        assert int(_stats().get("socks5_connect_tunnels_rejected", "0")) > before
    finally:
        for c in clients:
            c.close()
    print("  OK AT-9.4-I6 concurrent-tunnel cap")


# AC4 — WS regression (green anchor; reuse, do not re-author) ---------------
def test_ws_path_unaffected():
    """[P1][AT-9.4-I7] WS tunnel path unaffected. Regression is OWNED by
    tests/test_websocket.py + the WS dispatch (net-tcp-rpc-ext-server.c:2114);
    this is a documentation anchor — the WS suite is the green gate."""
    print("  SKIP AT-9.4-I7 WS-path regression -> see tests/test_websocket.py (green anchor)")


# AC3 — counters -----------------------------------------------------------
def test_stats_counters_increment():
    """[P1][AT-9.4-S1] image built T3_SERVER_SOCKS5_CONNECT=1: /stats exposes
    socks5_connect_tunnels_total and it increments after a tunneled CONNECT."""
    stats = _stats()
    assert "socks5_connect_tunnels_total" in stats, \
        "T3_SERVER_SOCKS5_CONNECT=1 must expose the tunnel counters"
    before = int(stats["socks5_connect_tunnels_total"])
    c = _client()
    try:
        c.open()
        assert c.socks5_connect(0x01, _target_v4(), TARGET_PORT)[1] == 0x00
    finally:
        c.close()
    assert int(_stats()["socks5_connect_tunnels_total"]) > before
    print("  OK AT-9.4-S1 tunnel counters increment")


if __name__ == "__main__":
    # RED-phase gate (teleproxy harness has no pytest; this env gate IS the skip).
    if os.environ.get("ATDD_9_4_ACTIVATE") != "1":
        print("SKIP: story 9.4 ATDD red-phase scaffold "
              "(set ATDD_9_4_ACTIVATE=1 after the server implements HTTP-stream "
              "0x5353 dispatch + length-delimited tunnel codec).")
        sys.exit(0)
    if not HAVE_DEPS:
        print(f"SKIP: deps unavailable ({_IMPORT_ERR}); add cryptography to requirements.txt.")
        sys.exit(0)

    tests = [
        test_dispatch_connect_over_http_stream,   # AC1
        test_dispatch_is_tag_agnostic,            # AC1
        test_length_delimited_roundtrip,          # AC2
        test_server_speaks_http_stream_not_ws,    # AC2
        test_ssrf_blocklist_rejects,              # AC4
        test_concurrent_tunnel_cap,               # AC4
        test_ws_path_unaffected,                  # AC4 (anchor)
        test_stats_counters_increment,            # AC3
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except Exception as e:  # noqa: BLE001 — harness mirrors tests/test_socks5.py
            print(f"  FAIL: {t.__name__}: {e}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"\n{failures} test(s) failed")
        sys.exit(1)
    print(f"\nAll {len(tests)} tests passed")
