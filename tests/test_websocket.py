#!/usr/bin/env python3
"""E2E tests for the Type3 WebSocket transport (RFC 6455) behind nginx/CF.

This transport lets Teleproxy live *behind* a TLS terminator (nginx, Cloudflare
Worker, Caddy, traefik...) rather than owning port 443 itself. The TLS frontend
does `proxy_pass http://teleproxy:PLAINTEXT_PORT/` on a WebSocket Upgrade
request; Teleproxy detects the HTTP GET + Upgrade headers, replies 101
Switching Protocols, and the rest of the session is obfuscated2 MTProto inside
RFC 6455 binary frames.

Tests in this file cover the handshake layer only (no full MTProto roundtrip
yet — that needs a client-side WS port to complete). We assert:

  1. Canonical RFC 6455 §1.3 example: the key "dGhlIHNhbXBsZSBub25jZQ==" MUST
     produce accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" — this proves our
     Sec-WebSocket-Accept computation is bit-exact with the spec.
  2. Random-key handshakes compute accept correctly against the Python
     reference implementation.
  3. Response headers match RFC 6455 §4.2.2 (101 status, Upgrade + Connection
     present, correctly spelled, Sec-WebSocket-Accept present).
  4. Non-WebSocket HTTP requests do NOT receive a 101 (so plain `GET /` on
     the same port does not accidentally upgrade).

End-to-end fake-TLS regression coverage lives in test_tls_e2e.py — we do
not duplicate it here to keep this suite focused on the WS layer.

Environment variables:
    TELEPROXY_HOST           default "teleproxy"
    TELEPROXY_WS_PORT        plaintext HTTP port listening for WS (e.g. 3129)
    TELEPROXY_SECRET         32-char hex secret
"""

import base64
import hashlib
import os
import re
import socket
import sys


# RFC 6455 §1.3 — "globally unique identifier" concatenated with the key
# before SHA-1 and base64 encoding.
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# RFC 6455 §1.3 canonical example — if our server's accept does not match
# this exact string for this exact input, the hash is broken.
RFC_EXAMPLE_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC_EXAMPLE_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f"\n        {detail}"
        print(msg)


def expected_accept(key):
    """Reference implementation of Sec-WebSocket-Accept (RFC 6455 §1.3)."""
    digest = hashlib.sha1(key.encode("ascii") + WS_GUID).digest()
    return base64.b64encode(digest).decode("ascii")


def send_ws_upgrade(host, port, key, path="/ws/test", timeout=5):
    """Open a TCP connection, send an HTTP Upgrade request, return raw response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    s.sendall(req.encode("ascii"))
    buf = bytearray()
    try:
        while b"\r\n\r\n" not in bytes(buf):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 8192:
                break
    except socket.timeout:
        pass
    finally:
        s.close()
    return bytes(buf)


def parse_http_response(raw):
    """Split raw HTTP response bytes into (status_code, headers_dict)."""
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        return None, {}
    m = re.match(rb"HTTP/\d\.\d\s+(\d+)", lines[0])
    if not m:
        return None, {}
    status = int(m.group(1))
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        if k:
            headers[k.strip().lower().decode("ascii", "replace")] = (
                v.strip().decode("ascii", "replace")
            )
    return status, headers


# ============================================================
# Test 1: RFC 6455 §1.3 canonical example — bit-exact correctness
# ============================================================

def test_rfc_canonical_example(host, port):
    print("\n[test_rfc_canonical_example]")
    raw = send_ws_upgrade(host, port, RFC_EXAMPLE_KEY)
    status, headers = parse_http_response(raw)

    check("status is 101", status == 101,
          f"got status={status}, raw[:120]={raw[:120]!r}")
    check("Sec-WebSocket-Accept matches canonical RFC value",
          headers.get("sec-websocket-accept") == RFC_EXAMPLE_ACCEPT,
          f"expected {RFC_EXAMPLE_ACCEPT!r}, got {headers.get('sec-websocket-accept')!r}")


# ============================================================
# Test 2: Random keys — accept key matches Python reference
# ============================================================

def test_random_keys(host, port):
    print("\n[test_random_keys]")
    for i in range(5):
        raw_key = os.urandom(16)
        key = base64.b64encode(raw_key).decode("ascii")
        raw = send_ws_upgrade(host, port, key, path=f"/ws/random-{i}")
        status, headers = parse_http_response(raw)
        want = expected_accept(key)
        got = headers.get("sec-websocket-accept")
        check(f"random key #{i} -> correct accept",
              status == 101 and got == want,
              f"key={key} want={want!r} got={got!r} status={status}")


# ============================================================
# Test 3: Response header shape (RFC 6455 §4.2.2)
# ============================================================

def test_response_headers(host, port):
    print("\n[test_response_headers]")
    raw = send_ws_upgrade(host, port, RFC_EXAMPLE_KEY)
    status, headers = parse_http_response(raw)

    check("upgrade header == 'websocket'",
          headers.get("upgrade", "").lower() == "websocket",
          f"got {headers.get('upgrade')!r}")
    check("connection header contains 'Upgrade'",
          "upgrade" in headers.get("connection", "").lower(),
          f"got {headers.get('connection')!r}")
    check("sec-websocket-accept header present",
          "sec-websocket-accept" in headers,
          f"headers={list(headers)}")


# ============================================================
# Test 4: Non-WebSocket HTTP request does NOT get 101
# ============================================================

def test_no_upgrade_on_plain_get(host, port):
    """Send a plain HTTP GET without Upgrade headers; we must not see 101.

    The current implementation either falls through to the non-WS path (so
    the response is non-101 or the connection closes). The important
    negative assertion is: status != 101.
    """
    print("\n[test_no_upgrade_on_plain_get]")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        buf = bytearray()
        try:
            for _ in range(4):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\r\n\r\n" in bytes(buf):
                    break
        except socket.timeout:
            pass
    finally:
        s.close()
    status, _ = parse_http_response(bytes(buf))
    check("plain GET did not receive 101 Switching Protocols",
          status != 101,
          f"got status={status}, raw[:120]={bytes(buf)[:120]!r}")


# ============================================================

def main():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    ws_port = int(os.environ.get("TELEPROXY_WS_PORT", "3129"))

    print(f"=== WebSocket (Type3) transport tests ===")
    print(f"host={host} ws_port={ws_port}\n")

    test_rfc_canonical_example(host, ws_port)
    test_random_keys(host, ws_port)
    test_response_headers(host, ws_port)
    test_no_upgrade_on_plain_get(host, ws_port)

    print(f"\n=== Result: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
