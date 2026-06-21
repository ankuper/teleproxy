"""
_t3_httpstream_client.py — self-contained Type3 HTTP-stream + obfs2 SOCKS5-tunnel
CLIENT for the story 9.4 ATDD red-phase tests.

This is the **inverse** of libteleproto3's `lib/tests/_t3_http_stream_mock.py`
(the server-side mock authored for story 9.2): here we play the *client* (the
role the shim / t3_client_* plays) so we can drive teleproxy's tunnel dispatch
over the HTTP-stream path without pulling a prebuilt shim binary into the test
image (story 9.4 Step-02 decision A).

Wire it speaks (matches the 9.2 framing contract, lib-v0.8.0):
  client -> server:
    POST <path> HTTP/1.1 ... Transfer-Encoding: chunked          (request head)
    chunk #1            = 64-byte obfs2 init: cleartext [0:56], AES-CTR [56:64];
                          tag 0xdddddddd @ [56:60], SOCKS5 sentinel 0x5353 @ [60:62]
    chunk #2, #3, ...   = AES-CTR ciphertext of one t3 frame each:
                            [wire_length:4 LE][inner][padding]
                          inner = [inner_len:2 LE][socks5 bytes]   (length-delimited)
  server -> client: HTTP/1.1 200 ... chunked; same framing, reversed key direction.

Canonical KDF (identical to t3_client_crypto.c / the 9.2 mock):
  enc_key = SHA256(rh[8:40] || secret)        enc_iv = rh[40:56]   (client write)
  dec_key = SHA256(reversed(rh[24:56]) || secret) dec_iv = reversed(rh[8:24]) (client read)
The 64-byte init is encrypted first (advancing enc by 64), then each frame.

!! ACTIVATION CAVEATS (story 9.4 — server side not implemented yet) !!
  * Transport: this client defaults to PLAINTEXT to teleproxy's HTTP-stream port
    (in prod nginx terminates TLS in front of teleproxy). Set use_tls=True if the
    test stand exposes teleproxy's TLS port directly. Confirm host/port/TLS and
    the request path (`/api/v1/data` in prod) when activating against a real
    T3_SERVER_SOCKS5_CONNECT=1 build.
  * Exact obfs2 init wire offset inside the first chunk + whether the server wants
    a session-header prefix are defined by AC1/AC2; confirm at activation. The KDF
    + length-delimited recipe here is correct regardless of offset.

Requires: cryptography.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TUNNEL_SENTINEL = 0x5353            # SOCKS5-tunnel sentinel at obfs2 header[60:62]
PADDED_INTERMEDIATE_TAG = 0xDDDDDDDD  # canonical tag at header[56:60] (9.2)


def _aes_ctr(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend()).encryptor()


def build_obfs2_tunnel_init(secret_key: bytes):
    """Return (wire_init_64, enc_ctx, dec_ctx) for a SOCKS5-tunnel obfs2 init.

    enc_ctx is already advanced past the 64-byte init (matches the server, which
    advances its read keystream by the header). dec_ctx starts at offset 0.
    """
    while True:
        rh = bytearray(os.urandom(64))
        # Type3 session header (matches t3_client_crypto.c): cmd=1, ver=1,
        # flags=T3_FLAG_PADDING(0x01), reserved=0.
        rh[0:4] = bytes([0x01, 0x01, 0x01, 0x00])
        # obfs2 reserved-prefix guard: header[4:8] must be non-zero.
        if rh[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    rh[56:60] = struct.pack("<I", PADDED_INTERMEDIATE_TAG)
    rh[60:62] = struct.pack("<H", TUNNEL_SENTINEL)   # -> 0x53 0x53

    enc_key = hashlib.sha256(bytes(rh[8:40]) + secret_key).digest()
    enc_iv = bytes(rh[40:56])
    dec_key = hashlib.sha256(bytes(rh[24:56])[::-1] + secret_key).digest()
    dec_iv = bytes(rh[8:24])[::-1]

    enc = _aes_ctr(enc_key, enc_iv)
    encrypted = enc.update(bytes(rh))   # consumes 64 bytes of keystream (enc now at offset 64)
    # obfs2 wire header: [0:56] CLEARTEXT (random preamble + keys, so the server can
    # re-derive enc_key from cleartext [8:40]); only [56:64] (tag+sentinel) is the
    # AES-CTR ciphertext, replaced in place — matches t3_client_crypto.c.
    wire_init = bytes(rh[0:56]) + encrypted[56:64]
    dec = _aes_ctr(dec_key, dec_iv)
    return wire_init, enc, dec


def parse_secret_hex(secret_hex: str) -> bytes:
    """ff + 32 hex (16-byte key) + domain -> 16-byte key."""
    return bytes.fromhex(secret_hex[2:34])


class HttpStreamTunnelClient:
    """Drives teleproxy's SOCKS5 tunnel over the Type3 HTTP-stream path."""

    def __init__(self, host: str, port: int, secret_key: bytes,
                 path: str = "/api/v1/data", use_tls: bool = False,
                 timeout: float = 10.0):
        self.host, self.port = host, port
        self.secret_key = secret_key
        self.path, self.use_tls, self.timeout = path, use_tls, timeout
        self._sock = None
        self._enc = None
        self._dec = None
        self._rbuf = bytearray()   # raw bytes read from the socket
        self._pending = bytearray()  # decrypted [wire_length][inner] stream

    # -- connection + handshake -------------------------------------------------
    def open(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Type3 auth is obfs2+secret, not the TLS cert
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self._sock = raw
        head = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
        self._sock.sendall(head.encode("ascii"))
        wire_init, self._enc, self._dec = build_obfs2_tunnel_init(self.secret_key)
        self._send_chunk(wire_init)
        self._consume_response_head()

    def _send_chunk(self, data: bytes) -> None:
        self._sock.sendall(b"%x\r\n" % len(data) + data + b"\r\n")

    def _consume_response_head(self) -> None:
        # Server replies HTTP/1.1 200 ... \r\n\r\n before the chunked body.
        deadline = self._sock.gettimeout()
        while b"\r\n\r\n" not in self._rbuf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("server closed before HTTP response head")
            self._rbuf += chunk
        idx = self._rbuf.index(b"\r\n\r\n") + 4
        if not self._rbuf[:idx].startswith(b"HTTP/1.1 200"):
            raise ConnectionError(f"unexpected response head: {bytes(self._rbuf[:idx])!r}")
        del self._rbuf[:idx]
        _ = deadline

    # -- length-delimited tunnel framing ---------------------------------------
    def send_msg(self, data: bytes) -> None:
        inner = struct.pack("<H", len(data)) + data
        frame = struct.pack("<I", len(inner)) + inner  # no padding from the test client
        self._sock.sendall(self._chunk(self._enc.update(frame)))

    @staticmethod
    def _chunk(data: bytes) -> bytes:
        return b"%x\r\n" % len(data) + data + b"\r\n"

    def _read_one_chunk_data(self) -> bytes:
        while b"\r\n" not in self._rbuf:
            self._fill()
        nl = self._rbuf.index(b"\r\n")
        size = int(bytes(self._rbuf[:nl]), 16)
        need = nl + 2 + size + 2
        while len(self._rbuf) < need:
            self._fill()
        data = bytes(self._rbuf[nl + 2: nl + 2 + size])
        del self._rbuf[:need]
        return data

    def _fill(self) -> None:
        chunk = self._sock.recv(4096)
        if not chunk:
            raise ConnectionError("server closed the tunnel")
        self._rbuf += chunk

    def recv_msg(self) -> bytes:
        """Return one inner SOCKS5 message (strip wire_length + 2-byte inner len + pad)."""
        while True:
            while len(self._pending) < 4:
                self._pending.extend(self._dec.update(self._read_one_chunk_data()))
            wire_length = struct.unpack("<I", bytes(self._pending[:4]))[0] & 0x7FFFFFFF
            while len(self._pending) < 4 + wire_length:
                self._pending.extend(self._dec.update(self._read_one_chunk_data()))
            frame = bytes(self._pending[4:4 + wire_length])
            del self._pending[:4 + wire_length]
            if len(frame) < 2:
                continue
            inner_len = frame[0] | (frame[1] << 8)
            return frame[2:2 + inner_len]

    # -- inner SOCKS5 over the tunnel (server terminates + connects to target) --
    def socks5_connect(self, atyp: int, addr: bytes, port: int) -> bytes:
        """NO-AUTH greeting + CONNECT through the tunnel; return the 10-byte REP reply."""
        self.send_msg(bytes([0x05, 0x01, 0x00]))            # greet: NO-AUTH
        greet_reply = self.recv_msg()
        if greet_reply[:2] != bytes([0x05, 0x00]):
            raise ConnectionError(f"tunnel greet rejected: {greet_reply!r}")
        req = bytes([0x05, 0x01, 0x00, atyp])
        if atyp == 0x03:
            req += bytes([len(addr)]) + addr
        else:
            req += addr
        req += struct.pack(">H", port)
        self.send_msg(req)
        return self.recv_msg()

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
