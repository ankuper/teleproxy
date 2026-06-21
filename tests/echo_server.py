#!/usr/bin/env python3
"""Trivial TCP echo target for the story 9.4 SOCKS5-tunnel test.

The tunnel's inner SOCKS5 CONNECT terminates at teleproxy, which then connects
out to THIS echo server; the test asserts payloads round-trip. Kept dependency-
free so it runs in the plain tester image.
"""
import os
import socket
import threading


def _handle(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def main():
    port = int(os.environ.get("ECHO_PORT", "9000"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    print(f"echo target listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
