#!/usr/bin/env python3
"""Minimal SOCKS5 proxy server for testing.

Supports no-auth and username/password auth (RFC 1929).
Handles CONNECT to IPv4 and IPv6 targets.

Usage:
    python3 socks5_server.py --port 1080
    python3 socks5_server.py --port 1080 --require-auth --user test --pass secret
"""

import argparse
import asyncio
import logging
import struct
import sys

log = logging.getLogger("socks5")


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        writer.close()


async def handle_client(reader, writer, *, require_auth=False, user=None, passwd=None):
    addr = writer.get_extra_info("peername")
    try:
        # Greeting
        ver = await reader.readexactly(1)
        if ver != b"\x05":
            return
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)

        if require_auth:
            if b"\x02" not in methods:
                writer.write(b"\x05\xff")  # no acceptable method
                await writer.drain()
                return
            writer.write(b"\x05\x02")  # username/password
            await writer.drain()

            # Auth sub-negotiation (RFC 1929)
            auth_ver = await reader.readexactly(1)
            if auth_ver != b"\x01":
                return
            ulen = (await reader.readexactly(1))[0]
            u = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            p = (await reader.readexactly(plen)).decode()
            if u != user or p != passwd:
                writer.write(b"\x01\x01")  # auth failure
                await writer.drain()
                log.warning("%s auth failed (user=%s)", addr, u)
                return
            writer.write(b"\x01\x00")  # auth success
            await writer.drain()
        else:
            writer.write(b"\x05\x00")  # no auth
            await writer.drain()

        # CONNECT request
        hdr = await reader.readexactly(4)
        if hdr[0] != 0x05 or hdr[1] != 0x01:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return

        atyp = hdr[3]
        if atyp == 0x01:  # IPv4
            raw_addr = await reader.readexactly(4)
            target_host = ".".join(str(b) for b in raw_addr)
        elif atyp == 0x04:  # IPv6
            raw_addr = await reader.readexactly(16)
            import socket
            target_host = socket.inet_ntop(socket.AF_INET6, raw_addr)
        elif atyp == 0x03:  # Domain
            dlen = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(dlen)).decode()
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return

        port_bytes = await reader.readexactly(2)
        target_port = struct.unpack("!H", port_bytes)[0]

        log.info("%s -> CONNECT %s:%d", addr, target_host, target_port)

        # Connect to target
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port), timeout=10
            )
        except Exception as e:
            log.warning("connect to %s:%d failed: %s", target_host, target_port, e)
            writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
            await writer.drain()
            return

        # Success response
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
        await writer.drain()

        # Relay data
        await asyncio.gather(
            relay(reader, t_writer),
            relay(t_reader, writer),
        )

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        writer.close()


async def main():
    parser = argparse.ArgumentParser(description="Minimal SOCKS5 server")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--require-auth", action="store_true")
    parser.add_argument("--user", default="test")
    parser.add_argument("--pass", dest="passwd", default="test")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")

    server = await asyncio.start_server(
        lambda r, w: handle_client(
            r, w,
            require_auth=args.require_auth,
            user=args.user,
            passwd=args.passwd,
        ),
        "0.0.0.0",
        args.port,
    )
    log.info("listening on port %d (auth=%s)", args.port, args.require_auth)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
