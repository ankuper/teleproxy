---
description: "Type3 HTTP Stream transport — run Teleproxy behind nginx with POST+chunked encoding for maximum ТСПУ resistance."
---

# HTTP Stream Transport (Type3)

HTTP stream is a second transport mode for Type3, alongside [WebSocket](websocket-transport.md). Instead of a WebSocket upgrade, the client sends a standard HTTP POST with `Transfer-Encoding: chunked`, and the server responds with `200 OK` + chunked response body. The MTProto stream flows inside HTTP chunks.

```
Client → TLS terminator (nginx) → [HTTP POST + chunked] → Teleproxy
```

From a DPI perspective, this looks like a normal HTTPS POST to a REST API — no WebSocket `Upgrade` header, no `101 Switching Protocols`, no WebSocket frame opcodes. This makes it resistant to WebSocket-specific DPI fingerprinting used by ТСПУ.

## When to use it

| Your situation | Recommended transport |
|---|---|
| ТСПУ blocks WebSocket upgrades | **HTTP stream** |
| Need maximum DPI resistance | **HTTP stream** |
| Cloudflare Workers fronting | **WebSocket** (Workers natively support WS) |
| Lowest latency / simplest setup | **WebSocket** |

!!! note "Transport auto-detection"
    Teleproxy auto-detects the transport mode by inspecting the first HTTP request line: `GET` → WebSocket, `POST` → HTTP stream. Both modes can share the same upstream port. No server-side configuration change is needed.

## How it works

1. The TLS terminator (nginx) accepts the client TLS handshake.
2. The client sends `POST /<path> HTTP/1.1` with `Transfer-Encoding: chunked`.
3. nginx forwards the request to Teleproxy on a plaintext HTTP port.
4. Teleproxy responds `HTTP/1.1 200 OK` with `Transfer-Encoding: chunked`.
5. Both directions stream MTProto data inside HTTP chunks: `<hex-length>\r\n<data>\r\n`.
6. Inside the chunks is the standard obfuscated-2 stream (Session Header + AES-256-CTR encrypted MTProto).

The first 4 bytes of the client's chunked payload are the Type3 Session Header, followed by the 64-byte obfuscated-2 initialization vector. From there, the encrypted MTProto stream continues identically to WebSocket mode — only the framing layer differs.

## nginx configuration

HTTP stream mode requires specific nginx directives to ensure full-duplex, low-latency streaming. Without these, nginx will buffer responses (causing client stalls) or timeout long-lived connections.

### Dedicated HTTP stream location

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # CRITICAL: reduce TLS buffer to prevent response header buffering
    ssl_buffer_size 4k;

    # HTTP stream endpoint
    location /api/v1/data {
        proxy_pass http://127.0.0.1:3129;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header Connection "";

        # Disable all buffering for bidirectional streaming
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
        client_max_body_size 0;

        # Long-lived connections (24h)
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

### Combined WebSocket + HTTP stream location

Both transport modes can share a single location block:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ""      close;
}

location /v1/api/mtpr {
    proxy_pass http://127.0.0.1:3129;
    proxy_http_version 1.1;

    # WebSocket upgrade headers (ignored for POST requests)
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;

    proxy_request_buffering off;
    proxy_buffering off;
    proxy_cache off;
    client_max_body_size 0;

    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
```

### Critical directives

| Directive | Required | Why |
|---|---|---|
| `proxy_buffering off` | **Yes** | Without this, nginx buffers upstream responses, causing client stalls |
| `proxy_request_buffering off` | **Yes** | Without this, nginx buffers the POST body before forwarding |
| `ssl_buffer_size 4k` | **Recommended** | Default 16 KB causes TLS record coalescing — the `200 OK` response headers (~120 bytes) get held in the TLS buffer until more data arrives, stalling the client |
| `proxy_read_timeout 86400s` | **Yes** | Default 60s would kill idle MTProto sessions |
| `client_max_body_size 0` | **Yes** | Allows infinite chunked POST body |

## Connection link

HTTP stream uses the same secret format as WebSocket. The transport mode is selected by the client based on the endpoint URL scheme:

- `wss://host/path` → WebSocket mode
- `https://host/path` → HTTP stream mode

Both modes use the same Type3 secret and the same upstream Teleproxy port.

## Verification

```bash
# Test HTTP stream handshake
curl -X POST \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/dev/null \
  -i https://your-domain.com/api/v1/data
```

Expected: `HTTP/1.1 200 OK` with `Transfer-Encoding: chunked`.

## Protocol specification

The HTTP stream transport is normatively defined in [`teleproto3/spec/wire-format.md` §1.3–§1.4](https://github.com/ankuper/teleproto3/blob/main/spec/wire-format.md).
