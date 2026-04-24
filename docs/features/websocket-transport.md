---
description: "Type3 WebSocket transport — run Teleproxy behind an external TLS terminator (nginx, Cloudflare Worker, Caddy) on a shared HTTPS port."
---

# WebSocket Transport (Type3)

Type3 is a WebSocket-based transport (RFC 6455) that lets Teleproxy live **behind** an external TLS terminator instead of owning port 443 itself. The external frontend (nginx, Caddy, Traefik, Cloudflare Worker) terminates TLS and `proxy_pass`-es WebSocket upstream to a plaintext Teleproxy port.

```
Client -> TLS terminator (nginx / CF Worker) -> [HTTP WebSocket upgrade] -> Teleproxy
```

Type3 does **not** replace fake-TLS. The two modes coexist side by side and are selected per-port: fake-TLS still listens on its dedicated 443 port as before; Type3 listens on a separate plaintext HTTP port (e.g. 3129).

## When to use it

| Your situation | Recommended transport |
|---|---|
| Dedicated VPS, nothing else on port 443 | **Fake-TLS** |
| VPS already serves a website through nginx/Caddy on 443 | **Type3 WebSocket** |
| You want a free Cloudflare fronting layer (Workers/Pages) | **Type3 WebSocket** |
| You want to use stock Telegram clients with no extra builds | **Fake-TLS** |
| You distribute a custom Telegram client build already | either — Type3 unlocks shared-443 deployments |

!!! note "Client compatibility"
    Stock Telegram clients understand Type1 (obfuscated2) and Type2 (fake-TLS). Type3 requires a client build that speaks WebSocket — either a custom tdesktop/Android/iOS build or an on-device bridge. If your users run stock clients, stay on fake-TLS.

## How it works

1. The TLS terminator accepts the client TLS handshake (using whatever certificate it has — Let's Encrypt, Cloudflare edge, etc.).
2. The client sends `GET /<path> HTTP/1.1` with `Upgrade: websocket` inside that TLS session.
3. The terminator forwards the upgrade request over a plain TCP connection to Teleproxy (`proxy_pass http://127.0.0.1:3129/`).
4. Teleproxy replies `101 Switching Protocols` with a spec-compliant `Sec-WebSocket-Accept` (verified against the RFC 6455 §1.3 canonical example in CI).
5. Subsequent MTProto traffic flows through RFC 6455 binary frames: server→client unmasked, client→server masked per spec.
6. Inside those frames is the ordinary obfuscated2 stream that fake-TLS already carries — the MTProto layer is unchanged.

Teleproxy sets `ws_state = WS_STATE_HANDSHAKE` on every accepted connection and runs a cheap WebSocket-upgrade probe in the first bytes. If the probe fails (not a WebSocket request), `ws_state` drops to `NONE` in microseconds and the existing fake-TLS / obfuscated2 flow runs with no observable change — there is no runtime cost for non-WS connections.

## Enabling Type3

Add a plaintext HTTP listener alongside the regular TLS port by passing `-H <port>` to the Teleproxy binary:

=== "Docker"

    ```bash
    docker run -d \
      --name teleproxy \
      -p 443:443 \
      -p 127.0.0.1:3129:3129 \
      -e SECRET=$SECRET \
      -e DIRECT_MODE=true \
      --restart unless-stopped \
      ghcr.io/teleproxy/teleproxy:latest \
      -H 3129
    ```

=== "CLI"

    ```bash
    ./teleproxy -S $SECRET -H 3129 --direct -p 8888 --aes-pwd proxy-secret data/proxy-multi.conf
    ```

The `-H 3129` argument is appended to whatever command the entrypoint builds, so `SECRET`, `DIRECT_MODE`, and any other env vars keep working the same way.

For complete deployment recipes (nginx colocation, Cloudflare Worker fronting), see [Deployment → WebSocket (Type3)](../deployment/websocket.md).

## Connection link

Clients connect using a Type3 secret that encodes `host[/path]`:

```
ff | <16-byte secret hex> | <host-and-path UTF-8 hex>
```

For example, with secret `f5c64bc3e21530a2a8a60ea82214ed47`, host `proxy.example.com`, and path `/ws/a3f7c2`:

```
ff f5c64bc3e21530a2a8a60ea82214ed47 70726f78792e6578616d706c652e636f6d2f77732f613366376332
   \_____________________________/ \_____________________________________________________/
           16-byte secret              "proxy.example.com/ws/a3f7c2" in hex
```

The `tg://proxy?...` link is:

```
tg://proxy?server=proxy.example.com&port=443&secret=fff5c64bc3e21530a2a8a60ea82214ed4770726f78792e6578616d706c652e636f6d2f77732f613366376332
```

A Type3-aware client splits the domain portion on the first `/`: left side is used for TLS SNI and the `Host:` header; right side is used as the WebSocket upgrade path. Clients that predate the `/path` extension fall back to `/v1/api/mtpr` when no `/` is present, which remains valid for legacy deployments.

## Threat model

What Type3 defends against, on axes where fake-TLS already does well:

- **SNI/IP blocking** when fronted through Cloudflare Workers: attacker must block the entire `*.workers.dev` surface to kill the transport, which carries high collateral cost.
- **Path-based fingerprinting**: paths are randomized per-install (e.g. `/ws/a3f7c2`), so a TSPU rule like "block any WebSocket upgrade to `/v1/api/mtpr`" has nothing to match on.
- **Active probing of the origin VPS**: with Cloudflare fronting, the origin IP is never exposed; unknown paths hit nginx's real 404.

What Type3 does **not** defend against (same limits as fake-TLS on these axes):

- **Traffic-shape fingerprinting of WebSocket + MTProto cadence**. A determined fingerprinter can classify "bidirectional WebSocket with MTProto-like ping rhythm." Mitigations — response-size padding in the Worker, MTProto frame padding server-side — are tracked as future work.
- **Link leakage**. If a `tg://proxy?server=…&secret=…` URL ends up in a public channel, `server=` is in plaintext and TSPU can block by SNI. Operational mitigation: rotate the Worker (new `<slug>.workers.dev`) — one API call, no origin changes.
- **State-CA TLS MITM**. Russian-CA-style state MITM breaks every TLS-based transport equally; not specific to Type3.

## Verification

Once Teleproxy is listening on `-H 3129` and the TLS terminator is configured, verify the handshake end-to-end:

```bash
curl -i \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://proxy.example.com/ws/a3f7c2
```

Expected response:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

The canonical `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` comes straight from RFC 6455 §1.3 — if your server returns it for that exact input key, the handshake is bit-exact correct.

Teleproxy logs the upgrade at verbosity 1:

```
WS_PARSE: WebSocket upgrade success: path=/ws/a3f7c2, key=dGhlIHNhbXBsZSBub25jZQ==
```
