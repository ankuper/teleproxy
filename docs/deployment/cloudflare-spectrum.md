---
description: "Run Teleproxy behind Cloudflare Spectrum to mask your server IP while preserving fake-TLS and DPI resistance."
---

# Cloudflare Spectrum

[Cloudflare Spectrum](https://developers.cloudflare.com/spectrum/) forwards raw TCP traffic through Cloudflare's edge network. This masks your origin server IP behind Cloudflare's anycast IPs while preserving full fake-TLS and DPI resistance.

```
Client -> Cloudflare Edge (TCP) -> [PROXY protocol] -> Teleproxy
```

Spectrum requires a Cloudflare Business or Enterprise plan.

## How it works

Spectrum proxies TCP at layer 4 without inspecting the payload. The fake-TLS handshake passes through unchanged. Cloudflare injects a PROXY protocol v2 header so Teleproxy can recover the real client IP.

The combination is effective for DPI resistance: censors see a TLS connection to a Cloudflare IP, which is indistinguishable from normal HTTPS traffic to any Cloudflare-hosted website.

## Configuration

### 1. Cloudflare Spectrum

In the Cloudflare dashboard, create a Spectrum application:

- **Protocol**: TCP
- **Edge port**: 443
- **Origin**: your server IP and port (e.g. `203.0.113.10:443`)
- **PROXY protocol**: Enabled (v2)

Point your domain's DNS A record to Cloudflare (proxied).

### 2. Teleproxy

Enable PROXY protocol on the Teleproxy side.

**Docker:**

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e PROXY_PROTOCOL=true \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

**TOML config:**

```toml
proxy_protocol = true
```

**CLI:**

```bash
./teleproxy --direct --proxy-protocol -H 443 -S <secret> -D www.google.com ...
```

### 3. Client link

Use the Cloudflare-proxied domain in your `tg://proxy` link:

```
tg://proxy?server=proxy.example.com&port=443&secret=ee<hex>...
```

## IP ACLs

When using Spectrum with IP ACLs, allow Cloudflare's edge IPs at accept time. Real client IPs are extracted from the PROXY header and checked separately.

Cloudflare publishes their IP ranges at [cloudflare.com/ips](https://www.cloudflare.com/ips/).

## Verification

```bash
# Check Spectrum is forwarding (from a different machine)
curl -v --connect-to proxy.example.com:443:proxy.example.com:443 \
  https://proxy.example.com 2>&1 | head -20

# Check PROXY protocol metrics
curl http://localhost:8888/metrics | grep proxy_protocol
```

## Notes

- Spectrum adds one network hop, adding a few milliseconds of latency
- Only TCP is forwarded; UDP is not supported
- Cloudflare's IPs are shared across millions of domains, making traffic analysis harder
- If Spectrum is misconfigured (PROXY protocol disabled), Teleproxy will reject all connections
