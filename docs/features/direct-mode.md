---
description: "Bypass Telegram middle-end relays for lower latency and higher throughput. Route clients straight to the nearest Telegram datacenter."
---

# Direct-to-DC Mode

By default, Teleproxy routes through Telegram's middle-end (ME) relay servers. Direct mode bypasses them:

```
Default:  Client -> Teleproxy -> ME relay -> Telegram DC
Direct:   Client -> Teleproxy -> Telegram DC
```

Enable with `--direct`:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats --direct
```

In direct mode:

- No `proxy-multi.conf` or `proxy-secret` files needed
- No config file argument required
- Connects directly to well-known Telegram DC addresses
- **Incompatible with `-P` (proxy tag)** — promoted channels require ME relays

Docker:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Connection Resilience

Direct mode includes built-in resilience:

- **IPv6 auto-detection** — probes IPv6 connectivity at startup and enables it automatically. The `-6` flag is no longer required.
- **Address failover** — each DC can have multiple addresses. If one fails, the next is tried.
- **Retry with backoff** — when all addresses fail, the proxy retries with exponential backoff (200ms, 400ms, 800ms) before giving up.

## Custom DC Addresses

Override the built-in DC address table with `--dc-override`:

```bash
./teleproxy --direct --dc-override 2:10.0.0.1:443 --dc-override 2:10.0.0.2:443 -S <secret> ...
```

IPv6 addresses use brackets:

```bash
./teleproxy --direct --dc-override 2:[2001:db8::1]:443 -S <secret> ...
```

Overrides for a DC replace its built-in addresses entirely. The flag is repeatable — multiple entries for the same DC are tried in order.

Docker: `DC_OVERRIDE=2:10.0.0.1:443,2:10.0.0.2:443`
