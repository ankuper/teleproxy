---
description: "Route Teleproxy outbound connections through a SOCKS5 proxy when the server IP is blocked by Telegram or for origin hiding."
---

# SOCKS5 Upstream Proxy

Route all outbound connections to Telegram DCs through a SOCKS5 proxy:

```
Client -> Teleproxy -> SOCKS5 proxy -> Telegram DC
```

This is useful when the server's IP is blocked by Telegram or when you want to hide the server's origin from Telegram's network.

## Configuration

### Docker

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e SOCKS5_PROXY=socks5://proxy.example.com:1080 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

With authentication:

```bash
-e SOCKS5_PROXY=socks5://user:pass@proxy.example.com:1080
```

### TOML config

```toml
socks5 = "socks5://proxy.example.com:1080"
```

### CLI flag

```bash
./teleproxy --direct --socks5 socks5://user:pass@proxy.example.com:1080 -H 443 -S <secret> ...
```

## URL format

Two schemes are supported:

| Scheme | DNS resolution | Use case |
|--------|---------------|----------|
| `socks5://` | Local (teleproxy resolves DC addresses) | Default — works with most SOCKS5 proxies |
| `socks5h://` | Remote (SOCKS5 proxy resolves hostnames) | Privacy-sensitive setups where DNS should not leak |

Full format: `socks5[h]://[user:pass@]host:port`

## Authentication

- **Anonymous**: `socks5://host:port` — no credentials, proxy must allow unauthenticated access
- **Username/Password**: `socks5://user:pass@host:port` — RFC 1929 authentication

## Monitoring

SOCKS5 connection stats are exposed on the stats endpoints:

`/stats` (tab-separated):

```
socks5_enabled	1
socks5_connects_attempted	42
socks5_connects_succeeded	40
socks5_connects_failed	2
```

`/metrics` (Prometheus):

```
teleproxy_socks5_connects_attempted_total 42
teleproxy_socks5_connects_succeeded_total 40
teleproxy_socks5_connects_failed_total 2
```

## Notes

- Works with both direct mode and ME relay mode
- Not reloadable via SIGHUP — requires a restart to change the SOCKS5 proxy
- IPv6 target addresses are supported if the SOCKS5 proxy supports them
