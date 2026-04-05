---
description: "Accept HAProxy PROXY protocol v1/v2 headers for real client IP preservation behind load balancers like HAProxy, nginx, or AWS NLB."
---

# PROXY Protocol

Accept [HAProxy PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) v1 (text) and v2 (binary) headers on client listeners. Required when running behind a load balancer (HAProxy, nginx, AWS NLB, etc.) that injects client IP via PROXY protocol.

Without this, IP ACLs, per-IP limits, per-secret IP tracking, and logging all see the load balancer's IP instead of the real client.

```
Client -> Load Balancer (PROXY protocol) -> Teleproxy
```

## Configuration

### Docker

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e PROXY_PROTOCOL=true \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

### TOML config

```toml
proxy_protocol = true
```

### CLI flag

```bash
./teleproxy --direct --proxy-protocol -H 443 -S <secret> ...
```

## How it works

When enabled, every client connection must start with a PROXY protocol header before any MTProto/TLS data. The proxy:

1. Reads the PROXY header (v1 or v2, auto-detected)
2. Extracts the real client IP and port
3. Replaces the connection's remote address with the extracted values
4. Re-checks IP ACLs against the real client IP
5. Proceeds with normal protocol detection (obfs2, fake-TLS, etc.)

Connections without a valid PROXY header are closed.

## IP ACL integration

When proxy protocol is enabled, two IP checks happen:

1. **At accept time**: the load balancer's IP is checked. If you use an IP allowlist, include the LB's address.
2. **After PROXY header**: the real client IP is checked against your blocklist/allowlist.

This means IP ACLs filter real clients, not the load balancer.

## PROXY protocol v2 LOCAL

Load balancers send LOCAL commands for health checks (no address payload). Teleproxy accepts these and keeps the original connection IP.

## Monitoring

Stats endpoint (`/stats`):

```
proxy_protocol_enabled	1
proxy_protocol_connections	42
proxy_protocol_errors	3
```

Prometheus (`/metrics`):

```
teleproxy_proxy_protocol_enabled 1
teleproxy_proxy_protocol_connections_total 42
teleproxy_proxy_protocol_errors_total 3
```

## Notes

- Both v1 (text) and v2 (binary) are supported and auto-detected
- Not reloadable via SIGHUP — requires a restart to enable/disable
- The stats/HTTP endpoint port is not affected — only client listeners expect the header
- IPv6 client addresses in PROXY headers are fully supported
