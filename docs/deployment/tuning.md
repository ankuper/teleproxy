---
description: "Size connection limits and worker counts for your server's available memory and CPU."
---

# Tuning

## Connection limits

Each open connection consumes memory in both kernel space (TCP socket buffers) and user space (crypto state, network buffers). The dominant cost is kernel TCP buffers: roughly **50-100 KB per connection** depending on traffic patterns and sysctl settings.

The `MAX_CONNECTIONS` environment variable (or `maxconn` in TOML) controls how many file descriptors the proxy will use per worker. The default is **10,000** — safe for machines with 1 GB+ RAM.

### Sizing for your server

A conservative formula:

```
max_connections = (RAM_MB - 300) * 10
```

This reserves 300 MB for the process itself (static tables, buffer pool, OS overhead) and allocates ~100 KB per connection.

| RAM | Recommended `MAX_CONNECTIONS` |
|-----|------------------------------|
| 512 MB | 2,000 |
| 1 GB | 7,000 |
| 2 GB | 10,000 (default) |
| 4 GB | 30,000 |
| 8 GB+ | 60,000 |

The hard compile-time limit is 65,536.

To override the default in Docker:

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    environment:
      MAX_CONNECTIONS: 30000
```

!!! tip
    If you see `connections_failed_lru` increasing in [metrics](/features/monitoring/), the proxy is evicting idle connections under memory pressure. Either lower `MAX_CONNECTIONS` or add RAM.

## Workers

`WORKERS` sets the number of worker processes. Default: **1**.

Each worker runs independently with its own connection table and buffer pool, so memory usage scales linearly with worker count. Set workers to your CPU core count for maximum throughput:

```yaml
environment:
  WORKERS: 4
  MAX_CONNECTIONS: 10000  # per worker — total capacity is 40,000
```

Note that `MAX_CONNECTIONS` is **per worker**. With 4 workers and 10,000 max connections each, the proxy can handle up to 40,000 concurrent connections total.

## Per-secret limits

For fine-grained control over individual secrets (connection caps, byte quotas, IP limits, rate limiting), see [Secrets & Limits](/features/secrets/).

## Kernel tuning

On Linux, reducing TCP buffer sizes frees kernel memory for more connections:

```bash
# Lower default TCP buffer sizes (bytes: min, default, max)
sysctl -w net.ipv4.tcp_rmem="4096 16384 131072"
sysctl -w net.ipv4.tcp_wmem="4096 16384 131072"
```

This drops per-socket kernel memory from ~46 KB to ~32 KB at the cost of slightly lower throughput for large file transfers. Telegram messages are small, so the impact is minimal.

For Docker, pass sysctl settings in compose:

```yaml
services:
  teleproxy:
    sysctls:
      net.ipv4.tcp_rmem: "4096 16384 131072"
      net.ipv4.tcp_wmem: "4096 16384 131072"
```

## Monitoring for capacity

Key metrics to watch (available at the `/stats` and `/metrics` endpoints):

| Metric | What it means |
|--------|--------------|
| `connections_failed_lru` | Connections evicted under memory pressure — lower `MAX_CONNECTIONS` or add RAM |
| `connections_failed_flood` | Connections rejected because a single client used too much buffer space |
| `total_special_connections` | Current active connections |
| `total_max_special_connections` | Configured connection limit |
| `total_network_buffers_used_size` | Current userspace buffer usage in bytes |

See [Monitoring](/features/monitoring/) for the full metrics reference.
