---
description: "Built-in HTTP stats endpoint and Prometheus metrics for Teleproxy. Track connections, traffic, per-secret usage, and DC health."
---

# Monitoring

## HTTP Stats Endpoint

```bash
curl http://localhost:8888/stats
```

Requires `--http-stats` flag. Accessible from private networks only (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Custom Network Access

To allow access from overlay/VPN networks (Tailscale, WireGuard, Netbird), use `--stats-allow-net`:

```bash
./teleproxy ... --stats-allow-net 100.64.0.0/10 --stats-allow-net fd00::/8
```

Repeatable — specify multiple times for multiple ranges. Both IPv4 and IPv6 CIDR notation supported.

## Prometheus Metrics

```bash
curl http://localhost:8888/metrics
```

Returns Prometheus exposition format on the same stats port. Includes per-secret metrics when labels are configured.

Available metrics include connection counts, per-secret connections, rejection counts, and IP ACL rejections.

### DC Latency Probes

When enabled, teleproxy periodically probes all 5 Telegram DCs with a TCP handshake and exposes the results as a Prometheus histogram:

```bash
# Enable with 30-second probe interval
./teleproxy ... --dc-probe-interval 30
```

Metrics exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `teleproxy_dc_latency_seconds` | histogram | TCP handshake RTT per DC (labels: `dc="1"`..`dc="5"`) |
| `teleproxy_dc_probe_failures_total` | counter | Failed probe attempts per DC |
| `teleproxy_dc_latency_last_seconds` | gauge | Most recent probe latency per DC |

The text `/stats` endpoint includes matching fields: `dc_probe_interval`, `dcN_probe_latency_last`, `dcN_probe_latency_avg`, `dcN_probe_count`, `dcN_probe_failures`.

Disabled by default. Set `dc_probe_interval` in the TOML config or use the `DC_PROBE_INTERVAL` environment variable in Docker.

## Grafana Dashboard

Import the [bundled dashboard](https://github.com/teleproxy/teleproxy/blob/main/dashboards/teleproxy.json) into Grafana:

1. Download `dashboards/teleproxy.json` from the repository
2. In Grafana → Dashboards → Import → Upload JSON file
3. Select your Prometheus datasource

The dashboard covers connections, per-secret usage, rejection rates, DC connectivity, and resource utilization.

## Health Checks

Docker containers include built-in health monitoring via the stats endpoint. Check with:

```bash
docker ps  # STATUS column shows health
```
