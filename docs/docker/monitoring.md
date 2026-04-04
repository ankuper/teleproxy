# Monitoring

## HTTP Stats

```bash
curl http://localhost:8888/stats
```

Returns a human-readable summary of active connections, traffic counters, and uptime.

## Prometheus Metrics

```bash
curl http://localhost:8888/metrics
```

Returns metrics in Prometheus exposition format. Available on the `--http-stats` port, restricted to private networks (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Set `STATS_ALLOW_NET` to extend access to additional CIDR ranges (e.g. Tailscale, WireGuard).

Includes per-secret connection metrics when secret labels are configured. See [Secrets & Limits](../features/secrets.md) for label configuration.

## Health Check

Docker containers include built-in health monitoring via the stats endpoint. Check container health with:

```bash
docker ps  # STATUS column shows health
```

For a ready-made Grafana dashboard, see [Monitoring → Grafana Dashboard](../features/monitoring.md#grafana-dashboard).

For CLI monitoring options and detailed metric descriptions, see [Monitoring](../features/monitoring.md).
