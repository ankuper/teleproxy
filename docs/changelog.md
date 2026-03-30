# Changelog

## 4.1.0

- `--stats-allow-net CIDR` flag to extend stats endpoint access beyond RFC1918 ranges (repeatable). Docker: `STATS_ALLOW_NET=100.64.0.0/10,fd00::/8`

## 4.0.0

Rebrand to Teleproxy. Binary renamed from `mtproto-proxy` to `teleproxy`.

- Binary name: `teleproxy` (was `mtproto-proxy`)
- Prometheus metrics prefix: `teleproxy_` (was `mtproxy_`)
- Docker user/paths: `/opt/teleproxy/` (was `/opt/mtproxy/`)
- Environment variables: `TELEPROXY_*` (old `MTPROXY_*` still accepted with deprecation warning)
- Docker image includes backward-compat symlink `mtproto-proxy -> teleproxy`
- CLI flags and behavior unchanged
