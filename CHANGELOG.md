# Changelog

## [4.1.0]

MTProto transport protocol compliance improvements.

- Detect and log transport error codes (-404, -429, etc.) from DCs in direct mode
- Detect transport error codes in medium mode client parse path
- Track quick ACK packets with `teleproxy_quickack_packets_total` counter
- Track transport errors with `teleproxy_transport_errors_total` counter
- Clarify full transport mode (seq_no + CRC32) scope in code comments

## [4.0.0]

Rebrand to Teleproxy. Binary renamed from `mtproto-proxy` to `teleproxy`.

- Binary name: `teleproxy` (was `mtproto-proxy`)
- Prometheus metrics prefix: `teleproxy_` (was `mtproxy_`)
- Docker user/paths: `/opt/teleproxy/` (was `/opt/mtproxy/`)
- Environment variables: `TELEPROXY_*` (old `MTPROXY_*` still accepted with deprecation warning)
- Docker image includes backward-compat symlink `mtproto-proxy -> teleproxy`
- CLI flags and behavior unchanged
