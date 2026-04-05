---
description: "Run Teleproxy as a systemd service with automatic restart, resource limits, and security hardening. Includes a complete unit file."
---

# Systemd

The recommended way to set up systemd is via the [install script](../getting-started/installation.md#one-liner-install-recommended), which creates the service, config file, and user automatically.

The sections below are for manual setup or reference.

## Service File

Create `/etc/systemd/system/teleproxy.service`:

```ini
[Unit]
Description=Teleproxy MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=teleproxy
ExecStart=/usr/local/bin/teleproxy --config /etc/teleproxy/config.toml -p 8888
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/teleproxy

[Install]
WantedBy=multi-user.target
```

## Config File

Create `/etc/teleproxy/config.toml`:

```toml
port = 443
http_stats = true
direct = true
workers = 1

[[secret]]
key = "your-32-hex-digit-secret-here"
label = "default"
```

Generate a secret with `teleproxy generate-secret`.

## Setup

```bash
systemctl daemon-reload
systemctl enable --now teleproxy
systemctl status teleproxy
```

## Reloading

Edit the config file and reload without dropping connections:

```bash
systemctl reload teleproxy
```

This sends SIGHUP, which reloads secrets and IP ACLs from the config file.

## Legacy (CLI-only)

If not using a config file, pass flags directly:

```ini
ExecStart=/usr/local/bin/teleproxy -S <secret> -H 443 -p 8888 --http-stats --direct
```
