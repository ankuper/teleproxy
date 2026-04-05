---
description: "Run Teleproxy in Docker with a single command. Auto-generates secrets and prints connection links. No config files needed."
---

# Docker Quick Start

The simplest way to run Teleproxy — no configuration needed:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

The container automatically:

- Downloads the latest proxy configuration from Telegram
- Generates a random secret if none provided
- Starts the proxy on port 443

Connection links are printed in the logs:

```bash
docker logs teleproxy
# ===== Connection Links =====
# https://t.me/proxy?server=203.0.113.1&port=443&secret=eecafe...
# =============================
```

If external IP detection fails (e.g. behind a corporate firewall), set the `EXTERNAL_IP` environment variable explicitly.

## With Fake-TLS (EE Mode)

Wrap MTProto traffic in a real TLS handshake, making it indistinguishable from normal HTTPS:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Direct-to-DC Mode

Bypass Telegram's middle-end relay servers and route clients straight to the nearest datacenter:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Available Tags

**GitHub Container Registry:**

- `ghcr.io/teleproxy/teleproxy:latest`
- `ghcr.io/teleproxy/teleproxy:{version}` (e.g. `4.7.0`, `4.7`, `4`)

**Docker Hub:**

- `rkline0x/teleproxy:latest`
- `rkline0x/teleproxy:{version}` (e.g. `4.7.0`, `4.7`, `4`)

Use Docker Hub if your environment has trouble pulling from ghcr.io (e.g. MikroTik RouterOS containers).

## Building Your Own Image

```bash
docker build -t teleproxy .
docker run -d --name teleproxy -p 443:443 -p 8888:8888 teleproxy
docker logs teleproxy 2>&1 | grep "Generated secret"
```

## Updating

Pull the latest image and recreate the container:

```bash
docker pull ghcr.io/teleproxy/teleproxy:latest
docker rm -f teleproxy
docker run -d --name teleproxy -p 443:443 -p 8888:8888 --restart unless-stopped ghcr.io/teleproxy/teleproxy:latest
```

With Docker Compose:

```bash
docker compose pull
docker compose up -d
```
