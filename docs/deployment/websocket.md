---
description: "Deploy Teleproxy as a WebSocket upstream behind nginx, Caddy, or a Cloudflare Worker — coexist with an existing site on port 443."
---

# WebSocket (Type3) Deployment

Three recipes for running Type3 behind an external TLS terminator. Pick the one that matches your starting state.

For the conceptual overview of Type3 and how it relates to fake-TLS, see [Features → WebSocket Transport](../features/websocket-transport.md).

## Before you start

- A Type3-aware Telegram client (stock clients speak Type1/Type2 only).
- A hex secret: `head -c 16 /dev/urandom | xxd -ps`.
- A random path suffix so the WebSocket URL doesn't become a fingerprint:
  ```bash
  PATH_SUFFIX="/ws/$(head -c 32 /dev/urandom | tr -dc 'a-f0-9' | head -c 12)"
  # e.g. /ws/a3f7c2e1b9d4
  ```

---

## Recipe 1 — Behind existing nginx

Your VPS already serves a website on 443 through nginx. You want to add Teleproxy as a new `location` block without touching anything else.

### 1. Run Teleproxy on a plaintext port

```bash
docker run -d \
  --name teleproxy \
  -p 127.0.0.1:3129:3129 \
  -p 127.0.0.1:8888:8888 \
  -e SECRET=$SECRET \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest \
  -H 3129
```

Teleproxy now listens on `127.0.0.1:3129` for plaintext HTTP traffic from nginx.

### 2. Add a location block to your existing nginx site

Edit the `server {}` block that serves your domain on 443 and append:

```nginx
location = /ws/a3f7c2e1b9d4 {
    proxy_pass http://127.0.0.1:3129;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
```

Use exactly the path suffix you generated in "Before you start". Reload nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Build the connection link

```bash
HOST_PATH="proxy.example.com${PATH_SUFFIX}"
HOST_PATH_HEX=$(printf '%s' "$HOST_PATH" | xxd -p | tr -d '\n')
SECRET_FIELD="ff${SECRET}${HOST_PATH_HEX}"
echo "tg://proxy?server=proxy.example.com&port=443&secret=${SECRET_FIELD}"
```

### 4. Verify

```bash
curl -i \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://proxy.example.com${PATH_SUFFIX}"
```

Expect `HTTP/1.1 101 Switching Protocols` with `Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.

---

## Recipe 2 — Greenfield VPS (nginx + Let's Encrypt + Teleproxy)

Fresh VPS, no nginx yet. You want a complete setup in one pass.

### 1. Install nginx and certbot

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

### 2. Get a TLS certificate

```bash
sudo certbot --nginx -d proxy.example.com --non-interactive --agree-tos -m you@example.com
```

Certbot creates and activates an nginx server block for your domain.

### 3. Run Teleproxy

```bash
docker run -d \
  --name teleproxy \
  -p 127.0.0.1:3129:3129 \
  -p 127.0.0.1:8888:8888 \
  -e SECRET=$SECRET \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest \
  -H 3129
```

### 4. Add the WebSocket location to nginx

Edit `/etc/nginx/sites-enabled/proxy.example.com` (the file certbot created) and insert inside the `server { listen 443 ssl; ... }` block:

```nginx
location = /ws/a3f7c2e1b9d4 {
    proxy_pass http://127.0.0.1:3129;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
```

Reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Build the link and verify

Same as Recipe 1 steps 3 and 4.

---

## Recipe 3 — Cloudflare Worker fronting (free)

Front the origin VPS through a free Cloudflare Worker at `<slug>.workers.dev`. This hides the origin IP behind Cloudflare's edge and gives you unlimited rotations at zero cost.

### 1. Set up the origin

Follow either Recipe 1 or Recipe 2 to get a working `https://origin.example.com` with Teleproxy behind nginx.

### 2. Create a Cloudflare Worker

In the Cloudflare dashboard (Workers & Pages → Create → Worker), paste this script:

```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    url.hostname = env.ORIGIN_HOST;
    url.protocol = "https:";
    return fetch(new Request(url, request), {
      headers: {
        ...Object.fromEntries(request.headers),
        host: env.ORIGIN_HOST,
      },
    });
  },
};
```

Cloudflare Workers proxy WebSocket traffic automatically when the request carries `Upgrade: websocket` headers — no special code needed.

Add a **Variable** (Settings → Variables):

- Name: `ORIGIN_HOST`
- Value: `origin.example.com`

Deploy. Your Worker is now live at `<slug>.<account>.workers.dev`.

### 3. Build the connection link

The link uses the **Worker** hostname, not the origin:

```bash
WORKER_DOMAIN="mtpr-a1b2c3.your-account.workers.dev"
HOST_PATH="${WORKER_DOMAIN}${PATH_SUFFIX}"
HOST_PATH_HEX=$(printf '%s' "$HOST_PATH" | xxd -p | tr -d '\n')
SECRET_FIELD="ff${SECRET}${HOST_PATH_HEX}"
echo "tg://proxy?server=${WORKER_DOMAIN}&port=443&secret=${SECRET_FIELD}"
```

### 4. Verify through the Worker

```bash
curl -i \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://${WORKER_DOMAIN}${PATH_SUFFIX}"
```

Expect the same `HTTP/1.1 101 Switching Protocols` response.

### 5. Rotate when needed

If a `tg://proxy?...` link leaks publicly, rotate the Worker — the origin never has to change:

1. In the dashboard, create a new Worker with a fresh name (or via API: `PUT /accounts/$CF_ACCOUNT_ID/workers/scripts/<new-slug>`).
2. Delete the old Worker.
3. Regenerate the link with the new `<new-slug>.workers.dev` hostname.

The origin VPS, nginx, TLS certificate, secret, and MTProto state all stay untouched.

---

## Troubleshooting

**`HTTP/1.1 400 Bad Request` instead of 101**
: The upgrade request is reaching Teleproxy but the WebSocket headers are malformed. Check that nginx is passing `Upgrade` and `Connection` headers (see the `location` block above) and that `proxy_http_version 1.1` is set.

**`HTTP/1.1 502 Bad Gateway`**
: nginx can't reach Teleproxy on `127.0.0.1:3129`. Confirm the container is up (`docker ps | grep teleproxy`) and that the port is bound to `127.0.0.1` (`ss -ltn | grep 3129`).

**Connection established but Telegram hangs on "Connecting..."**
: Stock Telegram clients don't understand Type3. Use a Type3-aware client build. See [Features → WebSocket Transport → When to use it](../features/websocket-transport.md#when-to-use-it).

**`Sec-WebSocket-Accept` missing from response**
: The connection reached Teleproxy but the upgrade request parser rejected it. Check Teleproxy logs at verbosity 2 (`-v -v`) for `WS_PARSE` lines describing what the parser saw.
