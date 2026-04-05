---
description: "اجرای Teleproxy در Docker با یک دستور. تولید خودکار رمزها و نمایش لینک‌های اتصال. بدون نیاز به فایل پیکربندی."
---

# شروع سریع Docker

ساده‌ترین روش اجرای Teleproxy - بدون نیاز به هیچ پیکربندی:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

کانتینر به‌صورت خودکار:

- آخرین پیکربندی پروکسی را از تلگرام دانلود می‌کند
- در صورت عدم ارائه، یک secret تصادفی تولید می‌کند
- پروکسی را روی پورت 443 راه‌اندازی می‌کند

لینک‌های اتصال در لاگ‌ها نمایش داده می‌شوند:

```bash
docker logs teleproxy
# ===== Connection Links =====
# https://t.me/proxy?server=203.0.113.1&port=443&secret=eecafe...
# =============================
```

اگر تشخیص خودکار IP خارجی ناموفق بود (مثلا پشت فایروال سازمانی)، متغیر محیطی `EXTERNAL_IP` را به‌صورت صریح تنظیم کنید.

## با Fake-TLS (حالت EE)

ترافیک MTProto را در یک handshake واقعی TLS بسته‌بندی می‌کند و آن را از HTTPS معمولی غیرقابل تشخیص می‌سازد:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## حالت اتصال مستقیم به DC

سرورهای واسط تلگرام را دور می‌زند و کلاینت‌ها را مستقیما به نزدیک‌ترین دیتاسنتر هدایت می‌کند:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## تگ‌های موجود

**GitHub Container Registry:**

- `ghcr.io/teleproxy/teleproxy:latest`
- `ghcr.io/teleproxy/teleproxy:{version}` (مثلا `4.7.0`، `4.7`، `4`)

**Docker Hub:**

- `rkline0x/teleproxy:latest`
- `rkline0x/teleproxy:{version}` (مثلا `4.7.0`، `4.7`، `4`)

اگر محیط شما در دانلود از ghcr.io مشکل دارد (مثلا کانتینرهای MikroTik RouterOS)، از Docker Hub استفاده کنید.

## ساخت ایمیج اختصاصی

```bash
docker build -t teleproxy .
docker run -d --name teleproxy -p 443:443 -p 8888:8888 teleproxy
docker logs teleproxy 2>&1 | grep "Generated secret"
```

## به‌روزرسانی

آخرین ایمیج را دانلود کرده و کانتینر را بازسازی کنید:

```bash
docker pull ghcr.io/teleproxy/teleproxy:latest
docker rm -f teleproxy
docker run -d --name teleproxy -p 443:443 -p 8888:8888 --restart unless-stopped ghcr.io/teleproxy/teleproxy:latest
```

با Docker Compose:

```bash
docker compose pull
docker compose up -d
```
