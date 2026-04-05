---
description: "مرجع کامل متغیرهای محیطی Docker برای Teleproxy: رمزها، دامنه TLS، کنترل دسترسی، مانیتورینگ و محدودیت‌ها."
---

# پیکربندی Docker

## متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|--------|---------|-------|
| `SECRET` | تولید خودکار | secret پروکسی - هر کدام ۳۲ کاراکتر هگزادسیمال. تکی، جدا شده با کاما، یا با برچسب |
| `SECRET_1`...`SECRET_16` | - | secret‌های شماره‌دار (در صورت تنظیم هر دو، با `SECRET` ترکیب می‌شوند) |
| `SECRET_LABEL_1`...`SECRET_LABEL_16` | - | برچسب برای secret‌های شماره‌دار |
| `SECRET_LIMIT_1`...`SECRET_LIMIT_16` | - | محدودیت اتصال به ازای هر secret |
| `SECRET_QUOTA_1`...`SECRET_QUOTA_16` | - | سهمیه ترافیک به ازای هر secret (به بایت، مثلا `10737418240` برای ۱۰ گیگابایت) |
| `SECRET_MAX_IPS_1`...`SECRET_MAX_IPS_16` | - | محدودیت IP یکتا به ازای هر secret |
| `SECRET_EXPIRES_1`...`SECRET_EXPIRES_16` | - | تاریخ انقضای secret (فرمت TOML datetime یا Unix timestamp) |
| `PORT` | 443 | پورت اتصال کلاینت‌ها |
| `STATS_PORT` | 8888 | پورت اندپوینت آمار |
| `WORKERS` | 1 | تعداد فرآیندهای کاری |
| `PROXY_TAG` | - | تگ از @MTProxybot (تبلیغ کانال) |
| `DIRECT_MODE` | false | اتصال مستقیم به DC‌های تلگرام |
| `RANDOM_PADDING` | false | فعال‌سازی فقط random padding (حالت DD) |
| `EXTERNAL_IP` | تشخیص خودکار | IP عمومی برای محیط‌های NAT |
| `EE_DOMAIN` | - | دامنه برای Fake-TLS. پشتیبانی از `host:port` برای بک‌اندهای TLS سفارشی |
| `IP_BLOCKLIST` | - | مسیر فایل لیست سیاه CIDR |
| `IP_ALLOWLIST` | - | مسیر فایل لیست سفید CIDR |
| `STATS_ALLOW_NET` | - | محدوده‌های CIDR جدا شده با کاما برای دسترسی به آمار (مثلا `100.64.0.0/10,fd00::/8`) |
| `SOCKS5_PROXY` | - | مسیریابی اتصالات بالادست به DC از طریق پروکسی SOCKS5 (`socks5://[user:pass@]host:port`) |
| `PROXY_PROTOCOL` | false | فعال‌سازی PROXY protocol نسخه ۱ و ۲ روی شنونده‌های کلاینت (برای HAProxy/nginx/NLB) |
| `DC_OVERRIDE` | - | بازنویسی آدرس‌های DC جدا شده با کاما برای حالت مستقیم (مثلا `2:1.2.3.4:443,2:5.6.7.8:443`) |
| `DC_PROBE_INTERVAL` | - | فاصله زمانی بررسی سلامت DC به ثانیه (مثلا `30`). غیرفعال در صورت عدم تنظیم یا `0` |

حداکثر ۱۶ secret (محدودیت باینری).

## Docker Compose

پیکربندی ساده:

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    restart: unless-stopped
```

با فایل `.env`:

```bash
SECRET=your_secret_here
PROXY_TAG=your_proxy_tag_here
```

## اتصال حجم (Volume)

کانتینر فایل `proxy-multi.conf` را در مسیر `/opt/teleproxy/data/` ذخیره می‌کند. یک حجم متصل کنید تا پیکربندی بین راه‌اندازی‌های مجدد حفظ شود:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -v /path/to/host/data:/opt/teleproxy/data \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

فایل `proxy-secret` در زمان ساخت ایمیج درون آن تعبیه شده است و نیازی به حجم جداگانه ندارد.

اگر `core.telegram.org` در دسترس نباشد، کانتینر از پیکربندی ذخیره‌شده در حجم استفاده می‌کند.

## به‌روزرسانی خودکار پیکربندی

یک وظیفه cron هر ۶ ساعت پیکربندی DC تلگرام را به‌روزرسانی می‌کند. این وظیفه آخرین پیکربندی را دانلود می‌کند، اعتبارسنجی می‌کند، با نسخه فعلی مقایسه می‌کند و در صورت تغییر، پروکسی را از طریق `SIGHUP` مجددا بارگذاری می‌کند. نیازی به پیکربندی نیست.

## بررسی سلامت

ایمیج Docker شامل بررسی سلامت داخلی است که اندپوینت آمار را نظارت می‌کند:

```bash
docker ps  # ستون STATUS را بررسی کنید
```

بررسی سلامت هر ۳۰ ثانیه پس از ۶۰ ثانیه مهلت اولیه راه‌اندازی اجرا می‌شود.
