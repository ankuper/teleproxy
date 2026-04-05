---
description: "پیکربندی حالت EE در Teleproxy برای پوشاندن MTProto در handshake واقعی TLS 1.3. ترافیک پروکسی از HTTPS معمولی قابل تشخیص نیست."
---

# Fake-TLS (حالت EE)

Teleproxy از حالت EE پشتیبانی می‌کند که ترافیک پروکسی را شبیه TLS 1.3 استاندارد نشان می‌دهد و شناسایی و مسدود کردن آن را دشوارتر می‌سازد.

## نحوه کار

secret کلاینت از این الگو پیروی می‌کند: `ee` + secret_سرور + دامنه_هگز

پیکربندی سرور - دامنه را اضافه کنید (باید از TLS 1.3 پشتیبانی کند):

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

تولید secret کامل کلاینت در یک مرحله:

```bash
teleproxy generate-secret www.google.com
# stdout:  eecafe...7777772e676f6f676c652e636f6d
# stderr:  Secret for -S:  cafe...
#          Domain:         www.google.com
```

مقدار stdout را در لینک‌های `tg://proxy` و مقدار `Secret for -S` را با فلگ `-S` استفاده کنید.

## بک‌اند TLS سفارشی (TCP Splitting) {#custom-tls-backend-tcp-splitting}

به جای تقلید یک وب‌سایت عمومی، وب‌سرور خود را با گواهی TLS معتبر پشت Teleproxy اجرا کنید. بازدیدکنندگان غیرپروکسی یک وب‌سایت HTTPS کاملا عملیاتی می‌بینند و سرور از یک وب‌سرور معمولی غیرقابل تشخیص است.

نحوه کار:

- Teleproxy روی پورت 443 گوش می‌دهد
- nginx روی یک پورت غیراستاندارد (مثلا 8443) با گواهی معتبر اجرا می‌شود
- رکورد DNS A دامنه به سرور Teleproxy اشاره می‌کند
- کلاینت‌های معتبر پروکسی به‌صورت عادی متصل می‌شوند؛ تمام ترافیک دیگر به nginx هدایت می‌شود

**مقاومت در برابر کاوش فعال:** هر اتصالی که اعتبارسنجی را رد نکند - secret اشتباه، مهر زمانی منقضی‌شده، SNI ناشناخته، handshake تکرار شده، ClientHello ناقص، یا ترافیک غیر TLS - به‌صورت شفاف به بک‌اند هدایت می‌شود. هر کسی که سرور را کاوش کند، یک وب‌سایت HTTPS واقعی مشاهده می‌کند.

الزامات:

- بک‌اند باید از TLS 1.3 پشتیبانی کند (در زمان راه‌اندازی بررسی می‌شود)
- مقدار `-D` باید نام هاست باشد، نه IP (TLS SNI طبق RFC 6066 از IP پشتیبانی نمی‌کند)

نمونه پیکربندی با nginx:

```nginx
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

اگر nginx فقط روی loopback گوش می‌دهد، رکوردی به `/etc/hosts` اضافه کنید:

```
127.0.0.1 mywebsite.com
```

اجرا با دامنه و پورت:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D mywebsite.com:8443 --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

!!! note
    برای تمدید گواهی از certbot با چالش DNS-01 استفاده کنید. چالش HTTP-01 کار نمی‌کند زیرا Teleproxy پورت 443 را اشغال کرده است.

## تغییر اندازه رکورد پویا (DRS)

اتصالات TLS به‌صورت خودکار از اندازه‌های تدریجی رکورد استفاده می‌کنند که رفتار وب‌سرورهای واقعی (Cloudflare، Go، Caddy) را تقلید می‌کند: رکوردهای کوچک به اندازه MTU در هنگام TCP slow-start (حدود ۱۴۵۰ بایت)، افزایش تا حدود ۴۰۹۶ بایت، و سپس حداکثر payload در TLS (حدود ۱۶۱۴۴ بایت). این کار تحلیل آماری ترافیک را که پروکسی را از طریق اندازه‌های یکنواخت رکورد شناسایی می‌کند، خنثی می‌سازد.

نیازی به پیکربندی نیست. DRS به‌صورت خودکار برای تمام اتصالات TLS فعال می‌شود.

## حالت DD (padding تصادفی)

برای ISP‌هایی که MTProto را از طریق اندازه بسته‌ها شناسایی می‌کنند، padding تصادفی اضافه می‌شود.

پیکربندی کلاینت: پیشوند `dd` را به secret اضافه کنید (`cafe...babe` تبدیل به `ddcafe...babe` می‌شود).

پیکربندی سرور: از `-R` استفاده کنید تا فقط کلاینت‌های دارای padding مجاز باشند.
