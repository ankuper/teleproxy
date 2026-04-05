---
description: "Cấu hình chế độ EE của Teleproxy để bọc MTProto trong TLS 1.3 handshake thực sự, khiến lưu lượng proxy không thể phân biệt với HTTPS."
---

# Fake-TLS (Chế độ EE)

Teleproxy hỗ trợ chế độ EE giúp lưu lượng proxy trông giống TLS 1.3 chuẩn, khiến nó khó bị phát hiện và chặn hơn.

## Cách hoạt động

Client secret sử dụng định dạng: `ee` + server_secret + domain_hex

Thiết lập phía server - thêm cấu hình domain (phải hỗ trợ TLS 1.3):

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Tạo client secret đầy đủ trong một bước:

```bash
teleproxy generate-secret www.google.com
# stdout:  eecafe...7777772e676f6f676c652e636f6d
# stderr:  Secret for -S:  cafe...
#          Domain:         www.google.com
```

Dùng giá trị stdout trong liên kết `tg://proxy` và giá trị `Secret for -S` với cờ `-S`.

## TLS Backend tùy chỉnh (TCP Splitting) {#custom-tls-backend-tcp-splitting}

Thay vì mô phỏng một website công khai, bạn có thể chạy web server riêng phía sau Teleproxy với chứng chỉ TLS thật. Khách truy cập không phải proxy sẽ thấy một website HTTPS hoạt động đầy đủ - server hoàn toàn không thể phân biệt với web server bình thường.

Cách hoạt động:

- Teleproxy lắng nghe trên port 443
- nginx chạy trên port không chuẩn (ví dụ: 8443) với chứng chỉ hợp lệ
- Bản ghi DNS A của domain trỏ đến máy chủ Teleproxy
- Client proxy hợp lệ kết nối bình thường; tất cả lưu lượng khác được chuyển tiếp đến nginx

**Kháng thăm dò chủ động:** Mọi kết nối không vượt qua xác thực - sai secret, timestamp hết hạn, SNI không xác định, handshake bị phát lại, ClientHello không đúng định dạng, hoặc lưu lượng không phải TLS - đều được chuyển tiếp minh bạch đến backend. Bất kỳ ai thăm dò đều thấy một website HTTPS thật.

Yêu cầu:

- Backend phải hỗ trợ TLS 1.3 (được kiểm tra khi khởi động)
- Giá trị `-D` phải là hostname, không phải IP (TLS SNI không hỗ trợ IP theo RFC 6066)

Ví dụ thiết lập với nginx:

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

Thêm bản ghi `/etc/hosts` nếu nginx chỉ lắng nghe trên loopback:

```
127.0.0.1 mywebsite.com
```

Chạy với domain và port:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D mywebsite.com:8443 --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

!!! note
    Sử dụng certbot với DNS-01 challenge để gia hạn chứng chỉ - HTTP-01 sẽ không hoạt động vì Teleproxy chiếm port 443.

## Thay đổi kích thước bản ghi động (DRS)

Kết nối TLS tự động sử dụng kích thước bản ghi tăng dần mô phỏng các HTTPS server thật (Cloudflare, Go, Caddy): bản ghi nhỏ bằng MTU trong giai đoạn TCP slow-start (~1450 byte), tăng dần lên ~4096 byte, rồi đến tối đa TLS payload (~16144 byte). Điều này đánh bại phân tích thống kê lưu lượng nhận dạng proxy qua kích thước bản ghi đồng nhất.

Không cần cấu hình - DRS tự động kích hoạt cho tất cả kết nối TLS.

## Chế độ DD (Padding ngẫu nhiên)

Đối với ISP phát hiện MTProto qua kích thước gói tin, padding ngẫu nhiên sẽ được thêm vào.

Thiết lập phía client: thêm tiền tố `dd` vào secret (`cafe...babe` thành `ddcafe...babe`).

Thiết lập phía server: dùng `-R` để chỉ chấp nhận client có padding.
