---
description: "Chạy Teleproxy trong vòng 2 phút. Tải secret, cấu hình và kết nối client Telegram đầu tiên qua proxy."
---

# Khởi động nhanh

Chạy Teleproxy trong vòng 2 phút.

## 1. Tải proxy secret

Khóa này dùng để mã hóa giao tiếp với máy chủ Telegram:

```bash
curl -fsSL https://core.telegram.org/getProxySecret -o proxy-secret
```

## 2. Tải cấu hình DC

File này chứa bản đồ địa chỉ các datacenter của Telegram. Nên cập nhật hàng ngày qua cron.

```bash
curl -fsSL https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```

## 3. Tạo client secret

Client sẽ sử dụng secret này để kết nối qua proxy của bạn:

```bash
./teleproxy generate-secret
```

Lưu lại kết quả - bạn sẽ cần nó cho bước tiếp theo và cho liên kết kết nối.

## 4. Chạy Teleproxy

```bash
./teleproxy \
  -u nobody \
  -p 8888 \
  -H 443 \
  -S <secret> \
  --http-stats \
  --aes-pwd proxy-secret proxy-multi.conf \
  -M 1
```

| Cờ | Mô tả |
|------|-------------|
| `-u nobody` | Bỏ quyền root sau khi bind port |
| `-H 443` | Port phía client (port mà người dùng kết nối đến) |
| `-p 8888` | Port thống kê HTTP - chỉ nên bind vào localhost hoặc mạng nội bộ |
| `-S <secret>` | Client secret. Lặp lại để dùng nhiều secret: `-S <s1> -S <s2>` |
| `--http-stats` | Bật trang thống kê HTTP tích hợp |
| `--aes-pwd proxy-secret` | Đường dẫn đến file proxy secret |
| `proxy-multi.conf` | Đường dẫn đến file cấu hình DC |
| `-M 1` | Số tiến trình worker |

## 5. Chia sẻ liên kết kết nối

Gửi cho người dùng một liên kết để tự động cấu hình Telegram:

```
tg://proxy?server=YOUR_SERVER_IP&port=443&secret=SECRET
```

Thay `YOUR_SERVER_IP` bằng IP công khai của máy chủ và `SECRET` bằng secret dạng hex từ bước 3.

## 6. Đăng ký với Telegram

Nhắn tin cho [@MTProxybot](https://t.me/MTProxybot) trên Telegram để đăng ký proxy và nhận proxy tag. Sau đó thêm vào lệnh khởi chạy:

```bash
./teleproxy ... -P <proxy-tag>
```

Proxy tag cho phép hiển thị kênh được tài trợ (bắt buộc theo yêu cầu của Telegram đối với proxy công khai) và giúp proxy của bạn được khám phá.

---

!!! tip
    Để thiết lập đơn giản nhất, hãy dùng [chế độ Direct-to-DC](../features/direct-mode.md) - không cần file cấu hình.

## Hoặc dùng Docker

Bỏ qua tất cả các bước trên chỉ với một lệnh:

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Container tự động tải file cấu hình, tạo secret ngẫu nhiên và in liên kết `tg://` vào log. Xem [Docker Quick Start](../docker/index.md) để biết chi tiết.
