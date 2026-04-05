---
description: "Chạy Teleproxy trong Docker chỉ với một lệnh. Tự động tạo secret và in link kết nối. Không cần file cấu hình."
---

# Docker Quick Start

Cách đơn giản nhất để chạy Teleproxy - không cần cấu hình gì:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Container tự động:

- Tải cấu hình proxy mới nhất từ Telegram
- Tạo secret ngẫu nhiên nếu không được cung cấp
- Khởi chạy proxy trên port 443

Liên kết kết nối được in trong log:

```bash
docker logs teleproxy
# ===== Connection Links =====
# https://t.me/proxy?server=203.0.113.1&port=443&secret=eecafe...
# =============================
```

Nếu phát hiện IP công khai thất bại (ví dụ: nằm sau tường lửa doanh nghiệp), hãy đặt biến môi trường `EXTERNAL_IP` một cách tường minh.

## Với Fake-TLS (Chế độ EE)

Bọc lưu lượng MTProto trong TLS handshake thật, khiến nó không thể phân biệt với HTTPS bình thường:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Chế độ Direct-to-DC

Bỏ qua các máy chủ trung gian của Telegram và định tuyến client trực tiếp đến datacenter gần nhất:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Tag có sẵn

**GitHub Container Registry:**

- `ghcr.io/teleproxy/teleproxy:latest`
- `ghcr.io/teleproxy/teleproxy:{version}` (ví dụ: `4.7.0`, `4.7`, `4`)

**Docker Hub:**

- `rkline0x/teleproxy:latest`
- `rkline0x/teleproxy:{version}` (ví dụ: `4.7.0`, `4.7`, `4`)

Dùng Docker Hub nếu môi trường của bạn gặp khó khăn khi pull từ ghcr.io (ví dụ: MikroTik RouterOS containers).

## Build image của riêng bạn

```bash
docker build -t teleproxy .
docker run -d --name teleproxy -p 443:443 -p 8888:8888 teleproxy
docker logs teleproxy 2>&1 | grep "Generated secret"
```

## Cập nhật

Pull image mới nhất và tạo lại container:

```bash
docker pull ghcr.io/teleproxy/teleproxy:latest
docker rm -f teleproxy
docker run -d --name teleproxy -p 443:443 -p 8888:8888 --restart unless-stopped ghcr.io/teleproxy/teleproxy:latest
```

Với Docker Compose:

```bash
docker compose pull
docker compose up -d
```
