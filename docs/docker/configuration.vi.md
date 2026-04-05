---
description: "Tham khảo đầy đủ các biến môi trường Docker cho Teleproxy: secret, domain TLS, kiểm soát truy cập, giám sát và giới hạn kết nối."
---

# Cấu hình Docker

## Biến môi trường

| Biến | Mặc định | Mô tả |
|----------|---------|-------------|
| `SECRET` | tự động tạo | Secret proxy - mỗi secret gồm 32 ký tự hex. Đơn lẻ, phân cách bằng dấu phẩy, hoặc có nhãn |
| `SECRET_1`...`SECRET_16` | — | Secret đánh số (kết hợp với `SECRET` nếu cả hai được đặt) |
| `SECRET_LABEL_1`...`SECRET_LABEL_16` | — | Nhãn cho secret đánh số |
| `SECRET_LIMIT_1`...`SECRET_LIMIT_16` | — | Giới hạn kết nối cho từng secret |
| `SECRET_QUOTA_1`...`SECRET_QUOTA_16` | — | Hạn mức dung lượng cho từng secret (ví dụ: `10737418240` cho 10 GB) |
| `SECRET_MAX_IPS_1`...`SECRET_MAX_IPS_16` | — | Giới hạn số IP duy nhất cho từng secret |
| `SECRET_EXPIRES_1`...`SECRET_EXPIRES_16` | — | Thời hạn cho từng secret (TOML datetime hoặc Unix timestamp) |
| `PORT` | 443 | Port kết nối client |
| `STATS_PORT` | 8888 | Port endpoint thống kê |
| `WORKERS` | 1 | Số tiến trình worker |
| `PROXY_TAG` | — | Tag từ @MTProxybot (quảng bá kênh) |
| `DIRECT_MODE` | false | Kết nối trực tiếp đến Telegram DC |
| `RANDOM_PADDING` | false | Chỉ bật padding ngẫu nhiên (chế độ DD) |
| `EXTERNAL_IP` | tự phát hiện | IP công khai cho môi trường NAT |
| `EE_DOMAIN` | — | Domain cho Fake-TLS. Chấp nhận `host:port` cho TLS backend tùy chỉnh |
| `IP_BLOCKLIST` | — | Đường dẫn đến file danh sách chặn CIDR |
| `IP_ALLOWLIST` | — | Đường dẫn đến file danh sách cho phép CIDR |
| `STATS_ALLOW_NET` | — | Các dải CIDR phân cách bằng dấu phẩy cho phép truy cập thống kê (ví dụ: `100.64.0.0/10,fd00::/8`) |
| `SOCKS5_PROXY` | — | Định tuyến kết nối upstream DC qua SOCKS5 proxy (`socks5://[user:pass@]host:port`) |
| `PROXY_PROTOCOL` | false | Bật PROXY protocol v1/v2 trên listener client (cho HAProxy/nginx/NLB) |
| `DC_OVERRIDE` | — | Ghi đè địa chỉ DC cho chế độ direct, phân cách bằng dấu phẩy (ví dụ: `2:1.2.3.4:443,2:5.6.7.8:443`) |
| `DC_PROBE_INTERVAL` | — | Số giây giữa các lần thăm dò sức khỏe DC (ví dụ: `30`). Tắt khi không đặt hoặc bằng `0` |

Tối đa 16 secret (giới hạn binary).

## Docker Compose

Thiết lập đơn giản:

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    restart: unless-stopped
```

Với file `.env`:

```bash
SECRET=your_secret_here
PROXY_TAG=your_proxy_tag_here
```

## Gắn Volume

Container lưu `proxy-multi.conf` trong `/opt/teleproxy/data/`. Gắn volume để lưu trữ cấu hình giữa các lần khởi động lại:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -v /path/to/host/data:/opt/teleproxy/data \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

`proxy-secret` được tích hợp sẵn vào image khi build - không cần volume cho file này.

Nếu không thể kết nối đến `core.telegram.org`, container sẽ dùng cấu hình đã lưu trong cache từ volume.

## Tự động làm mới cấu hình

Một cron job sẽ làm mới cấu hình DC của Telegram mỗi 6 giờ. Nó tải cấu hình mới nhất, kiểm tra tính hợp lệ, so sánh với cấu hình hiện tại, và hot-reload proxy qua `SIGHUP` nếu cấu hình thay đổi. Không cần thiết lập gì thêm.

## Kiểm tra sức khỏe

Docker image bao gồm health check tích hợp để giám sát endpoint thống kê:

```bash
docker ps  # Kiểm tra cột STATUS để xem trạng thái sức khỏe
```

Health check chạy mỗi 30 giây sau khoảng thời gian chờ khởi động 60 giây.
