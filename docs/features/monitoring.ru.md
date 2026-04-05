---
description: "Встроенный HTTP-эндпоинт статистики и метрики Prometheus для Teleproxy. Отслеживание подключений, трафика, посекретной нагрузки и состояния DC."
---

# Мониторинг

## HTTP-эндпоинт статистики

```bash
curl http://localhost:8888/stats
```

Требует флаг `--http-stats`. Доступен только из приватных сетей (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Расширение сетевого доступа

Для доступа из overlay/VPN-сетей (Tailscale, WireGuard, Netbird) используйте `--stats-allow-net`:

```bash
./teleproxy ... --stats-allow-net 100.64.0.0/10 --stats-allow-net fd00::/8
```

Флаг можно указывать несколько раз для нескольких диапазонов. Поддерживается CIDR-нотация IPv4 и IPv6.

## Метрики Prometheus

```bash
curl http://localhost:8888/metrics
```

Возвращает метрики в формате Prometheus exposition на том же порту статистики. Включает посекретные метрики при настроенных метках.

Доступные метрики: количество подключений, подключения по секретам, счётчики отклонений и отклонения по IP ACL.

### Зонды задержки DC

При включении teleproxy периодически выполняет TCP-рукопожатие со всеми 5 дата-центрами Telegram и публикует результаты в виде гистограммы Prometheus:

```bash
# Включение с интервалом 30 секунд
./teleproxy ... --dc-probe-interval 30
```

Публикуемые метрики:

| Метрика | Тип | Описание |
|---------|-----|----------|
| `teleproxy_dc_latency_seconds` | histogram | RTT TCP-рукопожатия по DC (метки: `dc="1"`..`dc="5"`) |
| `teleproxy_dc_probe_failures_total` | counter | Неудачные попытки зондирования по DC |
| `teleproxy_dc_latency_last_seconds` | gauge | Последняя измеренная задержка по DC |

Текстовый эндпоинт `/stats` содержит соответствующие поля: `dc_probe_interval`, `dcN_probe_latency_last`, `dcN_probe_latency_avg`, `dcN_probe_count`, `dcN_probe_failures`.

По умолчанию отключено. Задайте `dc_probe_interval` в TOML-конфиге или используйте переменную окружения `DC_PROBE_INTERVAL` в Docker.

## Дашборд Grafana {#grafana-dashboard}

Импортируйте [готовый дашборд](https://github.com/teleproxy/teleproxy/blob/main/dashboards/teleproxy.json) в Grafana:

1. Скачайте `dashboards/teleproxy.json` из репозитория
2. В Grafana: Dashboards → Import → Upload JSON file
3. Выберите источник данных Prometheus

Дашборд охватывает подключения, посекретную нагрузку, частоту отклонений, связность с DC и утилизацию ресурсов.

## Проверка здоровья

Docker-контейнеры включают встроенный мониторинг здоровья через эндпоинт статистики. Проверка:

```bash
docker ps  # столбец STATUS показывает состояние здоровья
```
