---
description: "Маршрутизация исходящих подключений Teleproxy через SOCKS5-прокси при блокировке IP сервера Telegram или для сокрытия источника."
---

# Upstream-прокси SOCKS5

Маршрутизация всех исходящих подключений к DC Telegram через SOCKS5-прокси:

```
Клиент -> Teleproxy -> SOCKS5-прокси -> Telegram DC
```

Полезно, когда IP сервера заблокирован Telegram или когда нужно скрыть источник сервера от сети Telegram.

## Конфигурация

### Docker

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e SOCKS5_PROXY=socks5://proxy.example.com:1080 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

С аутентификацией:

```bash
-e SOCKS5_PROXY=socks5://user:pass@proxy.example.com:1080
```

### TOML-конфиг

```toml
socks5 = "socks5://proxy.example.com:1080"
```

### Флаг CLI

```bash
./teleproxy --direct --socks5 socks5://user:pass@proxy.example.com:1080 -H 443 -S <secret> ...
```

## Формат URL

Поддерживаются две схемы:

| Схема | Резолв DNS | Применение |
|-------|-----------|------------|
| `socks5://` | Локальный (Teleproxy резолвит адреса DC) | По умолчанию — работает с большинством SOCKS5-прокси |
| `socks5h://` | Удалённый (SOCKS5-прокси резолвит хостнеймы) | Для сценариев с повышенной приватностью, где DNS не должен утекать |

Полный формат: `socks5[h]://[user:pass@]host:port`

## Аутентификация

- **Анонимная**: `socks5://host:port` — без учётных данных, прокси должен разрешать неаутентифицированный доступ
- **Логин/пароль**: `socks5://user:pass@host:port` — аутентификация по RFC 1929

## Мониторинг

Статистика подключений SOCKS5 доступна на эндпоинтах:

`/stats` (табуляция):

```
socks5_enabled	1
socks5_connects_attempted	42
socks5_connects_succeeded	40
socks5_connects_failed	2
```

`/metrics` (Prometheus):

```
teleproxy_socks5_connects_attempted_total 42
teleproxy_socks5_connects_succeeded_total 40
teleproxy_socks5_connects_failed_total 2
```

## Примечания

- Работает как в прямом режиме, так и в режиме ME relay
- Не перезагружается через SIGHUP — для смены SOCKS5-прокси требуется перезапуск
- IPv6-адреса назначения поддерживаются, если SOCKS5-прокси их поддерживает
