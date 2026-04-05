---
description: "Приём заголовков HAProxy PROXY protocol v1/v2 для сохранения реального IP клиента за балансировщиками нагрузки: HAProxy, nginx, AWS NLB."
---

# PROXY Protocol

Приём заголовков [HAProxy PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) v1 (текстовый) и v2 (бинарный) на клиентских слушателях. Необходим при работе за балансировщиком нагрузки (HAProxy, nginx, AWS NLB и др.), который передаёт IP клиента через PROXY protocol.

Без этого IP ACL, лимиты по IP, отслеживание IP по секретам и логирование будут видеть IP балансировщика вместо реального клиента.

```
Клиент -> Балансировщик (PROXY protocol) -> Teleproxy
```

## Конфигурация

### Docker

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e PROXY_PROTOCOL=true \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

### TOML-конфиг

```toml
proxy_protocol = true
```

### Флаг CLI

```bash
./teleproxy --direct --proxy-protocol -H 443 -S <secret> ...
```

## Как это работает

При включении каждое клиентское подключение должно начинаться с заголовка PROXY protocol до передачи любых данных MTProto/TLS. Прокси:

1. Читает заголовок PROXY (v1 или v2, автоопределение)
2. Извлекает реальный IP и порт клиента
3. Заменяет удалённый адрес подключения на извлечённые значения
4. Повторно проверяет IP ACL по реальному IP клиента
5. Продолжает обычное определение протокола (obfs2, fake-TLS и т.д.)

Подключения без валидного заголовка PROXY закрываются.

## Интеграция с IP ACL

При включённом PROXY protocol выполняются две проверки IP:

1. **При приёме подключения**: проверяется IP балансировщика. Если используется allowlist, добавьте в него адрес балансировщика.
2. **После заголовка PROXY**: реальный IP клиента проверяется по blocklist/allowlist.

Таким образом, IP ACL фильтруют реальных клиентов, а не балансировщик.

## PROXY protocol v2 LOCAL

Балансировщики отправляют команды LOCAL для проверок здоровья (без адресной нагрузки). Teleproxy принимает их и сохраняет исходный IP подключения.

## Мониторинг

Эндпоинт статистики (`/stats`):

```
proxy_protocol_enabled	1
proxy_protocol_connections	42
proxy_protocol_errors	3
```

Prometheus (`/metrics`):

```
teleproxy_proxy_protocol_enabled 1
teleproxy_proxy_protocol_connections_total 42
teleproxy_proxy_protocol_errors_total 3
```

## Примечания

- Поддерживаются v1 (текстовый) и v2 (бинарный) с автоопределением
- Не перезагружается через SIGHUP — для включения/отключения требуется перезапуск
- Порт статистики/HTTP-эндпоинта не затрагивается — заголовок ожидается только на клиентских слушателях
- IPv6-адреса клиентов в заголовках PROXY полностью поддерживаются
