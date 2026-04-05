---
description: "Запуск Teleproxy как systemd-сервиса с автоматическим перезапуском, лимитами ресурсов и усилением безопасности. Полный unit-файл."
---

# Systemd

Рекомендуемый способ настройки systemd — через [скрипт установки](../getting-started/installation.md#one-liner-install-recommended), который создаёт сервис, конфигурационный файл и пользователя автоматически.

Разделы ниже предназначены для ручной настройки или справки.

## Файл сервиса

Создайте `/etc/systemd/system/teleproxy.service`:

```ini
[Unit]
Description=Teleproxy MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=teleproxy
ExecStart=/usr/local/bin/teleproxy --config /etc/teleproxy/config.toml -p 8888
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/teleproxy

[Install]
WantedBy=multi-user.target
```

## Конфигурационный файл

Создайте `/etc/teleproxy/config.toml`:

```toml
port = 443
http_stats = true
direct = true
workers = 1

[[secret]]
key = "your-32-hex-digit-secret-here"
label = "default"
```

Сгенерировать секрет: `teleproxy generate-secret`.

## Настройка

```bash
systemctl daemon-reload
systemctl enable --now teleproxy
systemctl status teleproxy
```

## Перезагрузка

Отредактируйте конфигурационный файл и перезагрузите без разрыва подключений:

```bash
systemctl reload teleproxy
```

Отправляет SIGHUP, который перезагружает секреты и IP ACL из конфигурационного файла.

## Устаревший вариант (только CLI)

Если конфигурационный файл не используется, передавайте флаги напрямую:

```ini
ExecStart=/usr/local/bin/teleproxy -S <secret> -H 443 -p 8888 --http-stats --direct
```
