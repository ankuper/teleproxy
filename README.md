<!-- Язык / Language: [Русский](#teleproxy) · [English](#teleproxy-en) -->

<a name="teleproxy"></a>
# teleproxy

**Анти-DPI прокси для Telegram — серверная сторона Type3 (mtProxy3).**

Туннелирует MTProto внутри обычного HTTPS-потока: для DPI/ТСПУ это просто
веб-трафик, а не Telegram. Это сервер, к которому подключаются клиенты-форки
**T3ChatM**. Сам протокол и его реализация — в
[teleproto3](https://github.com/ankuper/teleproto3).

## Поднять свой узел

Нужен VPS, домен и TLS (обычно nginx на `:443` терминирует TLS и проксирует на
teleproxy). После запуска сервер выдаёт Type3-секрет / `tg://proxy?...`-ссылку —
её и раздаёшь пользователям. Детали сборки и конфигурации — в репозитории
(`docs/`, скрипты деплоя).

## Просто пользоваться (без своего сервера)

Скачай готовый клиент — прокси уже встроен, настраивать нечего:
→ **[T3ChatM — клиенты](https://github.com/ankuper/tdesktop/releases/latest)**
(Android / iOS / Desktop)

## Протокол

Type3: MTProto в HTTP-stream поверх TLS — для DPI неотличимо от обычного HTTPS.
Спецификация и библиотека: [teleproto3](https://github.com/ankuper/teleproto3).

---

<a name="teleproxy-en"></a>
# teleproxy (English)

**Anti-DPI proxy for Telegram — the server side of Type3 (mtProxy3).**

Tunnels MTProto inside an ordinary HTTPS stream: to DPI it's just web traffic,
not Telegram. This is the server the **T3ChatM** client forks connect to. The
protocol and its implementation live in
[teleproto3](https://github.com/ankuper/teleproto3).

## Run your own node

You need a VPS, a domain and TLS (typically nginx on `:443` terminating TLS and
proxying to teleproxy). On start the server emits a Type3 secret / `tg://proxy?...`
link to hand out. Build and config details are in the repository (`docs/`, deploy
scripts).

## Just use it (no server)

Download a ready client — the proxy is built in:
→ **[T3ChatM clients](https://github.com/ankuper/tdesktop/releases/latest)**
(Android / iOS / Desktop)

## Protocol

Type3: MTProto in an HTTP-stream over TLS — indistinguishable from HTTPS to DPI.
Spec and library: [teleproto3](https://github.com/ankuper/teleproto3).

---

## Поддержать инфраструктуру · Support

Поддержать сервера (TON):

`UQAYS0k0PEky8BUE1Rij90v8-CmOWsuhAzdLTHOzYC-qZ0pV`

Support the infrastructure (TON) — address above.

---

> Форк Telegram MTProxy с добавленным Type3-транспортом. Независимый проект,
> не аффилирован с Telegram Messenger.
> Fork of Telegram MTProxy with Type3 transport added. Independent project,
> not affiliated with Telegram Messenger.
