---
description: "Запуск E2E-тестов Teleproxy, Docker-интеграционных тестов и фаззинга. Выполнение тестов в CI и локально."
---

# Тестирование

Teleproxy включает полный набор тестов. Подробности см. в [TESTING.md](https://github.com/teleproxy/teleproxy/blob/main/TESTING.md) в репозитории.

## Запуск тестов (Docker)

```bash
make test
```

Собирает образ прокси, образ тест-раннера, запускает оба и выполняет проверки подключений. Если переменная `TELEPROXY_SECRET` не задана, генерируется случайный секрет.

## Запуск тестов (локально)

```bash
pip install -r tests/requirements.txt
export TELEPROXY_HOST=localhost
export TELEPROXY_PORT=443
python3 tests/test_proxy.py
```

## Набор тестов

- **HTTP-статистика**: доступность эндпоинта статистики
- **Метрики Prometheus**: валидность формата exposition
- **Порт MTProto**: приём TCP-подключений
- **E2E-тесты**: подключение реального Telegram-клиента (Telethon) через прокси
- **Фаззинг**: harness-ы libFuzzer с AddressSanitizer для парсеров протоколов

## Фаззинг

Требуется Clang:

```bash
make fuzz CC=clang
make fuzz-run
make fuzz-run FUZZ_DURATION=300  # произвольная длительность
```

Seed-корпус в `fuzz/corpus/`. Фаззеры запускаются автоматически в CI.

## Устранение проблем

- **Таймаут**: проверьте сеть — MTProto-прокси могут быть заблокированы некоторыми провайдерами
- **Порт занят**: тесты по умолчанию используют порты 18443/18888
