# Plan

## Goal

Опубликовать Linux-версию `tg-ws-proxy` в GitHub и довести проект до рабочего состояния для Telegram Desktop на Linux.

## Environment

- ОС: `Linux Mint 22.3 (Zena)`
- База: `Ubuntu noble`
- Архитектура: `x86_64`
- Основное окружение разработки и запуска: `conda` env `p313`
- Python для сервиса: `/home/alex/miniconda3/envs/p313/bin/python`

## Status

- `done`: собран Linux MVP прокси
- `done`: подготовка репозитория к публикации
- `done`: первичная публикация в GitHub
- `in_progress`: подготовка к проверке с Telegram Desktop на Linux

## Work Plan

1. Подготовить репозиторий к публикации.
   Статус: `done`
   Результат: локальный git-репозиторий, `.gitignore`, описанный план, чистое дерево файлов.

2. Опубликовать проект в GitHub.
   Статус: `done`
   Результат: настроенный `origin`, основной бранч `main`, первый push в `AlexZ1967/TG_proxy`.

3. Проверить установку и запуск на Linux.
   Статус: `pending`
   Результат: подтвержденный запуск в `conda` env `p313`, проверка `tg://socks` и ручной настройки Telegram Desktop.

4. Подготовить автозапуск через `systemd --user`.
   Статус: `pending`
   Результат: установленный unit с привязкой к интерпретатору из `conda` env `p313` и проверка через `systemctl --user status`.

5. Проверить работу с реальным Telegram Desktop.
   Статус: `pending`
   Результат: подтверждение, что трафик Telegram идет через локальный SOCKS5 и нет явных регрессий.

6. Ужесточить и стабилизировать проект.
   Статус: `pending`
   Результат: решение по TLS verification, дополнительным DC mapping, логированию и обработке ошибок.

## Immediate Next Step

Проверить работу прокси с реальным Telegram Desktop на Linux и подтвердить рабочую схему подключения.
