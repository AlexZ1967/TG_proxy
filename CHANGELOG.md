# Changelog

Формат основан на `Keep a Changelog`.

## [0.2.0] - Unreleased

### Added

- Лёгкий GUI на `tkinter` для ручного запуска и остановки прокси, сохранения конфига и просмотра хвоста логов.
- Portable launcher-скрипты `run_proxy.sh` и `run_gui.sh`.

### Changed

- Открыт следующий минорный цикл разработки.
- Все новые изменения проекта должны фиксироваться в этом файле.
- Проект переведён с `conda`-specific workflow на переносимый запуск через launcher'ы и обычный Python `3.10+`.

## [0.1.0] - 2026-03-06

### Added

- Первый Linux MVP для `tg-ws-proxy`.
- Локальный SOCKS5-прокси с WebSocket bridge для Telegram Desktop.
- XDG-конфиг и XDG-логи.
- CLI-команды `run`, `init-config`, `open-in-telegram`, `paths`.
- Базовая упаковка через `pyproject.toml`.
- `systemd --user` unit.
- План работ в `PLAN.md`.
