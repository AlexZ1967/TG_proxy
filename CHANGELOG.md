# Changelog

Формат основан на `Keep a Changelog`.

## [0.3.0] - Unreleased

### Changed

- Открыт следующий минорный цикл разработки после релиза `0.2.0`.
- Открытие `tg://socks` переведено на desktop-first поведение: сначала `gio open`/`xdg-open`, чтобы кнопка `Open Telegram` открывала Telegram Desktop, а не браузер.

## [0.2.0] - 2026-03-06

### Added

- Лёгкий GUI на GTK3 (`PyGObject`) для ручного запуска и остановки прокси, сохранения конфига и просмотра хвоста логов.
- Portable launcher-скрипты `run_proxy.sh` и `run_gui.sh`.

### Changed

- Обновлён пользовательский интерфейс: GUI переведён с `tkinter` на GTK3 для нормальных системных шрифтов и нативных виджетов Linux Mint.
- Проект переведён с `conda`-specific workflow на переносимый запуск через launcher'ы и обычный Python `3.10+`.
- Улучшено логирование сетевых ошибок: теперь для `Network is unreachable` пишутся этап и `dst:port`, а passthrough connect логируется отдельно без общего `unexpected error`.
- Шумные IPv6 passthrough-сбои с `Errno 101` понижены до `DEBUG`, чтобы не засорять обычный лог при рабочем IPv4/WS-трафике.
- Для известных DC без WS-маршрута логика переведена на тихий TCP fallback без `unknown DC`-шума.

## [0.1.0] - 2026-03-06

### Added

- Первый Linux MVP для `tg-ws-proxy`.
- Локальный SOCKS5-прокси с WebSocket bridge для Telegram Desktop.
- XDG-конфиг и XDG-логи.
- CLI-команды `run`, `init-config`, `open-in-telegram`, `paths`.
- Базовая упаковка через `pyproject.toml`.
- `systemd --user` unit.
- План работ в `PLAN.md`.
