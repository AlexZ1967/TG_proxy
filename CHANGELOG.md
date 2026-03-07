# Changelog

Формат основан на `Keep a Changelog`.

## [0.4.0] - Unreleased

### Added

- Новый формат `config.json`: `active_profile + profiles` вместо одного плоского набора параметров.
- GUI selector активного профиля с поддержкой `wss_local`, `mtproto_external`, `mtproto_sidecar` и `direct_disabled`.
- Общий helper для `tg://socks` и `tg://proxy`, чтобы `Open Telegram` мог работать от активного профиля.
- Кнопка `Copy Link` в GUI для копирования готового `tg://socks` / `tg://proxy` link от активного профиля.
- CLI-команда `check-profile` и кнопка `Check Profile` в GUI для проверки активного маршрута.

### Changed

- Открыт следующий минорный цикл разработки после релиза `0.3.0`.
- В проект добавлен формализованный roadmap следующего этапа: backup через внешний или sidecar `MTProxy`, профили переключения и сетевая диагностика.
- GUI и CLI переведены на profile-aware конфиг с совместимой миграцией legacy-JSON без `profiles`.
- Для MTProto-профилей добавлена ранняя валидация `server:port` перед открытием Telegram или копированием proxy link.
- Для `mtproto_external` добавлен практический self-check: resolve и TCP probe до target endpoint.
- Self-check переведён на диагностические статусы с деталями маршрута: `WSS OK`, `DNS issue`, `TCP fallback only`, `IPv6 unavailable`, `MTProxy unavailable`.

## [0.3.0] - 2026-03-06

### Added

- `.desktop` launcher для GTK GUI под Linux Mint.
- Русское описание и tooltip для опции `Verify TLS` в GUI.

### Changed

- Открытие `tg://socks` переведено на desktop-first поведение: сначала `gio open`/`xdg-open`, чтобы кнопка `Open Telegram` открывала Telegram Desktop, а не браузер.
- План обновлён под фактический рабочий режим: ручной GUI вместо постоянного `systemd`, следующий шаг смещён на desktop-интеграцию под Linux Mint.
- GUI теперь автоматически запускает proxy при открытии окна и автоматически останавливает свой процесс proxy при закрытии.
- В стартовый лог добавлен явный статус `TLS verification: enabled/disabled`.

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
