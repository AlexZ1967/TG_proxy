# Roadmap

## Scope

Следующий этап проекта: повысить устойчивость Telegram Desktop при замедлениях и блокировках в России, не ломая текущий рабочий сценарий `Telegram Desktop -> local SOCKS5 -> WSS`.

## Research Summary

- Telegram Desktop официально поддерживает `SOCKS5` и `MTProto`, а также умеет auto-switch между несколькими прокси в клиенте.
- Telegram рекомендует использовать доверенные proxy endpoint'ы и для MTProxy опирается на официальный `MTProxy` server, а не на произвольные совместимые реализации.
- По свежим сообщениям об ограничениях в России на февраль 2026 года, блокировки и замедления затрагивают не только IP, но и DNS/DPI, поэтому одного маршрута недостаточно.
- Практический вывод для проекта: не писать собственный MTProto transport с нуля внутри `tg_ws_proxy.py`, а добавить резервный маршрут через официальный MTProxy или внешний MTProto endpoint.

Источники:
- `core.telegram.org/proxy`
- `github.com/TelegramMessenger/MTProxy`
- `github.com/telegramdesktop/tdesktop/issues/25423`
- `techradar.com/.../russia-is-using-dns-and-dpi-to-block-youtube-telegram-and-whatsapp...`

## Engineering Decision

Новый минорный цикл должен идти по пути интеграции, а не переписывания протокола:

- `WSS local proxy` остаётся основным transport.
- `MTProto` добавляется как backup profile.
- Для `MTProto` используем один из двух поддерживаемых режимов:
  - внешний MTProto proxy, который пользователь уже знает;
  - локально управляемый sidecar на базе официального `MTProxy`.
- Самописную реализацию MTProto transport в Python не делать, пока не появится жёсткое техническое основание. Это сильно увеличит объём криптографии, обфускации, совместимости и сопровождения.

## Milestones

### M1. Profiles and Switching

Цель: дать пользователю быстрый и понятный выбор transport profile без ручной правки конфига.

Задачи:
- Перевести конфиг от одного активного набора параметров к списку профилей.
- Добавить profile types:
  - `wss_local`
  - `mtproto_external`
  - `mtproto_sidecar`
  - `direct_disabled` как явный режим без proxy-launch.
- Добавить `active_profile` и человекочитаемые имена профилей.
- В GUI добавить selector текущего профиля и статус текущего маршрута.
- В лог писать активный профиль при старте.

Definition of done:
- Пользователь может из GUI переключаться между профилями без ручного редактирования JSON.
- После перезапуска GUI выбранный профиль сохраняется.
- Для каждого профиля понятно, какой endpoint реально используется.

### M2. External MTProto Backup

Цель: дать резервный маршрут без разворачивания локального MTProxy.

Задачи:
- Добавить в конфиг профиль `mtproto_external`:
  - `server`
  - `port`
  - `secret`
  - `label`
- Добавить кнопку `Open Telegram with Profile` или эквивалентный action, который открывает Telegram на нужном proxy link:
  - `tg://proxy?...` для MTProto
  - `tg://socks?...` для текущего локального WSS/SOCKS.
- Добавить в GUI экспорт и копирование proxy link для активного профиля.
- Добавить быстрый self-check полей MTProto профиля до запуска.

Definition of done:
- Пользователь может завести внешний MTProto proxy в GUI.
- Telegram Desktop открывается на корректном `tg://proxy` link.
- В проекте не появляется собственная реализация MTProto transport.

### M3. Local MTProxy Sidecar

Цель: дать полностью локальный backup transport без ручного сопровождения отдельного MTProxy руками.

Задачи:
- Добавить интеграционный режим с официальным `TelegramMessenger/MTProxy`.
- Поддержать два способа запуска:
  - локальный бинарник `mtproto-proxy`
  - docker/podman container как fallback.
- Добавить helper-команду подготовки sidecar:
  - проверить наличие бинарника или контейнерного runtime;
  - подсказать, где взять `proxy-secret` и `proxy-multi.conf`;
  - сгенерировать локальный secret.
- Добавить управление lifecycle sidecar из GUI:
  - `Start sidecar`
  - `Stop sidecar`
  - `Show status`
- Добавить отдельный локальный порт sidecar, чтобы не конфликтовать с `127.0.0.1:1080`.

Definition of done:
- Sidecar поднимается и останавливается из проекта.
- Telegram Desktop можно перевести на локальный MTProto endpoint без ручного shell workflow.
- В документации есть поддерживаемый сценарий для Linux Mint.

### M4. Diagnostics

Цель: сократить время на разбор проблем с маршрутизацией.

Задачи:
- Добавить в GUI и CLI короткий self-test:
  - DNS resolve
  - IPv4 connect
  - IPv6 availability
  - WSS handshake к рабочему endpoint
  - sidecar availability, если выбран `mtproto_sidecar`
- Ввести понятные статусы:
  - `WSS OK`
  - `TCP fallback only`
  - `DNS issue`
  - `IPv6 unavailable`
  - `MTProxy unavailable`
- Логировать причину переключения профиля и неудачного health-check.

Definition of done:
- Пользователь может понять, почему профиль не работает, без чтения сырых traceback.
- `proxy.log` и GUI показывают один и тот же диагноз.

### M5. Network Hardening

Цель: уменьшить чувствительность к особенностям маршрута у конкретного провайдера.

Задачи:
- Добавить опцию предпочтения transport family:
  - `auto`
  - `prefer_ipv4`
  - `prefer_ipv6`
- Добавить диагностический DNS override только для self-test, без подмены всей системной сети.
- Развести INFO и DEBUG логирование ещё жёстче, чтобы обычный лог оставался читаемым.
- Добавить счётчики по профилям и типам сбоев.

Definition of done:
- Пользователь может быстро проверить гипотезу “ломается DNS” или “ломается IPv6”.
- Обычный режим остаётся тихим, а диагностика не требует правки кода.

## Recommended Implementation Order

1. `M1 Profiles and Switching`
2. `M2 External MTProto Backup`
3. `M4 Diagnostics`
4. `M3 Local MTProxy Sidecar`
5. `M5 Network Hardening`

Причина такого порядка:
- `M1` и `M2` дают наибольшую практическую пользу с минимальным риском.
- `M4` нужен до sidecar, иначе отладка будет слепой.
- `M3` полезен, но тяжелее в поддержке и packaging.
- `M5` стоит делать уже после появления нескольких реальных профилей.

## Explicit Non-Goals For Now

- Не реализовывать MTProto transport с нуля внутри Python proxy.
- Не делать system-wide VPN или system-wide DNS manager.
- Не включать постоянный `systemd`-автозапуск как основной сценарий.
- Не оптимизировать calls/video отдельно до стабилизации текстового и media traffic.
