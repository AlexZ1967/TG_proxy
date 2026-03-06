# tg-ws-proxy Linux MVP

Локальный SOCKS5-прокси для Telegram Desktop, который перенаправляет трафик через WebSocket к Telegram WebSocket endpoint'ам.

Схема:

```text
Telegram Desktop -> SOCKS5 127.0.0.1:1080 -> tg-ws-proxy -> WSS -> Telegram DC
```

Проект адаптирован под Linux:
- без Windows tray;
- с XDG-конфигом;
- с `systemd --user` unit;
- с helper-командой для `tg://socks`;
- с лёгким GUI на GTK3.

Документация проекта:
- план работ: [`PLAN.md`](PLAN.md)
- roadmap следующего этапа: [`ROADMAP.md`](ROADMAP.md)
- журнал изменений: [`CHANGELOG.md`](CHANGELOG.md)

Целевая среда проекта:
- `Linux Mint 22.3 (Zena)`
- Python `3.10+`
- переносимый запуск через shell launcher'ы
- Текущая версия разработки: `0.4.0`

## Установка

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Если вы не хотите использовать `venv`, можно запускать и через системный `python3`, если в нём уже установлена `cryptography`.

Для GUI нужен `PyGObject` (`python3-gi`). На Linux Mint он обычно уже есть в системном Python.

## Быстрый старт

Создать конфиг:

```bash
./run_proxy.sh init-config
```

Узнать пути:

```bash
./run_proxy.sh paths
```

Запустить прокси:

```bash
./run_proxy.sh run
```

Запустить лёгкий GUI:

```bash
./run_gui.sh
```

Кнопки `Open Telegram` и `Copy Link` теперь работают от активного профиля:
- `wss_local` -> `tg://socks`
- `mtproto_external` / `mtproto_sidecar` -> `tg://proxy`

Открыть настройку прокси в Telegram Desktop:

```bash
./run_proxy.sh open-in-telegram
```

Если `tg://` handler не сработал, настройте Telegram Desktop вручную:
- `Тип`: `SOCKS5`
- `Сервер`: `127.0.0.1`
- `Порт`: `1080`
- логин и пароль пустые

## Конфиг

По умолчанию:

`~/.config/tg-ws-proxy/config.json`

Пример:

```json
{
  "active_profile": "wss-local",
  "profiles": [
    {
      "id": "wss-local",
      "name": "Local WSS",
      "type": "wss_local",
      "listen_host": "127.0.0.1",
      "port": 1080,
      "dc_ip": [
        "2:149.154.167.220",
        "4:149.154.167.220"
      ],
      "verbose": false,
      "verify_tls": false
    },
    {
      "id": "mtproto-external",
      "name": "External MTProto",
      "type": "mtproto_external",
      "server": "",
      "port": 443,
      "secret": ""
    }
  ],
}
```

Плоский legacy-конфиг без `profiles` всё ещё читается и автоматически мигрируется в эту схему при следующем сохранении.

Лог:

`~/.local/state/tg-ws-proxy/proxy.log`

По умолчанию:
- активный профиль: `wss-local`
- WS-bridge включён для `DC2` и `DC4`
- остальные известные DC при необходимости уходят в обычный TCP fallback
- в GUI доступны также профили `mtproto-external`, `mtproto-sidecar` и `direct-disabled`

Если активный профиль не `wss_local`, локальный proxy-процесс через `run_proxy.sh run` не запускается. В таком случае используйте `Open Telegram` или явно выбирайте runnable-профиль:

```bash
./run_proxy.sh run --profile wss-local
```

## systemd --user

Unit теперь использует переносимый launcher [`run_proxy.sh`](run_proxy.sh).
Порядок выбора интерпретатора такой:
- `$TG_PROXY_PYTHON`, если переменная задана
- `./.venv/bin/python`, если локальное `venv` создано
- системный `python3`
- системный `python`

Скопировать unit:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/tg-ws-proxy.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tg-ws-proxy.service
```

Если нужен конкретный Python, можно перед запуском сервиса задать:

```bash
systemctl --user edit tg-ws-proxy.service
```

И добавить:

```ini
[Service]
Environment=TG_PROXY_PYTHON=/path/to/python
```

Проверить статус:

```bash
systemctl --user status tg-ws-proxy.service
journalctl --user -u tg-ws-proxy.service -f
```

## Замечания

- Базовая установка Linux-версии требует только `cryptography`.
- Проверка TLS по умолчанию отключена для совместимости с исходной реализацией. Для более строгого режима запускайте с `--verify-tls`.
- Локальный listen host по умолчанию `127.0.0.1`, чтобы не открыть SOCKS5 наружу.
- GUI сделан на GTK3 (`PyGObject`), чтобы использовать нативные системные шрифты и виджеты Linux Mint.
- `conda` можно использовать, но проект больше не привязан к нему.
- GUI теперь работает с profile-aware конфигом: активный профиль выбирается прямо в окне и сохраняется в `config.json`.
- Для MTProto-профилей GUI теперь умеет копировать готовый `tg://proxy` link и заранее валидирует `server:port`.

## Следующий этап

Следующий минорный цикл зафиксирован в [`ROADMAP.md`](ROADMAP.md).

Текущий технический курс:
- сохранить текущий локальный `WSS/SOCKS5` как основной режим;
- добавить backup profile через внешний `MTProto` proxy;
- при необходимости интегрировать локальный sidecar на базе официального `MTProxy`, а не писать собственную реализацию MTProto с нуля;
- добавить в GUI профили переключения и сетевую диагностику `DNS/IPv4/IPv6/WSS`.

## Linux Mint Launcher

Для запуска из меню Linux Mint можно установить `.desktop` launcher:

```bash
mkdir -p ~/.local/share/applications
cp desktop/tg-proxy.desktop ~/.local/share/applications/
update-desktop-database ~/.local/share/applications >/dev/null 2>&1 || true
```

После этого приложение `TG Proxy` появится в меню. Если проект лежит в другом каталоге, поправьте `Exec=` и `Path=` в [`desktop/tg-proxy.desktop`](desktop/tg-proxy.desktop).
