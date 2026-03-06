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
- с helper-командой для `tg://socks`.

Документация проекта:
- план работ: [`PLAN.md`](PLAN.md)
- журнал изменений: [`CHANGELOG.md`](CHANGELOG.md)

Целевая среда проекта:
- `Linux Mint 22.3 (Zena)`
- `conda` env `p313`
- Python из `p313`: `/home/alex/miniconda3/envs/p313/bin/python`
- Текущая версия разработки: `0.2.0`

## Установка

```bash
conda activate p313
pip install -r requirements.txt
```

## Быстрый старт

Создать конфиг:

```bash
conda run -n p313 python tg_ws_proxy.py init-config
```

Узнать пути:

```bash
conda run -n p313 python tg_ws_proxy.py paths
```

Запустить прокси:

```bash
conda run -n p313 python tg_ws_proxy.py run
```

Открыть настройку прокси в Telegram Desktop:

```bash
conda run -n p313 python tg_ws_proxy.py open-in-telegram
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
  "listen_host": "127.0.0.1",
  "port": 1080,
  "dc_ip": [
    "2:149.154.167.220",
    "4:149.154.167.220"
  ],
  "verbose": false,
  "verify_tls": false
}
```

Лог:

`~/.local/state/tg-ws-proxy/proxy.log`

## systemd --user

Unit уже настроен под интерпретатор:

`/home/alex/miniconda3/envs/p313/bin/python`

Скопировать unit:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/tg-ws-proxy.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tg-ws-proxy.service
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
- Для всех проверок и запуска по умолчанию используется `conda` env `p313`.
