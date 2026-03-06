from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import socket as _socket
import ssl
import struct
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


APP_NAME = "tg-ws-proxy"
DEFAULT_PORT = 1080
DEFAULT_HOST = "127.0.0.1"
DEFAULT_CONFIG = {
    "listen_host": DEFAULT_HOST,
    "port": DEFAULT_PORT,
    "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
    "verbose": False,
    "verify_tls": False,
}

log = logging.getLogger(APP_NAME)


def _xdg_dir(env_name: str, fallback: str) -> Path:
    base = os.environ.get(env_name)
    if base:
        return Path(base).expanduser() / APP_NAME
    return Path.home() / fallback / APP_NAME


def config_dir() -> Path:
    return _xdg_dir("XDG_CONFIG_HOME", ".config")


def state_dir() -> Path:
    return _xdg_dir("XDG_STATE_HOME", ".local/state")


def config_path() -> Path:
    return config_dir() / "config.json"


def log_path() -> Path:
    return state_dir() / "proxy.log"


def ensure_dirs() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)
    state_dir().mkdir(parents=True, exist_ok=True)


def load_config(path: Optional[Path] = None) -> dict[str, Any]:
    cfg_path = path or config_path()
    if not cfg_path.exists():
        return dict(DEFAULT_CONFIG)

    with cfg_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Config at {cfg_path} must be a JSON object")

    merged = dict(DEFAULT_CONFIG)
    merged.update(data)
    return merged


def save_config(data: dict[str, Any], path: Optional[Path] = None) -> Path:
    cfg_path = path or config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with cfg_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return cfg_path


def build_telegram_url(port: int, host: str = DEFAULT_HOST) -> str:
    return f"tg://socks?server={host}&port={port}"


def open_in_telegram(port: int, host: str = DEFAULT_HOST) -> str:
    url = build_telegram_url(port, host)
    try:
        result = webbrowser.open(url)
        if result:
            return url
    except Exception:
        pass

    try:
        subprocess.run(["xdg-open", url], check=True)
        return url
    except Exception:
        return url


def setup_logging(verbose: bool, to_file: bool = True) -> None:
    ensure_dirs()
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-5s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setLevel(logging.DEBUG if verbose else logging.INFO)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if to_file:
        file_handler = logging.FileHandler(log_path(), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


_TG_RANGES = [
    (struct.unpack("!I", _socket.inet_aton("185.76.151.0"))[0],
     struct.unpack("!I", _socket.inet_aton("185.76.151.255"))[0]),
    (struct.unpack("!I", _socket.inet_aton("149.154.160.0"))[0],
     struct.unpack("!I", _socket.inet_aton("149.154.175.255"))[0]),
    (struct.unpack("!I", _socket.inet_aton("91.105.192.0"))[0],
     struct.unpack("!I", _socket.inet_aton("91.105.193.255"))[0]),
    (struct.unpack("!I", _socket.inet_aton("91.108.0.0"))[0],
     struct.unpack("!I", _socket.inet_aton("91.108.255.255"))[0]),
]

_IP_TO_DC: Dict[str, int] = {
    "149.154.175.50": 1,
    "149.154.175.51": 1,
    "149.154.175.54": 1,
    "149.154.167.41": 2,
    "149.154.167.50": 2,
    "149.154.167.51": 2,
    "149.154.167.220": 2,
    "149.154.175.100": 3,
    "149.154.175.101": 3,
    "149.154.167.91": 4,
    "149.154.167.92": 4,
    "91.108.56.100": 5,
    "91.108.56.126": 5,
    "91.108.56.101": 5,
    "91.108.56.116": 5,
    "91.105.192.100": 203,
    "149.154.167.151": 2,
    "149.154.167.223": 2,
    "149.154.166.120": 4,
    "149.154.166.121": 4,
}

_dc_opt: Dict[int, Optional[str]] = {}
_ws_blacklist: Set[Tuple[int, bool]] = set()
_dc_fail_until: Dict[Tuple[int, bool], float] = {}
_DC_FAIL_COOLDOWN = 60.0


def make_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class WsHandshakeError(Exception):
    def __init__(
        self,
        status_code: int,
        status_line: str,
        headers: Optional[dict[str, str]] = None,
        location: Optional[str] = None,
    ) -> None:
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    masked = bytearray(data)
    for i in range(len(masked)):
        masked[i] ^= mask[i & 3]
    return bytes(masked)


class RawWebSocket:
    OP_TEXT = 0x1
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.closed = False

    @classmethod
    async def connect(
        cls,
        ip: str,
        domain: str,
        ssl_ctx: ssl.SSLContext,
        path: str = "/apiws",
        timeout: float = 10.0,
    ) -> "RawWebSocket":
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ssl_ctx, server_hostname=domain),
            timeout=timeout,
        )

        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: binary\r\n"
            "Origin: https://web.telegram.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36\r\n"
            "\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()

        lines: list[str] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"", b"\n", b"\r\n"):
                break
            lines.append(line.decode("utf-8", errors="replace").strip())

        if not lines:
            writer.close()
            raise WsHandshakeError(0, "empty response")

        first = lines[0]
        parts = first.split(" ", 2)
        try:
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status_code = 0

        if status_code == 101:
            return cls(reader, writer)

        headers: dict[str, str] = {}
        for header_line in lines[1:]:
            if ":" not in header_line:
                continue
            key, value = header_line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        writer.close()
        raise WsHandshakeError(status_code, first, headers, headers.get("location"))

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionError("websocket closed")
        self.writer.write(self._build_frame(self.OP_BINARY, data, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self.closed:
            opcode, payload = await self._read_frame()
            if opcode == self.OP_CLOSE:
                self.closed = True
                return None
            if opcode == self.OP_PING:
                self.writer.write(self._build_frame(self.OP_PONG, payload, mask=True))
                await self.writer.drain()
                continue
            if opcode == self.OP_PONG:
                continue
            if opcode in (self.OP_TEXT, self.OP_BINARY):
                return payload
        return None

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.write(self._build_frame(self.OP_CLOSE, b"", mask=True))
            await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        header = bytearray([0x80 | opcode])
        length = len(data)
        mask_bit = 0x80 if mask else 0x00
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack(">Q", length))

        if not mask:
            return bytes(header) + data

        mask_key = os.urandom(4)
        header.extend(mask_key)
        return bytes(header) + _xor_mask(data, mask_key)

    async def _read_frame(self) -> Tuple[int, bytes]:
        header = await self.reader.readexactly(2)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        if length == 126:
            length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await self.reader.readexactly(8))[0]

        mask_key = await self.reader.readexactly(4) if masked else None
        payload = await self.reader.readexactly(length)
        if mask_key:
            payload = _xor_mask(payload, mask_key)
        return opcode, payload


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _is_telegram_ip(ip: str) -> bool:
    try:
        n = struct.unpack("!I", _socket.inet_aton(ip))[0]
        return any(lo <= n <= hi for lo, hi in _TG_RANGES)
    except OSError:
        return False


def _is_http_transport(data: bytes) -> bool:
    return data[:5] == b"POST " or data[:4] == b"GET " or data[:5] == b"HEAD "


def _dc_from_init(data: bytes) -> Tuple[Optional[int], bool]:
    try:
        key = bytes(data[8:40])
        iv = bytes(data[40:56])
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b"\x00" * 64) + encryptor.finalize()
        plain = bytes(a ^ b for a, b in zip(data[56:64], keystream[56:64]))
        proto = struct.unpack("<I", plain[0:4])[0]
        dc_raw = struct.unpack("<h", plain[4:6])[0]
        if proto in (0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD):
            dc = abs(dc_raw)
            if 1 <= dc <= 1000:
                return dc, dc_raw < 0
    except Exception as exc:
        log.debug("DC extraction failed: %s", exc)
    return None, False


def _ws_domains(dc: int, is_media: bool) -> List[str]:
    base = "telegram.org" if dc > 5 else "web.telegram.org"
    if is_media:
        return [f"kws{dc}-1.{base}", f"kws{dc}.{base}"]
    return [f"kws{dc}.{base}", f"kws{dc}-1.{base}"]


class Stats:
    def __init__(self) -> None:
        self.connections_total = 0
        self.connections_ws = 0
        self.connections_tcp_fallback = 0
        self.connections_http_rejected = 0
        self.connections_passthrough = 0
        self.ws_errors = 0
        self.bytes_up = 0
        self.bytes_down = 0

    def summary(self) -> str:
        return (
            f"total={self.connections_total} ws={self.connections_ws} "
            f"tcp_fb={self.connections_tcp_fallback} "
            f"http_skip={self.connections_http_rejected} "
            f"pass={self.connections_passthrough} "
            f"err={self.ws_errors} "
            f"up={_human_bytes(self.bytes_up)} down={_human_bytes(self.bytes_down)}"
        )


_stats = Stats()


async def _bridge_ws(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ws: RawWebSocket,
    label: str,
    dc: Optional[int] = None,
    dst: Optional[str] = None,
    port: Optional[int] = None,
    is_media: bool = False,
) -> None:
    up_bytes = 0
    down_bytes = 0
    started = time.monotonic()

    async def tcp_to_ws() -> None:
        nonlocal up_bytes
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            _stats.bytes_up += len(chunk)
            up_bytes += len(chunk)
            await ws.send(chunk)

    async def ws_to_tcp() -> None:
        nonlocal down_bytes
        while True:
            payload = await ws.recv()
            if payload is None:
                return
            _stats.bytes_down += len(payload)
            down_bytes += len(payload)
            writer.write(payload)
            await writer.drain()

    tasks = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except BaseException:
                pass
        await ws.close()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info(
            "[%s] DC%s%s (%s:%s) WS session closed: up=%s down=%s in %.1fs",
            label,
            dc or "?",
            "m" if is_media else "",
            dst or "?",
            port or "?",
            _human_bytes(up_bytes),
            _human_bytes(down_bytes),
            time.monotonic() - started,
        )


async def _bridge_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    remote_reader: asyncio.StreamReader,
    remote_writer: asyncio.StreamWriter,
) -> None:
    async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter, up: bool) -> None:
        while True:
            data = await src.read(65536)
            if not data:
                return
            if up:
                _stats.bytes_up += len(data)
            else:
                _stats.bytes_down += len(data)
            dst.write(data)
            await dst.drain()

    tasks = [
        asyncio.create_task(forward(reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, writer, False)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except BaseException:
                pass
        for stream in (writer, remote_writer):
            stream.close()
            try:
                await stream.wait_closed()
            except Exception:
                pass


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _socks5_reply(status: int) -> bytes:
    return bytes([0x05, status, 0x00, 0x01]) + b"\x00" * 6


async def _tcp_fallback(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    dst: str,
    port: int,
    init: bytes,
    label: str,
) -> bool:
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(dst, port),
            timeout=10,
        )
    except Exception as exc:
        log.warning("[%s] TCP fallback connect to %s:%d failed: %s", label, dst, port, exc)
        return False

    _stats.connections_tcp_fallback += 1
    remote_writer.write(init)
    await remote_writer.drain()
    await _bridge_tcp(reader, writer, remote_reader, remote_writer)
    return True


class ProxyServer:
    def __init__(
        self,
        listen_host: str,
        port: int,
        dc_opt: Dict[int, str],
        verify_tls: bool = False,
    ) -> None:
        self.listen_host = listen_host
        self.port = port
        self.dc_opt = dc_opt
        self.ssl_ctx = make_ssl_context(verify_tls)

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        _stats.connections_total += 1
        peer = writer.get_extra_info("peername")
        label = f"{peer[0]}:{peer[1]}" if peer else "?"

        try:
            greeting = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            if greeting[0] != 5:
                writer.close()
                return

            await reader.readexactly(greeting[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            request = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            _, cmd, _, atyp = request
            if cmd != 1:
                writer.write(_socks5_reply(0x07))
                await writer.drain()
                writer.close()
                return

            if atyp == 1:
                dst = _socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                length = (await reader.readexactly(1))[0]
                dst = (await reader.readexactly(length)).decode("utf-8", errors="replace")
            elif atyp == 4:
                dst = _socket.inet_ntop(_socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(_socks5_reply(0x08))
                await writer.drain()
                writer.close()
                return

            port = struct.unpack("!H", await reader.readexactly(2))[0]

            if not _is_telegram_ip(dst):
                _stats.connections_passthrough += 1
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(dst, port),
                    timeout=10,
                )
                writer.write(_socks5_reply(0x00))
                await writer.drain()
                tasks = [
                    asyncio.create_task(_pipe(reader, remote_writer)),
                    asyncio.create_task(_pipe(remote_reader, writer)),
                ]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                return

            writer.write(_socks5_reply(0x00))
            await writer.drain()

            init = await asyncio.wait_for(reader.readexactly(64), timeout=15)
            if _is_http_transport(init):
                _stats.connections_http_rejected += 1
                writer.close()
                return

            dc, is_media = _dc_from_init(init)
            if dc is None:
                dc = _IP_TO_DC.get(dst)

            if dc is None or dc not in self.dc_opt:
                log.warning("[%s] unknown DC for %s:%d -> TCP fallback", label, dst, port)
                await _tcp_fallback(reader, writer, dst, port, init, label)
                return

            dc_key = (dc, is_media)
            now = time.monotonic()
            if dc_key in _ws_blacklist or now < _dc_fail_until.get(dc_key, 0):
                await _tcp_fallback(reader, writer, dst, port, init, label)
                return

            ws = None
            ws_failed_redirect = False
            all_redirects = True
            target_ip = self.dc_opt[dc]

            for domain in _ws_domains(dc, is_media):
                log.info(
                    "[%s] DC%d%s (%s:%d) -> wss://%s/apiws via %s",
                    label,
                    dc,
                    "m" if is_media else "",
                    dst,
                    port,
                    domain,
                    target_ip,
                )
                try:
                    ws = await RawWebSocket.connect(target_ip, domain, self.ssl_ctx)
                    all_redirects = False
                    break
                except WsHandshakeError as exc:
                    _stats.ws_errors += 1
                    if exc.is_redirect:
                        ws_failed_redirect = True
                        log.warning("[%s] DC%d redirect from %s -> %s", label, dc, domain, exc.location or "?")
                    else:
                        all_redirects = False
                        log.warning("[%s] DC%d WS handshake failed: %s", label, dc, exc.status_line)
                except Exception as exc:
                    _stats.ws_errors += 1
                    all_redirects = False
                    log.warning("[%s] DC%d WS connect failed: %s", label, dc, exc)

            if ws is None:
                if ws_failed_redirect and all_redirects:
                    _ws_blacklist.add(dc_key)
                else:
                    _dc_fail_until[dc_key] = now + _DC_FAIL_COOLDOWN
                await _tcp_fallback(reader, writer, dst, port, init, label)
                return

            _dc_fail_until.pop(dc_key, None)
            _stats.connections_ws += 1
            await ws.send(init)
            await _bridge_ws(reader, writer, ws, label, dc, dst, port, is_media)
        except asyncio.IncompleteReadError:
            log.debug("[%s] client disconnected", label)
        except asyncio.TimeoutError:
            log.warning("[%s] timeout during SOCKS5 handshake", label)
        except Exception as exc:
            log.error("[%s] unexpected error: %s", label, exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self, stop_event: Optional[asyncio.Event] = None) -> None:
        global _dc_opt
        _dc_opt = self.dc_opt

        server = await asyncio.start_server(self.handle_client, self.listen_host, self.port)

        async def log_stats() -> None:
            while True:
                await asyncio.sleep(60)
                blacklisted = ", ".join(
                    f"DC{dc}{'m' if media else ''}"
                    for dc, media in sorted(_ws_blacklist)
                ) or "none"
                log.info("stats: %s | ws_bl: %s", _stats.summary(), blacklisted)

        asyncio.create_task(log_stats())

        if stop_event is not None:
            async def wait_stop() -> None:
                await stop_event.wait()
                server.close()
                await server.wait_closed()

            asyncio.create_task(wait_stop())

        log.info("Listening on %s:%d", self.listen_host, self.port)
        for dc, ip in sorted(self.dc_opt.items()):
            log.info("DC%d via %s", dc, ip)

        async with server:
            try:
                await server.serve_forever()
            except asyncio.CancelledError:
                pass


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    parsed: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ":" not in entry:
            raise ValueError(f"Invalid DC mapping {entry!r}; expected DC:IP")
        dc_s, ip_s = entry.split(":", 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError) as exc:
            raise ValueError(f"Invalid DC mapping {entry!r}") from exc
        parsed[dc_n] = ip_s
    return parsed


def normalize_runtime_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)

    if args.listen_host is not None:
        cfg["listen_host"] = args.listen_host
    if args.port is not None:
        cfg["port"] = args.port
    if args.dc_ip:
        cfg["dc_ip"] = args.dc_ip
    if args.verbose:
        cfg["verbose"] = True
    if args.verify_tls:
        cfg["verify_tls"] = True

    return cfg


async def run_from_config(cfg: dict[str, Any]) -> None:
    dc_opt = parse_dc_ip_list(list(cfg["dc_ip"]))
    server = ProxyServer(
        listen_host=str(cfg["listen_host"]),
        port=int(cfg["port"]),
        dc_opt=dc_opt,
        verify_tls=bool(cfg.get("verify_tls", False)),
    )
    await server.run()


def cmd_run(args: argparse.Namespace) -> int:
    cfg = normalize_runtime_config(args)
    setup_logging(bool(cfg.get("verbose", False)))
    log.info("Config path: %s", Path(args.config).expanduser() if args.config else config_path())
    log.info("Log path: %s", log_path())
    try:
        asyncio.run(run_from_config(cfg))
    except KeyboardInterrupt:
        log.info("Shutting down. Final stats: %s", _stats.summary())
    return 0


def cmd_init_config(args: argparse.Namespace) -> int:
    target = Path(args.config).expanduser() if args.config else config_path()
    if target.exists() and not args.force:
        print(f"Config already exists: {target}", file=sys.stderr)
        return 1
    written = save_config(dict(DEFAULT_CONFIG), target)
    print(written)
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    url = open_in_telegram(int(cfg["port"]), str(cfg["listen_host"]))
    print(url)
    return 0


def cmd_paths(_: argparse.Namespace) -> int:
    print(f"config={config_path()}")
    print(f"log={log_path()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Telegram Desktop WebSocket bridge proxy for Linux")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run the local SOCKS5 proxy")
    run_parser.add_argument("--config", help="Path to config.json")
    run_parser.add_argument("--listen-host", help="Listen host; default 127.0.0.1")
    run_parser.add_argument("--port", type=int, help="SOCKS5 listen port")
    run_parser.add_argument("--dc-ip", action="append", help="DC:IP mapping; may be passed multiple times")
    run_parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    run_parser.add_argument("--verify-tls", action="store_true", help="Enable TLS certificate validation")
    run_parser.set_defaults(func=cmd_run)

    init_parser = subparsers.add_parser("init-config", help="Write default XDG config")
    init_parser.add_argument("--config", help="Path to config.json")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing config")
    init_parser.set_defaults(func=cmd_init_config)

    open_parser = subparsers.add_parser("open-in-telegram", help="Try to open tg://socks link")
    open_parser.add_argument("--config", help="Path to config.json")
    open_parser.set_defaults(func=cmd_open)

    paths_parser = subparsers.add_parser("paths", help="Print XDG config and log paths")
    paths_parser.set_defaults(func=cmd_paths)

    parser.set_defaults(func=cmd_run, command="run", config=None, listen_host=None, port=None, dc_ip=None, verbose=False, verify_tls=False)
    return parser


def main() -> int:
    parser = build_parser()
    argv = sys.argv[1:]
    if argv and argv[0] not in {
        "run",
        "init-config",
        "open-in-telegram",
        "paths",
        "-h",
        "--help",
    }:
        argv = ["run", *argv]
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
