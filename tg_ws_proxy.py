from __future__ import annotations

import argparse
import asyncio
import base64
import copy
from dataclasses import dataclass
import json
import logging
import os
import shutil
import socket as _socket
import secrets
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


APP_NAME = "tg-ws-proxy"
DEFAULT_PORT = 1080
DEFAULT_HOST = "127.0.0.1"
PROFILE_WSS_LOCAL = "wss_local"
PROFILE_MTPROTO_EXTERNAL = "mtproto_external"
PROFILE_MTPROTO_SIDECAR = "mtproto_sidecar"
PROFILE_DIRECT_DISABLED = "direct_disabled"
DEFAULT_WSS_PROFILE_ID = "wss-local"
ADDRESS_AUTO = "auto"
ADDRESS_PREFER_IPV4 = "prefer_ipv4"
ADDRESS_PREFER_IPV6 = "prefer_ipv6"

DIAG_WSS_OK = "WSS OK"
DIAG_MTPROXY_OK = "MTProxy OK"
DIAG_TCP_FALLBACK_ONLY = "TCP fallback only"
DIAG_DNS_ISSUE = "DNS issue"
DIAG_IPV6_UNAVAILABLE = "IPv6 unavailable"
DIAG_MTPROXY_UNAVAILABLE = "MTProxy unavailable"
DIAG_DISABLED = "Disabled"

_TG_IPV6_PROBES = [
    "2001:67c:4e8:f002::a",
    "2001:67c:4e8:f002::b",
]


@dataclass
class ProfileDiagnosis:
    ok: bool
    status: str
    summary: str
    details: list[str]


def _read_recent_log_lines(limit: int = 300) -> list[str]:
    path = log_path()
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    return [line.rstrip("\n") for line in lines[-limit:]]


def make_default_profiles() -> list[dict[str, Any]]:
    return [
        {
            "id": DEFAULT_WSS_PROFILE_ID,
            "name": "Local WSS",
            "type": PROFILE_WSS_LOCAL,
            "listen_host": DEFAULT_HOST,
            "port": DEFAULT_PORT,
            "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
            "verbose": False,
            "verify_tls": False,
            "address_family": ADDRESS_AUTO,
        },
        {
            "id": "mtproto-external",
            "name": "External MTProto",
            "type": PROFILE_MTPROTO_EXTERNAL,
            "server": "",
            "port": 443,
            "secret": "",
            "address_family": ADDRESS_AUTO,
            "diagnostic_dns_override": "",
        },
        {
            "id": "mtproto-sidecar",
            "name": "Local MTProxy Sidecar",
            "type": PROFILE_MTPROTO_SIDECAR,
            "listen_host": DEFAULT_HOST,
            "port": 11080,
            "secret": "",
            "stats_port": 11081,
            "workers": 1,
            "proxy_tag": "",
            "mode": "auto",
            "binary_path": "",
            "container_runtime": "",
            "container_image": "",
            "address_family": ADDRESS_AUTO,
            "diagnostic_dns_override": "",
        },
        {
            "id": "direct-disabled",
            "name": "Disabled",
            "type": PROFILE_DIRECT_DISABLED,
        },
    ]


def make_default_config() -> dict[str, Any]:
    return {
        "active_profile": DEFAULT_WSS_PROFILE_ID,
        "profiles": make_default_profiles(),
    }


DEFAULT_CONFIG = make_default_config()

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


def _safe_profile_token(profile: dict[str, Any]) -> str:
    token = str(profile.get("id") or profile.get("name") or "profile").strip().lower()
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in token)
    return safe or "profile"


def sidecar_dir(profile: dict[str, Any]) -> Path:
    return state_dir() / "sidecar" / _safe_profile_token(profile)


def sidecar_pid_path(profile: dict[str, Any]) -> Path:
    return sidecar_dir(profile) / "mtproxy.pid"


def sidecar_state_path(profile: dict[str, Any]) -> Path:
    return sidecar_dir(profile) / "sidecar-state.json"


def sidecar_log_path(profile: dict[str, Any]) -> Path:
    return sidecar_dir(profile) / "mtproxy.log"


def sidecar_secret_path(profile: dict[str, Any]) -> Path:
    return sidecar_dir(profile) / "proxy-secret"


def sidecar_config_path(profile: dict[str, Any]) -> Path:
    return sidecar_dir(profile) / "proxy-multi.conf"


def sidecar_files(profile: dict[str, Any]) -> dict[str, Path]:
    return {
        "dir": sidecar_dir(profile),
        "pid": sidecar_pid_path(profile),
        "state": sidecar_state_path(profile),
        "log": sidecar_log_path(profile),
        "proxy_secret": sidecar_secret_path(profile),
        "proxy_multi_conf": sidecar_config_path(profile),
    }


def generate_mtproto_secret() -> str:
    return secrets.token_hex(16)


def _normalize_address_family(value: Optional[str]) -> str:
    if value in {ADDRESS_AUTO, ADDRESS_PREFER_IPV4, ADDRESS_PREFER_IPV6}:
        return str(value)
    return ADDRESS_AUTO


def _profile_defaults(profile_type: str, profile_id: str, name: Optional[str] = None) -> dict[str, Any]:
    if profile_type == PROFILE_WSS_LOCAL:
        return {
            "id": profile_id,
            "name": name or "Local WSS",
            "type": PROFILE_WSS_LOCAL,
            "listen_host": DEFAULT_HOST,
            "port": DEFAULT_PORT,
            "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
            "verbose": False,
            "verify_tls": False,
            "address_family": ADDRESS_AUTO,
        }
    if profile_type == PROFILE_MTPROTO_EXTERNAL:
        return {
            "id": profile_id,
            "name": name or "External MTProto",
            "type": PROFILE_MTPROTO_EXTERNAL,
            "server": "",
            "port": 443,
            "secret": "",
            "address_family": ADDRESS_AUTO,
            "diagnostic_dns_override": "",
        }
    if profile_type == PROFILE_MTPROTO_SIDECAR:
        return {
            "id": profile_id,
            "name": name or "Local MTProxy Sidecar",
            "type": PROFILE_MTPROTO_SIDECAR,
            "listen_host": DEFAULT_HOST,
            "port": 11080,
            "secret": "",
            "stats_port": 11081,
            "workers": 1,
            "proxy_tag": "",
            "mode": "auto",
            "binary_path": "",
            "container_runtime": "",
            "container_image": "",
            "address_family": ADDRESS_AUTO,
            "diagnostic_dns_override": "",
        }
    return {
        "id": profile_id,
        "name": name or "Disabled",
        "type": PROFILE_DIRECT_DISABLED,
    }


def _normalize_profile(profile: dict[str, Any], index: int) -> dict[str, Any]:
    profile_id = str(profile.get("id") or f"profile-{index + 1}")
    profile_type = str(profile.get("type") or PROFILE_DIRECT_DISABLED)
    if profile_type not in {
        PROFILE_WSS_LOCAL,
        PROFILE_MTPROTO_EXTERNAL,
        PROFILE_MTPROTO_SIDECAR,
        PROFILE_DIRECT_DISABLED,
    }:
        profile_type = PROFILE_DIRECT_DISABLED

    defaults = _profile_defaults(profile_type, profile_id, str(profile.get("name") or ""))
    normalized = copy.deepcopy(defaults)
    normalized.update(profile)
    normalized["id"] = profile_id
    normalized["type"] = profile_type
    normalized["name"] = str(normalized.get("name") or defaults["name"])
    if "address_family" in normalized:
        normalized["address_family"] = _normalize_address_family(normalized.get("address_family"))
    if profile_type == PROFILE_MTPROTO_SIDECAR:
        normalized["stats_port"] = int(normalized.get("stats_port", 11081))
        normalized["workers"] = int(normalized.get("workers", 1))
        normalized["mode"] = str(normalized.get("mode") or "auto")
    return normalized


def _normalize_config(data: dict[str, Any]) -> dict[str, Any]:
    if "profiles" not in data:
        legacy = _profile_defaults(PROFILE_WSS_LOCAL, DEFAULT_WSS_PROFILE_ID, "Local WSS")
        for key in ("listen_host", "port", "dc_ip", "verbose", "verify_tls"):
            if key in data:
                legacy[key] = data[key]
        cfg = make_default_config()
        cfg["profiles"][0] = legacy
        return cfg

    raw_profiles = data.get("profiles")
    if not isinstance(raw_profiles, list):
        raise ValueError("Config field 'profiles' must be a list")

    profiles = [_normalize_profile(profile, index) for index, profile in enumerate(raw_profiles) if isinstance(profile, dict)]
    if not profiles:
        profiles = make_default_profiles()

    active_profile = str(data.get("active_profile") or profiles[0]["id"])
    if active_profile not in {profile["id"] for profile in profiles}:
        active_profile = profiles[0]["id"]

    return {
        "active_profile": active_profile,
        "profiles": profiles,
    }


def load_config(path: Optional[Path] = None) -> dict[str, Any]:
    cfg_path = path or config_path()
    if not cfg_path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)

    with cfg_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Config at {cfg_path} must be a JSON object")

    return _normalize_config(data)


def save_config(data: dict[str, Any], path: Optional[Path] = None) -> Path:
    cfg_path = path or config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = _normalize_config(data)
    with cfg_path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return cfg_path


def get_profile(config: dict[str, Any], profile_id: Optional[str] = None) -> dict[str, Any]:
    active_id = profile_id or str(config.get("active_profile") or "")
    for profile in config.get("profiles", []):
        if profile.get("id") == active_id:
            return profile
    profiles = config.get("profiles") or make_default_profiles()
    return profiles[0]


def profile_display_name(profile: dict[str, Any]) -> str:
    profile_type = str(profile.get("type", PROFILE_DIRECT_DISABLED))
    labels = {
        PROFILE_WSS_LOCAL: "WSS",
        PROFILE_MTPROTO_EXTERNAL: "MTProto",
        PROFILE_MTPROTO_SIDECAR: "Sidecar",
        PROFILE_DIRECT_DISABLED: "Disabled",
    }
    return f"{profile.get('name', 'Profile')} [{labels.get(profile_type, profile_type)}]"


def build_telegram_socks_url(port: int, host: str = DEFAULT_HOST) -> str:
    return f"tg://socks?server={host}&port={port}"


def build_telegram_mtproto_url(server: str, port: int, secret: str) -> str:
    query = urlencode({"server": server, "port": port, "secret": secret})
    return f"tg://proxy?{query}"


def build_profile_telegram_url(profile: dict[str, Any]) -> str:
    profile_type = str(profile.get("type", PROFILE_DIRECT_DISABLED))

    if profile_type == PROFILE_WSS_LOCAL:
        return build_telegram_socks_url(
            int(profile.get("port", DEFAULT_PORT)),
            str(profile.get("listen_host") or DEFAULT_HOST),
        )

    if profile_type in {PROFILE_MTPROTO_EXTERNAL, PROFILE_MTPROTO_SIDECAR}:
        server = str(profile.get("server") or profile.get("listen_host") or "").strip()
        secret = str(profile.get("secret") or "").strip()
        port = int(profile.get("port", 443))
        if not server:
            raise ValueError("MTProto profile server is empty")
        if not secret:
            raise ValueError("MTProto profile secret is empty")
        return build_telegram_mtproto_url(server, port, secret)

    raise ValueError("Disabled profile does not provide a Telegram proxy link")


def validate_profile_telegram_target(profile: dict[str, Any]) -> str:
    url = build_profile_telegram_url(profile)
    profile_type = str(profile.get("type", PROFILE_DIRECT_DISABLED))
    if profile_type in {PROFILE_MTPROTO_EXTERNAL, PROFILE_MTPROTO_SIDECAR}:
        server = str(profile.get("server") or profile.get("listen_host") or "").strip()
        port = int(profile.get("port", 443))
        try:
            _socket.getaddrinfo(server, port, proto=_socket.IPPROTO_TCP)
        except OSError as exc:
            raise ValueError(f"Cannot resolve MTProto server {server}:{port}: {exc}") from exc
    return url


def _preferred_families(address_family: str) -> list[int]:
    normalized = _normalize_address_family(address_family)
    if normalized == ADDRESS_PREFER_IPV4:
        return [_socket.AF_INET, _socket.AF_INET6]
    if normalized == ADDRESS_PREFER_IPV6:
        return [_socket.AF_INET6, _socket.AF_INET]
    return [_socket.AF_UNSPEC]


def _connection_family(host: str, address_family: str) -> int:
    try:
        _socket.inet_pton(_socket.AF_INET6, host)
        return _socket.AF_INET6
    except OSError:
        pass
    try:
        _socket.inet_pton(_socket.AF_INET, host)
        return _socket.AF_INET
    except OSError:
        pass
    normalized = _normalize_address_family(address_family)
    if normalized == ADDRESS_PREFER_IPV4:
        return _socket.AF_INET
    if normalized == ADDRESS_PREFER_IPV6:
        return _socket.AF_INET6
    return _socket.AF_UNSPEC


def _resolve_target(
    host: str,
    port: int,
    address_family: str = ADDRESS_AUTO,
    diagnostic_dns_override: str = "",
) -> list[tuple[int, int, int, str, tuple]]:
    query_host = diagnostic_dns_override.strip() or host
    errors: list[str] = []
    results: list[tuple[int, int, int, str, tuple]] = []
    for family in _preferred_families(address_family):
        try:
            resolved = _socket.getaddrinfo(
                query_host,
                port,
                family=family,
                type=_socket.SOCK_STREAM,
                proto=_socket.IPPROTO_TCP,
            )
        except OSError as exc:
            errors.append(str(exc))
            continue
        for item in resolved:
            if item not in results:
                results.append(item)
        if results and family != _socket.AF_UNSPEC:
            break
    if not results:
        raise OSError("; ".join(errors) if errors else f"unable to resolve {query_host}:{port}")
    return results


def _download_to_file(url: str, path: Path) -> None:
    with urllib.request.urlopen(url, timeout=20) as response:
        data = response.read()
    path.write_bytes(data)


def prepare_sidecar_profile(profile: dict[str, Any], refresh: bool = False) -> dict[str, Any]:
    if str(profile.get("type")) != PROFILE_MTPROTO_SIDECAR:
        raise ValueError("Selected profile is not mtproto_sidecar")

    files = sidecar_files(profile)
    files["dir"].mkdir(parents=True, exist_ok=True)

    if refresh or not files["proxy_secret"].exists():
        _download_to_file("https://core.telegram.org/getProxySecret", files["proxy_secret"])
    if refresh or not files["proxy_multi_conf"].exists():
        _download_to_file("https://core.telegram.org/getProxyConfig", files["proxy_multi_conf"])

    if not str(profile.get("secret") or "").strip():
        profile["secret"] = generate_mtproto_secret()
    return profile


def _find_executable(explicit: str, candidates: list[str]) -> str:
    if explicit:
        explicit_path = Path(explicit).expanduser()
        if explicit_path.exists():
            return str(explicit_path)
        raise ValueError(f"Configured executable not found: {explicit}")
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise ValueError(f"None of the executables are available: {', '.join(candidates)}")


def _sidecar_runtime_mode(profile: dict[str, Any]) -> str:
    mode = str(profile.get("mode") or "auto").strip().lower()
    return mode if mode in {"auto", "binary", "container"} else "auto"


def _load_sidecar_state(profile: dict[str, Any]) -> dict[str, Any]:
    path = sidecar_state_path(profile)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_sidecar_state(profile: dict[str, Any], data: dict[str, Any]) -> None:
    path = sidecar_state_path(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _clear_sidecar_state(profile: dict[str, Any]) -> None:
    for path in (sidecar_state_path(profile), sidecar_pid_path(profile)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def sidecar_status(profile: dict[str, Any]) -> ProfileDiagnosis:
    if str(profile.get("type")) != PROFILE_MTPROTO_SIDECAR:
        raise ValueError("Selected profile is not mtproto_sidecar")

    state = _load_sidecar_state(profile)
    host = str(profile.get("listen_host") or DEFAULT_HOST)
    port = int(profile.get("port", 11080))
    details = [f"target {host}:{port}"]
    files = sidecar_files(profile)

    if state.get("mode") == "binary":
        pid = int(state.get("pid", 0) or 0)
        if pid and _pid_is_running(pid):
            return ProfileDiagnosis(
                ok=True,
                status=DIAG_MTPROXY_OK,
                summary=f"{profile.get('name', 'Sidecar')}: local MTProxy binary is running",
                details=[*details, f"pid={pid}"],
            )
        _clear_sidecar_state(profile)
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_MTPROXY_UNAVAILABLE,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar binary is not running",
            details=details,
        )

    if state.get("mode") == "container":
        runtime = str(state.get("runtime") or "")
        name = str(state.get("container_name") or "")
        if runtime and name:
            result = subprocess.run(
                [runtime, "inspect", "-f", "{{.State.Running}}", name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip() == "true":
                return ProfileDiagnosis(
                    ok=True,
                    status=DIAG_MTPROXY_OK,
                    summary=f"{profile.get('name', 'Sidecar')}: sidecar container is running",
                    details=[*details, f"container={name}", f"runtime={runtime}"],
                )
        _clear_sidecar_state(profile)
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_MTPROXY_UNAVAILABLE,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar container is not running",
            details=details,
        )

    if files["proxy_secret"].exists() and files["proxy_multi_conf"].exists():
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_MTPROXY_UNAVAILABLE,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar is prepared but not started",
            details=[*details, f"dir={files['dir']}"],
        )

    return ProfileDiagnosis(
        ok=False,
        status=DIAG_MTPROXY_UNAVAILABLE,
        summary=f"{profile.get('name', 'Sidecar')}: sidecar is not prepared",
        details=details,
    )


def _wait_for_local_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
        with _socket.socket(family, _socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                if sock.connect_ex((host, port)) == 0:
                    return True
            except OSError:
                pass
        time.sleep(0.2)
    return False


def start_sidecar_profile(profile: dict[str, Any]) -> ProfileDiagnosis:
    profile = prepare_sidecar_profile(profile)
    status = sidecar_status(profile)
    if status.ok:
        return status

    files = sidecar_files(profile)
    host = str(profile.get("listen_host") or DEFAULT_HOST)
    port = int(profile.get("port", 11080))
    stats_port = int(profile.get("stats_port", port + 1))
    workers = max(1, int(profile.get("workers", 1)))
    mode = _sidecar_runtime_mode(profile)
    proxy_tag = str(profile.get("proxy_tag") or "").strip()

    binary_cmd = [
        "-p",
        str(stats_port),
        "-H",
        str(port),
        "-S",
        str(profile["secret"]).strip(),
        "--aes-pwd",
        str(files["proxy_secret"]),
        str(files["proxy_multi_conf"]),
        "-M",
        str(workers),
    ]
    if proxy_tag:
        binary_cmd.extend(["-P", proxy_tag])

    if mode in {"auto", "binary"}:
        try:
            binary = _find_executable(str(profile.get("binary_path") or ""), ["mtproto-proxy"])
        except ValueError:
            binary = ""
        if binary:
            with files["log"].open("a", encoding="utf-8") as log_handle:
                proc = subprocess.Popen(
                    [binary, *binary_cmd],
                    cwd=str(files["dir"]),
                    stdout=log_handle,
                    stderr=log_handle,
                    start_new_session=True,
                )
            files["pid"].write_text(str(proc.pid), encoding="utf-8")
            _save_sidecar_state(profile, {"mode": "binary", "pid": proc.pid, "started_at": time.time()})
            if _wait_for_local_port(host, port):
                return sidecar_status(profile)
            return ProfileDiagnosis(
                ok=False,
                status=DIAG_MTPROXY_UNAVAILABLE,
                summary=f"{profile.get('name', 'Sidecar')}: binary started but {host}:{port} did not open in time",
                details=[f"log={files['log']}"],
            )

    runtime = str(profile.get("container_runtime") or "").strip()
    image = str(profile.get("container_image") or "").strip()
    if mode in {"auto", "container"}:
        if not runtime:
            try:
                runtime = _find_executable("", ["docker", "podman"])
            except ValueError:
                runtime = ""
        if runtime and image:
            container_name = f"tg-ws-mtproxy-{_safe_profile_token(profile)}"
            run_cmd = [
                runtime,
                "run",
                "--rm",
                "-d",
                "--name",
                container_name,
                "-p",
                f"127.0.0.1:{port}:{port}",
                "-p",
                f"127.0.0.1:{stats_port}:{stats_port}",
                "-v",
                f"{files['dir']}:/opt/mtproxy",
                image,
                "mtproto-proxy",
                *binary_cmd,
            ]
            result = subprocess.run(run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            if result.returncode == 0:
                _save_sidecar_state(
                    profile,
                    {
                        "mode": "container",
                        "runtime": runtime,
                        "container_name": container_name,
                        "started_at": time.time(),
                    },
                )
                if _wait_for_local_port(host, port):
                    return sidecar_status(profile)
                return ProfileDiagnosis(
                    ok=False,
                    status=DIAG_MTPROXY_UNAVAILABLE,
                    summary=f"{profile.get('name', 'Sidecar')}: container started but {host}:{port} did not open in time",
                    details=[result.stdout.strip() or result.stderr.strip()],
                )
            return ProfileDiagnosis(
                ok=False,
                status=DIAG_MTPROXY_UNAVAILABLE,
                summary=f"{profile.get('name', 'Sidecar')}: container start failed",
                details=[result.stderr.strip() or result.stdout.strip() or "no runtime output"],
            )

    return ProfileDiagnosis(
        ok=False,
        status=DIAG_MTPROXY_UNAVAILABLE,
        summary=f"{profile.get('name', 'Sidecar')}: no supported binary or container runtime available",
        details=[
            "binary: configure binary_path or install mtproto-proxy",
            "container: set container_runtime/container_image or install docker/podman",
        ],
    )


def stop_sidecar_profile(profile: dict[str, Any]) -> ProfileDiagnosis:
    state = _load_sidecar_state(profile)
    if not state:
        return ProfileDiagnosis(
            ok=True,
            status=DIAG_DISABLED,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar is already stopped",
            details=[],
        )

    if state.get("mode") == "binary":
        pid = int(state.get("pid", 0) or 0)
        if pid and _pid_is_running(pid):
            try:
                os.kill(pid, 15)
            except OSError:
                pass
            deadline = time.monotonic() + 3.0
            while _pid_is_running(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            if _pid_is_running(pid):
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        _clear_sidecar_state(profile)
        return ProfileDiagnosis(
            ok=True,
            status=DIAG_DISABLED,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar binary stopped",
            details=[],
        )

    if state.get("mode") == "container":
        runtime = str(state.get("runtime") or "")
        name = str(state.get("container_name") or "")
        if runtime and name:
            subprocess.run([runtime, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        _clear_sidecar_state(profile)
        return ProfileDiagnosis(
            ok=True,
            status=DIAG_DISABLED,
            summary=f"{profile.get('name', 'Sidecar')}: sidecar container stopped",
            details=[],
        )

    _clear_sidecar_state(profile)
    return ProfileDiagnosis(
        ok=True,
        status=DIAG_DISABLED,
        summary=f"{profile.get('name', 'Sidecar')}: sidecar state cleared",
        details=[],
    )


def _probe_ipv6_telegram(timeout: float) -> tuple[bool, str]:
    last_error = "no IPv6 probe attempted"
    for host in _TG_IPV6_PROBES:
        try:
            with _socket.create_connection((host, 443), timeout=timeout):
                return True, f"IPv6 probe reachable via {host}:443"
        except OSError as exc:
            last_error = f"{host}:443 -> {exc}"
    return False, last_error


def _probe_ipv4_target(ip: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with _socket.create_connection((ip, port), timeout=timeout):
            return True, f"IPv4 probe reachable via {ip}:{port}"
    except OSError as exc:
        return False, f"{ip}:{port} -> {exc}"


def _recent_live_traffic_status() -> tuple[Optional[str], list[str]]:
    lines = _read_recent_log_lines()
    if not lines:
        return None, ["no recent log lines"]

    ws_lines = [line for line in lines if " -> wss://" in line or "WS session closed" in line]
    tcp_fb_lines = [line for line in lines if "TCP fallback" in line]

    details = [
        f"recent log window: ws_events={len(ws_lines)} tcp_fallback_events={len(tcp_fb_lines)}"
    ]

    if ws_lines:
        return DIAG_WSS_OK, details
    if tcp_fb_lines:
        return DIAG_TCP_FALLBACK_ONLY, details
    return None, details


def _diagnose_wss_profile(profile: dict[str, Any], timeout: float) -> ProfileDiagnosis:
    name = str(profile.get("name") or profile.get("id") or "profile")
    runtime_cfg = runtime_config_from_profile(profile)
    dc_opt = parse_dc_ip_list(list(runtime_cfg["dc_ip"]))
    host = str(runtime_cfg["listen_host"])
    port = int(runtime_cfg["port"])
    address_family = _normalize_address_family(runtime_cfg.get("address_family"))
    details = [f"local endpoint {host}:{port}", f"address_family={address_family}"]

    local_family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
    with _socket.socket(local_family, _socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            listening = sock.connect_ex((host, port)) == 0
        except OSError as exc:
            return ProfileDiagnosis(
                ok=False,
                status=DIAG_TCP_FALLBACK_ONLY,
                summary=f"{name}: cannot check local endpoint {host}:{port}: {exc}",
                details=details,
            )
    details.append("local endpoint is listening" if listening else "local endpoint is not listening")

    dc, target_ip = sorted(dc_opt.items())[0]
    domain = _ws_domains(dc, False)[0]
    details.append(f"test route DC{dc} -> {domain} via {target_ip}")

    ipv4_ok, ipv4_note = _probe_ipv4_target(target_ip, 443, timeout)
    details.append(ipv4_note if ipv4_ok else f"IPv4 probe failed: {ipv4_note}")
    live_status, live_details = _recent_live_traffic_status()
    details.extend(live_details)

    async def _probe_ws() -> None:
        ws = await RawWebSocket.connect(
            target_ip,
            domain,
            make_ssl_context(bool(runtime_cfg.get("verify_tls", False))),
            timeout=timeout,
            address_family=address_family,
        )
        await ws.close()

    try:
        asyncio.run(_probe_ws())
    except Exception as exc:
        ipv6_ok, ipv6_note = _probe_ipv6_telegram(timeout)
        details.append(ipv6_note if ipv6_ok else f"IPv6 probe failed: {ipv6_note}")
        details.append(f"WSS probe failed: {exc}")
        if live_status == DIAG_WSS_OK:
            return ProfileDiagnosis(
                ok=True,
                status=DIAG_WSS_OK,
                summary=f"{name}: recent live traffic used WSS, although the current probe failed",
                details=details,
            )
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_TCP_FALLBACK_ONLY,
            summary=f"{name}: WSS probe failed for DC{dc}; local route will rely on TCP fallback",
            details=details,
        )

    ipv6_ok, ipv6_note = _probe_ipv6_telegram(timeout)
    details.append(ipv6_note if ipv6_ok else f"IPv6 probe failed: {ipv6_note}")
    if live_status == DIAG_TCP_FALLBACK_ONLY:
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_TCP_FALLBACK_ONLY,
            summary=f"{name}: recent live traffic shows only TCP fallback despite successful WSS probe",
            details=details,
        )
    return ProfileDiagnosis(
        ok=True,
        status=DIAG_WSS_OK,
        summary=f"{name}: upstream WSS probe succeeded for DC{dc} via {domain}",
        details=details,
    )


def _diagnose_mtproto_profile(profile: dict[str, Any], timeout: float) -> ProfileDiagnosis:
    name = str(profile.get("name") or profile.get("id") or "profile")
    server = str(profile.get("server") or profile.get("listen_host") or "").strip()
    port = int(profile.get("port", 443))
    address_family = _normalize_address_family(profile.get("address_family"))
    dns_override = str(profile.get("diagnostic_dns_override") or "").strip()
    details = [f"target {server}:{port}", f"address_family={address_family}"]
    if dns_override:
        details.append(f"diagnostic_dns_override={dns_override}")

    try:
        url = build_profile_telegram_url(profile)
    except ValueError as exc:
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_MTPROXY_UNAVAILABLE,
            summary=f"{name}: {exc}",
            details=details,
        )

    try:
        addrinfo = _resolve_target(
            server,
            port,
            address_family=address_family,
            diagnostic_dns_override=dns_override,
        )
    except OSError as exc:
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_DNS_ISSUE,
            summary=f"{name}: cannot resolve {server}:{port}",
            details=[*details, str(exc)],
        )

    families = {info[0] for info in addrinfo}
    resolved = []
    if _socket.AF_INET in families:
        resolved.append("IPv4")
    if _socket.AF_INET6 in families:
        resolved.append("IPv6")
    details.append("resolved families: " + (", ".join(resolved) if resolved else "unknown"))

    ipv4_note = None
    for family, _, _, _, sockaddr in addrinfo:
        if family == _socket.AF_INET:
            ok, note = _probe_ipv4_target(sockaddr[0], sockaddr[1], timeout)
            ipv4_note = note if ok else f"IPv4 probe failed: {note}"
            break
    if ipv4_note:
        details.append(ipv4_note)

    last_error = "no address attempted"
    for family, socktype, proto, _, sockaddr in addrinfo:
        try:
            with _socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
            return ProfileDiagnosis(
                ok=True,
                status=DIAG_MTPROXY_OK,
                summary=f"{name}: target {server}:{port} is reachable; proxy link is ready",
                details=[*details, f"proxy link {url}"],
            )
        except OSError as exc:
            last_error = str(exc)

    if _socket.AF_INET6 in families and _socket.AF_INET not in families and "Network is unreachable" in last_error:
        return ProfileDiagnosis(
            ok=False,
            status=DIAG_IPV6_UNAVAILABLE,
            summary=f"{name}: only IPv6 target is available, but IPv6 route is unreachable",
            details=[*details, last_error],
        )

    return ProfileDiagnosis(
        ok=False,
        status=DIAG_MTPROXY_UNAVAILABLE,
        summary=f"{name}: TCP connect to {server}:{port} failed",
        details=[*details, last_error],
    )


def diagnose_profile(profile: dict[str, Any], timeout: float = 3.0) -> ProfileDiagnosis:
    profile_type = str(profile.get("type", PROFILE_DIRECT_DISABLED))
    name = str(profile.get("name") or profile.get("id") or "profile")

    if profile_type == PROFILE_WSS_LOCAL:
        return _diagnose_wss_profile(profile, timeout)

    if profile_type == PROFILE_MTPROTO_EXTERNAL:
        return _diagnose_mtproto_profile(profile, timeout)

    if profile_type == PROFILE_MTPROTO_SIDECAR:
        sidecar_diag = sidecar_status(profile)
        if sidecar_diag.ok:
            return _diagnose_mtproto_profile(profile, timeout)
        return sidecar_diag

    return ProfileDiagnosis(
        ok=True,
        status=DIAG_DISABLED,
        summary=f"{name}: profile is disabled and does not expose a proxy target",
        details=[],
    )


def check_profile(profile: dict[str, Any], timeout: float = 3.0) -> tuple[bool, str]:
    diagnosis = diagnose_profile(profile, timeout=timeout)
    return diagnosis.ok, f"{diagnosis.status}: {diagnosis.summary}"


def open_telegram_url(url: str) -> str:

    try:
        subprocess.run(["gio", "open", url], check=True)
        return url
    except Exception:
        pass

    try:
        subprocess.run(["xdg-open", url], check=True)
        return url
    except Exception:
        pass

    try:
        subprocess.run(
            ["/home/alex/Telegram/Telegram", url],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return url
    except Exception:
        pass

    try:
        subprocess.run(["telegram-desktop", url], check=True)
        return url
    except Exception:
        pass

    try:
        subprocess.run(["telegram", url], check=True)
        return url
    except Exception:
        return url


def open_in_telegram(
    port: Optional[int] = None,
    host: str = DEFAULT_HOST,
    profile: Optional[dict[str, Any]] = None,
) -> str:
    if profile is None:
        if port is None:
            raise ValueError("port is required when profile is not provided")
        url = build_telegram_socks_url(port, host)
    else:
        url = validate_profile_telegram_target(profile)
    return open_telegram_url(url)


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
        address_family: str = ADDRESS_AUTO,
    ) -> "RawWebSocket":
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                443,
                ssl=ssl_ctx,
                server_hostname=domain,
                family=_connection_family(ip, address_family),
            ),
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
    address_family: str = ADDRESS_AUTO,
) -> bool:
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(dst, port, family=_connection_family(dst, address_family)),
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
        address_family: str = ADDRESS_AUTO,
    ) -> None:
        self.listen_host = listen_host
        self.port = port
        self.dc_opt = dc_opt
        self.ssl_ctx = make_ssl_context(verify_tls)
        self.address_family = _normalize_address_family(address_family)

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        _stats.connections_total += 1
        peer = writer.get_extra_info("peername")
        label = f"{peer[0]}:{peer[1]}" if peer else "?"
        dst = "?"
        port = 0
        stage = "socks5 greeting"

        try:
            greeting = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            if greeting[0] != 5:
                writer.close()
                return

            stage = "socks5 methods"
            await reader.readexactly(greeting[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            stage = "socks5 request"
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
                stage = "passthrough connect"
                try:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            dst,
                            port,
                            family=_connection_family(dst, self.address_family),
                        ),
                        timeout=10,
                    )
                except asyncio.TimeoutError:
                    log.warning("[%s] passthrough connect to %s:%d timed out", label, dst, port)
                    writer.write(_socks5_reply(0x05))
                    await writer.drain()
                    return
                except OSError as exc:
                    if ":" in dst and exc.errno == 101:
                        log.debug(
                            "[%s] passthrough IPv6 connect to %s:%d failed: %s",
                            label,
                            dst,
                            port,
                            exc,
                        )
                    else:
                        log.warning(
                            "[%s] passthrough connect to %s:%d failed: %s",
                            label,
                            dst,
                            port,
                            exc,
                        )
                    writer.write(_socks5_reply(0x05))
                    await writer.drain()
                    return
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

            stage = "mtproto init"
            init = await asyncio.wait_for(reader.readexactly(64), timeout=15)
            if _is_http_transport(init):
                _stats.connections_http_rejected += 1
                writer.close()
                return

            dc, is_media = _dc_from_init(init)
            if dc is None:
                dc = _IP_TO_DC.get(dst)

            if dc is None:
                log.warning("[%s] unknown DC for %s:%d -> TCP fallback", label, dst, port)
                await _tcp_fallback(reader, writer, dst, port, init, label, self.address_family)
                return

            if dc not in self.dc_opt:
                log.info("[%s] DC%d not configured for WS -> TCP fallback to %s:%d", label, dc, dst, port)
                await _tcp_fallback(reader, writer, dst, port, init, label, self.address_family)
                return

            dc_key = (dc, is_media)
            now = time.monotonic()
            if dc_key in _ws_blacklist or now < _dc_fail_until.get(dc_key, 0):
                await _tcp_fallback(reader, writer, dst, port, init, label, self.address_family)
                return

            ws = None
            ws_failed_redirect = False
            all_redirects = True
            target_ip = self.dc_opt[dc]

            for domain in _ws_domains(dc, is_media):
                stage = f"ws connect {domain}"
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
                    ws = await RawWebSocket.connect(
                        target_ip,
                        domain,
                        self.ssl_ctx,
                        address_family=self.address_family,
                    )
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
                stage = "tcp fallback"
                if ws_failed_redirect and all_redirects:
                    _ws_blacklist.add(dc_key)
                else:
                    _dc_fail_until[dc_key] = now + _DC_FAIL_COOLDOWN
                await _tcp_fallback(reader, writer, dst, port, init, label, self.address_family)
                return

            _dc_fail_until.pop(dc_key, None)
            _stats.connections_ws += 1
            stage = "ws bridge"
            await ws.send(init)
            await _bridge_ws(reader, writer, ws, label, dc, dst, port, is_media)
        except asyncio.IncompleteReadError:
            log.debug("[%s] client disconnected", label)
        except asyncio.TimeoutError:
            log.warning("[%s] timeout during %s for %s:%s", label, stage, dst, port or "?")
        except OSError as exc:
            if exc.errno == 101:
                log.warning(
                    "[%s] network unreachable during %s for %s:%s: %s",
                    label,
                    stage,
                    dst,
                    port or "?",
                    exc,
                )
            else:
                log.error(
                    "[%s] OS error during %s for %s:%s: %s",
                    label,
                    stage,
                    dst,
                    port or "?",
                    exc,
                )
        except Exception as exc:
            log.error(
                "[%s] unexpected error during %s for %s:%s: %s",
                label,
                stage,
                dst,
                port or "?",
                exc,
            )
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
        log.info(
            "TLS verification: %s",
            "enabled" if self.ssl_ctx.verify_mode != ssl.CERT_NONE else "disabled",
        )
        log.info("Address family: %s", self.address_family)
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


def runtime_config_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    if str(profile.get("type")) != PROFILE_WSS_LOCAL:
        raise ValueError(
            f"Profile '{profile.get('name', profile.get('id', '?'))}' is not runnable as local WSS proxy"
        )

    return {
        "listen_host": str(profile.get("listen_host") or DEFAULT_HOST),
        "port": int(profile.get("port", DEFAULT_PORT)),
        "dc_ip": list(profile.get("dc_ip") or []),
        "verbose": bool(profile.get("verbose", False)),
        "verify_tls": bool(profile.get("verify_tls", False)),
        "address_family": _normalize_address_family(profile.get("address_family")),
    }


def normalize_runtime_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    profile = get_profile(cfg, getattr(args, "profile", None))
    runtime_cfg = runtime_config_from_profile(profile)

    if args.listen_host is not None:
        runtime_cfg["listen_host"] = args.listen_host
    if args.port is not None:
        runtime_cfg["port"] = args.port
    if args.dc_ip:
        runtime_cfg["dc_ip"] = args.dc_ip
    if args.verbose:
        runtime_cfg["verbose"] = True
    if args.verify_tls:
        runtime_cfg["verify_tls"] = True
    if getattr(args, "address_family", None):
        runtime_cfg["address_family"] = _normalize_address_family(args.address_family)

    return runtime_cfg


async def run_from_config(cfg: dict[str, Any]) -> None:
    dc_opt = parse_dc_ip_list(list(cfg["dc_ip"]))
    server = ProxyServer(
        listen_host=str(cfg["listen_host"]),
        port=int(cfg["port"]),
        dc_opt=dc_opt,
        verify_tls=bool(cfg.get("verify_tls", False)),
        address_family=str(cfg.get("address_family") or ADDRESS_AUTO),
    )
    await server.run()


def cmd_run(args: argparse.Namespace) -> int:
    try:
        cfg = normalize_runtime_config(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

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
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        url = open_in_telegram(profile=profile)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(url)
    return 0


def cmd_paths(_: argparse.Namespace) -> int:
    print(f"config={config_path()}")
    print(f"log={log_path()}")
    return 0


def cmd_check_profile(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        diagnosis = diagnose_profile(profile)
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1
    print(("OK: " if diagnosis.ok else "FAIL: ") + f"{diagnosis.status}: {diagnosis.summary}")
    for detail in diagnosis.details:
        print(f"- {detail}")
    return 0 if diagnosis.ok else 1


def cmd_prepare_sidecar(args: argparse.Namespace) -> int:
    cfg_path = Path(args.config).expanduser() if args.config else None
    cfg = load_config(cfg_path)
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        updated = prepare_sidecar_profile(profile, refresh=bool(args.refresh))
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for index, existing in enumerate(cfg["profiles"]):
        if existing.get("id") == updated.get("id"):
            cfg["profiles"][index] = updated
            break
    save_config(cfg, cfg_path)
    print(f"OK: prepared {updated.get('name', updated.get('id', 'sidecar'))}")
    for name, path in sidecar_files(updated).items():
        if name == "dir":
            print(f"- {name}={path}")
    return 0


def cmd_start_sidecar(args: argparse.Namespace) -> int:
    cfg_path = Path(args.config).expanduser() if args.config else None
    cfg = load_config(cfg_path)
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        diagnosis = start_sidecar_profile(profile)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    save_config(cfg, cfg_path)
    print(("OK: " if diagnosis.ok else "FAIL: ") + f"{diagnosis.status}: {diagnosis.summary}")
    for detail in diagnosis.details:
        print(f"- {detail}")
    return 0 if diagnosis.ok else 1


def cmd_stop_sidecar(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        diagnosis = stop_sidecar_profile(profile)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(("OK: " if diagnosis.ok else "FAIL: ") + f"{diagnosis.status}: {diagnosis.summary}")
    return 0 if diagnosis.ok else 1


def cmd_sidecar_status(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    profile = get_profile(cfg, getattr(args, "profile", None))
    try:
        diagnosis = sidecar_status(profile)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(("OK: " if diagnosis.ok else "FAIL: ") + f"{diagnosis.status}: {diagnosis.summary}")
    for detail in diagnosis.details:
        print(f"- {detail}")
    return 0 if diagnosis.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Telegram Desktop WebSocket bridge proxy for Linux")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run the local SOCKS5 proxy")
    run_parser.add_argument("--config", help="Path to config.json")
    run_parser.add_argument("--profile", help="Profile id; defaults to active_profile")
    run_parser.add_argument("--listen-host", help="Listen host; default 127.0.0.1")
    run_parser.add_argument("--port", type=int, help="SOCKS5 listen port")
    run_parser.add_argument("--dc-ip", action="append", help="DC:IP mapping; may be passed multiple times")
    run_parser.add_argument(
        "--address-family",
        choices=[ADDRESS_AUTO, ADDRESS_PREFER_IPV4, ADDRESS_PREFER_IPV6],
        help="Preferred address family for diagnostics/runtime config",
    )
    run_parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    run_parser.add_argument("--verify-tls", action="store_true", help="Enable TLS certificate validation")
    run_parser.set_defaults(func=cmd_run)

    init_parser = subparsers.add_parser("init-config", help="Write default XDG config")
    init_parser.add_argument("--config", help="Path to config.json")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing config")
    init_parser.set_defaults(func=cmd_init_config)

    open_parser = subparsers.add_parser("open-in-telegram", help="Try to open tg://socks link")
    open_parser.add_argument("--config", help="Path to config.json")
    open_parser.add_argument("--profile", help="Profile id; defaults to active_profile")
    open_parser.set_defaults(func=cmd_open)

    check_parser = subparsers.add_parser("check-profile", help="Validate and probe the selected profile")
    check_parser.add_argument("--config", help="Path to config.json")
    check_parser.add_argument("--profile", help="Profile id; defaults to active_profile")
    check_parser.set_defaults(func=cmd_check_profile)

    prepare_sidecar_parser = subparsers.add_parser("prepare-sidecar", help="Download official MTProxy files and initialize sidecar secret")
    prepare_sidecar_parser.add_argument("--config", help="Path to config.json")
    prepare_sidecar_parser.add_argument("--profile", help="Sidecar profile id; defaults to active_profile")
    prepare_sidecar_parser.add_argument("--refresh", action="store_true", help="Refresh proxy-secret and proxy-multi.conf")
    prepare_sidecar_parser.set_defaults(func=cmd_prepare_sidecar)

    start_sidecar_parser = subparsers.add_parser("start-sidecar", help="Start the selected MTProxy sidecar profile")
    start_sidecar_parser.add_argument("--config", help="Path to config.json")
    start_sidecar_parser.add_argument("--profile", help="Sidecar profile id; defaults to active_profile")
    start_sidecar_parser.set_defaults(func=cmd_start_sidecar)

    stop_sidecar_parser = subparsers.add_parser("stop-sidecar", help="Stop the selected MTProxy sidecar profile")
    stop_sidecar_parser.add_argument("--config", help="Path to config.json")
    stop_sidecar_parser.add_argument("--profile", help="Sidecar profile id; defaults to active_profile")
    stop_sidecar_parser.set_defaults(func=cmd_stop_sidecar)

    sidecar_status_parser = subparsers.add_parser("sidecar-status", help="Show current status of the selected MTProxy sidecar profile")
    sidecar_status_parser.add_argument("--config", help="Path to config.json")
    sidecar_status_parser.add_argument("--profile", help="Sidecar profile id; defaults to active_profile")
    sidecar_status_parser.set_defaults(func=cmd_sidecar_status)

    paths_parser = subparsers.add_parser("paths", help="Print XDG config and log paths")
    paths_parser.set_defaults(func=cmd_paths)

    parser.set_defaults(
        func=cmd_run,
        command="run",
        config=None,
        profile=None,
        listen_host=None,
        port=None,
        dc_ip=None,
        address_family=None,
        verbose=False,
        verify_tls=False,
    )
    return parser


def main() -> int:
    parser = build_parser()
    argv = sys.argv[1:]
    if argv and argv[0] not in {
        "run",
        "init-config",
        "open-in-telegram",
        "check-profile",
        "prepare-sidecar",
        "start-sidecar",
        "stop-sidecar",
        "sidecar-status",
        "paths",
        "-h",
        "--help",
    }:
        argv = ["run", *argv]
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
