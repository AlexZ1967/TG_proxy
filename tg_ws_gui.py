from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Optional

import tg_ws_proxy


class ProxyGui:
    def __init__(self, root: tk.Tk, config_arg: Optional[str] = None) -> None:
        self.root = root
        self.root.title("TG Proxy")
        self.root.geometry("760x560")
        self.root.minsize(700, 500)

        self.config_file = (
            Path(config_arg).expanduser() if config_arg else tg_ws_proxy.config_path()
        )
        self.proc: Optional[subprocess.Popen[str]] = None
        self.log_offset = 0

        self.cfg = tg_ws_proxy.load_config(self.config_file)

        self.status_var = tk.StringVar(value="Stopped")
        self.endpoint_var = tk.StringVar(value="")
        self.port_var = tk.StringVar(value=str(self.cfg["port"]))
        self.host_var = tk.StringVar(value=str(self.cfg["listen_host"]))
        self.verbose_var = tk.BooleanVar(value=bool(self.cfg.get("verbose", False)))
        self.verify_tls_var = tk.BooleanVar(
            value=bool(self.cfg.get("verify_tls", False))
        )

        self.dc_text: tk.Text
        self.log_text: tk.Text
        self.start_button: ttk.Button
        self.stop_button: ttk.Button
        self.save_button: ttk.Button

        self._build_ui()
        self._refresh_status()
        self._poll_log()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        style.configure("Title.TLabel", font=("Sans", 16, "bold"))
        style.configure("Status.TLabel", font=("Sans", 11, "bold"))

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(3, weight=1)

        header = ttk.Frame(outer)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Telegram Proxy", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(header, textvariable=self.status_var, style="Status.TLabel").grid(
            row=0, column=1, sticky="e"
        )
        ttk.Label(header, textvariable=self.endpoint_var).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(4, 0)
        )

        controls = ttk.LabelFrame(outer, text="Proxy Settings", padding=12)
        controls.grid(row=1, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)

        ttk.Label(controls, text="Listen host").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.host_var, width=18).grid(
            row=0, column=1, sticky="w", padx=(12, 0)
        )

        ttk.Label(controls, text="Port").grid(row=0, column=2, sticky="w", padx=(18, 0))
        ttk.Entry(controls, textvariable=self.port_var, width=8).grid(
            row=0, column=3, sticky="w", padx=(12, 0)
        )

        ttk.Checkbutton(
            controls, text="Verbose logging", variable=self.verbose_var
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Checkbutton(
            controls, text="Verify TLS", variable=self.verify_tls_var
        ).grid(row=1, column=2, columnspan=2, sticky="w", pady=(10, 0))

        ttk.Label(controls, text="DC -> IP mappings").grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(12, 6)
        )

        self.dc_text = tk.Text(controls, height=5, width=60, wrap="none")
        self.dc_text.grid(row=3, column=0, columnspan=4, sticky="ew")
        self.dc_text.insert("1.0", "\n".join(self.cfg["dc_ip"]))

        buttons = ttk.Frame(outer)
        buttons.grid(row=2, column=0, sticky="ew", pady=12)
        buttons.columnconfigure(5, weight=1)

        self.start_button = ttk.Button(buttons, text="Start", command=self.start_proxy)
        self.start_button.grid(row=0, column=0, padx=(0, 8))

        self.stop_button = ttk.Button(buttons, text="Stop", command=self.stop_proxy)
        self.stop_button.grid(row=0, column=1, padx=(0, 8))

        self.save_button = ttk.Button(buttons, text="Save Config", command=self.save_config)
        self.save_button.grid(row=0, column=2, padx=(0, 8))

        ttk.Button(
            buttons, text="Open in Telegram", command=self.open_in_telegram
        ).grid(row=0, column=3, padx=(0, 8))
        ttk.Button(buttons, text="Open Log", command=self.open_log).grid(
            row=0, column=4, padx=(0, 8)
        )
        ttk.Button(buttons, text="Refresh", command=self._refresh_status).grid(
            row=0, column=5, sticky="e"
        )

        log_frame = ttk.LabelFrame(outer, text="Log Tail", padding=12)
        log_frame.grid(row=3, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def current_config(self) -> dict:
        try:
            port = int(self.port_var.get().strip())
        except ValueError as exc:
            raise ValueError("Port must be an integer") from exc

        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")

        dc_lines = [
            line.strip()
            for line in self.dc_text.get("1.0", "end").splitlines()
            if line.strip()
        ]
        if not dc_lines:
            raise ValueError("At least one DC mapping is required")

        tg_ws_proxy.parse_dc_ip_list(dc_lines)

        return {
            "listen_host": self.host_var.get().strip() or tg_ws_proxy.DEFAULT_HOST,
            "port": port,
            "dc_ip": dc_lines,
            "verbose": bool(self.verbose_var.get()),
            "verify_tls": bool(self.verify_tls_var.get()),
        }

    def save_config(self) -> bool:
        try:
            cfg = self.current_config()
        except ValueError as exc:
            messagebox.showerror("Invalid config", str(exc), parent=self.root)
            return False

        tg_ws_proxy.save_config(cfg, self.config_file)
        self.cfg = cfg
        self._append_log_line(f"[gui] Config saved to {self.config_file}")
        self._refresh_status()
        return True

    def start_proxy(self) -> None:
        if self.proc and self.proc.poll() is None:
            self._refresh_status()
            return

        if not self.save_config():
            return

        if self._is_listening(self.cfg["listen_host"], self.cfg["port"]):
            messagebox.showinfo(
                "Already running",
                f"Proxy already listens on {self.cfg['listen_host']}:{self.cfg['port']}",
                parent=self.root,
            )
            self._refresh_status()
            return

        cmd = [
            sys.executable,
            str(Path(__file__).with_name("tg_ws_proxy.py")),
            "run",
            "--config",
            str(self.config_file),
        ]
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(Path(__file__).resolve().parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.root.after(600, self._refresh_status)

    def stop_proxy(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
            self.proc = None
        self._refresh_status()

    def open_in_telegram(self) -> None:
        if not self.save_config():
            return
        url = tg_ws_proxy.open_in_telegram(self.cfg["port"], self.cfg["listen_host"])
        self._append_log_line(f"[gui] Opened {url}")

    def open_log(self) -> None:
        path = tg_ws_proxy.log_path()
        try:
            subprocess.run(["xdg-open", str(path)], check=False)
        except Exception as exc:
            messagebox.showerror("Open log failed", str(exc), parent=self.root)

    def _refresh_status(self) -> None:
        try:
            cfg = self.current_config()
        except ValueError:
            cfg = self.cfg

        listening = self._is_listening(cfg["listen_host"], int(cfg["port"]))
        owned = bool(self.proc and self.proc.poll() is None)

        if listening and owned:
            self.status_var.set("Running from GUI")
        elif listening:
            self.status_var.set("Running externally")
        else:
            self.status_var.set("Stopped")

        self.endpoint_var.set(
            f"Endpoint: {cfg['listen_host']}:{cfg['port']}    Config: {self.config_file}"
        )
        self.start_button.state(["!disabled"] if not listening else ["disabled"])
        self.stop_button.state(["!disabled"] if owned else ["disabled"])

        if self.proc and self.proc.poll() is not None:
            self.proc = None

    def _poll_log(self) -> None:
        path = tg_ws_proxy.log_path()
        try:
            if path.exists():
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(self.log_offset)
                    chunk = f.read()
                    self.log_offset = f.tell()
                if chunk:
                    self._append_log_text(chunk)
        except Exception:
            pass

        self._refresh_status()
        self.root.after(1000, self._poll_log)

    def _append_log_text(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _append_log_line(self, text: str) -> None:
        self._append_log_text(text + "\n")

    @staticmethod
    def _is_listening(host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            try:
                return sock.connect_ex((host, port)) == 0
            except OSError:
                return False

    def _on_close(self) -> None:
        if self.proc and self.proc.poll() is None:
            if not messagebox.askyesno(
                "Exit",
                "Proxy was started from this window. Stop it and close?",
                parent=self.root,
            ):
                return
            self.stop_proxy()
        self.root.destroy()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lightweight GUI for tg-ws-proxy")
    parser.add_argument("--config", help="Path to config.json")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = tk.Tk()
    ProxyGui(root, config_arg=args.config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
