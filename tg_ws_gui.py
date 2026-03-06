from __future__ import annotations

import argparse
import socket
import subprocess
from pathlib import Path
from typing import Optional

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk

import tg_ws_proxy


class ProxyWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application, config_arg: Optional[str] = None) -> None:
        super().__init__(application=app, title="TG Proxy")
        self.set_default_size(900, 700)
        self.set_size_request(820, 620)
        self.set_border_width(16)

        self.config_file = (
            Path(config_arg).expanduser() if config_arg else tg_ws_proxy.config_path()
        )
        self.proc: Optional[subprocess.Popen[str]] = None
        self.log_offset = 0
        self.cfg = tg_ws_proxy.load_config(self.config_file)

        self.status_label: Gtk.Label
        self.endpoint_label: Gtk.Label
        self.host_entry: Gtk.Entry
        self.port_entry: Gtk.Entry
        self.verbose_check: Gtk.CheckButton
        self.verify_tls_check: Gtk.CheckButton
        self.dc_view: Gtk.TextView
        self.log_view: Gtk.TextView
        self.start_button: Gtk.Button
        self.stop_button: Gtk.Button

        self._build_ui()
        self._refresh_status()
        self._poll_log()
        GLib.timeout_add_seconds(1, self._tick)
        GLib.idle_add(self._auto_start)

    def _install_css(self) -> None:
        provider = Gtk.CssProvider()
        provider.load_from_data(
            b"""
            textview.dc-mappings {
                font: 12pt "DejaVu Sans Mono";
            }
            textview.log-tail {
                font: 11pt "DejaVu Sans Mono";
            }
            """
        )
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def _build_ui(self) -> None:
        self._install_css()

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.add(outer)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        outer.pack_start(header, False, False, 0)

        title = Gtk.Label(xalign=0)
        title.set_markup("<span font='16' weight='bold'>TG Proxy</span>")
        header.pack_start(title, True, True, 0)

        self.status_label = Gtk.Label(label="Stopped", xalign=1)
        self.status_label.set_markup("<b>Stopped</b>")
        header.pack_end(self.status_label, False, False, 0)

        self.endpoint_label = Gtk.Label(xalign=0)
        self.endpoint_label.set_line_wrap(True)
        self.endpoint_label.set_selectable(True)
        outer.pack_start(self.endpoint_label, False, False, 0)

        settings_frame = Gtk.Frame(label="Proxy Settings")
        outer.pack_start(settings_frame, False, False, 0)

        settings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        settings_box.set_border_width(14)
        settings_frame.add(settings_box)

        grid = Gtk.Grid(column_spacing=14, row_spacing=12)
        settings_box.pack_start(grid, False, False, 0)

        host_label = Gtk.Label(label="Listen host", xalign=0)
        grid.attach(host_label, 0, 0, 1, 1)
        self.host_entry = Gtk.Entry()
        self.host_entry.set_text(str(self.cfg["listen_host"]))
        self.host_entry.set_hexpand(True)
        grid.attach(self.host_entry, 1, 0, 1, 1)

        port_label = Gtk.Label(label="Port", xalign=0)
        grid.attach(port_label, 2, 0, 1, 1)
        self.port_entry = Gtk.Entry()
        self.port_entry.set_width_chars(8)
        self.port_entry.set_text(str(self.cfg["port"]))
        grid.attach(self.port_entry, 3, 0, 1, 1)

        self.verbose_check = Gtk.CheckButton(label="Verbose logging")
        self.verbose_check.set_active(bool(self.cfg.get("verbose", False)))
        grid.attach(self.verbose_check, 0, 1, 2, 1)

        self.verify_tls_check = Gtk.CheckButton(label="Verify TLS")
        self.verify_tls_check.set_active(bool(self.cfg.get("verify_tls", False)))
        grid.attach(self.verify_tls_check, 2, 1, 2, 1)

        mappings_label = Gtk.Label(label="DC -> IP mappings", xalign=0)
        settings_box.pack_start(mappings_label, False, False, 0)

        mappings_scroller = Gtk.ScrolledWindow()
        mappings_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        mappings_scroller.set_shadow_type(Gtk.ShadowType.IN)
        mappings_scroller.set_min_content_height(120)
        settings_box.pack_start(mappings_scroller, False, False, 0)

        self.dc_view = Gtk.TextView()
        self.dc_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.dc_view.set_monospace(True)
        self.dc_view.get_style_context().add_class("dc-mappings")
        self.dc_view.get_buffer().set_text("\n".join(self.cfg["dc_ip"]))
        mappings_scroller.add(self.dc_view)

        buttons_grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        outer.pack_start(buttons_grid, False, False, 0)
        for index in range(6):
            buttons_grid.insert_column(index)

        self.start_button = Gtk.Button(label="Start")
        self.start_button.set_hexpand(True)
        self.start_button.connect("clicked", self._on_start)
        buttons_grid.attach(self.start_button, 0, 0, 1, 1)

        self.stop_button = Gtk.Button(label="Stop")
        self.stop_button.set_hexpand(True)
        self.stop_button.connect("clicked", self._on_stop)
        buttons_grid.attach(self.stop_button, 1, 0, 1, 1)

        save_button = Gtk.Button(label="Save Config")
        save_button.set_hexpand(True)
        save_button.connect("clicked", self._on_save)
        buttons_grid.attach(save_button, 2, 0, 1, 1)

        open_button = Gtk.Button(label="Open Telegram")
        open_button.set_hexpand(True)
        open_button.connect("clicked", self._on_open_telegram)
        buttons_grid.attach(open_button, 3, 0, 1, 1)

        log_button = Gtk.Button(label="Open Log")
        log_button.set_hexpand(True)
        log_button.connect("clicked", self._on_open_log)
        buttons_grid.attach(log_button, 4, 0, 1, 1)

        refresh_button = Gtk.Button(label="Refresh")
        refresh_button.set_hexpand(True)
        refresh_button.connect("clicked", self._on_refresh)
        buttons_grid.attach(refresh_button, 5, 0, 1, 1)

        log_frame = Gtk.Frame(label="Log Tail")
        outer.pack_start(log_frame, True, True, 0)

        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        log_box.set_border_width(14)
        log_frame.add(log_box)

        log_scroller = Gtk.ScrolledWindow()
        log_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        log_scroller.set_shadow_type(Gtk.ShadowType.IN)
        log_box.pack_start(log_scroller, True, True, 0)

        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.log_view.set_monospace(True)
        self.log_view.get_style_context().add_class("log-tail")
        log_scroller.add(self.log_view)

    def _show_message(
        self,
        message_type: Gtk.MessageType,
        title: str,
        text: str,
    ) -> None:
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=message_type,
            buttons=Gtk.ButtonsType.OK,
            text=title,
        )
        dialog.format_secondary_text(text)
        dialog.run()
        dialog.destroy()

    def _append_log_line(self, text: str) -> None:
        self._append_log_text(text + "\n")

    def _append_log_text(self, text: str) -> None:
        buffer = self.log_view.get_buffer()
        end_iter = buffer.get_end_iter()
        buffer.insert(end_iter, text)
        mark = buffer.create_mark(None, buffer.get_end_iter(), False)
        self.log_view.scroll_mark_onscreen(mark)

    def current_config(self) -> dict:
        try:
            port = int(self.port_entry.get_text().strip())
        except ValueError as exc:
            raise ValueError("Port must be an integer") from exc

        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")

        dc_buffer = self.dc_view.get_buffer()
        start = dc_buffer.get_start_iter()
        end = dc_buffer.get_end_iter()
        dc_lines = [
            line.strip()
            for line in dc_buffer.get_text(start, end, True).splitlines()
            if line.strip()
        ]
        if not dc_lines:
            raise ValueError("At least one DC mapping is required")

        tg_ws_proxy.parse_dc_ip_list(dc_lines)

        return {
            "listen_host": self.host_entry.get_text().strip() or tg_ws_proxy.DEFAULT_HOST,
            "port": port,
            "dc_ip": dc_lines,
            "verbose": self.verbose_check.get_active(),
            "verify_tls": self.verify_tls_check.get_active(),
        }

    def save_config(self) -> bool:
        try:
            cfg = self.current_config()
        except ValueError as exc:
            self._show_message(Gtk.MessageType.ERROR, "Invalid config", str(exc))
            return False

        tg_ws_proxy.save_config(cfg, self.config_file)
        self.cfg = cfg
        self._append_log_line(f"[gui] Config saved to {self.config_file}")
        self._refresh_status()
        return True

    def _spawn_proxy(self) -> subprocess.Popen[str]:
        script = Path(__file__).with_name("run_proxy.sh")
        return subprocess.Popen(
            [str(script), "run", "--config", str(self.config_file)],
            cwd=str(Path(__file__).resolve().parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def _auto_start(self) -> bool:
        try:
            cfg = self.current_config()
        except ValueError:
            cfg = self.cfg

        if self._is_listening(cfg["listen_host"], cfg["port"]):
            self._refresh_status()
            return False

        if self.save_config():
            self.proc = self._spawn_proxy()
            GLib.timeout_add(700, self._refresh_status_once)
        return False

    def _on_start(self, _: Gtk.Button) -> None:
        if self.proc and self.proc.poll() is None:
            self._refresh_status()
            return

        if not self.save_config():
            return

        if self._is_listening(self.cfg["listen_host"], self.cfg["port"]):
            self._show_message(
                Gtk.MessageType.INFO,
                "Already running",
                f"Proxy already listens on {self.cfg['listen_host']}:{self.cfg['port']}",
            )
            self._refresh_status()
            return

        self.proc = self._spawn_proxy()
        GLib.timeout_add(700, self._refresh_status_once)

    def _on_stop(self, _: Gtk.Button) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
            self.proc = None
        self._refresh_status()

    def _on_save(self, _: Gtk.Button) -> None:
        self.save_config()

    def _on_open_telegram(self, _: Gtk.Button) -> None:
        if not self.save_config():
            return
        url = tg_ws_proxy.open_in_telegram(self.cfg["port"], self.cfg["listen_host"])
        self._append_log_line(f"[gui] Opened {url}")

    def _on_open_log(self, _: Gtk.Button) -> None:
        try:
            subprocess.run(["xdg-open", str(tg_ws_proxy.log_path())], check=False)
        except Exception as exc:
            self._show_message(Gtk.MessageType.ERROR, "Open log failed", str(exc))

    def _on_refresh(self, _: Gtk.Button) -> None:
        self._refresh_status()

    def _refresh_status_once(self) -> bool:
        self._refresh_status()
        return False

    def _refresh_status(self) -> None:
        try:
            cfg = self.current_config()
        except ValueError:
            cfg = self.cfg

        if self.proc and self.proc.poll() is not None:
            self.proc = None

        listening = self._is_listening(cfg["listen_host"], int(cfg["port"]))
        owned = bool(self.proc and self.proc.poll() is None)

        if listening and owned:
            self.status_label.set_markup("<b>Running from GUI</b>")
        elif listening:
            self.status_label.set_markup("<b>Running externally</b>")
        else:
            self.status_label.set_markup("<b>Stopped</b>")

        self.endpoint_label.set_text(
            f"Endpoint: {cfg['listen_host']}:{cfg['port']}    Config: {self.config_file}"
        )
        self.start_button.set_sensitive(not listening)
        self.stop_button.set_sensitive(owned)

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

    def _tick(self) -> bool:
        self._poll_log()
        self._refresh_status()
        return True

    @staticmethod
    def _is_listening(host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            try:
                return sock.connect_ex((host, port)) == 0
            except OSError:
                return False

    def do_delete_event(self, event) -> bool:
        if self.proc and self.proc.poll() is None:
            self._on_stop(self.stop_button)
        return False


class ProxyGuiApplication(Gtk.Application):
    def __init__(self, config_arg: Optional[str] = None) -> None:
        super().__init__(application_id="org.alexz.tgproxy")
        self.config_arg = config_arg

    def do_activate(self) -> None:
        win = ProxyWindow(self, config_arg=self.config_arg)
        win.show_all()
        win.present()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lightweight GTK GUI for tg-ws-proxy")
    parser.add_argument("--config", help="Path to config.json")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    app = ProxyGuiApplication(config_arg=args.config)
    return app.run(None)


if __name__ == "__main__":
    raise SystemExit(main())
