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
        self.set_default_size(940, 760)
        self.set_size_request(860, 660)
        self.set_border_width(16)

        self.config_file = (
            Path(config_arg).expanduser() if config_arg else tg_ws_proxy.config_path()
        )
        self.proc: Optional[subprocess.Popen[str]] = None
        self.log_offset = 0
        self.cfg = tg_ws_proxy.load_config(self.config_file)
        self.selected_profile_id = str(self.cfg.get("active_profile") or "")
        self._changing_profile = False

        self.status_label: Gtk.Label
        self.endpoint_label: Gtk.Label
        self.profile_combo: Gtk.ComboBoxText
        self.profile_name_entry: Gtk.Entry
        self.profile_type_label: Gtk.Label
        self.profile_check_label: Gtk.Label
        self.address_family_combo: Gtk.ComboBoxText
        self.diagnostic_dns_entry: Gtk.Entry
        self.profile_stack: Gtk.Stack
        self.host_entry: Gtk.Entry
        self.port_entry: Gtk.Entry
        self.verbose_check: Gtk.CheckButton
        self.verify_tls_check: Gtk.CheckButton
        self.dc_view: Gtk.TextView
        self.mtproto_server_entry: Gtk.Entry
        self.mtproto_port_entry: Gtk.Entry
        self.mtproto_secret_entry: Gtk.Entry
        self.sidecar_host_entry: Gtk.Entry
        self.sidecar_port_entry: Gtk.Entry
        self.sidecar_secret_entry: Gtk.Entry
        self.sidecar_stats_port_entry: Gtk.Entry
        self.sidecar_workers_entry: Gtk.Entry
        self.sidecar_mode_combo: Gtk.ComboBoxText
        self.sidecar_binary_path_entry: Gtk.Entry
        self.sidecar_container_runtime_entry: Gtk.Entry
        self.sidecar_container_image_entry: Gtk.Entry
        self.log_view: Gtk.TextView
        self.start_button: Gtk.Button
        self.stop_button: Gtk.Button

        self._build_ui()
        self._populate_profile_combo()
        self._load_selected_profile_into_widgets()
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

        profile_grid = Gtk.Grid(column_spacing=14, row_spacing=12)
        settings_box.pack_start(profile_grid, False, False, 0)

        profile_label = Gtk.Label(label="Profile", xalign=0)
        profile_grid.attach(profile_label, 0, 0, 1, 1)
        self.profile_combo = Gtk.ComboBoxText()
        self.profile_combo.set_hexpand(True)
        self.profile_combo.connect("changed", self._on_profile_changed)
        profile_grid.attach(self.profile_combo, 1, 0, 1, 1)

        profile_name_label = Gtk.Label(label="Name", xalign=0)
        profile_grid.attach(profile_name_label, 2, 0, 1, 1)
        self.profile_name_entry = Gtk.Entry()
        self.profile_name_entry.set_hexpand(True)
        profile_grid.attach(self.profile_name_entry, 3, 0, 1, 1)

        type_title = Gtk.Label(label="Type", xalign=0)
        profile_grid.attach(type_title, 0, 1, 1, 1)
        self.profile_type_label = Gtk.Label(xalign=0)
        profile_grid.attach(self.profile_type_label, 1, 1, 3, 1)

        check_button = Gtk.Button(label="Check Profile")
        check_button.connect("clicked", self._on_check_profile)
        profile_grid.attach(check_button, 0, 2, 1, 1)

        self.profile_check_label = Gtk.Label(xalign=0)
        self.profile_check_label.set_line_wrap(True)
        self.profile_check_label.set_max_width_chars(90)
        profile_grid.attach(self.profile_check_label, 1, 2, 3, 1)

        family_label = Gtk.Label(label="Address family", xalign=0)
        profile_grid.attach(family_label, 0, 3, 1, 1)
        self.address_family_combo = Gtk.ComboBoxText()
        self.address_family_combo.append(tg_ws_proxy.ADDRESS_AUTO, "Auto")
        self.address_family_combo.append(tg_ws_proxy.ADDRESS_PREFER_IPV4, "Prefer IPv4")
        self.address_family_combo.append(tg_ws_proxy.ADDRESS_PREFER_IPV6, "Prefer IPv6")
        self.address_family_combo.set_active_id(tg_ws_proxy.ADDRESS_AUTO)
        profile_grid.attach(self.address_family_combo, 1, 3, 1, 1)

        dns_label = Gtk.Label(label="Diag DNS override", xalign=0)
        profile_grid.attach(dns_label, 2, 3, 1, 1)
        self.diagnostic_dns_entry = Gtk.Entry()
        self.diagnostic_dns_entry.set_hexpand(True)
        self.diagnostic_dns_entry.set_placeholder_text("Optional IP/host used only by Check Profile")
        profile_grid.attach(self.diagnostic_dns_entry, 3, 3, 1, 1)

        self.profile_stack = Gtk.Stack()
        self.profile_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        settings_box.pack_start(self.profile_stack, False, False, 0)

        self.profile_stack.add_named(self._build_wss_page(), tg_ws_proxy.PROFILE_WSS_LOCAL)
        self.profile_stack.add_named(
            self._build_mtproto_page(),
            tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL,
        )
        self.profile_stack.add_named(
            self._build_sidecar_page(),
            tg_ws_proxy.PROFILE_MTPROTO_SIDECAR,
        )
        self.profile_stack.add_named(
            self._build_disabled_page(),
            tg_ws_proxy.PROFILE_DIRECT_DISABLED,
        )

        buttons_grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        outer.pack_start(buttons_grid, False, False, 0)
        for index in range(7):
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

        copy_button = Gtk.Button(label="Copy Link")
        copy_button.set_hexpand(True)
        copy_button.connect("clicked", self._on_copy_link)
        buttons_grid.attach(copy_button, 4, 0, 1, 1)

        log_button = Gtk.Button(label="Open Log")
        log_button.set_hexpand(True)
        log_button.connect("clicked", self._on_open_log)
        buttons_grid.attach(log_button, 5, 0, 1, 1)

        refresh_button = Gtk.Button(label="Refresh")
        refresh_button.set_hexpand(True)
        refresh_button.connect("clicked", self._on_refresh)
        buttons_grid.attach(refresh_button, 6, 0, 1, 1)

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

    def _build_wss_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        grid = Gtk.Grid(column_spacing=14, row_spacing=12)
        box.pack_start(grid, False, False, 0)

        host_label = Gtk.Label(label="Listen host", xalign=0)
        grid.attach(host_label, 0, 0, 1, 1)
        self.host_entry = Gtk.Entry()
        self.host_entry.set_hexpand(True)
        grid.attach(self.host_entry, 1, 0, 1, 1)

        port_label = Gtk.Label(label="Port", xalign=0)
        grid.attach(port_label, 2, 0, 1, 1)
        self.port_entry = Gtk.Entry()
        self.port_entry.set_width_chars(8)
        grid.attach(self.port_entry, 3, 0, 1, 1)

        self.verbose_check = Gtk.CheckButton(label="Verbose logging")
        self.verbose_check.set_tooltip_text(
            "Включать подробный лог уровня DEBUG. Полезно для диагностики, "
            "но лог становится значительно шумнее."
        )
        grid.attach(self.verbose_check, 0, 1, 2, 1)

        self.verify_tls_check = Gtk.CheckButton(label="Verify TLS")
        self.verify_tls_check.set_tooltip_text(
            "Проверять TLS-сертификат и имя хоста при WSS-подключении. "
            "Безопаснее, но может ломать совместимость."
        )
        grid.attach(self.verify_tls_check, 2, 1, 2, 1)

        verbose_hint = Gtk.Label(
            label=(
                "Verbose logging: включает подробный технический лог для отладки. "
                "Для обычной работы обычно лучше держать выключенным."
            ),
            xalign=0,
        )
        verbose_hint.set_line_wrap(True)
        verbose_hint.set_max_width_chars(80)
        box.pack_start(verbose_hint, False, False, 0)

        tls_hint = Gtk.Label(
            label=(
                "Verify TLS: включает строгую проверку сертификата и имени хоста для WSS. "
                "Безопаснее, но иногда мешает подключению."
            ),
            xalign=0,
        )
        tls_hint.set_line_wrap(True)
        tls_hint.set_max_width_chars(80)
        box.pack_start(tls_hint, False, False, 0)

        mappings_label = Gtk.Label(label="DC -> IP mappings", xalign=0)
        box.pack_start(mappings_label, False, False, 0)

        mappings_scroller = Gtk.ScrolledWindow()
        mappings_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        mappings_scroller.set_shadow_type(Gtk.ShadowType.IN)
        mappings_scroller.set_min_content_height(120)
        box.pack_start(mappings_scroller, False, False, 0)

        self.dc_view = Gtk.TextView()
        self.dc_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.dc_view.set_monospace(True)
        self.dc_view.get_style_context().add_class("dc-mappings")
        mappings_scroller.add(self.dc_view)
        return box

    def _build_mtproto_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        info = Gtk.Label(
            label=(
                "Резервный внешний MTProto profile. Локальный proxy-процесс для него не запускается. "
                "Кнопка Open Telegram откроет tg://proxy с параметрами этого профиля."
            ),
            xalign=0,
        )
        info.set_line_wrap(True)
        box.pack_start(info, False, False, 0)

        grid = Gtk.Grid(column_spacing=14, row_spacing=12)
        box.pack_start(grid, False, False, 0)

        server_label = Gtk.Label(label="Server", xalign=0)
        grid.attach(server_label, 0, 0, 1, 1)
        self.mtproto_server_entry = Gtk.Entry()
        self.mtproto_server_entry.set_hexpand(True)
        grid.attach(self.mtproto_server_entry, 1, 0, 1, 1)

        port_label = Gtk.Label(label="Port", xalign=0)
        grid.attach(port_label, 2, 0, 1, 1)
        self.mtproto_port_entry = Gtk.Entry()
        self.mtproto_port_entry.set_width_chars(8)
        grid.attach(self.mtproto_port_entry, 3, 0, 1, 1)

        secret_label = Gtk.Label(label="Secret", xalign=0)
        grid.attach(secret_label, 0, 1, 1, 1)
        self.mtproto_secret_entry = Gtk.Entry()
        self.mtproto_secret_entry.set_visibility(False)
        self.mtproto_secret_entry.set_invisible_char("*")
        self.mtproto_secret_entry.set_hexpand(True)
        grid.attach(self.mtproto_secret_entry, 1, 1, 3, 1)
        return box

    def _build_sidecar_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        info = Gtk.Label(
            label=(
                "Профиль для будущего локального MTProxy sidecar. Схема уже заведена в конфиг, "
                "теперь sidecar можно подготовить и запустить через Start/Stop."
            ),
            xalign=0,
        )
        info.set_line_wrap(True)
        box.pack_start(info, False, False, 0)

        grid = Gtk.Grid(column_spacing=14, row_spacing=12)
        box.pack_start(grid, False, False, 0)

        host_label = Gtk.Label(label="Listen host", xalign=0)
        grid.attach(host_label, 0, 0, 1, 1)
        self.sidecar_host_entry = Gtk.Entry()
        self.sidecar_host_entry.set_hexpand(True)
        grid.attach(self.sidecar_host_entry, 1, 0, 1, 1)

        port_label = Gtk.Label(label="Port", xalign=0)
        grid.attach(port_label, 2, 0, 1, 1)
        self.sidecar_port_entry = Gtk.Entry()
        self.sidecar_port_entry.set_width_chars(8)
        grid.attach(self.sidecar_port_entry, 3, 0, 1, 1)

        secret_label = Gtk.Label(label="Secret", xalign=0)
        grid.attach(secret_label, 0, 1, 1, 1)
        self.sidecar_secret_entry = Gtk.Entry()
        self.sidecar_secret_entry.set_visibility(False)
        self.sidecar_secret_entry.set_invisible_char("*")
        self.sidecar_secret_entry.set_hexpand(True)
        grid.attach(self.sidecar_secret_entry, 1, 1, 3, 1)

        stats_label = Gtk.Label(label="Stats port", xalign=0)
        grid.attach(stats_label, 0, 2, 1, 1)
        self.sidecar_stats_port_entry = Gtk.Entry()
        self.sidecar_stats_port_entry.set_width_chars(8)
        grid.attach(self.sidecar_stats_port_entry, 1, 2, 1, 1)

        workers_label = Gtk.Label(label="Workers", xalign=0)
        grid.attach(workers_label, 2, 2, 1, 1)
        self.sidecar_workers_entry = Gtk.Entry()
        self.sidecar_workers_entry.set_width_chars(8)
        grid.attach(self.sidecar_workers_entry, 3, 2, 1, 1)

        mode_label = Gtk.Label(label="Mode", xalign=0)
        grid.attach(mode_label, 0, 3, 1, 1)
        self.sidecar_mode_combo = Gtk.ComboBoxText()
        self.sidecar_mode_combo.append("auto", "Auto")
        self.sidecar_mode_combo.append("binary", "Binary")
        self.sidecar_mode_combo.append("container", "Container")
        self.sidecar_mode_combo.set_active_id("auto")
        grid.attach(self.sidecar_mode_combo, 1, 3, 1, 1)

        binary_label = Gtk.Label(label="Binary path", xalign=0)
        grid.attach(binary_label, 0, 4, 1, 1)
        self.sidecar_binary_path_entry = Gtk.Entry()
        self.sidecar_binary_path_entry.set_hexpand(True)
        grid.attach(self.sidecar_binary_path_entry, 1, 4, 3, 1)

        runtime_label = Gtk.Label(label="Container runtime", xalign=0)
        grid.attach(runtime_label, 0, 5, 1, 1)
        self.sidecar_container_runtime_entry = Gtk.Entry()
        self.sidecar_container_runtime_entry.set_hexpand(True)
        self.sidecar_container_runtime_entry.set_placeholder_text("docker or podman")
        grid.attach(self.sidecar_container_runtime_entry, 1, 5, 1, 1)

        image_label = Gtk.Label(label="Container image", xalign=0)
        grid.attach(image_label, 2, 5, 1, 1)
        self.sidecar_container_image_entry = Gtk.Entry()
        self.sidecar_container_image_entry.set_hexpand(True)
        grid.attach(self.sidecar_container_image_entry, 3, 5, 1, 1)
        return box

    def _build_disabled_page(self) -> Gtk.Widget:
        label = Gtk.Label(
            label=(
                "Этот профиль не запускает локальный proxy и не открывает proxy link в Telegram. "
                "Его можно использовать как явный режим без proxy."
            ),
            xalign=0,
        )
        label.set_line_wrap(True)
        return label

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

    def _current_log_path(self) -> Path:
        profile = self._selected_profile()
        if str(profile.get("type")) == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            return tg_ws_proxy.sidecar_log_path(profile)
        return tg_ws_proxy.log_path()

    def _set_profile_check_result(self, ok: Optional[bool], message: str) -> None:
        escaped = GLib.markup_escape_text(message)
        if ok is True:
            self.profile_check_label.set_markup(f"<span foreground='#1b7f3b'><b>OK:</b> {escaped}</span>")
        elif ok is False:
            self.profile_check_label.set_markup(f"<span foreground='#b42318'><b>FAIL:</b> {escaped}</span>")
        else:
            self.profile_check_label.set_markup(f"<span foreground='#555753'>{escaped}</span>")

    @staticmethod
    def _diagnosis_message(diagnosis: tg_ws_proxy.ProfileDiagnosis) -> str:
        if diagnosis.details:
            return f"{diagnosis.status}: {diagnosis.summary} | " + " | ".join(diagnosis.details)
        return f"{diagnosis.status}: {diagnosis.summary}"

    def _populate_profile_combo(self) -> None:
        self._changing_profile = True
        self.profile_combo.remove_all()
        for profile in self.cfg.get("profiles", []):
            self.profile_combo.append(profile["id"], tg_ws_proxy.profile_display_name(profile))
        active_id = str(self.cfg.get("active_profile") or self.selected_profile_id)
        self.profile_combo.set_active_id(active_id)
        if not self.profile_combo.get_active_id() and self.cfg.get("profiles"):
            fallback_id = self.cfg["profiles"][0]["id"]
            self.profile_combo.set_active_id(fallback_id)
            active_id = fallback_id
        self.selected_profile_id = active_id
        self._changing_profile = False

    def _selected_profile(self) -> dict:
        return tg_ws_proxy.get_profile(self.cfg, self.selected_profile_id)

    def _coerce_port(self, text: str, field_name: str) -> int:
        try:
            port = int(text.strip())
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer") from exc
        if not (1 <= port <= 65535):
            raise ValueError(f"{field_name} must be between 1 and 65535")
        return port

    def _wss_profile_from_widgets(self, profile: dict) -> dict:
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
            **profile,
            "name": self.profile_name_entry.get_text().strip() or profile.get("name") or "Local WSS",
            "listen_host": self.host_entry.get_text().strip() or tg_ws_proxy.DEFAULT_HOST,
            "port": self._coerce_port(self.port_entry.get_text(), "Port"),
            "dc_ip": dc_lines,
            "verbose": self.verbose_check.get_active(),
            "verify_tls": self.verify_tls_check.get_active(),
            "address_family": self.address_family_combo.get_active_id() or tg_ws_proxy.ADDRESS_AUTO,
        }

    def _mtproto_profile_from_widgets(self, profile: dict) -> dict:
        return {
            **profile,
            "name": self.profile_name_entry.get_text().strip() or profile.get("name") or "External MTProto",
            "server": self.mtproto_server_entry.get_text().strip(),
            "port": self._coerce_port(self.mtproto_port_entry.get_text(), "Port"),
            "secret": self.mtproto_secret_entry.get_text().strip(),
            "address_family": self.address_family_combo.get_active_id() or tg_ws_proxy.ADDRESS_AUTO,
            "diagnostic_dns_override": self.diagnostic_dns_entry.get_text().strip(),
        }

    def _sidecar_profile_from_widgets(self, profile: dict) -> dict:
        return {
            **profile,
            "name": self.profile_name_entry.get_text().strip() or profile.get("name") or "Local MTProxy Sidecar",
            "listen_host": self.sidecar_host_entry.get_text().strip() or tg_ws_proxy.DEFAULT_HOST,
            "port": self._coerce_port(self.sidecar_port_entry.get_text(), "Port"),
            "secret": self.sidecar_secret_entry.get_text().strip(),
            "stats_port": self._coerce_port(self.sidecar_stats_port_entry.get_text(), "Stats port"),
            "workers": max(1, int(self.sidecar_workers_entry.get_text().strip() or "1")),
            "mode": self.sidecar_mode_combo.get_active_id() or "auto",
            "binary_path": self.sidecar_binary_path_entry.get_text().strip(),
            "container_runtime": self.sidecar_container_runtime_entry.get_text().strip(),
            "container_image": self.sidecar_container_image_entry.get_text().strip(),
            "address_family": self.address_family_combo.get_active_id() or tg_ws_proxy.ADDRESS_AUTO,
            "diagnostic_dns_override": self.diagnostic_dns_entry.get_text().strip(),
        }

    def _disabled_profile_from_widgets(self, profile: dict) -> dict:
        return {
            **profile,
            "name": self.profile_name_entry.get_text().strip() or profile.get("name") or "Disabled",
        }

    def _sync_selected_profile_to_cfg(self) -> bool:
        profile = self._selected_profile()
        profile_type = str(profile.get("type"))
        try:
            if profile_type == tg_ws_proxy.PROFILE_WSS_LOCAL:
                updated = self._wss_profile_from_widgets(profile)
            elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL:
                updated = self._mtproto_profile_from_widgets(profile)
            elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
                updated = self._sidecar_profile_from_widgets(profile)
            else:
                updated = self._disabled_profile_from_widgets(profile)
        except ValueError as exc:
            self._show_message(Gtk.MessageType.ERROR, "Invalid config", str(exc))
            return False

        for index, existing in enumerate(self.cfg.get("profiles", [])):
            if existing.get("id") == updated.get("id"):
                self.cfg["profiles"][index] = updated
                break
        self.cfg["active_profile"] = updated["id"]
        return True

    def save_config(self) -> bool:
        if not self._sync_selected_profile_to_cfg():
            return False

        tg_ws_proxy.save_config(self.cfg, self.config_file)
        self.cfg = tg_ws_proxy.load_config(self.config_file)
        self._populate_profile_combo()
        self._load_selected_profile_into_widgets()
        self._append_log_line(f"[gui] Config saved to {self.config_file}")
        self._refresh_status()
        return True

    def _load_selected_profile_into_widgets(self) -> None:
        profile = self._selected_profile()
        profile_type = str(profile.get("type"))
        self.profile_name_entry.set_text(str(profile.get("name") or ""))
        type_labels = {
            tg_ws_proxy.PROFILE_WSS_LOCAL: "Local WSS/SOCKS5",
            tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL: "External MTProto",
            tg_ws_proxy.PROFILE_MTPROTO_SIDECAR: "Local MTProxy Sidecar",
            tg_ws_proxy.PROFILE_DIRECT_DISABLED: "Disabled",
        }
        self.profile_type_label.set_text(type_labels.get(profile_type, profile_type))
        self.profile_stack.set_visible_child_name(profile_type)
        self._set_profile_check_result(None, "Нажмите Check Profile для проверки активного маршрута.")
        self.log_offset = 0
        self.log_view.get_buffer().set_text("")
        self.address_family_combo.set_active_id(
            str(profile.get("address_family") or tg_ws_proxy.ADDRESS_AUTO)
        )
        self.diagnostic_dns_entry.set_text(str(profile.get("diagnostic_dns_override") or ""))

        if profile_type == tg_ws_proxy.PROFILE_WSS_LOCAL:
            self.host_entry.set_text(str(profile.get("listen_host") or tg_ws_proxy.DEFAULT_HOST))
            self.port_entry.set_text(str(profile.get("port", tg_ws_proxy.DEFAULT_PORT)))
            self.verbose_check.set_active(bool(profile.get("verbose", False)))
            self.verify_tls_check.set_active(bool(profile.get("verify_tls", False)))
            self.dc_view.get_buffer().set_text("\n".join(profile.get("dc_ip") or []))
        elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL:
            self.mtproto_server_entry.set_text(str(profile.get("server") or ""))
            self.mtproto_port_entry.set_text(str(profile.get("port", 443)))
            self.mtproto_secret_entry.set_text(str(profile.get("secret") or ""))
        elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            self.sidecar_host_entry.set_text(str(profile.get("listen_host") or tg_ws_proxy.DEFAULT_HOST))
            self.sidecar_port_entry.set_text(str(profile.get("port", 11080)))
            self.sidecar_secret_entry.set_text(str(profile.get("secret") or ""))
            self.sidecar_stats_port_entry.set_text(str(profile.get("stats_port", 11081)))
            self.sidecar_workers_entry.set_text(str(profile.get("workers", 1)))
            self.sidecar_mode_combo.set_active_id(str(profile.get("mode") or "auto"))
            self.sidecar_binary_path_entry.set_text(str(profile.get("binary_path") or ""))
            self.sidecar_container_runtime_entry.set_text(str(profile.get("container_runtime") or ""))
            self.sidecar_container_image_entry.set_text(str(profile.get("container_image") or ""))

    def _profile_endpoint_text(self, profile: dict) -> str:
        profile_type = str(profile.get("type"))
        if profile_type == tg_ws_proxy.PROFILE_WSS_LOCAL:
            return f"SOCKS5 {profile.get('listen_host', tg_ws_proxy.DEFAULT_HOST)}:{profile.get('port', tg_ws_proxy.DEFAULT_PORT)}"
        if profile_type == tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL:
            server = str(profile.get("server") or "<empty>")
            return f"MTProto {server}:{profile.get('port', 443)}"
        if profile_type == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            return (
                f"Sidecar {profile.get('listen_host', tg_ws_proxy.DEFAULT_HOST)}:{profile.get('port', 11080)} "
                f"mode={profile.get('mode', 'auto')}"
            )
        return "No local proxy endpoint"

    def _spawn_proxy(self) -> subprocess.Popen[str]:
        script = Path(__file__).with_name("run_proxy.sh")
        return subprocess.Popen(
            [
                str(script),
                "run",
                "--config",
                str(self.config_file),
                "--profile",
                self.selected_profile_id,
            ],
            cwd=str(Path(__file__).resolve().parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def _auto_start(self) -> bool:
        profile = self._selected_profile()
        if str(profile.get("type")) != tg_ws_proxy.PROFILE_WSS_LOCAL:
            self._refresh_status()
            return False

        host = str(profile.get("listen_host") or tg_ws_proxy.DEFAULT_HOST)
        port = int(profile.get("port", tg_ws_proxy.DEFAULT_PORT))
        if self._is_listening(host, port):
            self._refresh_status()
            return False

        if self.save_config():
            self.proc = self._spawn_proxy()
            GLib.timeout_add(700, self._refresh_status_once)
        return False

    def _on_profile_changed(self, _: Gtk.ComboBoxText) -> None:
        if self._changing_profile:
            return

        new_id = self.profile_combo.get_active_id()
        if not new_id or new_id == self.selected_profile_id:
            return

        old_id = self.selected_profile_id
        if not self._sync_selected_profile_to_cfg():
            self._changing_profile = True
            self.profile_combo.set_active_id(old_id)
            self._changing_profile = False
            return

        self.selected_profile_id = new_id
        self.cfg["active_profile"] = new_id
        self._load_selected_profile_into_widgets()
        self._refresh_status()

    def _on_start(self, _: Gtk.Button) -> None:
        profile = self._selected_profile()
        profile_type = str(profile.get("type"))
        if profile_type == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            if not self.save_config():
                return
            diagnosis = tg_ws_proxy.start_sidecar_profile(self._selected_profile())
            tg_ws_proxy.save_config(self.cfg, self.config_file)
            self.cfg = tg_ws_proxy.load_config(self.config_file)
            self._set_profile_check_result(diagnosis.ok, self._diagnosis_message(diagnosis))
            self._append_log_line(
                f"[gui] Sidecar start: {'OK' if diagnosis.ok else 'FAIL'} - {self._diagnosis_message(diagnosis)}"
            )
            self._refresh_status()
            return

        if profile_type != tg_ws_proxy.PROFILE_WSS_LOCAL:
            self._show_message(
                Gtk.MessageType.INFO,
                "No local runner",
                "Текущий профиль не запускает локальный WSS proxy. Для него используйте Open Telegram.",
            )
            return

        if self.proc and self.proc.poll() is None:
            self._refresh_status()
            return

        if not self.save_config():
            return

        profile = self._selected_profile()
        host = str(profile.get("listen_host") or tg_ws_proxy.DEFAULT_HOST)
        port = int(profile.get("port", tg_ws_proxy.DEFAULT_PORT))
        if self._is_listening(host, port):
            self._show_message(
                Gtk.MessageType.INFO,
                "Already running",
                f"Proxy already listens on {host}:{port}",
            )
            self._refresh_status()
            return

        self.proc = self._spawn_proxy()
        GLib.timeout_add(700, self._refresh_status_once)

    def _on_stop(self, _: Gtk.Button) -> None:
        profile = self._selected_profile()
        if str(profile.get("type")) == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            diagnosis = tg_ws_proxy.stop_sidecar_profile(profile)
            self._set_profile_check_result(diagnosis.ok, self._diagnosis_message(diagnosis))
            self._append_log_line(f"[gui] Sidecar stop: {self._diagnosis_message(diagnosis)}")
            self._refresh_status()
            return
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
        try:
            url = tg_ws_proxy.open_in_telegram(profile=self._selected_profile())
        except ValueError as exc:
            self._set_profile_check_result(False, str(exc))
            self._show_message(Gtk.MessageType.ERROR, "Open Telegram failed", str(exc))
            return
        self._set_profile_check_result(True, "Proxy link validated and sent to Telegram.")
        self._append_log_line(f"[gui] Opened {url}")

    def _on_copy_link(self, _: Gtk.Button) -> None:
        if not self.save_config():
            return
        try:
            url = tg_ws_proxy.validate_profile_telegram_target(self._selected_profile())
        except ValueError as exc:
            self._set_profile_check_result(False, str(exc))
            self._show_message(Gtk.MessageType.ERROR, "Copy link failed", str(exc))
            return

        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(url, -1)
        clipboard.store()
        self._set_profile_check_result(True, "Proxy link validated and copied to clipboard.")
        self._append_log_line(f"[gui] Copied {url}")

    def _on_check_profile(self, _: Gtk.Button) -> None:
        if not self._sync_selected_profile_to_cfg():
            return
        profile = self._selected_profile()
        diagnosis = tg_ws_proxy.diagnose_profile(profile)
        message = self._diagnosis_message(diagnosis)
        self._set_profile_check_result(diagnosis.ok, message)
        self._append_log_line(
            f"[gui] Profile check: {'OK' if diagnosis.ok else 'FAIL'} - {message}"
        )

    def _on_open_log(self, _: Gtk.Button) -> None:
        try:
            subprocess.run(["xdg-open", str(self._current_log_path())], check=False)
        except Exception as exc:
            self._show_message(Gtk.MessageType.ERROR, "Open log failed", str(exc))

    def _on_refresh(self, _: Gtk.Button) -> None:
        self._refresh_status()

    def _refresh_status_once(self) -> bool:
        self._refresh_status()
        return False

    def _refresh_status(self) -> None:
        if self.proc and self.proc.poll() is not None:
            self.proc = None

        profile = self._selected_profile()
        profile_type = str(profile.get("type"))
        owned = bool(self.proc and self.proc.poll() is None)

        if profile_type == tg_ws_proxy.PROFILE_WSS_LOCAL:
            host = str(profile.get("listen_host") or tg_ws_proxy.DEFAULT_HOST)
            port = int(profile.get("port", tg_ws_proxy.DEFAULT_PORT))
            listening = self._is_listening(host, port)
            if listening and owned:
                self.status_label.set_markup("<b>Running from GUI</b>")
            elif listening:
                self.status_label.set_markup("<b>Running externally</b>")
            else:
                self.status_label.set_markup("<b>Stopped</b>")
            self.start_button.set_sensitive(not listening)
            self.stop_button.set_sensitive(owned)
        elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_EXTERNAL:
            self.status_label.set_markup("<b>External MTProto profile</b>")
            self.start_button.set_sensitive(False)
            self.stop_button.set_sensitive(False)
        elif profile_type == tg_ws_proxy.PROFILE_MTPROTO_SIDECAR:
            diagnosis = tg_ws_proxy.sidecar_status(profile)
            if diagnosis.ok:
                self.status_label.set_markup("<b>Sidecar running</b>")
                self.start_button.set_sensitive(False)
                self.stop_button.set_sensitive(True)
            else:
                self.status_label.set_markup("<b>Sidecar stopped</b>")
                self.start_button.set_sensitive(True)
                self.stop_button.set_sensitive(False)
        else:
            self.status_label.set_markup("<b>Disabled profile</b>")
            self.start_button.set_sensitive(False)
            self.stop_button.set_sensitive(False)

        self.endpoint_label.set_text(
            f"Profile: {tg_ws_proxy.profile_display_name(profile)}    "
            f"Endpoint: {self._profile_endpoint_text(profile)}    "
            f"Config: {self.config_file}"
        )

    def _poll_log(self) -> None:
        path = self._current_log_path()
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
