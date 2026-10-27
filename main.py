import os
import posixpath
import threading
import queue
import shlex
import time
import json
import codecs
import socket
import socketserver
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
import paramiko
from paramiko.config import SSHConfig
try:
    import pyte
except ImportError:
    pyte = None

APP_NAME = "Remoute SSH Access"
ALIAS = "linux-vm"
CONNECTIONS_PATH = Path(os.environ.get("APPDATA", str(Path.home()))) / "RemouteSSHAccess" / "connections.json"


def load_connections():
    try:
        data = json.loads(CONNECTIONS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_connections(connections):
    CONNECTIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONNECTIONS_PATH.write_text(json.dumps(connections, ensure_ascii=False, indent=2), encoding="utf-8")


def default_identity_file():
    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        candidate = Path.home() / ".ssh" / name
        if candidate.is_file():
            return str(candidate)
    return ""


def load_ssh_config(alias=ALIAS):
    """Read the current user's OpenSSH config and resolve an alias."""
    config_path = Path.home() / ".ssh" / "config"
    if not config_path.exists():
        raise FileNotFoundError(
            f"SSH config not found: {config_path}\n"
            "Create it first and add a Host linux-vm entry."
        )

    config = SSHConfig()
    with config_path.open("r", encoding="utf-8") as f:
        config.parse(f)
    result = config.lookup(alias)

    host = result.get("hostname", alias)
    port = int(result.get("port", 22))
    username = result.get("user") or os.environ.get("USERNAME") or os.environ.get("USER")
    identity_files = result.get("identityfile", [])
    if isinstance(identity_files, str):
        identity_files = [identity_files]

    expanded = []
    for item in identity_files:
        item = item.replace("~", str(Path.home()), 1) if item.startswith("~") else item
        expanded.append(os.path.expandvars(item))

    return {
        "alias": alias,
        "host": host,
        "port": port,
        "username": username,
        "identity_files": expanded,
        "config_path": str(config_path),
    }


class _ForwardHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def _relay(source, target):
        try:
            while True:
                data = source.recv(32768)
                if not data:
                    break
                target.sendall(data)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            try:
                if isinstance(target, paramiko.Channel):
                    target.shutdown_write()
                else:
                    target.shutdown(socket.SHUT_WR)
            except (OSError, EOFError, paramiko.SSHException):
                pass

    def handle(self):
        transport = self.server.transport
        if not transport or not transport.is_active():
            return
        channel = None
        try:
            channel = transport.open_channel("direct-tcpip", self.server.destination, self.request.getpeername(), timeout=10)
            if channel is None:
                return
            upstream = threading.Thread(target=self._relay, args=(self.request, channel), daemon=True)
            downstream = threading.Thread(target=self._relay, args=(channel, self.request), daemon=True)
            upstream.start()
            downstream.start()
            upstream.join()
            downstream.join()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            if channel:
                channel.close()


class _ForwardServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SSHManager:
    def __init__(self):
        self.client = None
        self.sftp = None
        self.info = None
        self.forwards = []

    def connect(self, info, passphrase=None, password=None):
        self.close()
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Only trust hosts already present in known_hosts; don't silently accept new keys.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        auth_mode = info.get("auth_mode", "auto")
        use_keys = auth_mode != "password"
        kwargs = {
            "hostname": info["host"],
            "port": info["port"],
            "username": info["username"],
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 15,
            "allow_agent": use_keys,
            "look_for_keys": use_keys,
        }
        if use_keys and info.get("identity_file"):
            kwargs["key_filename"] = info["identity_file"]
        if passphrase:
            kwargs["passphrase"] = passphrase
        if password is not None:
            kwargs["password"] = password

        try:
            client.connect(**kwargs)
            self.client = client
            self.sftp = client.open_sftp()
            self.info = info
            return info
        except Exception:
            client.close()
            raise

    def close(self):
        for server in self.forwards:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        self.forwards.clear()
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.sftp = None
        self.client = None
        self.info = None

    def start_forward(self, local_port, destination_host, destination_port):
        if not self.client or not self.client.get_transport() or not self.client.get_transport().is_active():
            raise RuntimeError("SSH-соединение не активно.")
        server = _ForwardServer(("127.0.0.1", local_port), _ForwardHandler)
        server.transport = self.client.get_transport()
        server.destination = (destination_host, destination_port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.forwards.append(server)
        return server

    def open_shell(self, width=120, height=32):
        if not self.client or not self.client.get_transport() or not self.client.get_transport().is_active():
            raise RuntimeError("SSH-соединение не активно.")
        return self.client.invoke_shell(term="xterm-256color", width=width, height=height)

    def stop_forward(self, server):
        if server in self.forwards:
            server.shutdown()
            server.server_close()
            self.forwards.remove(server)

    def run(self, command, timeout=25):
        if not self.client:
            raise RuntimeError("Not connected.")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return exit_code, out, err

    def listdir(self, path):
        if not self.sftp:
            raise RuntimeError("Not connected.")
        path = path or "."
        attrs = self.sftp.listdir_attr(path)
        items = []
        for a in attrs:
            is_dir = (a.st_mode & 0o170000) == 0o040000
            items.append({
                "name": a.filename,
                "is_dir": is_dir,
                "size": a.st_size,
                "mtime": a.st_mtime,
            })
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return items

    def upload(self, local_path, remote_path):
        self.sftp.put(local_path, remote_path)

    def download(self, remote_path, local_path):
        self.sftp.get(remote_path, local_path)

    def read_preview(self, remote_path, limit=1024 * 1024):
        with self.sftp.open(remote_path, "rb") as remote_file:
            data = remote_file.read(limit + 1)
        if b"\x00" in data:
            raise ValueError("Похоже, это двоичный файл. Для него используйте скачивание.")
        truncated = len(data) > limit
        text = data[:limit].decode("utf-8", errors="replace")
        if truncated:
            text += "\n\n… Показан только первый 1 МБ файла."
        return text

    def mkdir(self, remote_path):
        self.sftp.mkdir(remote_path)

    def rename(self, old_path, new_path):
        self.sftp.rename(old_path, new_path)

    def remove(self, remote_path, is_dir=False):
        if is_dir:
            self.sftp.rmdir(remote_path)
        else:
            self.sftp.remove(remote_path)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self._apply_game_tune_theme()
        self.title(APP_NAME)
        self.geometry("1280x820")
        self.minsize(1080, 700)
        self.configure(fg_color="#0B0F19")

        self.ssh = SSHManager()
        self.events = queue.Queue()
        self.connected = False
        self.remote_path = "/home"
        self.remote_items = []
        self.selected_remote = None
        self.service_names = []
        self.connections = load_connections()
        self._import_legacy_alias()
        self.selected_connection = None
        self.active_connection = None
        self.command_history = []
        self.history_index = 0
        self.shell_channel = None
        self.shell_events = queue.Queue()
        self.shell_screen = None
        self.shell_stream = None
        self.shell_decoder = None

        self._build_ui()
        self.after(150, self._process_events)
        self.after(50, self._process_shell_output)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._set_status("Нет подключения")

    @staticmethod
    def _apply_game_tune_theme():
        theme = ctk.ThemeManager.theme
        theme["CTk"]["fg_color"] = ["#0B0F19", "#0B0F19"]
        theme["CTkToplevel"]["fg_color"] = ["#0B0F19", "#0B0F19"]
        theme["CTkFrame"].update({"fg_color": ["#121827", "#121827"], "top_fg_color": ["#171F30", "#171F30"], "border_color": ["#2B3549", "#2B3549"], "corner_radius": 14})
        theme["CTkButton"].update({"fg_color": ["#6558D9", "#6558D9"], "hover_color": ["#776BFF", "#776BFF"], "text_color": ["#F6F5FF", "#F6F5FF"], "corner_radius": 9})
        theme["CTkEntry"].update({"fg_color": ["#0D1320", "#0D1320"], "border_color": ["#2B3549", "#2B3549"], "text_color": ["#E8ECF5", "#E8ECF5"], "placeholder_text_color": ["#8D9AB2", "#8D9AB2"], "border_width": 1, "corner_radius": 9})
        theme["CTkTextbox"].update({"fg_color": ["#0D1320", "#0D1320"], "text_color": ["#E8ECF5", "#E8ECF5"], "border_color": ["#2B3549", "#2B3549"], "scrollbar_button_color": ["#33405A", "#33405A"], "scrollbar_button_hover_color": ["#776BFF", "#776BFF"], "corner_radius": 10})
        theme["CTkCheckBox"].update({"fg_color": ["#6558D9", "#6558D9"], "hover_color": ["#776BFF", "#776BFF"], "border_color": ["#53617D", "#53617D"], "text_color": ["#E8ECF5", "#E8ECF5"]})
        theme["CTkOptionMenu"].update({"fg_color": ["#222A3B", "#222A3B"], "button_color": ["#6558D9", "#6558D9"], "button_hover_color": ["#776BFF", "#776BFF"], "text_color": ["#E8ECF5", "#E8ECF5"], "corner_radius": 9})

    def _import_legacy_alias(self):
        try:
            legacy = load_ssh_config()
        except Exception:
            return
        if any(c.get("host") == legacy["host"] and int(c.get("port", 22)) == legacy["port"] for c in self.connections):
            return
        self.connections.append({
            "name": ALIAS,
            "host": legacy["host"],
            "port": legacy["port"],
            "username": legacy["username"] or "",
            "identity_file": legacy["identity_files"][0] if legacy["identity_files"] else "",
            "pinned": True,
            "last_used": 0,
        })
        try:
            save_connections(self.connections)
        except OSError:
            pass

    def _build_connection_manager(self):
        self.connection_manager = ctk.CTkFrame(self, corner_radius=0, fg_color="#0B0F19")
        self.connection_manager.pack(fill="both", expand=True)
        hero = ctk.CTkFrame(self.connection_manager, corner_radius=16, fg_color="#121827")
        hero.pack(fill="x", padx=30, pady=(26, 12))
        ctk.CTkLabel(hero, text="Remoute SSH Access", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#E8ECF5").pack(anchor="w", padx=22, pady=(18, 3))
        ctk.CTkLabel(hero, text="БЕЗОПАСНОЕ ПОДКЛЮЧЕНИЕ К LINUX-СЕРВЕРАМ", font=ctk.CTkFont(family="Segoe UI", size=10), text_color="#8D9AB2").pack(anchor="w", padx=22, pady=(0, 18))
        body = ctk.CTkFrame(self.connection_manager, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=30, pady=(0, 26))
        form = ctk.CTkFrame(body, corner_radius=16, fg_color="#121827")
        form.pack(side="left", fill="both", expand=True, padx=(0, 10))
        ctk.CTkLabel(form, text="НОВОЕ ПОДКЛЮЧЕНИЕ", font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#8D9AB2").pack(anchor="w", padx=18, pady=(16, 3))
        self.connection_fields = {}
        for key, title, hint, default in (("name", "Название", "Например, Production", ""), ("host", "Адрес / IP", "server.example.com", ""), ("port", "Порт", "22", "22"), ("username", "Пользователь", "username", "")):
            ctk.CTkLabel(form, text=title).pack(anchor="w", padx=14, pady=(10, 2))
            entry = ctk.CTkEntry(form, placeholder_text=hint)
            entry.pack(fill="x", padx=14)
            if key == "port":
                entry.insert(0, default)
            self.connection_fields[key] = entry
        ctk.CTkLabel(form, text="SSH-ключ (необязательно)").pack(anchor="w", padx=14, pady=(10, 2))
        keyrow = ctk.CTkFrame(form, fg_color="transparent")
        keyrow.pack(fill="x", padx=14)
        self.key_entry = ctk.CTkEntry(keyrow, placeholder_text="Автопоиск в ~/.ssh")
        self.key_entry.pack(side="left", fill="x", expand=True)
        if default_identity_file():
            self.key_entry.insert(0, default_identity_file())
        ctk.CTkButton(keyrow, text="Обзор…", width=84, fg_color="#222A3B", hover_color="#33405A", command=self.choose_key_file).pack(side="left", padx=(6, 0))
        ctk.CTkLabel(form, text="Способ входа").pack(anchor="w", padx=14, pady=(10, 2))
        self.auth_mode_menu = ctk.CTkOptionMenu(form, values=["Автоматически", "Только пароль", "Только ключ/агент"])
        self.auth_mode_menu.pack(anchor="w", padx=14)
        ctk.CTkLabel(form, text="В автоматическом режиме пароль будет запрошен, если ключи не подойдут.", text_color="#8D9AB2", wraplength=420).pack(anchor="w", padx=14, pady=(4, 0))
        self.pin_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(form, text="Закрепить подключение", variable=self.pin_var).pack(anchor="w", padx=14, pady=12)
        actions = ctk.CTkFrame(form, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(4, 12))
        self.connection_form_connect = ctk.CTkButton(actions, text="Подключиться", fg_color="#6558D9", hover_color="#776BFF", height=38, corner_radius=9, command=self.connect_clicked)
        self.connection_form_connect.pack(side="left", padx=4)
        ctk.CTkButton(actions, text="Сохранить", command=self.save_current_connection, fg_color="#222A3B", hover_color="#33405A", height=38, corner_radius=9).pack(side="left", padx=4)
        book = ctk.CTkFrame(body, width=300, corner_radius=16, fg_color="#121827")
        book.pack(side="right", fill="both", padx=(8, 0))
        book.pack_propagate(False)
        ctk.CTkLabel(book, text="Подключения", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=12, pady=10)
        self.connection_list = ctk.CTkScrollableFrame(book)
        self.connection_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        ctk.CTkButton(book, text="Удалить выбранное", command=self.delete_saved_connection, fg_color="#6A343E", hover_color="#873C4C", corner_radius=9).pack(fill="x", padx=10, pady=(0, 10))
        self._refresh_connection_list()

    def choose_key_file(self):
        path = filedialog.askopenfilename(title="Выберите приватный SSH-ключ", initialdir=str(Path.home() / ".ssh"))
        if path:
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, path)

    def _refresh_connection_list(self):
        for child in self.connection_list.winfo_children():
            child.destroy()
        ordered = sorted(self.connections, key=lambda item: (not item.get("pinned", False), -item.get("last_used", 0)))
        if not ordered:
            ctk.CTkLabel(self.connection_list, text="История подключений появится здесь.", wraplength=220, text_color="#8D9AB2").pack(padx=8, pady=14)
        for item in ordered:
            title = ("★ " if item.get("pinned") else "") + (item.get("name") or item.get("host", "SSH"))
            ctk.CTkButton(self.connection_list, text=f"{title}\n{item.get('username') or ''}@{item.get('host')}:{item.get('port', 22)}", anchor="w", fg_color="transparent", hover_color="#344052", command=lambda c=item: self._fill_connection(c)).pack(fill="x", padx=4, pady=3)

    def _fill_connection(self, connection):
        self.selected_connection = connection
        for key in ("name", "host", "port", "username"):
            self.connection_fields[key].delete(0, "end")
            self.connection_fields[key].insert(0, str(connection.get(key, "")))
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, connection.get("identity_file", ""))
        self.pin_var.set(bool(connection.get("pinned")))
        mode = connection.get("auth_mode", "auto")
        self.auth_mode_menu.set({"password": "Только пароль", "key": "Только ключ/агент"}.get(mode, "Автоматически"))

    def delete_saved_connection(self):
        if not self.selected_connection:
            messagebox.showinfo("Подключения", "Сначала выберите запись в списке.")
            return
        target = self.selected_connection
        self.connections = [c for c in self.connections if c is not target]
        self.selected_connection = None
        save_connections(self.connections)
        self._refresh_connection_list()

    def _current_connection(self):
        info = {key: field.get().strip() for key, field in self.connection_fields.items()}
        if not info["host"]:
            raise ValueError("Введите адрес или IP-адрес сервера.")
        try:
            info["port"] = int(info["port"] or 22)
            if not 1 <= info["port"] <= 65535:
                raise ValueError()
        except ValueError:
            raise ValueError("Порт должен быть числом от 1 до 65535.")
        info["username"] = info["username"] or os.environ.get("USERNAME") or os.environ.get("USER") or ""
        info["identity_file"] = os.path.expandvars(os.path.expanduser(self.key_entry.get().strip()))
        mode_label = self.auth_mode_menu.get()
        info["auth_mode"] = {"Только пароль": "password", "Только ключ/агент": "key"}.get(mode_label, "auto")
        if info["auth_mode"] != "password" and info["identity_file"] and not Path(info["identity_file"]).is_file():
            raise ValueError("Файл SSH-ключа не найден. Укажите существующий приватный ключ.")
        info["alias"] = info["name"] or info["host"]
        info["pinned"] = self.pin_var.get()
        return info

    def save_current_connection(self):
        try:
            info = self._current_connection()
        except ValueError as exc:
            messagebox.showerror("Подключение", str(exc))
            return
        self._remember_connection(info)
        self._set_status("Подключение сохранено")

    def _remember_connection(self, info):
        entry = {key: info.get(key) for key in ("name", "host", "port", "username", "identity_file", "auth_mode", "pinned")}
        entry["last_used"] = time.time()
        self.connections = [c for c in self.connections if not (c.get("host") == entry["host"] and int(c.get("port", 22)) == entry["port"] and c.get("username", "") == entry["username"])]
        self.connections.append(entry)
        save_connections(self.connections)
        self._refresh_connection_list()

    def _build_ui(self):
        self.app_frame = ctk.CTkFrame(self, fg_color="#0B0F19", corner_radius=0)
        top = ctk.CTkFrame(self.app_frame, corner_radius=16, fg_color="#121827")
        top.pack(fill="x", padx=18, pady=(16, 12))
        brand = ctk.CTkFrame(top, fg_color="transparent")
        brand.pack(side="left", padx=16, pady=12)
        logo = ctk.CTkFrame(brand, width=40, height=40, corner_radius=12, fg_color="#8B7CFF")
        logo.pack(side="left")
        logo.pack_propagate(False)
        ctk.CTkLabel(logo, text="R", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color="#FFFFFF").pack(expand=True)
        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", padx=(12, 0))
        ctk.CTkLabel(brand_text, text="REMOUTE SSH ACCESS", font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"), text_color="#E8ECF5").pack(anchor="w")
        ctk.CTkLabel(brand_text, text="УПРАВЛЕНИЕ СЕРВЕРАМИ", font=ctk.CTkFont(family="Segoe UI", size=9), text_color="#8D9AB2").pack(anchor="w", pady=(2, 0))
        self.connection_label = ctk.CTkLabel(top, text="● Нет подключения", text_color="#E07A7A")
        self.connection_label.pack(side="right", padx=(8, 14))
        self.connect_button = ctk.CTkButton(top, text="Отключиться", command=self.disconnect_current, width=150, height=38, corner_radius=9, fg_color="#6558D9", hover_color="#776BFF")
        self.connect_button.pack(side="right", padx=14, pady=10)

        workspace = ctk.CTkFrame(self.app_frame, fg_color="transparent")
        workspace.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        sidebar = ctk.CTkFrame(workspace, width=218, corner_radius=16, fg_color="#121827")
        sidebar.pack(side="left", fill="y", padx=(0, 12))
        sidebar.pack_propagate(False)
        ctk.CTkLabel(sidebar, text="РАБОЧЕЕ ПРОСТРАНСТВО", font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"), text_color="#8D9AB2").pack(anchor="w", padx=16, pady=(18, 10))
        self.nav_buttons = {}
        self.tabs = ctk.CTkTabview(workspace, corner_radius=16, fg_color="#121827", segmented_button_fg_color="#171F30", segmented_button_selected_color="#6558D9", segmented_button_selected_hover_color="#776BFF", segmented_button_unselected_color="#171F30", segmented_button_unselected_hover_color="#222A3B")
        self.tabs.pack(side="left", fill="both", expand=True)
        nav_items = [
            ("Обзор", "◈"), ("Файлы", "▤"), ("Службы", "⚙"), ("Терминал", "⌘"),
            ("Журналы", "≡"), ("SSH-туннели", "⇄"), ("Процессы", "▧"), ("Docker", "▣"),
        ]
        for name, icon in nav_items:
            button = ctk.CTkButton(sidebar, text=f"{icon}   {name}", anchor="w", height=40, corner_radius=9, fg_color="transparent", hover_color="#222A3B", text_color="#B9C5DA", command=lambda value=name: self._select_section(value))
            button.pack(fill="x", padx=9, pady=3)
            self.nav_buttons[name] = button
        tabs = ["Обзор", "Файлы", "Службы", "Терминал", "Журналы", "SSH-туннели", "Процессы", "Docker"]
        for name in tabs:
            self.tabs.add(name)
        self.tabs._segmented_button.grid_forget()

        self._build_overview()
        self._build_files()
        self._build_services()
        self._build_terminal()
        self._build_logs()
        self._build_tunnels()
        self._build_processes()
        self._build_docker()
        self._build_connection_manager()

        self.status = ctk.CTkLabel(self.app_frame, text="Готов к работе", anchor="w", text_color="#8D9AB2", font=ctk.CTkFont(family="Segoe UI", size=11))
        self.status.pack(fill="x", padx=24, pady=(0, 8))
        self._select_section("Обзор")

    def _select_section(self, name):
        tab_name = name
        self.tabs.set(tab_name)
        for label, button in self.nav_buttons.items():
            selected = label == name
            button.configure(fg_color="#302E58" if selected else "transparent", text_color="#FFFFFF" if selected else "#B9C5DA")

    def _build_overview(self):
        tab = self.tabs.tab("Обзор")
        intro = ctk.CTkLabel(tab, text="Состояние сервера", font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"))
        intro.pack(anchor="w", padx=14, pady=(14, 8))
        cards = ctk.CTkFrame(tab, fg_color="transparent")
        cards.pack(fill="x", padx=10)
        self.metric_labels = {}
        for key, title in [("host", "СЕРВЕР"), ("uptime", "РАБОТАЕТ"), ("cpu", "ЗАГРУЗКА CPU"), ("ram", "ПАМЯТЬ"), ("disk", "ДИСК /")]:
            card = ctk.CTkFrame(cards, corner_radius=14, fg_color="#171F30")
            card.pack(side="left", fill="both", expand=True, padx=4, pady=4)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color="#8D9AB2").pack(
                anchor="w", padx=14, pady=(14, 4)
            )
            label = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=16, weight="bold"), wraplength=170)
            label.pack(anchor="w", padx=12, pady=(0, 14))
            self.metric_labels[key] = label

        actions = ctk.CTkFrame(tab, corner_radius=14, fg_color="#121827")
        actions.pack(fill="x", padx=14, pady=12)
        ctk.CTkButton(actions, text="Обновить показатели", command=self.refresh_metrics, fg_color="#6558D9", hover_color="#776BFF").pack(side="left", padx=8, pady=8)
        ctk.CTkButton(actions, text="Проверить сбои служб", command=self.check_failed_services, fg_color="#222A3B", hover_color="#33405A").pack(
            side="left", padx=8, pady=8
        )
        self.overview_output = ctk.CTkTextbox(tab, height=270)
        self.overview_output.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.overview_output.insert("end", "Подключитесь к серверу и обновите показатели.\n")
        self.overview_output.configure(state="disabled")

    def _build_files(self):
        tab = self.tabs.tab("Файлы")
        path_row = ctk.CTkFrame(tab, fg_color="transparent")
        path_row.pack(fill="x", padx=10, pady=(12, 6))
        ctk.CTkLabel(path_row, text="Удалённый путь:").pack(side="left", padx=(4, 6))
        self.path_entry = ctk.CTkEntry(path_row, placeholder_text="/home/пользователь")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=4)
        self.path_entry.insert(0, ".")
        ctk.CTkButton(path_row, text="Перейти", width=78, command=self.browse_remote, fg_color="#6558D9", hover_color="#776BFF").pack(side="left", padx=4)
        ctk.CTkButton(path_row, text="Домой", width=72, command=self.go_home, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(path_row, text="Вверх", width=70, command=self.go_parent).pack(side="left", padx=4)

        self.file_list = ctk.CTkTextbox(tab, height=330, wrap="none", font=ctk.CTkFont(family="Consolas", size=12), activate_scrollbars=True)
        self.file_list.pack(fill="both", expand=True, padx=14, pady=6)
        self.file_list.configure(state="disabled")
        self._bind_row_selection(self.file_list)
        self.file_line_items = {}
        self.file_list.bind("<Double-Button-1>", self.open_selected_file)

        buttons = ctk.CTkFrame(tab, fg_color="#121827", corner_radius=14)
        buttons.pack(fill="x", padx=10, pady=(4, 12))
        ctk.CTkButton(buttons, text="Обновить", command=self.browse_remote, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Загрузить файл", command=self.upload_file, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Скачать выбранное", command=self.download_file, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Просмотр", command=self.preview_remote_file, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Новая папка", command=self.create_folder, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Переименовать", command=self.rename_remote, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Удалить выбранное", command=self.delete_remote, fg_color="#6A343E", hover_color="#873C4C").pack(
            side="left", padx=4
        )
        ctk.CTkLabel(tab, text="Дважды щёлкните по папке, чтобы открыть её.", text_color="#8D9AB2").pack(
            anchor="w", padx=16, pady=(0, 8)
        )

    def _build_services(self):
        tab = self.tabs.tab("Службы")
        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(row, text="Фильтр:").pack(side="left", padx=(0, 6))
        self.service_filter = ctk.CTkEntry(row, placeholder_text="например, ssh, nginx, docker", width=260)
        self.service_filter.pack(side="left", padx=4)
        ctk.CTkButton(row, text="Показать службы", command=self.load_services, fg_color="#6558D9", hover_color="#776BFF").pack(side="left", padx=4)
        ctk.CTkButton(row, text="Запустить", command=lambda: self.service_action("start"), fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(row, text="Остановить", command=lambda: self.service_action("stop"), fg_color="#6A343E", hover_color="#873C4C").pack(
            side="left", padx=4
        )
        ctk.CTkButton(row, text="Перезапустить", command=lambda: self.service_action("restart"), fg_color="#69552F", hover_color="#80683B").pack(
            side="left", padx=4
        )
        self.selected_service_name = None
        self.service_rows = []
        self.services_loaded = False
        table = ctk.CTkFrame(tab, fg_color="#121827", corner_radius=12)
        table.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.services_box = ctk.CTkTextbox(table, wrap="none", font=ctk.CTkFont(family="Consolas", size=11), activate_scrollbars=True)
        self.services_box.pack(fill="both", expand=True, padx=8, pady=8)
        self.services_box.configure(state="disabled")
        self._bind_row_selection(self.services_box)
        self._render_services()

    def _build_terminal(self):
        tab = self.tabs.tab("Терминал")
        self.terminal_tabs = ctk.CTkTabview(tab)
        self.terminal_tabs.pack(fill="both", expand=True, padx=8, pady=8)
        self.terminal_tabs.add("Интерактивный SSH-терминал")
        self.terminal_tabs.add("SSH-команды")
        self._build_interactive_terminal(self.terminal_tabs.tab("Интерактивный SSH-терминал"))
        self._build_command_console(self.terminal_tabs.tab("SSH-команды"))

    def _build_interactive_terminal(self, tab):
        controls = ctk.CTkFrame(tab, fg_color="transparent")
        controls.pack(fill="x", padx=8, pady=(8, 4))
        self.shell_start_button = ctk.CTkButton(controls, text="Открыть оболочку", command=self.open_shell_clicked)
        self.shell_start_button.pack(side="left", padx=4)
        self.shell_stop_button = ctk.CTkButton(controls, text="Закрыть оболочку", command=self.close_shell, state="disabled", fg_color="#6A343E", hover_color="#873C4C")
        self.shell_stop_button.pack(side="left", padx=4)
        ctk.CTkButton(controls, text="Копировать выделенное", command=self._copy_shell_selection, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkLabel(controls, text="Полноценная SSH-оболочка с PTY · Ctrl+C прерывает команду", text_color="#8D9AB2").pack(side="left", padx=10)
        self.shell_view = ctk.CTkTextbox(tab, wrap="none", font=ctk.CTkFont(family="Consolas", size=12), activate_scrollbars=True)
        self.shell_view.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.shell_view.bind("<KeyPress>", self._shell_keypress)
        self.shell_view.bind("<Shift-Insert>", self._shell_paste)
        self.shell_view.bind("<<Paste>>", self._shell_paste)
        self.shell_view.bind("<Configure>", self._resize_shell)
        self.shell_view.insert("end", "Нажмите «Открыть оболочку», чтобы запустить интерактивный SSH-сеанс.\n")
        self.shell_view.configure(state="normal")

    def _build_command_console(self, tab):
        ctk.CTkLabel(
            tab,
            text="Разовые команды запускаются отдельно на сервере.",
            text_color="#8D9AB2",
            wraplength=980,
        ).pack(anchor="w", padx=14, pady=(12, 6))
        quick = ctk.CTkFrame(tab, fg_color="transparent")
        quick.pack(fill="x", padx=10, pady=4)
        for label, cmd in [
            ("Кто я?", "whoami"),
            ("Процессы", "ps aux --sort=-%mem | head -n 15"),
            ("Диски", "df -h"),
            ("Сеть", "ip -br addr; ip route"),
            ("Сбои служб", "systemctl --failed --no-pager"),
        ]:
            ctk.CTkButton(quick, text=label, command=lambda c=cmd: self.run_command(c), width=130).pack(side="left", padx=4)
        self.command_entry = ctk.CTkEntry(tab, placeholder_text="Введите команду Linux…")
        self.command_entry.pack(fill="x", padx=14, pady=(8, 5))
        self.command_entry.bind("<Return>", lambda event: self.run_custom_command())
        self.command_entry.bind("<Up>", self._command_history_up)
        self.command_entry.bind("<Down>", self._command_history_down)
        ctk.CTkButton(tab, text="Выполнить", command=self.run_custom_command, fg_color="#6558D9", hover_color="#776BFF").pack(anchor="e", padx=14, pady=(0, 8))
        self.terminal_output = ctk.CTkTextbox(tab)
        self.terminal_output.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.terminal_output.insert("end", "Здесь появится результат команды.\n")
        self.terminal_output.configure(state="disabled")

    def open_shell_clicked(self):
        if pyte is None:
            messagebox.showerror("SSH-терминал", "Для терминального экрана нужен пакет pyte. Установите зависимости командой: pip install -r requirements.txt")
            return
        if self.shell_channel and not self.shell_channel.closed:
            self.shell_view.focus_set()
            return
        width, height = self._terminal_dimensions()
        self._run_async("Открытие SSH-терминала", lambda: self.ssh.open_shell(width, height), self._shell_opened)

    def _terminal_dimensions(self):
        if not hasattr(self, "shell_view"):
            return 120, 32
        widget = self.shell_view._textbox
        width = max(40, min(220, widget.winfo_width() // 9))
        height = max(10, min(70, widget.winfo_height() // 18))
        return width, height

    def _shell_opened(self, channel):
        width, height = self._terminal_dimensions()
        self.shell_channel = channel
        self.shell_screen = pyte.Screen(width, height)
        self.shell_stream = pyte.Stream(self.shell_screen)
        self.shell_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.shell_start_button.configure(state="disabled")
        self.shell_stop_button.configure(state="normal")
        self._render_shell_screen()
        self.shell_view.focus_set()
        threading.Thread(target=self._read_shell, args=(channel,), daemon=True).start()
        self._set_status("Интерактивный SSH-терминал запущен")

    def _read_shell(self, channel):
        try:
            while self.shell_channel is channel and not channel.closed:
                if channel.recv_ready():
                    data = channel.recv(65536)
                    if not data:
                        break
                    self.shell_events.put(("data", channel, data))
                elif not channel.get_transport() or not channel.get_transport().is_active():
                    break
                else:
                    time.sleep(0.015)
            self.shell_events.put(("closed", channel, None))
        except Exception as exc:
            self.shell_events.put(("error", channel, str(exc)))

    def _process_shell_output(self):
        changed = False
        try:
            while True:
                kind, channel, payload = self.shell_events.get_nowait()
                if channel is not self.shell_channel:
                    continue
                if kind == "data" and self.shell_stream and self.shell_decoder:
                    self.shell_stream.feed(self.shell_decoder.decode(payload))
                    changed = True
                elif kind == "closed":
                    self.shell_channel = None
                    self.shell_start_button.configure(state="normal")
                    self.shell_stop_button.configure(state="disabled")
                    self._set_status("Интерактивный терминал закрыт")
                elif kind == "error":
                    self.shell_channel = None
                    self.shell_start_button.configure(state="normal")
                    self.shell_stop_button.configure(state="disabled")
                    self._set_status(f"Ошибка терминала: {payload}")
        except queue.Empty:
            pass
        if changed:
            self._render_shell_screen()
        self.after(50, self._process_shell_output)

    def _render_shell_screen(self):
        if not self.shell_screen:
            return
        text_widget = self.shell_view._textbox
        palette = {
            "black": "#000000", "red": "#cd3131", "green": "#0dbc79", "yellow": "#e5e510",
            "blue": "#2472c8", "magenta": "#bc3fbc", "cyan": "#11a8cd", "white": "#e5e5e5",
            "brightblack": "#666666", "brightred": "#f14c4c", "brightgreen": "#23d18b", "brightyellow": "#f5f543",
            "brightblue": "#3b8eea", "brightmagenta": "#d670d6", "brightcyan": "#29b8db", "brightwhite": "#ffffff",
        }
        text_widget.delete("1.0", "end")
        for y in range(self.shell_screen.lines):
            row = self.shell_screen.buffer[y]
            run = []
            run_tag = None
            for x in range(self.shell_screen.columns):
                cell = row[x]
                fg, bg = cell.fg, cell.bg
                if cell.reverse:
                    fg, bg = bg, fg
                if y == self.shell_screen.cursor.y and x == self.shell_screen.cursor.x and not self.shell_screen.cursor.hidden:
                    fg, bg = bg, fg
                tag = f"term_{fg}_{bg}_{int(cell.bold)}_{int(getattr(cell, 'italics', False))}_{int(cell.underscore)}"
                if tag != run_tag:
                    if run:
                        text_widget.insert("end", "".join(run), (run_tag,))
                    run = []
                    run_tag = tag
                    if tag not in text_widget.tag_names():
                        text_widget.tag_configure(tag, foreground=palette.get(fg, fg if fg.startswith("#") else "#d4d4d4"), background=palette.get(bg, bg if bg.startswith("#") else "#1e1e1e"), font=ctk.CTkFont(family="Consolas", size=12, weight="bold" if cell.bold else "normal", slant="italic" if getattr(cell, "italics", False) else "roman"), underline=bool(cell.underscore))
                run.append(cell.data or " ")
            if run:
                text_widget.insert("end", "".join(run), (run_tag,))
            if y < self.shell_screen.lines - 1:
                text_widget.insert("end", "\n")
        cursor = self.shell_screen.cursor
        text_widget.mark_set("insert", f"{cursor.y + 1}.{cursor.x}")
        text_widget.see(f"{cursor.y + 1}.{cursor.x}")

    def _send_shell_input(self, data):
        channel = self.shell_channel
        if not channel or channel.closed or not data:
            return
        try:
            channel.sendall(data.encode("utf-8"))
        except Exception as exc:
            self.shell_events.put(("error", channel, str(exc)))

    def _shell_keypress(self, event):
        if event.state & 0x4 and event.state & 0x1 and event.keysym.lower() == "c":
            self._copy_shell_selection()
            return "break"
        if event.state & 0x4 and event.state & 0x1 and event.keysym.lower() == "v":
            return self._shell_paste(event)
        if event.keysym == "Insert" and event.state & 0x1:
            return self._shell_paste(event)
        keys = {
            "Return": "\r", "KP_Enter": "\r", "BackSpace": "\x7f", "Tab": "\t", "Escape": "\x1b",
            "Up": "\x1b[A", "Down": "\x1b[B", "Right": "\x1b[C", "Left": "\x1b[D",
            "Home": "\x1b[H", "End": "\x1b[F", "Delete": "\x1b[3~", "Prior": "\x1b[5~", "Next": "\x1b[6~",
        }
        function_keys = {"F1": "\x1bOP", "F2": "\x1bOQ", "F3": "\x1bOR", "F4": "\x1bOS", "F5": "\x1b[15~", "F6": "\x1b[17~", "F7": "\x1b[18~", "F8": "\x1b[19~", "F9": "\x1b[20~", "F10": "\x1b[21~", "F11": "\x1b[23~", "F12": "\x1b[24~"}
        data = keys.get(event.keysym) or function_keys.get(event.keysym)
        if data is None and event.state & 0x4 and event.keysym.isalpha():
            data = chr(ord(event.keysym.lower()) - ord("a") + 1)
        elif data is None and event.char and event.char >= " ":
            data = event.char
        self._send_shell_input(data or "")
        return "break"

    def _copy_shell_selection(self):
        try:
            selected = self.shell_view._textbox.get("sel.first", "sel.last")
        except tk.TclError:
            return
        if selected:
            self.clipboard_clear()
            self.clipboard_append(selected)

    def _shell_paste(self, event=None):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            text = ""
        self._send_shell_input(text)
        return "break"

    def _resize_shell(self, event=None):
        if not self.shell_channel or not self.shell_screen:
            return
        width, height = self._terminal_dimensions()
        if width == self.shell_screen.columns and height == self.shell_screen.lines:
            return
        try:
            self.shell_screen.resize(lines=height, columns=width)
            self.shell_channel.resize_pty(width=width, height=height)
            self._render_shell_screen()
        except Exception:
            pass

    def close_shell(self):
        channel = self.shell_channel
        self.shell_channel = None
        if channel:
            try:
                channel.close()
            except Exception:
                pass
        self.shell_start_button.configure(state="normal")
        self.shell_stop_button.configure(state="disabled")
        self._set_status("Интерактивный терминал закрыт")

    def _build_logs(self):
        tab = self.tabs.tab("Журналы")
        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(row, text="Журнал:").pack(side="left", padx=(0, 6))
        self.log_unit = ctk.CTkEntry(row, placeholder_text="Имя службы, например ssh", width=260)
        self.log_unit.pack(side="left", padx=4)
        ctk.CTkButton(row, text="Последние ошибки", command=self.show_errors, fg_color="#6558D9", hover_color="#776BFF").pack(side="left", padx=4)
        ctk.CTkButton(row, text="Системный журнал (50)", command=self.show_journal, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        ctk.CTkButton(row, text="Журнал службы (100)", command=self.show_unit_journal, fg_color="#222A3B", hover_color="#33405A").pack(side="left", padx=4)
        self.logs_output = ctk.CTkTextbox(tab)
        self.logs_output.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.logs_output.insert("end", "Здесь появится содержимое журнала.\n")
        self.logs_output.configure(state="disabled")

    def _build_tunnels(self):
        tab = self.tabs.tab("SSH-туннели")
        ctk.CTkLabel(tab, text="Локальный TCP-туннель через текущее SSH-соединение", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=14, pady=(14, 4))
        ctk.CTkLabel(tab, text="Например, откройте 127.0.0.1:15432, чтобы обращаться к PostgreSQL на сервере или в его локальной сети.", text_color="#8D9AB2", wraplength=980).pack(anchor="w", padx=14, pady=(0, 12))
        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=14, pady=4)
        self.tunnel_local_port = ctk.CTkEntry(form, width=130, placeholder_text="15432")
        self.tunnel_local_port.insert(0, "15432")
        self.tunnel_local_port.pack(side="left", padx=(10, 5), pady=10)
        ctk.CTkLabel(form, text="на локальном ПК →").pack(side="left", padx=4)
        self.tunnel_remote_host = ctk.CTkEntry(form, width=220, placeholder_text="127.0.0.1")
        self.tunnel_remote_host.insert(0, "127.0.0.1")
        self.tunnel_remote_host.pack(side="left", padx=5)
        ctk.CTkLabel(form, text=":").pack(side="left")
        self.tunnel_remote_port = ctk.CTkEntry(form, width=120, placeholder_text="5432")
        self.tunnel_remote_port.insert(0, "5432")
        self.tunnel_remote_port.pack(side="left", padx=5)
        ctk.CTkButton(form, text="Создать туннель", command=self.start_tunnel).pack(side="left", padx=8)
        ctk.CTkLabel(tab, text="Активные туннели", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=14, pady=(18, 6))
        self.tunnel_list = ctk.CTkScrollableFrame(tab)
        self.tunnel_list.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self._refresh_tunnel_list()

    def _build_processes(self):
        tab = self.tabs.tab("Процессы")
        ctk.CTkLabel(tab, text="Процессы на сервере", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=14, pady=(14, 6))
        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=4)
        ctk.CTkButton(actions, text="Обновить список", command=self.load_processes).pack(side="left", padx=4)
        ctk.CTkButton(actions, text="Завершить выбранный", command=self.terminate_selected_process, fg_color="#6A343E", hover_color="#873C4C").pack(side="left", padx=4)
        ctk.CTkLabel(tab, text="Выберите строку процесса и завершайте только процессы, которые вам знакомы.", text_color="#8D9AB2").pack(anchor="w", padx=14, pady=(2, 6))
        self.process_rows = ctk.CTkScrollableFrame(tab)
        self.process_rows.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.process_entries = []
        self.selected_process_pid = None
        ctk.CTkLabel(self.process_rows, text="Нажмите «Обновить список» после подключения.", text_color="#8D9AB2").pack(anchor="w", padx=8, pady=10)

    def load_processes(self):
        command = "ps -eo pid,user,%cpu,%mem,stat,comm --sort=-%cpu | head -n 26"
        def task():
            code, out, err = self.ssh.run(command)
            if code != 0:
                raise RuntimeError(err or out or f"Команда завершилась с кодом {code}")
            return out
        self._run_async("Список процессов", task, self._render_processes)

    def _render_processes(self, output):
        for child in self.process_rows.winfo_children():
            child.destroy()
        self.process_entries = []
        lines = [line for line in output.splitlines() if line.strip()]
        for line in lines:
            fields = line.split(None, 5)
            pid = int(fields[0]) if fields and fields[0].isdigit() else None
            self.process_entries.append((pid, line))
        if self.selected_process_pid and not any(pid == self.selected_process_pid for pid, _ in self.process_entries):
            self.selected_process_pid = None
        for pid, line in self.process_entries:
            selected = pid is not None and pid == self.selected_process_pid
            ctk.CTkButton(self.process_rows, text=line, anchor="w", font=ctk.CTkFont(family="Consolas", size=12), fg_color="#302E58" if selected else "#171F30", hover_color="#222C42", command=lambda value=pid: self._select_process(value)).pack(fill="x", padx=4, pady=2)
        if not lines:
            ctk.CTkLabel(self.process_rows, text="Процессы не найдены.", text_color="#8D9AB2").pack(anchor="w", padx=8, pady=10)

    def _select_process(self, pid):
        self.selected_process_pid = pid
        self._render_processes("\n".join(line for _, line in self.process_entries))

    def terminate_selected_process(self):
        pid = self.selected_process_pid
        if not pid or pid <= 1:
            messagebox.showinfo("Процессы", "Выберите строку процесса из списка.")
            return
        if not messagebox.askyesno("Завершить процесс", f"Отправить SIGTERM процессу PID {pid}?\n\nСначала обновите список, если процесс мог измениться."):
            return
        def task():
            code, out, err = self.ssh.run(f"kill -TERM {pid}")
            if code != 0:
                raise RuntimeError(err or out or f"Не удалось завершить PID {pid}.")
            return f"SIGTERM отправлен процессу {pid}."
        self._run_async("Завершение процесса", task, lambda text: (messagebox.showinfo("Процессы", text), self.load_processes()))

    def _build_docker(self):
        tab = self.tabs.tab("Docker")
        ctk.CTkLabel(tab, text="Контейнеры Docker", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=14, pady=(14, 6))
        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=4)
        action_rows = [ctk.CTkFrame(actions, fg_color="transparent"), ctk.CTkFrame(actions, fg_color="transparent")]
        for action_row in action_rows:
            action_row.pack(fill="x", pady=2)
        buttons = [
            ("Обновить", lambda: self.load_docker(), "#6558D9", "#776BFF"),
            ("Запустить", lambda: self.docker_action("start"), "#222A3B", "#33405A"),
            ("Остановить", lambda: self.docker_action("stop"), "#6A343E", "#873C4C"),
            ("Перезапустить", lambda: self.docker_action("restart"), "#69552F", "#80683B"),
            ("Удалить", lambda: self.docker_action("rm"), "#6A343E", "#873C4C"),
            ("Журнал", lambda: self.docker_action("logs"), "#222A3B", "#33405A"),
            ("Сведения", lambda: self.docker_action("inspect"), "#222A3B", "#33405A"),
            ("Статистика", lambda: self.docker_action("stats"), "#222A3B", "#33405A"),
            ("Команда…", self.docker_exec_command, "#222A3B", "#33405A"),
            ("Копировать ID", self.copy_docker_id, "#222A3B", "#33405A"),
        ]
        for index, (title, command, color, hover) in enumerate(buttons):
            row = action_rows[0] if index < 5 else action_rows[1]
            ctk.CTkButton(row, text=title, command=command, width=124, height=34, fg_color=color, hover_color=hover).pack(side="left", padx=4)
        ctk.CTkLabel(tab, text="ID, имя, образ и состояние контейнера. Docker должен быть установлен и доступен пользователю SSH.", text_color="#8D9AB2", wraplength=980).pack(anchor="w", padx=14, pady=(2, 6))
        self.docker_rows = ctk.CTkScrollableFrame(tab, height=300)
        self.docker_rows.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.docker_details = ctk.CTkTextbox(tab, height=130)
        self.docker_details.pack(fill="x", padx=14, pady=(0, 14))
        self.docker_details.insert("end", "Выберите контейнер, затем действие.\n")
        self.docker_details.configure(state="disabled")
        self.docker_containers = []
        self.selected_container = None
        ctk.CTkLabel(self.docker_rows, text="Нажмите «Обновить» после подключения.", text_color="#8D9AB2").pack(anchor="w", padx=8, pady=10)

    def load_docker(self):
        command = "docker ps -a --format '{{json .}}'"
        def task():
            code, out, err = self.ssh.run(command)
            if code != 0:
                raise RuntimeError(err or out or "Не удалось получить список контейнеров Docker.")
            containers = []
            for line in out.splitlines():
                if line.strip():
                    containers.append(json.loads(line))
            return containers
        self._run_async("Список Docker-контейнеров", task, self._render_docker)

    def _render_docker(self, containers):
        self.docker_containers = containers
        if self.selected_container:
            self.selected_container = next((item for item in containers if item.get("ID") == self.selected_container.get("ID")), None)
        for child in self.docker_rows.winfo_children():
            child.destroy()
        if not containers:
            ctk.CTkLabel(self.docker_rows, text="Контейнеры не найдены.", text_color="#8D9AB2").pack(anchor="w", padx=8, pady=10)
        for item in containers:
            selected = bool(self.selected_container and item.get("ID") == self.selected_container.get("ID"))
            label = f"{item.get('ID', '')[:12]}   {item.get('Names', '')}   |   {item.get('Image', '')}   |   {item.get('Status', '')}"
            ctk.CTkButton(self.docker_rows, text=label, anchor="w", font=ctk.CTkFont(family="Consolas", size=12), fg_color="#302E58" if selected else "#171F30", hover_color="#222C42", command=lambda container=item: self._select_container(container)).pack(fill="x", padx=4, pady=2)

    def _select_container(self, container):
        self.selected_container = container
        self._render_docker(self.docker_containers)
        summary = f"ID: {container.get('ID')}\nИмя: {container.get('Names')}\nОбраз: {container.get('Image')}\nСостояние: {container.get('Status')}\nПорты: {container.get('Ports') or 'не опубликованы'}"
        self._set_text(self.docker_details, summary)

    def docker_action(self, action):
        if not self.selected_container:
            messagebox.showinfo("Docker", "Сначала выберите контейнер в списке.")
            return
        container_id = self.selected_container.get("ID", "")
        if not container_id or not all(char in "0123456789abcdefABCDEF" for char in container_id):
            messagebox.showerror("Docker", "Некорректный ID контейнера.")
            return
        action_title = {"start": "Запустить", "stop": "Остановить", "restart": "Перезапустить", "logs": "Показать журнал", "inspect": "Показать сведения", "stats": "Показать статистику", "rm": "Удалить"}[action]
        if action in ("stop", "restart") and not messagebox.askyesno("Docker", f"{action_title} контейнер {self.selected_container.get('Names', container_id)}?"):
            return
        if action == "rm" and not messagebox.askyesno("Удалить контейнер", f"Удалить контейнер {self.selected_container.get('Names', container_id)}?\n\nРаботающий контейнер сначала нужно остановить. Образы и тома не удаляются."):
            return
        def task():
            if action == "logs":
                command = f"docker logs --tail 200 --timestamps {container_id}"
            elif action == "inspect":
                command = f"docker inspect {container_id}"
            elif action == "stats":
                command = f"docker stats --no-stream --no-trunc {container_id}"
            elif action == "rm":
                command = f"docker rm {container_id}"
            else:
                command = f"docker {action} {container_id}"
            code, out, err = self.ssh.run(command)
            if code != 0:
                raise RuntimeError(err or out or f"docker {action} завершился с кодом {code}")
            return out.strip() or f"Контейнер {container_id}: {action} выполнен"
        def done(output):
            self._set_text(self.docker_details, output)
            if action not in ("logs", "inspect", "stats"):
                if action == "rm":
                    self.selected_container = None
                self.load_docker()
        self._run_async(f"Docker · {action_title.lower()}", task, done)

    def docker_exec_command(self):
        if not self.selected_container:
            messagebox.showinfo("Docker", "Сначала выберите контейнер в списке.")
            return
        container_id = self.selected_container.get("ID", "")
        if not container_id or not all(char in "0123456789abcdefABCDEF" for char in container_id):
            messagebox.showerror("Docker", "Некорректный ID контейнера.")
            return
        window = ctk.CTkToplevel(self)
        window.title("Команда в контейнере")
        window.geometry("640x400")
        window.minsize(520, 340)
        window.configure(fg_color="#0B0F19")
        window.transient(self)
        self.update_idletasks()
        x = self.winfo_rootx() + max(0, (self.winfo_width() - 640) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - 400) // 2)
        window.geometry(f"640x400+{x}+{y}")

        card = ctk.CTkFrame(window, fg_color="#121827", corner_radius=16)
        card.pack(fill="both", expand=True, padx=16, pady=16)
        ctk.CTkLabel(card, text="Команда в контейнере", font=ctk.CTkFont(size=18, weight="bold"), text_color="#E8ECF5").pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(card, text=f"Контейнер: {self.selected_container.get('Names', container_id)} · {container_id[:12]}", text_color="#8D9AB2").pack(anchor="w", padx=18, pady=(0, 4))
        ctk.CTkLabel(card, text="Команда будет запущена через /bin/sh внутри выбранного контейнера.", text_color="#8D9AB2", wraplength=560).pack(anchor="w", padx=18, pady=(0, 10))
        command_box = ctk.CTkTextbox(card, wrap="word", font=ctk.CTkFont(family="Consolas", size=12), height=180)
        command_box.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        command_box.insert("1.0", "")

        controls = ctk.CTkFrame(card, fg_color="transparent")
        controls.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(controls, text="Отмена", command=window.destroy, fg_color="#222A3B", hover_color="#33405A", width=110).pack(side="right", padx=4)

        def execute():
            command_text = command_box.get("1.0", "end").strip()
            if not command_text:
                messagebox.showinfo("Команда в контейнере", "Введите команду для выполнения.", parent=window)
                command_box.focus_set()
                return
            window.destroy()
            self._execute_docker_command(container_id, command_text)

        ctk.CTkButton(controls, text="Выполнить", command=execute, fg_color="#6558D9", hover_color="#776BFF", width=130).pack(side="right", padx=4)
        command_box._textbox.bind("<Control-Return>", lambda _event: (execute(), "break")[1])
        window.bind("<Escape>", lambda _event: window.destroy())
        window.after(80, window.grab_set)
        command_box.focus_set()

    def _execute_docker_command(self, container_id, command_text):
        quoted_command = shlex.quote(command_text.strip())
        command = f"docker exec {container_id} sh -lc {quoted_command}"

        def task():
            code, out, err = self.ssh.run(command)
            result = out + (("\n" if out and err else "") + err if err else "")
            if code != 0:
                raise RuntimeError(result.strip() or f"Команда завершилась с кодом {code}.")
            return f"Команда: {command_text.strip()}\n[код выхода: {code}]\n{result}".rstrip()

        self._run_async("Команда в Docker-контейнере", task, lambda output: self._set_text(self.docker_details, output))

    def copy_docker_id(self):
        if not self.selected_container:
            messagebox.showinfo("Docker", "Сначала выберите контейнер в списке.")
            return
        container_id = self.selected_container.get("ID", "")
        if not container_id:
            messagebox.showerror("Docker", "У выбранного контейнера нет ID.")
            return
        self.clipboard_clear()
        self.clipboard_append(container_id)
        self._set_status("ID контейнера скопирован")

    def _refresh_tunnel_list(self):
        for child in self.tunnel_list.winfo_children():
            child.destroy()
        if not self.ssh.forwards:
            ctk.CTkLabel(self.tunnel_list, text="Активных туннелей нет.", text_color="#8D9AB2").pack(anchor="w", padx=8, pady=10)
        for server in self.ssh.forwards:
            row = ctk.CTkFrame(self.tunnel_list)
            row.pack(fill="x", pady=4)
            local_port = server.server_address[1]
            host, port = server.destination
            ctk.CTkLabel(row, text=f"127.0.0.1:{local_port}  →  {host}:{port}").pack(side="left", padx=12, pady=8)
            ctk.CTkButton(row, text="Остановить", width=110, fg_color="#6A343E", hover_color="#873C4C", command=lambda s=server: self.stop_tunnel(s)).pack(side="right", padx=8, pady=6)

    def start_tunnel(self):
        try:
            local_port = int(self.tunnel_local_port.get().strip())
            remote_port = int(self.tunnel_remote_port.get().strip())
            remote_host = self.tunnel_remote_host.get().strip()
            if not 1 <= local_port <= 65535 or not 1 <= remote_port <= 65535 or not remote_host:
                raise ValueError
            server = self.ssh.start_forward(local_port, remote_host, remote_port)
        except ValueError:
            messagebox.showerror("SSH-туннель", "Укажите адрес и порты в диапазоне от 1 до 65535.")
            return
        except OSError as exc:
            messagebox.showerror("SSH-туннель", f"Не удалось открыть локальный порт. Возможно, он уже занят.\n\n{exc}")
            return
        except Exception as exc:
            messagebox.showerror("SSH-туннель", str(exc))
            return
        self._refresh_tunnel_list()
        self._set_status(f"Туннель 127.0.0.1:{server.server_address[1]} → {remote_host}:{remote_port} запущен")

    def stop_tunnel(self, server):
        self.ssh.stop_forward(server)
        self._refresh_tunnel_list()
        self._set_status("SSH-туннель остановлен")

    def _set_status(self, text):
        self.status.configure(text=text)

    def _bind_row_selection(self, widget):
        text_widget = widget._textbox
        text_widget.tag_configure("selected_row", background="#302E58", foreground="#FFFFFF")
        widget.selected_line = None
        def select_line(event):
            index = text_widget.index(f"@{event.x},{event.y}")
            line = int(index.split(".", 1)[0])
            if line < 1 or not text_widget.get(f"{line}.0", f"{line}.end").strip():
                return
            was_disabled = str(text_widget.cget("state")) == "disabled"
            if was_disabled:
                text_widget.configure(state="normal")
            widget.selected_line = line
            text_widget.tag_remove("selected_row", "1.0", "end")
            text_widget.tag_add("selected_row", f"{line}.0", f"{line}.end")
            if was_disabled:
                text_widget.configure(state="disabled")
        text_widget.bind("<Button-1>", select_line, add="+")

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _append_text(self, widget, text):
        widget.configure(state="normal")
        widget.insert("end", text)
        widget.see("end")
        widget.configure(state="disabled")

    def _run_async(self, label, func, callback=None):
        if not self.connected and label != "Connect":
            messagebox.showwarning("Нет подключения", "Сначала подключитесь к SSH-серверу.")
            return

        self._set_status(f"{label}…")

        def worker():
            try:
                result = func()
                self.events.put(("ok", label, result, callback))
            except Exception as exc:
                self.events.put(("error", label, str(exc), callback))

        threading.Thread(target=worker, daemon=True).start()


    def _process_events(self):
        try:
            while True:
                kind, label, result, callback = self.events.get_nowait()
                if kind == "passphrase_required":
                    phrase = simpledialog.askstring(
                        "Парольная фраза SSH-ключа",
                        "Введите парольную фразу приватного SSH-ключа:",
                        show="*",
                        parent=self,
                    )
                    if phrase is None:
                        self.connect_button.configure(state="normal", text="Отключиться")
                        self.connection_form_connect.configure(state="normal")
                        self._set_status("Подключение отменено")
                    else:
                        self._retry_connect_with_passphrase(phrase)
                elif kind == "password_required":
                    password = simpledialog.askstring(
                        "SSH-аутентификация",
                        "Введите пароль пользователя SSH. Пароль используется только для этого входа и не сохраняется:",
                        show="*",
                        parent=self,
                    )
                    if password is None:
                        self.connect_button.configure(state="normal", text="Отключиться")
                        self.connection_form_connect.configure(state="normal")
                        self._set_status("Подключение отменено")
                    else:
                        self._retry_connect_with_password(password)
                elif kind == "connected":
                    self.connected = True
                    self._remember_connection(result)
                    self.connect_button.configure(state="normal", text="Отключиться")
                    self.connection_form_connect.configure(state="normal")
                    self.connection_manager.pack_forget()
                    self.app_frame.pack(fill="both", expand=True)
                    self.connection_label.configure(text=f"● Подключено: {result.get('alias') or result['host']}", text_color="#62D6A4")
                    self._set_status(f"Подключено к {result['host']}:{result['port']} · пользователь {result['username']}")
                    self._append_text(self.terminal_output, f"\n[подключено] {result.get('alias') or result['host']} → {result['host']}:{result['port']}\n")
                    self._refresh_tunnel_list()
                    self.refresh_metrics()
                    self.browse_remote()
                elif kind == "connect_error":
                    self.connected = False
                    self.connect_button.configure(state="normal", text="Отключиться")
                    self.connection_form_connect.configure(state="normal")
                    self.connection_label.configure(text="● Нет подключения", text_color="#E07A7A")
                    messagebox.showerror("Ошибка подключения SSH", f"Не удалось подключиться к серверу.\n\n{result}")
                    self._set_status("Не удалось подключиться")
                elif kind == "error":
                    self._set_status(f"Ошибка: {label}")
                    messagebox.showerror("Ошибка операции", f"{label}\n\n{result}")
                else:
                    self._set_status(f"Готово: {label}")
                    if callback:
                        callback(result)
        except queue.Empty:
            pass
        self.after(150, self._process_events)

    def connect_clicked(self):
        try:
            info = self._current_connection()
        except ValueError as exc:
            messagebox.showerror("Подключение", str(exc))
            return
        self.pending_connection = info
        self.pending_passphrase = None
        self.connect_button.configure(state="disabled")
        self.connection_form_connect.configure(state="disabled")
        self._set_status("Подключение…")

        def worker():
            try:
                info = self.ssh.connect(self.pending_connection)
                self.events.put(("connected", "Connect", info, None))
            except paramiko.PasswordRequiredException:
                self.events.put(("passphrase_required", "Connect", None, None))
            except paramiko.AuthenticationException as exc:
                if self.pending_connection.get("auth_mode", "auto") == "key":
                    self.events.put(("connect_error", "Connect", str(exc), None))
                else:
                    self.events.put(("password_required", "Connect", None, None))
            except Exception as exc:
                self.events.put(("connect_error", "Connect", str(exc), None))

        threading.Thread(target=worker, daemon=True).start()

    def _retry_connect_with_passphrase(self, passphrase):
        self.pending_passphrase = passphrase
        self.connect_button.configure(state="disabled")
        self.connection_form_connect.configure(state="disabled")
        self._set_status("Повторная проверка SSH-аутентификации…")

        def worker():
            try:
                info = self.ssh.connect(self.pending_connection, passphrase=passphrase)
                self.events.put(("connected", "Connect", info, None))
            except paramiko.AuthenticationException as exc:
                if self.pending_connection.get("auth_mode", "auto") == "key":
                    self.events.put(("connect_error", "Connect", str(exc), None))
                else:
                    self.events.put(("password_required", "Connect", None, None))
            except Exception as exc:
                self.events.put(("connect_error", "Connect", str(exc), None))

        threading.Thread(target=worker, daemon=True).start()

    def _retry_connect_with_password(self, password):
        self.connect_button.configure(state="disabled")
        self.connection_form_connect.configure(state="disabled")
        self._set_status("Проверка пароля SSH…")

        def worker():
            try:
                info = self.ssh.connect(self.pending_connection, passphrase=self.pending_passphrase, password=password)
                self.events.put(("connected", "Connect", info, None))
            except paramiko.PasswordRequiredException:
                self.events.put(("passphrase_required", "Connect", None, None))
            except Exception as exc:
                self.events.put(("connect_error", "Connect", str(exc), None))

        threading.Thread(target=worker, daemon=True).start()

    def disconnect_current(self):
        self.close_shell()
        self.ssh.close()
        self.connected = False
        self._refresh_tunnel_list()
        self.connection_label.configure(text="● Нет подключения", text_color="#E07A7A")
        self.app_frame.pack_forget()
        self.connection_manager.pack(fill="both", expand=True, padx=40, pady=32)
        self._set_status("Отключено")

    def _command_history_up(self, event=None):
        if self.command_history:
            self.history_index = max(0, self.history_index - 1)
            self.command_entry.delete(0, "end")
            self.command_entry.insert(0, self.command_history[self.history_index])
        return "break"

    def _command_history_down(self, event=None):
        if self.command_history:
            self.history_index = min(len(self.command_history), self.history_index + 1)
            self.command_entry.delete(0, "end")
            if self.history_index < len(self.command_history):
                self.command_entry.insert(0, self.command_history[self.history_index])
        return "break"

    def refresh_metrics(self):
        command = r"""printf 'HOST='; hostname
printf 'UPTIME='; awk '{printf "%.0f", $1}' /proc/uptime
printf 'LOAD='; awk '{print $1" "$2" "$3}' /proc/loadavg
printf 'MEM='; free -b | awk '/Mem:/ {printf "%s %s %s", $3, $2, $7}'
printf 'DISK='; df -P -h / | awk 'NR==2 {printf "%s %s %s", $3, $2, $5}'
printf '\n'"""
        def task():
            code, out, err = self.ssh.run(command)
            if code != 0:
                raise RuntimeError(err or out or f"Command exited with {code}")
            values = {}
            for part in out.strip().splitlines():
                if "=" in part:
                    k, v = part.split("=", 1)
                    values[k] = v.strip()
            return values, out, err
        self._run_async("Обновление показателей", task, self._metrics_done)

    def _metrics_done(self, result):
        values, out, err = result
        self.metric_labels["host"].configure(text=values.get("HOST", "—"))
        try:
            uptime_seconds = max(0, int(values.get("UPTIME", "")))
            days, remainder = divmod(uptime_seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes = remainder // 60
            uptime_parts = ([f"{days} дн."] if days else []) + ([f"{hours} ч."] if hours else []) + [f"{minutes} мин."]
            uptime_text = " ".join(uptime_parts)
        except ValueError:
            uptime_text = "—"
        self.metric_labels["uptime"].configure(text=uptime_text)
        self.metric_labels["cpu"].configure(text=values.get("LOAD", "—"))
        mem = values.get("MEM", "").split()
        if len(mem) == 3:
            used, total, available = map(int, mem)
            self.metric_labels["ram"].configure(text=f"{used/1024**3:.1f} / {total/1024**3:.1f} ГиБ\nдоступно {available/1024**3:.1f}")
        else:
            self.metric_labels["ram"].configure(text="—")
        self.metric_labels["disk"].configure(text=values.get("DISK", "—"))
        summary = (
            f"Имя сервера: {values.get('HOST', '—')}\n"
            f"Время работы: {uptime_text}\n"
            f"Средняя нагрузка: {values.get('LOAD', '—')}\n"
            f"Память (занято / всего / доступно, байт): {values.get('MEM', '—')}\n"
            f"Корневой раздел (занято / всего / заполнено): {values.get('DISK', '—')}"
        )
        self._set_text(self.overview_output, summary + (("\n\nПредупреждение: " + err) if err else ""))

    def check_failed_services(self):
        self.run_command("systemctl --failed --no-pager")

    def run_command(self, command):
        if not command.strip():
            return
        def task():
            code, out, err = self.ssh.run(command)
            return f"Команда: {command}\n[код выхода: {code}]\n{out}{('\\n' + err) if err else ''}\n"
        self._run_async("Выполнение команды", task, lambda text: self._append_text(self.terminal_output, text))

    def run_custom_command(self):
        command = self.command_entry.get().strip()
        if not command:
            return
        if not self.command_history or self.command_history[-1] != command:
            self.command_history.append(command)
        self.history_index = len(self.command_history)
        self.command_entry.delete(0, "end")
        self.run_command(command)

    def browse_remote(self):
        path = self.path_entry.get().strip() or "."
        def task():
            normalized = self.ssh.sftp.normalize(path)
            items = self.ssh.listdir(normalized)
            return normalized, items
        self._run_async("Список удалённых файлов", task, self._files_done)

    def _files_done(self, result):
        path, items = result
        self.remote_path = path
        self.remote_items = items
        self.file_list.selected_line = None
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, path)
        lines = [f"{'ТИП':<8} {'РАЗМЕР':>10}  {'ИЗМЕНЁН':<16}  ИМЯ", "─" * 112]
        self.file_line_items = {}
        row_tags = []
        for item in items:
            kind = "ПАПКА" if item["is_dir"] else "ФАЙЛ"
            size = "—" if item["is_dir"] else self._format_file_size(item["size"])
            try:
                modified = datetime.fromtimestamp(item["mtime"]).strftime("%Y-%m-%d %H:%M")
            except (OverflowError, OSError, TypeError, ValueError):
                modified = "—"
            name = item["name"]
            shown_name = name if len(name) <= 64 else name[:61] + "…"
            line_number = len(lines) + 1
            lines.append(f"{kind:<8} {size:>10}  {modified:<16}  {shown_name}")
            self.file_line_items[line_number] = item
            row_tags.append((line_number, "file_directory" if item["is_dir"] else "file_regular"))
        if not items:
            lines.append("Папка пуста")
        self._set_text(self.file_list, "\n".join(lines))
        text_widget = self.file_list._textbox
        text_widget.configure(state="normal")
        text_widget.tag_configure("table_header", foreground="#B9C5DA", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"))
        text_widget.tag_configure("file_directory", foreground="#A99FFF")
        text_widget.tag_configure("file_regular", foreground="#D5DCEC")
        text_widget.tag_add("table_header", "1.0", "1.end")
        for line_number, tag in row_tags:
            text_widget.tag_add(tag, f"{line_number}.0", f"{line_number}.end")
        text_widget.tag_raise("selected_row")
        text_widget.configure(state="disabled")
        self._set_status(f"Показано объектов: {len(items)} · {path}")

    @staticmethod
    def _format_file_size(size):
        value = float(size)
        for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
            if value < 1024 or unit == "ТиБ":
                return f"{int(value)} {unit}" if unit == "Б" else f"{value:.1f} {unit}"
            value /= 1024
        return "—"

    def go_home(self):
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, ".")
        self.browse_remote()

    def go_parent(self):
        path = self.path_entry.get().strip() or "."
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, posixpath.dirname(path.rstrip("/")) or "/")
        self.browse_remote()

    def rename_remote(self):
        item = self._selected_file_from_text()
        if not item:
            messagebox.showinfo("Переименование", "Выберите файл или папку.")
            return
        name = simpledialog.askstring("Переименование", "Новое имя:", initialvalue=item["name"])
        if not name or name == item["name"]:
            return
        if name in (".", "..") or "/" in name or "\\" in name:
            messagebox.showerror("Переименование", "Укажите имя без символов-разделителей пути.")
            return
        source = posixpath.join(self.remote_path, item["name"])
        target = posixpath.join(self.remote_path, name)
        if not messagebox.askyesno("Переименование", f"Переименовать?\n\n{source}\n→ {target}"):
            return
        self._run_async("Переименование объекта", lambda: (self.ssh.rename(source, target), target)[1], lambda _: self.browse_remote())

    def _selected_file_from_text(self):
        selected_line = getattr(self.file_list, "selected_line", None)
        return self.file_line_items.get(selected_line)

    def open_selected_file(self, event=None):
        item = self._selected_file_from_text()
        if not item:
            return
        if item["is_dir"]:
            next_path = posixpath.join(self.remote_path, item["name"])
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, next_path)
            self.browse_remote()
        else:
            messagebox.showinfo("Удалённый файл", "Двойной щелчок открывает папки. Чтобы получить файл, выберите его и нажмите «Скачать выбранное».")

    def upload_file(self):
        local = filedialog.askopenfilename(title="Выберите файл для загрузки")
        if not local:
            return
        remote = posixpath.join(self.remote_path, os.path.basename(local))
        if not messagebox.askyesno("Загрузка файла", f"Загрузить этот файл?\n\n{local}\n→ {remote}"):
            return
        self._run_async("Загрузка файла", lambda: (self.ssh.upload(local, remote), remote)[1],
                        lambda result: (self._append_text(self.terminal_output, f"Файл загружен: {result}\n"), self.browse_remote()))

    def download_file(self):
        item = self._selected_file_from_text()
        if not item:
            messagebox.showinfo("Скачивание", "Сначала выберите файл в списке.")
            return
        if item["is_dir"]:
            messagebox.showinfo("Скачивание", "Выберите файл, а не папку.")
            return
        local = filedialog.asksaveasfilename(title="Сохранить скачанный файл", initialfile=item["name"])
        if not local:
            return
        remote = posixpath.join(self.remote_path, item["name"])
        self._run_async("Скачивание файла", lambda: (self.ssh.download(remote, local), local)[1],
                        lambda result: messagebox.showinfo("Скачивание завершено", f"Файл сохранён:\n{result}"))

    def preview_remote_file(self):
        item = self._selected_file_from_text()
        if not item:
            messagebox.showinfo("Просмотр файла", "Сначала выберите файл в списке.")
            return
        if item["is_dir"]:
            messagebox.showinfo("Просмотр файла", "Для просмотра выберите файл, а не папку.")
            return
        remote = posixpath.join(self.remote_path, item["name"])
        self._run_async("Просмотр файла", lambda: self.ssh.read_preview(remote), lambda text: self._show_file_preview(item["name"], text))

    def _show_file_preview(self, name, text):
        window = ctk.CTkToplevel(self)
        window.title(f"Просмотр · {name}")
        window.geometry("900x620")
        window.minsize(640, 420)
        window.configure(fg_color="#0B0F19")
        ctk.CTkLabel(window, text=name, font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"), text_color="#E8ECF5").pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(window, text="Только чтение · максимум 1 МБ", text_color="#8D9AB2").pack(anchor="w", padx=16, pady=(0, 8))
        preview = ctk.CTkTextbox(window, wrap="none", font=ctk.CTkFont(family="Consolas", size=12), fg_color="#0D1320", text_color="#E8ECF5", corner_radius=10)
        preview.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        preview.insert("end", text)
        preview.configure(state="disabled")

    def create_folder(self):
        name = simpledialog.askstring("Новая папка", "Имя папки:")
        if not name:
            return
        if "/" in name or name in (".", ".."):
            messagebox.showerror("Некорректное имя", "Введите простое имя папки без косой черты.")
            return
        path = posixpath.join(self.remote_path, name)
        self._run_async("Создание папки", lambda: (self.ssh.mkdir(path), path)[1],
                        lambda result: (self._set_status(f"Создана папка: {result}"), self.browse_remote()))

    def delete_remote(self):
        item = self._selected_file_from_text()
        if not item:
            messagebox.showinfo("Удаление", "Сначала выберите файл или пустую папку.")
            return
        path = posixpath.join(self.remote_path, item["name"])
        kind = "папку" if item["is_dir"] else "файл"
        if not messagebox.askyesno("Подтверждение удаления", f"Удалить удалённый {kind}?\n\n{path}\n\nЭто действие нельзя отменить."):
            return
        self._run_async("Удаление объекта", lambda: (self.ssh.remove(path, item["is_dir"]), path)[1],
                        lambda result: self.browse_remote())

    def load_services(self):
        pattern = self.service_filter.get().strip()
        command = "systemctl list-units --type=service --all --no-pager --no-legend"
        if pattern:
            # Filter is applied locally to avoid shell injection.
            pass
        def task():
            code, out, err = self.ssh.run(command)
            if code not in (0, 1):
                raise RuntimeError(err or out)
            lines = [line.rstrip() for line in out.splitlines() if line.strip()]
            if pattern:
                lines = [line for line in lines if pattern.lower() in line.lower()]
            return lines
        self._run_async("Список служб", task, self._services_done)

    def _services_done(self, lines):
        rows = []
        for line in lines:
            parts = line.split(None, 4)
            if len(parts) >= 4 and parts[0].endswith(".service"):
                rows.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "state": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })
        self.service_rows = rows
        self.services_loaded = True
        self.service_names = [row["unit"] for row in rows]
        self.services_box.selected_line = None
        self._render_services()
        self._set_status(f"Загружено служб: {len(rows)}")

    def _render_services(self):
        heading = f"{'СЛУЖБА':<34} {'ЗАГРУЗКА':<9} {'АКТИВНОСТЬ':<11} {'СОСТОЯНИЕ':<11} ОПИСАНИЕ"
        lines = [heading, "─" * 112]
        self.service_line_units = {}
        row_tags = []

        def fit(value, width):
            value = str(value or "—")
            return value if len(value) <= width else value[:width - 1] + "…"

        for service in self.service_rows:
            line_number = len(lines) + 1
            description = fit(service["description"], 42)
            lines.append(
                f"{fit(service['unit'], 34):<34} {fit(service['load'], 9):<9} "
                f"{fit(service['active'], 11):<11} {fit(service['state'], 11):<11} {description}"
            )
            self.service_line_units[line_number] = service["unit"]
            state_tag = "service_running" if service["active"] == "active" and service["state"] == "running" else "service_other"
            row_tags.append((line_number, state_tag))
        if not self.service_rows:
            hint = "Подходящие службы не найдены." if self.services_loaded else "Подключитесь и нажмите «Показать службы»."
            lines.append(hint)

        self._set_text(self.services_box, "\n".join(lines))
        text_widget = self.services_box._textbox
        text_widget.configure(state="normal")
        text_widget.tag_configure("table_header", foreground="#B9C5DA", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"))
        text_widget.tag_configure("service_running", foreground="#62D6A4")
        text_widget.tag_configure("service_other", foreground="#D5DCEC")
        text_widget.tag_add("table_header", "1.0", "1.end")
        for line_number, tag in row_tags:
            text_widget.tag_add(tag, f"{line_number}.0", f"{line_number}.end")
        text_widget.tag_raise("selected_row")
        text_widget.configure(state="disabled")

    def service_action(self, action):
        action_title = {"start": "Запустить", "stop": "Остановить", "restart": "Перезапустить"}[action]
        selection = self._selected_service_name()
        if not selection:
            selection = simpledialog.askstring(f"{action_title} службу", "Введите имя службы systemd, например ssh.service:")
        if not selection:
            return
        if not selection.endswith(".service"):
            selection += ".service"
        if action in ("stop", "restart") and not messagebox.askyesno("Подтверждение", f"{action_title} службу {selection}?"):
            return
        # Restrict service unit to a safe systemd unit name.
        if not all(c.isalnum() or c in "_.@:-" for c in selection):
            messagebox.showerror("Некорректное имя службы", "Используйте простое имя службы systemd.")
            return
        command = f"systemctl {action} {shlex.quote(selection)}"
        def task():
            code, out, err = self.ssh.run(command)
            return f"Команда: {command}\n[код выхода: {code}]\n{out}{('\\n' + err) if err else ''}"
        self._run_async(f"{action_title} службу", task, lambda text: (self._append_text(self.terminal_output, text + "\n"), self.load_services()))

    def _selected_service_name(self):
        return self.service_line_units.get(getattr(self.services_box, "selected_line", None))

    def show_errors(self):
        self._show_log("journalctl -p err -n 100 --no-pager")

    def show_journal(self):
        self._show_log("journalctl -n 50 --no-pager")

    def show_unit_journal(self):
        unit = self.log_unit.get().strip()
        if not unit:
            messagebox.showinfo("Журнал службы", "Введите имя службы, например ssh или ssh.service.")
            return
        if not all(c.isalnum() or c in "_.@:-" for c in unit):
            messagebox.showerror("Некорректное имя службы", "Используйте простое имя службы systemd.")
            return
        if not unit.endswith(".service"):
            unit += ".service"
        self._show_log(f"journalctl -u {shlex.quote(unit)} -n 100 --no-pager")

    def _show_log(self, command):
        def task():
            code, out, err = self.ssh.run(command)
            return f"Команда: {command}\n[код выхода: {code}]\n{out}{('\\n' + err) if err else ''}"
        self._run_async("Чтение журнала", task, lambda text: self._set_text(self.logs_output, text))

    def on_close(self):
        self.close_shell()
        self.ssh.close()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
