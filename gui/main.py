"""Главное окно приложения"""
import os
import flet as ft
from typing import Optional

from .theme import AppTheme
from .profiles import ProfileManager, EncryptionProfile
from .key_manager import KeyManager
from .crypto_engine import CryptoEngine, OperationResult


class CryptoApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.profile_manager = ProfileManager()
        self.key_manager = KeyManager()
        self.selected_profile_index: int = 0
        self.dropped_files: list[str] = []
        self.current_view: str = "encrypt"
        self.password_field: Optional[ft.TextField] = None
        self.output_dir: Optional[str] = None

        # UI refs
        self.content_area = ft.Column(expand=True)
        self.sidebar_profiles = ft.Column(spacing=4)
        self.log_area = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO)
        self.file_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.drop_zone_text = ft.Text(
            "Перетащите файлы сюда",
            size=16, color=AppTheme.TEXT_SECONDARY, weight=ft.FontWeight.W_500
        )
        self.drop_zone_subtext = ft.Text(
            "или нажмите для выбора файлов",
            size=12, color=AppTheme.TEXT_MUTED
        )
        self.status_text = ft.Text("", size=13, color=AppTheme.TEXT_SECONDARY)

    def build(self):
        self.page.title = "CryptoUtil"
        self.page.bgcolor = AppTheme.BG_PRIMARY
        self.page.padding = 0
        self.page.spacing = 0
        self.page.window.min_width = 1100
        self.page.window.min_height = 700
        self.page.window.width = 1280
        self.page.window.height = 800
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.theme = ft.Theme(
            color_scheme_seed=AppTheme.ACCENT_PRIMARY,
        )

        # File pickers
        self.file_picker = ft.FilePicker(on_result=self._on_file_picked)
        self.dir_picker = ft.FilePicker(on_result=self._on_dir_picked)
        self.key_file_picker = ft.FilePicker(on_result=self._on_key_file_picked)
        self.page.overlay.extend([self.file_picker, self.dir_picker, self.key_file_picker])

        # Keyboard
        self.page.on_keyboard_event = self._on_keyboard

        # Layout
        sidebar = self._build_sidebar()
        main_content = self._build_main_content()

        layout = ft.Row(
            controls=[sidebar, main_content],
            spacing=0,
            expand=True,
        )

        self.page.add(layout)
        self._refresh_profiles()
        self._switch_view("encrypt")

    # ─── SIDEBAR ────────────────────────────────────────────────────────

    def _build_sidebar(self) -> ft.Container:
        nav_buttons = ft.Column(
            controls=[
                self._nav_button("Шифрование", "encrypt", ft.Icons.LOCK),
                self._nav_button("Расшифровка", "decrypt", ft.Icons.LOCK_OPEN),
                self._nav_button("Подпись", "sign", ft.Icons.EDIT_NOTE),
                self._nav_button("Проверка", "verify", ft.Icons.VERIFIED),
                self._nav_button("Хеширование", "hash", ft.Icons.TAG),
                self._nav_button("Ключи", "keys", ft.Icons.KEY),
            ],
            spacing=2,
        )

        profiles_header = ft.Container(
            content=ft.Row(
                controls=[
                    ft.Text(
                        "ПРОФИЛИ",
                        size=11,
                        color=AppTheme.TEXT_MUTED,
                        weight=ft.FontWeight.W_700,
                    ),
                    ft.IconButton(
                        icon=ft.Icons.ADD_CIRCLE_OUTLINE,
                        icon_color=AppTheme.TEXT_MUTED,
                        icon_size=18,
                        tooltip="Создать профиль",
                        on_click=self._show_create_profile_dialog,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            padding=ft.padding.only(left=16, right=8, top=16, bottom=4),
        )

        profiles_section = ft.Column(
            controls=[
                profiles_header,
                ft.Container(
                    content=self.sidebar_profiles,
                    padding=ft.padding.symmetric(horizontal=8),
                ),
            ],
            spacing=0,
        )

        return ft.Container(
            width=AppTheme.SIDEBAR_WIDTH,
            bgcolor=AppTheme.BG_SECONDARY,
            border=ft.border.only(right=ft.BorderSide(1, AppTheme.BORDER_COLOR)),
            content=ft.Column(
                controls=[
                    # Logo
                    ft.Container(
                        content=ft.Row(
                            controls=[
                                ft.Icon(ft.Icons.SHIELD, color=AppTheme.ACCENT_PRIMARY, size=28),
                                ft.Column(
                                    controls=[
                                        ft.Text("CryptoUtil", size=18,
                                                weight=ft.FontWeight.W_700,
                                                color=AppTheme.TEXT_PRIMARY),
                                        ft.Text("v1.0.0", size=10,
                                                color=AppTheme.TEXT_MUTED),
                                    ],
                                    spacing=0,
                                ),
                            ],
                            spacing=10,
                        ),
                        padding=ft.padding.all(20),
                        border=ft.border.only(bottom=ft.BorderSide(1, AppTheme.BORDER_COLOR)),
                    ),
                    # Navigation
                    ft.Container(
                        content=nav_buttons,
                        padding=ft.padding.symmetric(horizontal=8, vertical=12),
                    ),
                    ft.Divider(height=1, color=AppTheme.BORDER_COLOR),
                    # Profiles
                    ft.Container(
                        content=profiles_section,
                        expand=True,
                    ),
                ],
                spacing=0,
                expand=True,
            ),
        )

    def _nav_button(self, text: str, view: str, icon: str = None) -> ft.Container:
        is_active = self.current_view == view

        row_controls = []
        if icon:
            row_controls.append(
                ft.Icon(icon, size=18,
                        color=AppTheme.ACCENT_PRIMARY if is_active else AppTheme.TEXT_MUTED)
            )
        row_controls.append(
            ft.Text(
                text, size=14,
                color=AppTheme.ACCENT_PRIMARY if is_active else AppTheme.TEXT_SECONDARY,
                weight=ft.FontWeight.W_600 if is_active else ft.FontWeight.W_400,
            )
        )

        btn = ft.Container(
            content=ft.Row(controls=row_controls, spacing=10),
            padding=ft.padding.symmetric(horizontal=16, vertical=10),
            border_radius=8,
            bgcolor=f"{AppTheme.ACCENT_PRIMARY}15" if is_active else None,
            on_click=lambda e, v=view: self._switch_view(v),
            ink=True,
        )
        return btn

    # ─── MAIN CONTENT ───────────────────────────────────────────────────

    def _build_main_content(self) -> ft.Container:
        return ft.Container(
            content=self.content_area,
            expand=True,
            padding=ft.padding.all(24),
        )

    def _switch_view(self, view: str):
        self.current_view = view
        self.content_area.controls.clear()

        builders = {
            "encrypt": self._build_encrypt_view,
            "decrypt": self._build_decrypt_view,
            "sign": self._build_sign_view,
            "verify": self._build_verify_view,
            "hash": self._build_hash_view,
            "keys": self._build_keys_view,
        }

        builder = builders.get(view)
        if builder:
            self.content_area.controls.append(builder())

        self.page.update()
        self._rebuild_sidebar_nav()

    def _rebuild_sidebar_nav(self):
        sidebar = self.page.controls[0].controls[0]
        nav_col = sidebar.content.controls[1].content
        views_data = [
            ("Шифрование", "encrypt", ft.Icons.LOCK),
            ("Расшифровка", "decrypt", ft.Icons.LOCK_OPEN),
            ("Подпись", "sign", ft.Icons.EDIT_NOTE),
            ("Проверка", "verify", ft.Icons.VERIFIED),
            ("Хеширование", "hash", ft.Icons.TAG),
            ("Ключи", "keys", ft.Icons.KEY),
        ]
        nav_col.controls = [self._nav_button(l, v, i) for l, v, i in views_data]
        self.page.update()

    # ─── ENCRYPT VIEW ───────────────────────────────────────────────────

    def _build_encrypt_view(self) -> ft.Column:
        self.dropped_files.clear()
        self.file_list.controls.clear()
        self.log_area.controls.clear()

        profile = self._get_selected_profile()

        self.password_field = ft.TextField(
            **AppTheme.input_decoration("Пароль", ft.Icons.LOCK_OUTLINE),
            password=True,
            can_reveal_password=True,
            width=400,
        )

        # Подсказка зависит от режима
        if profile:
            if profile.mode == "symmetric" and profile.use_password:
                password_hint = "Пароль для шифрования данных (обязательно)"
            elif profile.mode in ("hybrid", "asymmetric"):
                password_hint = "Пароль от приватного ключа (если ключ зашифрован)"
            else:
                password_hint = "Пароль (опционально)"
        else:
            password_hint = "Пароль"

        password_label = ft.Text(password_hint, size=12, color=AppTheme.TEXT_MUTED)

        profile_info = self._build_profile_info_card(profile) if profile else ft.Container()
        drop_zone = self._build_drop_zone()

        action_row = ft.Row(
            controls=[
                ft.ElevatedButton(
                    "Зашифровать",
                    icon=ft.Icons.LOCK,
                    bgcolor=AppTheme.ACCENT_PRIMARY,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._encrypt_files,
                ),
                ft.OutlinedButton(
                    "Папка назначения",
                    icon=ft.Icons.FOLDER_OPEN,
                    height=44,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=10),
                        side=ft.BorderSide(1, AppTheme.BORDER_COLOR),
                    ),
                    on_click=lambda _: self.dir_picker.get_directory_path(
                        dialog_title="Папка для результатов"
                    ),
                ),
                self.status_text,
            ],
            spacing=12,
        )

        return ft.Column(
            controls=[
                ft.Text("Шифрование файлов", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Text("Выберите профиль и перетащите файлы для шифрования",
                        size=14, color=AppTheme.TEXT_SECONDARY),
                ft.Container(height=12),
                profile_info,
                ft.Container(height=12),
                self.password_field,
                password_label,
                ft.Container(height=8),
                drop_zone,
                ft.Container(height=4),
                ft.Container(content=self.file_list, height=120, border_radius=8),
                ft.Container(height=8),
                action_row,
                ft.Container(height=8),
                ft.Text("Журнал операций", size=14, weight=ft.FontWeight.W_600,
                        color=AppTheme.TEXT_PRIMARY),
                ft.Container(
                    content=self.log_area,
                    **AppTheme.card_style(),
                    height=160,
                    expand=True,
                ),
            ],
            spacing=4,
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

    # ─── DECRYPT VIEW ───────────────────────────────────────────────────

    def _build_decrypt_view(self) -> ft.Column:
        self.dropped_files.clear()
        self.file_list.controls.clear()
        self.log_area.controls.clear()

        self.password_field = ft.TextField(
            **AppTheme.input_decoration("Пароль", ft.Icons.LOCK_OUTLINE),
            password=True,
            can_reveal_password=True,
            width=400,
        )

        profile = self._get_selected_profile()
        profile_info = self._build_profile_info_card(profile) if profile else ft.Container()
        drop_zone = self._build_drop_zone()

        action_row = ft.Row(
            controls=[
                ft.ElevatedButton(
                    "Расшифровать",
                    icon=ft.Icons.LOCK_OPEN,
                    bgcolor=AppTheme.SUCCESS,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._decrypt_files,
                ),
                ft.OutlinedButton(
                    "Папка назначения",
                    icon=ft.Icons.FOLDER_OPEN,
                    height=44,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=10),
                        side=ft.BorderSide(1, AppTheme.BORDER_COLOR),
                    ),
                    on_click=lambda _: self.dir_picker.get_directory_path(
                        dialog_title="Папка для результатов"
                    ),
                ),
                self.status_text,
            ],
            spacing=12,
        )

        return ft.Column(
            controls=[
                ft.Text("Расшифровка файлов", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Text("Перетащите зашифрованные файлы",
                        size=14, color=AppTheme.TEXT_SECONDARY),
                ft.Container(height=12),
                profile_info,
                ft.Container(height=12),
                self.password_field,
                ft.Container(height=8),
                drop_zone,
                ft.Container(height=4),
                ft.Container(content=self.file_list, height=120, border_radius=8),
                ft.Container(height=8),
                action_row,
                ft.Container(height=8),
                ft.Text("Журнал", size=14, weight=ft.FontWeight.W_600,
                        color=AppTheme.TEXT_PRIMARY),
                ft.Container(content=self.log_area, **AppTheme.card_style(),
                            height=160, expand=True),
            ],
            spacing=4, expand=True, scroll=ft.ScrollMode.AUTO,
        )

    # ─── SIGN VIEW ──────────────────────────────────────────────────────

    def _build_sign_view(self) -> ft.Column:
        self.dropped_files.clear()
        self.file_list.controls.clear()
        self.log_area.controls.clear()

        self.password_field = ft.TextField(
            **AppTheme.input_decoration("Пароль для приватного ключа", ft.Icons.LOCK_OUTLINE),
            password=True,
            can_reveal_password=True,
            width=400,
        )

        profile = self._get_selected_profile()
        drop_zone = self._build_drop_zone()

        action_row = ft.Row(
            controls=[
                ft.ElevatedButton(
                    "Подписать",
                    icon=ft.Icons.EDIT_NOTE,
                    bgcolor=AppTheme.ACCENT_SECONDARY,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._sign_files,
                ),
                self.status_text,
            ],
            spacing=12,
        )

        algo_text = profile.signature_algorithm if profile else "не выбран"

        return ft.Column(
            controls=[
                ft.Text("Цифровая подпись", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Text(f"Алгоритм: {algo_text}",
                        size=14, color=AppTheme.TEXT_SECONDARY),
                ft.Container(height=12),
                self.password_field,
                ft.Container(height=8),
                drop_zone,
                ft.Container(height=4),
                ft.Container(content=self.file_list, height=120, border_radius=8),
                ft.Container(height=8),
                action_row,
                ft.Container(height=8),
                ft.Container(content=self.log_area, **AppTheme.card_style(),
                            height=200, expand=True),
            ],
            spacing=4, expand=True, scroll=ft.ScrollMode.AUTO,
        )

    # ─── VERIFY VIEW ────────────────────────────────────────────────────

    def _build_verify_view(self) -> ft.Column:
        self.dropped_files.clear()
        self.file_list.controls.clear()
        self.log_area.controls.clear()

        self.sig_file_field = ft.TextField(
            **AppTheme.input_decoration("Путь к файлу подписи (.sig)", ft.Icons.VERIFIED),
            width=500,
        )

        drop_zone = self._build_drop_zone()

        action_row = ft.Row(
            controls=[
                ft.ElevatedButton(
                    "Проверить подпись",
                    icon=ft.Icons.VERIFIED,
                    bgcolor=AppTheme.SUCCESS,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._verify_files,
                ),
                ft.OutlinedButton(
                    "Выбрать .sig файл",
                    icon=ft.Icons.FILE_OPEN,
                    height=44,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=10),
                        side=ft.BorderSide(1, AppTheme.BORDER_COLOR),
                    ),
                    on_click=lambda _: self.key_file_picker.pick_files(
                        dialog_title="Выберите файл подписи",
                        allowed_extensions=["sig"],
                    ),
                ),
                self.status_text,
            ],
            spacing=12,
        )

        return ft.Column(
            controls=[
                ft.Text("Проверка подписи", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Container(height=12),
                self.sig_file_field,
                ft.Container(height=8),
                drop_zone,
                ft.Container(height=4),
                ft.Container(content=self.file_list, height=120, border_radius=8),
                ft.Container(height=8),
                action_row,
                ft.Container(height=8),
                ft.Container(content=self.log_area, **AppTheme.card_style(),
                            height=200, expand=True),
            ],
            spacing=4, expand=True, scroll=ft.ScrollMode.AUTO,
        )

    # ─── HASH VIEW ──────────────────────────────────────────────────────

    def _build_hash_view(self) -> ft.Column:
        self.dropped_files.clear()
        self.file_list.controls.clear()
        self.log_area.controls.clear()

        profile = self._get_selected_profile()
        algorithms = ["sha256", "sha512", "blake2", "sha3-256", "sha3-512"]

        self.hash_algo_dropdown = ft.Dropdown(
            label="Алгоритм хеширования",
            width=300,
            options=[ft.dropdown.Option(a) for a in algorithms],
            value=profile.hash_algorithm if profile else "sha256",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )

        self.hash_text_field = ft.TextField(
            **AppTheme.input_decoration("Текст для хеширования", ft.Icons.TEXT_FIELDS),
            multiline=True,
            min_lines=2,
            max_lines=4,
        )

        self.hash_result = ft.TextField(
            label="Результат",
            read_only=True,
            border_color=AppTheme.BORDER_COLOR,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.SUCCESS,
            border_radius=8,
            multiline=True,
            min_lines=2,
            max_lines=3,
        )

        drop_zone = self._build_drop_zone()

        action_row = ft.Row(
            controls=[
                ft.ElevatedButton(
                    "Хешировать файлы",
                    icon=ft.Icons.TAG,
                    bgcolor=AppTheme.WARNING,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._hash_files,
                ),
                ft.ElevatedButton(
                    "Хешировать текст",
                    icon=ft.Icons.TEXT_SNIPPET,
                    bgcolor=AppTheme.ACCENT_SECONDARY,
                    color="white",
                    height=44,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                    on_click=self._hash_text,
                ),
                self.status_text,
            ],
            spacing=12,
        )

        return ft.Column(
            controls=[
                ft.Text("Хеширование", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Container(height=12),
                ft.Row([self.hash_algo_dropdown], spacing=12),
                ft.Container(height=8),
                self.hash_text_field,
                ft.Container(height=8),
                drop_zone,
                ft.Container(height=4),
                ft.Container(content=self.file_list, height=100, border_radius=8),
                ft.Container(height=8),
                action_row,
                ft.Container(height=8),
                self.hash_result,
                ft.Container(height=8),
                ft.Container(content=self.log_area, **AppTheme.card_style(),
                            height=160, expand=True),
            ],
            spacing=4, expand=True, scroll=ft.ScrollMode.AUTO,
        )

    # ─── KEYS VIEW ──────────────────────────────────────────────────────

    def _build_keys_view(self) -> ft.Column:
        self.log_area.controls.clear()
        profile = self._get_selected_profile()

        # USB detection
        usb_drives = KeyManager.detect_removable_drives()
        usb_list = ft.Column(spacing=6)

        if usb_drives:
            for drive in usb_drives:
                keys_on_drive = KeyManager.find_keys_on_drive(drive.path)
                keys_info = f" | {len(keys_on_drive)} ключ(ей)" if keys_on_drive else ""

                usb_card = ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.USB, color=AppTheme.SUCCESS, size=24),
                            ft.Column(
                                controls=[
                                    ft.Text(drive.drive_label, size=14,
                                            weight=ft.FontWeight.W_600,
                                            color=AppTheme.TEXT_PRIMARY),
                                    ft.Text(
                                        f"{drive.free_space_mb:.0f} MB свободно{keys_info}",
                                        size=12, color=AppTheme.TEXT_SECONDARY
                                    ),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                            ft.Row(
                                controls=[
                                    ft.IconButton(
                                        icon=ft.Icons.SAVE_ALT,
                                        tooltip="Сохранить ключи на USB",
                                        icon_color=AppTheme.ACCENT_PRIMARY,
                                        on_click=lambda e, d=drive: self._save_keys_to_usb(d),
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DOWNLOAD,
                                        tooltip="Загрузить ключи с USB",
                                        icon_color=AppTheme.SUCCESS,
                                        on_click=lambda e, d=drive: self._load_keys_from_usb(d),
                                    ),
                                ],
                                spacing=0,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    **AppTheme.card_style(),
                )
                usb_list.controls.append(usb_card)
        else:
            usb_list.controls.append(
                ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.USB_OFF, color=AppTheme.TEXT_MUTED, size=20),
                            ft.Text("USB-накопители не обнаружены",
                                    size=13, color=AppTheme.TEXT_MUTED),
                        ],
                        spacing=8,
                    ),
                    padding=ft.padding.all(12),
                )
            )

        # Key generation
        self.key_password_field = ft.TextField(
            **AppTheme.input_decoration("Пароль для ключа (опционально)", ft.Icons.LOCK_OUTLINE),
            password=True,
            can_reveal_password=True,
            width=400,
        )

        profile_name = profile.name if profile else "не выбран"
        profile_mode = profile.mode if profile else "-"
        profile_rsa = str(profile.rsa_key_size) if profile else "-"

        return ft.Column(
            controls=[
                ft.Text("Управление ключами", size=24,
                        weight=ft.FontWeight.W_700, color=AppTheme.TEXT_PRIMARY),
                ft.Text("Генерация, хранение и управление криптографическими ключами",
                        size=14, color=AppTheme.TEXT_SECONDARY),
                ft.Container(height=16),

                # USB section
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.USB, color=AppTheme.ACCENT_PRIMARY, size=20),
                        ft.Text("USB-накопители", size=16,
                                weight=ft.FontWeight.W_600, color=AppTheme.TEXT_PRIMARY),
                    ],
                    spacing=8,
                ),
                ft.Container(height=4),
                usb_list,
                ft.Container(
                    content=ft.TextButton(
                        "Обновить список USB",
                        icon=ft.Icons.REFRESH,
                        on_click=lambda _: self._switch_view("keys"),
                    ),
                ),
                ft.Divider(color=AppTheme.BORDER_COLOR),

                # Key generation section
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.KEY, color=AppTheme.ACCENT_PRIMARY, size=20),
                        ft.Text("Генерация ключей", size=16,
                                weight=ft.FontWeight.W_600, color=AppTheme.TEXT_PRIMARY),
                    ],
                    spacing=8,
                ),
                ft.Container(height=4),
                ft.Text(
                    f"Профиль: {profile_name} | Режим: {profile_mode} | RSA: {profile_rsa}",
                    size=13, color=AppTheme.TEXT_SECONDARY,
                ),
                ft.Container(height=8),
                self.key_password_field,
                ft.Container(height=8),
                ft.Row(
                    controls=[
                        ft.ElevatedButton(
                            "Генерировать ключи",
                            icon=ft.Icons.KEY,
                            bgcolor=AppTheme.ACCENT_PRIMARY,
                            color="white",
                            height=44,
                            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
                            on_click=self._generate_keys,
                        ),
                        ft.OutlinedButton(
                            "Папка для ключей",
                            icon=ft.Icons.FOLDER_OPEN,
                            height=44,
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                side=ft.BorderSide(1, AppTheme.BORDER_COLOR),
                            ),
                            on_click=lambda _: self.dir_picker.get_directory_path(
                                dialog_title="Папка для сохранения ключей"
                            ),
                        ),
                    ],
                    spacing=12,
                ),
                ft.Container(height=12),
                ft.Text("Журнал", size=14, weight=ft.FontWeight.W_600,
                        color=AppTheme.TEXT_PRIMARY),
                ft.Container(content=self.log_area, **AppTheme.card_style(),
                            height=200, expand=True),
            ],
            spacing=4, expand=True, scroll=ft.ScrollMode.AUTO,
        )

    # ─── DROP ZONE ──────────────────────────────────────────────────────

    def _build_drop_zone(self) -> ft.Container:
        self.drop_zone_text.value = "Перетащите файлы сюда"
        self.drop_zone_subtext.value = "или нажмите для выбора"

        drop_content = ft.Column(
            controls=[
                ft.Icon(ft.Icons.CLOUD_UPLOAD_OUTLINED,
                        color=AppTheme.ACCENT_PRIMARY, size=48),
                self.drop_zone_text,
                self.drop_zone_subtext,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=8,
        )

        drop_container = ft.Container(
            content=drop_content,
            height=160,
            border=ft.border.all(2, f"{AppTheme.ACCENT_PRIMARY}40"),
            border_radius=16,
            bgcolor=f"{AppTheme.ACCENT_PRIMARY}08",
            alignment=ft.alignment.center,
            on_click=lambda _: self.file_picker.pick_files(
                allow_multiple=True,
                dialog_title="Выберите файлы",
            ),
            ink=True,
        )

        return drop_container

    # ─── PROFILE CARD ───────────────────────────────────────────────────

    def _build_profile_info_card(self, profile: EncryptionProfile) -> ft.Container:
        chips = []

        # Mode chip
        chips.append(ft.Container(
            content=ft.Text(profile.mode.upper(), size=11,
                            color="white", weight=ft.FontWeight.W_700),
            bgcolor=profile.color,
            border_radius=4,
            padding=ft.padding.symmetric(horizontal=8, vertical=3),
        ))

        # Symmetric algorithm chip
        chips.append(ft.Container(
            content=ft.Text(profile.symmetric_algorithm, size=11,
                            color=AppTheme.TEXT_PRIMARY),
            bgcolor=AppTheme.BG_INPUT,
            border_radius=4,
            padding=ft.padding.symmetric(horizontal=8, vertical=3),
            border=ft.border.all(1, AppTheme.BORDER_COLOR),
        ))

        # RSA chip
        if profile.mode in ("hybrid", "asymmetric"):
            chips.append(ft.Container(
                content=ft.Text(f"RSA-{profile.rsa_key_size}", size=11,
                                color=AppTheme.TEXT_PRIMARY),
                bgcolor=AppTheme.BG_INPUT,
                border_radius=4,
                padding=ft.padding.symmetric(horizontal=8, vertical=3),
                border=ft.border.all(1, AppTheme.BORDER_COLOR),
            ))

        # Auto-sign chip
        if profile.auto_sign:
            chips.append(ft.Container(
                content=ft.Text("Автоподпись", size=11, color=AppTheme.SUCCESS),
                bgcolor=f"{AppTheme.SUCCESS}15",
                border_radius=4,
                padding=ft.padding.symmetric(horizontal=8, vertical=3),
            ))

        return ft.Container(
            content=ft.Row(
                controls=[
                    ft.Container(
                        width=4,
                        height=50,
                        bgcolor=profile.color,
                        border_radius=2,
                    ),
                    ft.Column(
                        controls=[
                            ft.Text(profile.name, size=15,
                                    weight=ft.FontWeight.W_600,
                                    color=AppTheme.TEXT_PRIMARY),
                            ft.Row(controls=chips, spacing=6, wrap=True),
                        ],
                        spacing=6,
                        expand=True,
                    ),
                ],
                spacing=12,
            ),
            **AppTheme.card_style(),
        )

    # ─── PROFILES SIDEBAR ───────────────────────────────────────────────

    def _refresh_profiles(self):
        self.sidebar_profiles.controls.clear()

        for i, profile in enumerate(self.profile_manager.profiles):
            is_selected = i == self.selected_profile_index

            card = ft.Container(
                content=ft.Row(
                    controls=[
                        ft.Container(
                            width=4, height=36,
                            bgcolor=profile.color if is_selected else "transparent",
                            border_radius=2,
                        ),
                        ft.Column(
                            controls=[
                                ft.Text(
                                    profile.name, size=13,
                                    weight=ft.FontWeight.W_600 if is_selected else ft.FontWeight.W_400,
                                    color=AppTheme.TEXT_PRIMARY if is_selected else AppTheme.TEXT_SECONDARY,
                                    max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS,
                                ),
                                ft.Text(
                                    profile.description, size=10,
                                    color=AppTheme.TEXT_MUTED,
                                    max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS,
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                    ],
                    spacing=8,
                ),
                padding=ft.padding.symmetric(horizontal=8, vertical=8),
                border_radius=8,
                bgcolor=f"{profile.color}15" if is_selected else None,
                on_click=lambda e, idx=i: self._select_profile(idx),
                ink=True,
            )
            self.sidebar_profiles.controls.append(card)

        self.page.update()

    def _select_profile(self, index: int):
        self.selected_profile_index = index
        self._refresh_profiles()
        self._switch_view(self.current_view)

    def _get_selected_profile(self) -> Optional[EncryptionProfile]:
        return self.profile_manager.get_profile(self.selected_profile_index)

    # ─── FILE OPERATIONS ────────────────────────────────────────────────

    def _on_file_picked(self, e: ft.FilePickerResultEvent):
        if e.files:
            for f in e.files:
                if f.path and f.path not in self.dropped_files:
                    self.dropped_files.append(f.path)
                    self._add_file_to_list(f.path)
            self._update_drop_zone_count()
            self.page.update()

    def _on_dir_picked(self, e: ft.FilePickerResultEvent):
        if e.path:
            self.output_dir = e.path
            self.status_text.value = f"Выход: {os.path.basename(e.path)}"
            self.status_text.color = AppTheme.ACCENT_PRIMARY
            self.page.update()

    def _on_key_file_picked(self, e: ft.FilePickerResultEvent):
        if e.files and hasattr(self, 'sig_file_field'):
            self.sig_file_field.value = e.files[0].path
            self.page.update()

    def _add_file_to_list(self, filepath: str):
        filename = os.path.basename(filepath)
        try:
            size = os.path.getsize(filepath)
            size_str = self._format_size(size)
        except OSError:
            size_str = "?"

        item = ft.Container(
            content=ft.Row(
                controls=[
                    ft.Icon(ft.Icons.INSERT_DRIVE_FILE,
                            color=AppTheme.ACCENT_PRIMARY, size=18),
                    ft.Text(filename, size=13, color=AppTheme.TEXT_PRIMARY,
                            expand=True, max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(size_str, size=12, color=AppTheme.TEXT_MUTED),
                    ft.IconButton(
                        icon=ft.Icons.CLOSE,
                        icon_size=16,
                        icon_color=AppTheme.TEXT_MUTED,
                        tooltip="Удалить",
                        on_click=lambda e, fp=filepath: self._remove_file(fp),
                    ),
                ],
                spacing=8,
            ),
            padding=ft.padding.symmetric(horizontal=12, vertical=4),
            border_radius=6,
            bgcolor=AppTheme.BG_CARD,
            data=filepath,  # store filepath in data for easy removal
        )
        self.file_list.controls.append(item)

    def _remove_file(self, filepath: str):
        if filepath in self.dropped_files:
            self.dropped_files.remove(filepath)
        self.file_list.controls = [
            c for c in self.file_list.controls
            if getattr(c, 'data', None) != filepath
        ]
        self._update_drop_zone_count()
        self.page.update()

    def _update_drop_zone_count(self):
        count = len(self.dropped_files)
        if count > 0:
            self.drop_zone_text.value = f"Выбрано файлов: {count}"
            self.drop_zone_subtext.value = "Нажмите чтобы добавить ещё"
        else:
            self.drop_zone_text.value = "Перетащите файлы сюда"
            self.drop_zone_subtext.value = "или нажмите для выбора"

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ["Б", "КБ", "МБ", "ГБ"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} ТБ"

    # ─── LOG ────────────────────────────────────────────────────────────

    def _add_log(self, message: str, is_error: bool = False, is_success: bool = False):
        if is_error:
            color = AppTheme.ERROR
            icon = ft.Icons.ERROR_OUTLINE
        elif is_success:
            color = AppTheme.SUCCESS
            icon = ft.Icons.CHECK_CIRCLE_OUTLINE
        else:
            color = AppTheme.TEXT_SECONDARY
            icon = ft.Icons.INFO_OUTLINE

        self.log_area.controls.append(
            ft.Container(
                content=ft.Row(
                    controls=[
                        ft.Icon(icon, color=color, size=16),
                        ft.Text(message, size=12, color=color,
                                expand=True, max_lines=3,
                                overflow=ft.TextOverflow.ELLIPSIS,
                                selectable=True),
                    ],
                    spacing=8,
                ),
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
            )
        )
        self.page.update()

    # ─── CRYPTO ACTIONS ─────────────────────────────────────────────────

    def _encrypt_files(self, e):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return
        if not self.dropped_files:
            self._add_log("Файлы не выбраны", is_error=True)
            return

        password = None
        if self.password_field and self.password_field.value:
            password = self.password_field.value

        for filepath in list(self.dropped_files):
            self._add_log(f"Шифрование: {os.path.basename(filepath)}...")
            result = CryptoEngine.encrypt_file(filepath, profile, password, self.output_dir)

            if result.success:
                out_name = os.path.basename(result.output_path) if result.output_path else ""
                self._add_log(f"Зашифровано -> {out_name}", is_success=True)

                if result.details:
                    # Показываем источник ключа
                    key_src = result.details.get('key_source', '')
                    if key_src:
                        self._add_log(f"  Ключ: {key_src}")

                    # Показываем путь к сохранённому ключу
                    key_file = result.details.get('key_file', '')
                    if key_file:
                        self._add_log(f"  Файл ключа: {os.path.basename(key_file)}")

                    # Предупреждение о новых ключах
                    warning = result.details.get('warning', '')
                    if warning:
                        self._add_log(f"  ⚠️ {warning}", is_error=True)

                    # Пути к сгенерированным ключам
                    priv = result.details.get('private_key_path', '')
                    pub = result.details.get('public_key_path', '')
                    if priv:
                        self._add_log(f"  Приватный ключ: {priv}")
                        # Обновляем профиль
                        profile.private_key_path = priv
                    if pub:
                        self._add_log(f"  Публичный ключ: {pub}")
                        profile.public_key_path = pub

                    if priv or pub:
                        self.profile_manager.update_profile(
                            self.selected_profile_index, profile
                        )

                    # Хеш
                    h = result.details.get('hash', '')
                    ha = result.details.get('hash_algorithm', '')
                    if h:
                        self._add_log(f"  Хеш ({ha}): {h[:48]}...")

                    # Подпись
                    sig = result.details.get('signature_file', '')
                    if sig:
                        self._add_log(f"  Подпись: {os.path.basename(sig)}", is_success=True)

                    sig_err = result.details.get('signature_error', '')
                    if sig_err:
                        self._add_log(f"  Ошибка подписи: {sig_err}", is_error=True)
            else:
                self._add_log(result.message, is_error=True)

    def _decrypt_files(self, e):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return
        if not self.dropped_files:
            self._add_log("Файлы не выбраны", is_error=True)
            return

        password = None
        if self.password_field and self.password_field.value:
            password = self.password_field.value

        for filepath in list(self.dropped_files):
            self._add_log(f"Расшифровка: {os.path.basename(filepath)}...")
            result = CryptoEngine.decrypt_file(filepath, profile, password, self.output_dir)
            if result.success:
                out_name = os.path.basename(result.output_path) if result.output_path else ""
                self._add_log(f"Успешно расшифровано -> {out_name}", is_success=True)
            else:
                self._add_log(f"Ошибка: {result.message}", is_error=True)

    def _sign_files(self, e):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return
        if not self.dropped_files:
            self._add_log("Файлы не выбраны", is_error=True)
            return

        password = None
        if self.password_field and self.password_field.value:
            password = self.password_field.value

        for filepath in list(self.dropped_files):
            self._add_log(f"Подпись: {os.path.basename(filepath)}...")
            result = CryptoEngine.sign_file(filepath, profile, password)
            if result.success:
                self._add_log(f"Подписано: {result.message}", is_success=True)
            else:
                self._add_log(f"Ошибка: {result.message}", is_error=True)

    def _verify_files(self, e):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return
        if not self.dropped_files:
            self._add_log("Файлы не выбраны", is_error=True)
            return

        sig_path = None
        if hasattr(self, 'sig_file_field') and self.sig_file_field.value:
            sig_path = self.sig_file_field.value

        for filepath in list(self.dropped_files):
            actual_sig = sig_path or (filepath + ".sig")
            self._add_log(f"Проверка: {os.path.basename(filepath)}...")
            result = CryptoEngine.verify_signature(filepath, actual_sig, profile)
            if result.success:
                self._add_log(result.message, is_success=True)
            else:
                self._add_log(result.message, is_error=True)

    def _hash_files(self, e):
        if not self.dropped_files:
            self._add_log("Файлы не выбраны", is_error=True)
            return

        algo = "sha256"
        if hasattr(self, 'hash_algo_dropdown') and self.hash_algo_dropdown.value:
            algo = self.hash_algo_dropdown.value

        results = []
        for filepath in list(self.dropped_files):
            self._add_log(f"Хеширование: {os.path.basename(filepath)}...")
            result = CryptoEngine.hash_file(filepath, algo)
            if result.success:
                hash_val = result.details["hash"]
                self._add_log(
                    f"{os.path.basename(filepath)}: {hash_val[:48]}...",
                    is_success=True
                )
                results.append(f"{os.path.basename(filepath)}: {hash_val}")
            else:
                self._add_log(f"Ошибка: {result.message}", is_error=True)

        if hasattr(self, 'hash_result') and results:
            self.hash_result.value = "\n".join(results)
            self.page.update()

    def _hash_text(self, e):
        if not hasattr(self, 'hash_text_field') or not self.hash_text_field.value:
            self._add_log("Введите текст для хеширования", is_error=True)
            return

        from src.hashing import HashManager

        algo = "sha256"
        if hasattr(self, 'hash_algo_dropdown') and self.hash_algo_dropdown.value:
            algo = self.hash_algo_dropdown.value

        text_data = self.hash_text_field.value.encode('utf-8')

        try:
            hasher = HashManager.get_hasher(algo)
            hash_bytes = hasher.hash_data(text_data)
            hash_hex = hash_bytes.hex()

            if hasattr(self, 'hash_result'):
                self.hash_result.value = hash_hex

            self._add_log(f"Хеш текста ({algo}): {hash_hex[:48]}...", is_success=True)
            self.page.update()
        except Exception as ex:
            self._add_log(f"Ошибка: {str(ex)}", is_error=True)

    # ─── KEY OPERATIONS ─────────────────────────────────────────────────

    def _generate_keys(self, e):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return

        output_dir = self.output_dir or KeyManager.get_local_key_dir()

        password = None
        if hasattr(self, 'key_password_field') and self.key_password_field.value:
            password = self.key_password_field.value

        self._add_log(f"Генерация ключей для профиля: {profile.name}...")

        result = CryptoEngine.generate_keys(profile, output_dir, password)
        if result.success:
            self._add_log(result.message, is_success=True)
            if result.output_path:
                self._add_log(f"  Сохранено в: {result.output_path}")

            # Update profile with key paths
            if result.details:
                profile.private_key_path = result.details.get("private_key_path", "")
                profile.public_key_path = result.details.get("public_key_path", "")
                self.profile_manager.update_profile(self.selected_profile_index, profile)
                self._add_log("  Пути ключей сохранены в профиль", is_success=True)
        else:
            self._add_log(f"Ошибка: {result.message}", is_error=True)

    def _save_keys_to_usb(self, drive):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return

        if not profile.private_key_path or not os.path.exists(profile.private_key_path):
            self._add_log("Сначала сгенерируйте ключи", is_error=True)
            return

        if not profile.public_key_path or not os.path.exists(profile.public_key_path):
            self._add_log("Публичный ключ не найден", is_error=True)
            return

        try:
            with open(profile.private_key_path, "rb") as f:
                priv_data = f.read()
            with open(profile.public_key_path, "rb") as f:
                pub_data = f.read()

            paths = KeyManager.save_keys_to_drive(
                drive.path, profile.name, priv_data, pub_data
            )

            self._add_log(f"Ключи сохранены на {drive.drive_label}", is_success=True)
            self._add_log(f"  {paths['private_key_path']}")
        except Exception as ex:
            self._add_log(f"Ошибка сохранения на USB: {str(ex)}", is_error=True)

    def _load_keys_from_usb(self, drive):
        profile = self._get_selected_profile()
        if not profile:
            self._add_log("Профиль не выбран", is_error=True)
            return

        keys_found = KeyManager.find_keys_on_drive(drive.path)
        if not keys_found:
            self._add_log("Ключи не найдены на этом накопителе", is_error=True)
            return

        key_info = keys_found[0]

        if key_info["private_key_exists"]:
            profile.private_key_path = key_info["private_key_path"]
        if key_info["public_key_exists"]:
            profile.public_key_path = key_info["public_key_path"]

        self.profile_manager.update_profile(self.selected_profile_index, profile)

        self._add_log(
            f"Ключи загружены с {drive.drive_label} (профиль: {key_info['profile_name']})",
            is_success=True
        )
        if profile.private_key_path:
            self._add_log(f"  Приватный: {profile.private_key_path}")
        if profile.public_key_path:
            self._add_log(f"  Публичный: {profile.public_key_path}")

    # ─── CREATE PROFILE DIALOG ──────────────────────────────────────────

    def _show_create_profile_dialog(self, e):
        name_field = ft.TextField(
            **AppTheme.input_decoration("Название профиля", ft.Icons.LABEL_OUTLINE),
        )
        desc_field = ft.TextField(
            **AppTheme.input_decoration("Описание", ft.Icons.DESCRIPTION),
        )
        mode_dd = ft.Dropdown(
            label="Режим шифрования",
            options=[
                ft.dropdown.Option("hybrid", "Гибридный (RSA + симметричный)"),
                ft.dropdown.Option("symmetric", "Симметричный (пароль/ключ)"),
                ft.dropdown.Option("asymmetric", "Асимметричный (только RSA)"),
            ],
            value="hybrid",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )
        sym_dd = ft.Dropdown(
            label="Симметричный алгоритм",
            options=[
                ft.dropdown.Option("AES", "AES-256-GCM"),
                ft.dropdown.Option("ChaCha20", "ChaCha20-Poly1305"),
            ],
            value="AES",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )
        rsa_dd = ft.Dropdown(
            label="Размер RSA ключа",
            options=[
                ft.dropdown.Option("2048"),
                ft.dropdown.Option("3072"),
                ft.dropdown.Option("4096"),
            ],
            value="2048",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )
        sig_dd = ft.Dropdown(
            label="Алгоритм подписи",
            options=[
                ft.dropdown.Option("Ed25519"),
                ft.dropdown.Option("RSA"),
            ],
            value="Ed25519",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )
        hash_dd = ft.Dropdown(
            label="Алгоритм хеширования",
            options=[
                ft.dropdown.Option(a) for a in
                ["sha256", "sha512", "blake2", "sha3-256", "sha3-512"]
            ],
            value="sha256",
            border_color=AppTheme.BORDER_COLOR,
            focused_border_color=AppTheme.ACCENT_PRIMARY,
            bgcolor=AppTheme.BG_INPUT,
            color=AppTheme.TEXT_PRIMARY,
            border_radius=8,
        )
        use_password_cb = ft.Checkbox(
            label="Использовать пароль",
            value=False,
            check_color=AppTheme.ACCENT_PRIMARY,
        )
        auto_sign_cb = ft.Checkbox(
            label="Автоподпись при шифровании",
            value=False,
            check_color=AppTheme.ACCENT_PRIMARY,
        )

        color_options = ["#3b82f6", "#ef4444", "#f59e0b", "#10b981", "#8b5cf6", "#ec4899"]
        selected_color = [color_options[0]]

        color_containers = []
        for i, c in enumerate(color_options):
            cc = ft.Container(
                width=28, height=28,
                bgcolor=c,
                border_radius=14,
                border=ft.border.all(2, "white" if i == 0 else "transparent"),
                data=c,
            )
            color_containers.append(cc)

        def on_color_click(e):
            selected_color[0] = e.control.data
            for cc in color_containers:
                cc.border = ft.border.all(
                    2, "white" if cc.data == selected_color[0] else "transparent"
                )
            self.page.update()

        for cc in color_containers:
            cc.on_click = on_color_click

        color_row = ft.Row(controls=color_containers, spacing=6)

        def save_profile(e):
            if not name_field.value:
                name_field.error_text = "Введите название"
                self.page.update()
                return

            from datetime import datetime
            new_profile = EncryptionProfile(
                name=name_field.value,
                description=desc_field.value or "",
                mode=mode_dd.value,
                symmetric_algorithm=sym_dd.value,
                rsa_key_size=int(rsa_dd.value),
                signature_algorithm=sig_dd.value,
                hash_algorithm=hash_dd.value,
                use_password=use_password_cb.value,
                auto_sign=auto_sign_cb.value,
                color=selected_color[0],
                created_at=datetime.now().isoformat(),
            )
            self.profile_manager.add_profile(new_profile)
            self._refresh_profiles()
            dialog.open = False
            self.page.update()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Создать профиль", weight=ft.FontWeight.W_700, size=20),
            bgcolor=AppTheme.BG_SECONDARY,
            content=ft.Container(
                content=ft.Column(
                    controls=[
                        name_field,
                        desc_field,
                        mode_dd,
                        ft.Row([sym_dd, rsa_dd], spacing=12),
                        ft.Row([sig_dd, hash_dd], spacing=12),
                        ft.Row([use_password_cb, auto_sign_cb], spacing=12),
                        ft.Text("Цвет:", size=13, color=AppTheme.TEXT_SECONDARY),
                        color_row,
                    ],
                    spacing=12,
                    tight=True,
                    scroll=ft.ScrollMode.AUTO,
                ),
                width=520,
                height=480,
            ),
            actions=[
                ft.TextButton(
                    "Отмена",
                    on_click=lambda e: self._close_dialog(dialog),
                ),
                ft.ElevatedButton(
                    "Создать",
                    bgcolor=AppTheme.ACCENT_PRIMARY,
                    color="white",
                    on_click=save_profile,
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()

    def _close_dialog(self, dialog):
        dialog.open = False
        self.page.update()

    # ─── KEYBOARD ───────────────────────────────────────────────────────

    def _on_keyboard(self, e: ft.KeyboardEvent):
        views = ["encrypt", "decrypt", "sign", "verify", "hash", "keys"]
        if e.ctrl:
            key_map = {"1": 0, "2": 1, "3": 2, "4": 3, "5": 4, "6": 5}
            idx = key_map.get(e.key)
            if idx is not None and idx < len(views):
                self._switch_view(views[idx])