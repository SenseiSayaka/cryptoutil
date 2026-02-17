"""Тема и константы оформления"""
import flet as ft


class AppTheme:
    # Цвета
    BG_PRIMARY = "#0a0e17"
    BG_SECONDARY = "#111827"
    BG_CARD = "#1a2332"
    BG_CARD_HOVER = "#1f2b3d"
    BG_INPUT = "#0d1421"

    ACCENT_PRIMARY = "#3b82f6"
    ACCENT_SECONDARY = "#8b5cf6"
    ACCENT_GRADIENT_START = "#3b82f6"
    ACCENT_GRADIENT_END = "#8b5cf6"

    TEXT_PRIMARY = "#f1f5f9"
    TEXT_SECONDARY = "#94a3b8"
    TEXT_MUTED = "#64748b"

    SUCCESS = "#10b981"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"

    BORDER_COLOR = "#1e293b"
    BORDER_ACTIVE = "#3b82f6"

    # Размеры
    SIDEBAR_WIDTH = 280
    BORDER_RADIUS = 12
    CARD_PADDING = 20

    @classmethod
    def card_style(cls):
        return {
            "bgcolor": cls.BG_CARD,
            "border_radius": cls.BORDER_RADIUS,
            "padding": cls.CARD_PADDING,
            "border": ft.border.all(1, cls.BORDER_COLOR),
        }

    @classmethod
    def input_style(cls):
        return ft.InputBorder.OUTLINE

    @classmethod
    def input_decoration(cls, label: str, icon: str = None):
        return {
            "label": label,
            "label_style": ft.TextStyle(color=cls.TEXT_SECONDARY, size=13),
            "border": cls.input_style(),
            "border_color": cls.BORDER_COLOR,
            "focused_border_color": cls.ACCENT_PRIMARY,
            "bgcolor": cls.BG_INPUT,
            "color": cls.TEXT_PRIMARY,
            "cursor_color": cls.ACCENT_PRIMARY,
            "border_radius": 8,
            "content_padding": ft.padding.symmetric(horizontal=16, vertical=12),
            "prefix_icon": icon,
        }