"""Точка входа для GUI"""
import flet as ft
from gui.main import CryptoApp


def main(page: ft.Page):
    app = CryptoApp(page)
    app.build()


if __name__ == "__main__":
    ft.app(target=main)