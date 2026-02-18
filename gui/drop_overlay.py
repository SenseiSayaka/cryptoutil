"""Невидимый tkinter overlay для drag & drop файлов из ОС"""
import threading
import re
from tkinterdnd2 import TkinterDnD, DND_FILES
import tkinter as tk
from typing import Callable, Optional


class DropOverlay:
    """
    Прозрачное tkinter окно поверх Flet drop_zone.
    Перехватывает файлы перетащенные из ОС и вызывает callback.
    """

    def __init__(self, on_files_dropped: Callable[[list[str]], None]):
        self.on_files_dropped = on_files_dropped
        self._root: Optional[TkinterDnD.Tk] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sync_thread: Optional[threading.Thread] = None

        # Текущая позиция/размер зоны (обновляется снаружи)
        self._zone_x: int = 0
        self._zone_y: int = 0
        self._zone_w: int = 400
        self._zone_h: int = 160

        # Callbacks для hover эффектов
        self.on_hover_enter: Optional[Callable] = None
        self.on_hover_leave: Optional[Callable] = None

    def start(self):
        """Запустить overlay в отдельном потоке"""
        self._running = True
        self._thread = threading.Thread(target=self._run_tkinter, daemon=True)
        self._thread.start()

    def stop(self):
        """Остановить overlay"""
        self._running = False
        if self._root:
            try:
                self._root.quit()
                self._root.destroy()
            except Exception:
                pass

    def update_position(self, x: int, y: int, w: int, h: int):
        """Обновить позицию и размер overlay"""
        self._zone_x = x
        self._zone_y = y
        self._zone_w = w
        self._zone_h = h

        if self._root:
            try:
                self._root.geometry(f"{w}x{h}+{x}+{y}")
            except Exception:
                pass

    def _run_tkinter(self):
        self._root = TkinterDnD.Tk()
        self._root.title("")
        self._root.overrideredirect(True)         # без рамки
        self._root.attributes("-topmost", True)   # поверх всех окон
        self._root.attributes("-alpha", 0.01)     # почти прозрачный
        self._root.geometry(
            f"{self._zone_w}x{self._zone_h}+{self._zone_x}+{self._zone_y}"
        )

        label = tk.Label(self._root, text="", bg="white")
        label.pack(fill="both", expand=True)
        label.drop_target_register(DND_FILES)
        label.dnd_bind('<<Drop>>', self._on_drop)
        label.dnd_bind('<<DropEnter>>', self._on_enter)
        label.dnd_bind('<<DropLeave>>', self._on_leave)

        self._root.mainloop()

    def _parse_paths(self, raw: str) -> list[str]:
        """Парсим пути (могут быть в {} если содержат пробелы)"""
        files = re.findall(r'\{[^}]+\}|[^\s]+', raw)
        return [f.strip('{}') for f in files if f.strip('{}')]

    def _on_drop(self, event):
        files = self._parse_paths(event.data)
        if files and self.on_files_dropped:
            self.on_files_dropped(files)
        if self.on_hover_leave:
            self.on_hover_leave()

    def _on_enter(self, event):
        if self.on_hover_enter:
            self.on_hover_enter()

    def _on_leave(self, event):
        if self.on_hover_leave:
            self.on_hover_leave()