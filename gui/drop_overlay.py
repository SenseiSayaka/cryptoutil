"""Невидимый tkinter overlay для drag & drop файлов из ОС"""
import threading
import re
import platform
from tkinterdnd2 import TkinterDnD, DND_FILES
import tkinter as tk
from typing import Callable, Optional


class DropOverlay:
    """
    Прозрачное tkinter окно поверх Flet drop_zone.
    
    Ключевая идея: окно по умолчанию МАЛЕНЬКОЕ (1x1 за экраном) — не перехватывает клики.
    Разворачивается до полного размера ТОЛЬКО когда зажата ЛКМ (идёт перетаскивание).
    Это решает конфликт между OLE DnD (нужно видимое окно) и обычными кликами.
    """

    def __init__(self, on_files_dropped: Callable[[list[str]], None]):
        self.on_files_dropped = on_files_dropped
        self._root: Optional[TkinterDnD.Tk] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self._zone_x: int = 100
        self._zone_y: int = 300
        self._zone_w: int = 800
        self._zone_h: int = 160

        # Флаг: скрыт ли overlay снаружи (диалог, вкладка ключей)
        self._hidden: bool = False
        # Флаг: сейчас идёт drag (ЛКМ зажата)
        self._dragging: bool = False

        self.on_hover_enter: Optional[Callable] = None
        self.on_hover_leave: Optional[Callable] = None

        self._is_windows = platform.system() == "Windows"

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run_tkinter, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._root:
            try:
                self._root.quit()
                self._root.destroy()
            except Exception:
                pass

    def hide(self):
        """Скрыть overlay (диалог открыт, вкладка ключей и т.п.)"""
        self._hidden = True
        if self._root:
            try:
                self._root.after(0, self._apply_state)
            except Exception:
                pass

    def show(self):
        """Вернуть overlay."""
        self._hidden = False
        if self._root:
            try:
                self._root.after(0, self._apply_state)
            except Exception:
                pass

    def update_position(self, x: int, y: int, w: int, h: int):
        """Обновить целевую позицию drop-зоны."""
        if x == -9999:
            self.hide()
            return
        self._zone_x = x
        self._zone_y = y
        self._zone_w = max(1, w)
        self._zone_h = max(1, h)
        if self._root:
            try:
                self._root.after(0, self._apply_state)
            except Exception:
                pass

    def _apply_state(self):
        """Применить текущее состояние окна (вызывается в tkinter-потоке)."""
        if not self._root:
            return
        try:
            if self._hidden:
                # Полностью скрываем — withdraw убирает из обработки ввода
                self._root.withdraw()
            else:
                self._root.deiconify()
                self._root.attributes("-topmost", True)
                if self._dragging:
                    # Полный размер — ловим дроп
                    self._root.geometry(
                        f"{self._zone_w}x{self._zone_h}"
                        f"+{self._zone_x}+{self._zone_y}"
                    )
                else:
                    # Маленький и за экраном — не мешает кликам
                    self._root.geometry("1x1+-100+-100")
        except Exception:
            pass

    def _poll_drag(self):
        """
        Опрашивает состояние ЛКМ каждые 50мс.
        Если ЛКМ зажата — разворачиваем overlay на drop-зону.
        Если отпущена — сворачиваем обратно.
        Работает только в tkinter-потоке через after().
        """
        if not self._running:
            return

        if self._is_windows:
            try:
                import ctypes
                # GetAsyncKeyState(VK_LBUTTON=1): старший бит = зажата
                state = ctypes.windll.user32.GetAsyncKeyState(1)
                lmb_down = bool(state & 0x8000)
            except Exception:
                lmb_down = False
        else:
            lmb_down = False

        if lmb_down != self._dragging:
            self._dragging = lmb_down
            self._apply_state()

        if self._root:
            self._root.after(50, self._poll_drag)

    def _run_tkinter(self):
        self._root = TkinterDnD.Tk()
        self._root.title("")
        self._root.overrideredirect(True)
        self._root.attributes("-topmost", True)
        self._root.attributes("-alpha", 0.01)
        # Стартуем маленьким — не мешаем кликам
        self._root.geometry("1x1+-100+-100")

        label = tk.Label(self._root, text="", bg="white")
        label.pack(fill="both", expand=True)
        label.drop_target_register(DND_FILES)
        label.dnd_bind("<<Drop>>",      self._on_drop)
        label.dnd_bind("<<DropEnter>>", self._on_enter)
        label.dnd_bind("<<DropLeave>>", self._on_leave)

        # Запускаем поллинг ЛКМ
        self._root.after(100, self._poll_drag)
        self._root.mainloop()

    def _parse_paths(self, raw: str) -> list[str]:
        files = re.findall(r'\{[^}]+\}|[^\s]+', raw)
        return [f.strip("{}") for f in files if f.strip("{}")]

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
