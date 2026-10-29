"""Clear anything copied from the browser out of the system clipboard after 60 s."""

from __future__ import annotations

from PyQt6.QtCore import QObject, Qt, QTimer
from PyQt6.QtGui import QGuiApplication

from cyber_browser import config


class ClipboardGuard(QObject):
    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._clipboard = QGuiApplication.clipboard()
        self._owned_text: str | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear_if_ours)
        self._clipboard.dataChanged.connect(self._on_changed)

    def _on_changed(self) -> None:
        # Only content copied while *our* app is focused counts as ours.
        if QGuiApplication.applicationState() != Qt.ApplicationState.ApplicationActive:
            self._owned_text = None
            self._timer.stop()
            return
        text = self._clipboard.text()
        if not text and not self._clipboard.mimeData().hasImage():
            return
        self._owned_text = text
        self._timer.start(config.CLIPBOARD_CLEAR_MS)

    def clear_if_ours(self) -> None:
        """Clear only if the clipboard still holds what was copied from us."""
        if self._owned_text is not None and self._clipboard.text() == self._owned_text:
            self._clipboard.clear()
        self._owned_text = None

    def clear_now(self) -> None:
        self._timer.stop()
        self.clear_if_ours()
