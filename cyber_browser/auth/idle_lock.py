"""Automatic lock after 5 minutes without mouse or keyboard activity."""

from __future__ import annotations

import time

from PyQt6.QtCore import QEvent, QObject, QTimer, pyqtSignal

from cyber_browser import config

_ACTIVITY_EVENTS = {
    QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress,
    QEvent.Type.Wheel, QEvent.Type.TouchBegin, QEvent.Type.TabletMove,
}


class IdleLock(QObject):
    """Application-wide event filter. Emits ``timed_out`` after ``timeout_ms`` of no input."""

    timed_out = pyqtSignal()

    def __init__(self, timeout_ms: int = config.IDLE_LOCK_MS, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.timeout_ms = timeout_ms
        self._last_activity = time.monotonic()
        self._armed = False
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        self._last_activity = time.monotonic()
        self._armed = True
        self._timer.start()

    def stop(self) -> None:
        self._armed = False
        self._timer.stop()

    def remaining_seconds(self) -> int:
        elapsed = time.monotonic() - self._last_activity
        return max(0, int(self.timeout_ms / 1000 - elapsed))

    def _tick(self) -> None:
        if self._armed and self.remaining_seconds() <= 0:
            self.stop()
            self.timed_out.emit()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802 - Qt API
        if self._armed and event.type() in _ACTIVITY_EVENTS:
            self._last_activity = time.monotonic()
        return False
