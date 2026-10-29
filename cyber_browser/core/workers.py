"""Run blocking work (Tor control, HTTP, Argon2, Drive) off the UI thread.

Usage::

    run_async(lambda: slow_call(x), on_done=handle_result, on_error=handle_error)

Callbacks always run on the GUI thread, so they may touch widgets.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Callable

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot

log = logging.getLogger(__name__)

_pending: set["_Relay"] = set()


class _Relay(QObject):
    """Lives on the GUI thread; signals emitted from the pool are queued to it."""

    done = pyqtSignal(object)
    failed = pyqtSignal(object)

    def __init__(self, on_done: Callable[[Any], None] | None,
                 on_error: Callable[[Exception], None] | None) -> None:
        super().__init__()
        self._on_done = on_done
        self._on_error = on_error
        self.done.connect(self._handle_done)
        self.failed.connect(self._handle_failed)

    @pyqtSlot(object)
    def _handle_done(self, result: Any) -> None:
        _pending.discard(self)
        if self._on_done:
            self._on_done(result)

    @pyqtSlot(object)
    def _handle_failed(self, exc: Exception) -> None:
        _pending.discard(self)
        if self._on_error:
            self._on_error(exc)
        else:
            log.warning("background task failed: %s", exc)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any], relay: _Relay) -> None:
        super().__init__()
        self._fn = fn
        self._relay = relay

    def run(self) -> None:  # executed on a pool thread
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - forwarded to the GUI thread
            log.debug("task error:\n%s", traceback.format_exc())
            signal, payload = self._relay.failed, exc
        else:
            signal, payload = self._relay.done, result
        try:
            signal.emit(payload)
        except RuntimeError:
            pass  # the application is shutting down and the relay is already gone


def run_async(fn: Callable[[], Any],
              on_done: Callable[[Any], None] | None = None,
              on_error: Callable[[Exception], None] | None = None) -> None:
    """Execute ``fn`` on the global thread pool. Must be called from the GUI thread."""
    relay = _Relay(on_done, on_error)
    _pending.add(relay)
    QThreadPool.globalInstance().start(_Task(fn, relay))
