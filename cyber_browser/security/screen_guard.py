"""Hide every browser window from screenshots, screen recording and screen sharing.

On Windows 10 (2004+) / 11 we call ``SetWindowDisplayAffinity`` with
``WDA_EXCLUDEFROMCAPTURE``: the window is shown normally on the monitor, but
any capture (PrintScreen, Snipping Tool, OBS, Teams/Zoom sharing, remote
desktop recorders) sees an empty area. The flag stays in force while the
window is in the background or minimised.

On older Windows builds we fall back to ``WDA_MONITOR`` (window captured as black).
Other operating systems have no reliable equivalent; ``protect_window`` then
returns ``False``.
"""

from __future__ import annotations

import logging
import sys

from PyQt6.QtCore import QEvent, QObject
from PyQt6.QtWidgets import QWidget

log = logging.getLogger(__name__)

WDA_MONITOR = 0x01
WDA_EXCLUDEFROMCAPTURE = 0x11


def protect_window(widget: QWidget) -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    hwnd = int(widget.winId())
    user32 = ctypes.windll.user32
    if user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE):
        return True
    ok = bool(user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR))
    if not ok:
        log.warning("SetWindowDisplayAffinity failed for %s", widget)
    return ok


def is_supported() -> bool:
    return sys.platform == "win32"


class ScreenGuardFilter(QObject):
    """Application-wide event filter: protects every top-level window
    (main window, dialogs, menus, pop-ups) the moment it is shown."""

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802 - Qt API
        if (event.type() == QEvent.Type.Show and isinstance(obj, QWidget)
                and obj.isWindow() and not obj.property("_cb_protected")):
            if protect_window(obj):
                obj.setProperty("_cb_protected", True)
        return False
