"""Application controller: login -> browser window -> lock -> login …

Owns everything that outlives a single browsing session: the Tor controller,
the unlocked vault, the Drive connection, the global security filters
(idle lock, screen-capture guard, drag-and-drop blocker, clipboard guard)
and the secure temp area.
"""

from __future__ import annotations

import logging
import os
import sys
import time

# QtWebEngineWidgets must be imported before QApplication is created.
from PyQt6.QtWebEngineWidgets import QWebEngineView  # noqa: F401
from PyQt6.QtCore import QObject, Qt, QTimer
from PyQt6.QtNetwork import QNetworkProxy
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget

from cyber_browser import config
from cyber_browser.auth.crypto_vault import UserVault
from cyber_browser.auth.idle_lock import IdleLock
from cyber_browser.core.tor_controller import TorController
from cyber_browser.core.workers import run_async
from cyber_browser.drive import drive_client
from cyber_browser.drive.transfer import TransferManager
from cyber_browser.i18n.strings import is_rtl, language, set_language, system_language, tr
from cyber_browser.security.clipboard_guard import ClipboardGuard
from cyber_browser.security.file_guard import DropBlocker, SecureTempArea
from cyber_browser.security.screen_guard import ScreenGuardFilter
from cyber_browser.ui.browser_window import BrowserWindow
from cyber_browser.ui.dialogs import LoginDialog, ReauthDialog

log = logging.getLogger(__name__)

DEFAULT_SETTINGS = {
    "ui_lang": None,              # filled from the OS language
    "site_lang": config.DEFAULT_SITE_LANGUAGE,
    "security": "standard",
    "tr_engine": "argos",
    "tr_mode": "ask",
    "pinned_country": None,
    "lock_country": False,
}


class AppController(QObject):
    def __init__(self, qapp: QApplication) -> None:
        super().__init__()
        self.qapp = qapp
        self.tor = TorController()
        self.vault: UserVault | None = None
        self.drive: drive_client.DriveVault | None = None
        self.window: BrowserWindow | None = None
        self.temp = SecureTempArea()
        self.transfers = TransferManager(self)
        self.settings: dict = dict(DEFAULT_SETTINGS)
        self._reauth_until = 0.0
        self._quitting = False

        # Global guards – installed once, active for every window and dialog.
        self.idle = IdleLock(parent=self)
        self.idle.timed_out.connect(self.lock)
        self.screen_guard = ScreenGuardFilter(self)
        self.drop_blocker = DropBlocker(self)
        for event_filter in (self.idle, self.screen_guard, self.drop_blocker):
            qapp.installEventFilter(event_filter)
        self.clipboard = ClipboardGuard(self)

        self._temp_timer = QTimer(self)
        self._temp_timer.setInterval(60_000)
        self._temp_timer.timeout.connect(self.temp.cleanup_old)
        self._temp_timer.start()

        qapp.aboutToQuit.connect(self._on_quit)
        set_language(system_language())
        self.apply_direction()

    # ============================================================ lifecycle
    def start(self) -> None:
        self._show_login()

    def _show_login(self) -> None:
        if self._quitting:
            return
        dialog = LoginDialog(self.apply_direction)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self.quit()
            return
        self.vault = dialog.vault
        self.settings = dict(DEFAULT_SETTINGS)
        if self.vault is not None:
            self.settings.update(self.vault.data.get("settings", {}))
            self._restore_drive()
        if self.settings.get("ui_lang") in ("he", "en"):
            set_language(self.settings["ui_lang"])
        self.settings["ui_lang"] = language()
        self.apply_direction()

        self.window = BrowserWindow(self)
        self.window.show()
        self.idle.start()

    def lock(self) -> None:
        """Auto-lock / lock button: destroy the session and return to the login screen."""
        if self.window is None:
            return
        self.idle.stop()
        # Close any open dialog first so no nested event loop outlives the window.
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible():
                widget.reject()
        QTimer.singleShot(0, self._finish_lock)

    def _finish_lock(self) -> None:
        if QApplication.activeModalWidget() is not None or self.transfers.busy:
            QTimer.singleShot(200, self._finish_lock)
            return
        if self.window is not None:
            self.window.shutdown()
            self.window = None
        self.clipboard.clear_now()
        self.temp.wipe_all()
        self._close_vault()
        QTimer.singleShot(300, self._show_login)

    def panic(self) -> None:
        """Ctrl+Shift+X: wipe clipboard immediately (whatever is in it) and lock."""
        QApplication.clipboard().clear()
        self.lock()

    def quit(self) -> None:
        self._quitting = True
        self.qapp.quit()

    def _on_quit(self) -> None:
        self._quitting = True
        self.idle.stop()
        self.clipboard.clear_now()
        if self.window is not None:
            self.window.shutdown()
            self.window = None
        self.temp.destroy()
        self._close_vault()
        self.tor.close()

    def _close_vault(self) -> None:
        if self.vault is not None:
            try:
                self.save_settings()
            except Exception:  # noqa: BLE001 - never block locking on a save error
                log.exception("could not save settings")
            self.vault.lock()
        self.vault = None
        self.drive = None
        self._reauth_until = 0.0

    # ============================================================== settings
    def save_settings(self) -> None:
        if self.vault is not None and not self.vault.is_locked:
            self.vault.data["settings"] = dict(self.settings)
            self.vault.save()

    def apply_direction(self) -> None:
        self.qapp.setLayoutDirection(Qt.LayoutDirection.RightToLeft if is_rtl()
                                     else Qt.LayoutDirection.LeftToRight)

    def set_ui_language(self, lang: str) -> None:
        set_language(lang)
        self.settings["ui_lang"] = lang
        self.apply_direction()
        self.save_settings()
        if self.window is not None:
            self.window.retranslate()

    def notify(self, message: str) -> None:
        if self.window is not None:
            self.window.statusBar().showMessage(message, 8000)

    # ======================================================== authentication
    def ensure_reauth(self, parent: QWidget | None) -> bool:
        """Both passwords + TOTP, remembered for ``REAUTH_GRACE_SECONDS``."""
        if self.vault is None:
            return False
        if time.monotonic() < self._reauth_until:
            return True
        if ReauthDialog(self.vault, parent).exec() == QDialog.DialogCode.Accepted:
            self._reauth_until = time.monotonic() + config.REAUTH_GRACE_SECONDS
            return True
        return False

    # ================================================================= Drive
    def _restore_drive(self) -> None:
        token = self.vault.data.get("drive_token") if self.vault else None
        if token:
            try:
                self.drive = drive_client.DriveVault(token, self.vault.file_key)
            except Exception:  # noqa: BLE001 - revoked/corrupt token: user can re-link
                log.exception("could not restore Drive session")
                self.drive = None

    def persist_drive_token(self) -> None:
        if self.vault is None or self.drive is None:
            return
        token = self.drive.token_json()
        if token != self.vault.data.get("drive_token"):
            self.vault.data["drive_token"] = token
            self.vault.save()

    def link_drive(self, parent: QWidget | None) -> None:
        if self.vault is None:
            return
        secrets_path = config.google_client_secrets_path()
        if not secrets_path.exists():
            QMessageBox.warning(parent, tr("menu_drive_link"), tr("drive_no_credentials", path=secrets_path))
            return
        if not self.ensure_reauth(parent):
            return
        QMessageBox.information(parent, tr("menu_drive_link"), tr("drive_linking"))
        vault = self.vault

        def done(token: str) -> None:
            if self.vault is not vault:
                return
            vault.data["drive_token"] = token
            vault.save()
            self.drive = drive_client.DriveVault(token, vault.file_key)
            self.notify(tr("drive_linked"))

        run_async(lambda: drive_client.authorize(secrets_path), done,
                  lambda exc: self.notify(tr("drive_link_failed", error=exc)))

    def unlink_drive(self) -> None:
        if self.vault is not None:
            self.vault.data.pop("drive_token", None)
            self.vault.save()
        self.drive = None
        self.notify(tr("drive_unlinked"))


def configure_engine() -> None:
    """Hand the Chromium switches (Tor proxy, no local DNS, no WebRTC leaks) to the engine.

    Must run before QApplication is created. Qt WebEngine reads them from the
    ``QTWEBENGINE_CHROMIUM_FLAGS`` environment variable – switches placed in argv
    are NOT reliably honoured (verified: with argv only, Chromium silently fell
    back to the system proxy settings).
    """
    flags = " ".join(f'"{flag}"' if " " in flag else flag for flag in config.chromium_flags())
    existing = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = f"{existing} {flags}".strip()


def configure_proxy() -> None:
    """Second, independent route to the same result: Qt's application proxy is
    forwarded to Chromium too, and covers any other Qt networking."""
    QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.Socks5Proxy,
                                                    config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT))


def main() -> None:
    logging.basicConfig(level=os.environ.get("CYBER_LOG", "WARNING"))
    configure_engine()
    qapp = QApplication(sys.argv)
    qapp.setApplicationName(config.APP_NAME)
    qapp.setApplicationDisplayName(config.APP_DISPLAY_NAME)
    qapp.setQuitOnLastWindowClosed(False)   # the lock screen closes all windows
    configure_proxy()
    controller = AppController(qapp)
    QTimer.singleShot(0, controller.start)
    sys.exit(qapp.exec())
