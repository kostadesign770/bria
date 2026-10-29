"""Main browser window.

Layout::

    [◀][▶][⟳][⌂] [ address bar .................. ] [country ▾][🔒 lock][Change country now]
    [🛡️ KILL-SWITCH] [📁 vault] [🌐 translate] [⚙] [🚨 panic] [🔒 lock]
    ┌ red kill-switch banner (only when Tor is down) ┐
    ┌ insecure-site bar / translation bar (on demand) ┐
    │ web view  –or–  full "browsing blocked" screen │
    └ status: IP | country | Tor | next change | auto-lock | user ┘

Identity rotation (timer every 10 min, button, or country menu):
    NEWNYM (+ exit country) -> cookies/cache/visited-links wiped -> the whole
    off-the-record profile is replaced (kills old connections, storage, service
    workers) -> page reloaded -> IP/country refreshed in the status bar.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

from PyQt6.QtCore import QTimer, QUrl, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QActionGroup, QFont, QKeySequence, QShortcut
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineScript
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu,
    QMessageBox, QPushButton, QSizePolicy, QStackedWidget, QToolBar, QToolButton, QVBoxLayout, QWidget,
)

from cyber_browser import config
from cyber_browser.core.ip_info import IpInfo, fetch_ip_info
from cyber_browser.core.tor_controller import FALLBACK_EXIT_COUNTRIES, TorControlError, TorHealth
from cyber_browser.core.workers import run_async
from cyber_browser.i18n.countries import country_name
from cyber_browser.i18n.strings import language, language_name, tr
from cyber_browser.security import fingerprint
from cyber_browser.security.permissions import apply_security_level, harden_page, harden_profile
from cyber_browser.translate.translator import (
    JS_SOURCE, ArgosEngine, GoogleBlocked, MissingModel, detect_language, engine_for,
)

if TYPE_CHECKING:
    from cyber_browser.app import AppController

APP_WORLD = QWebEngineScript.ScriptWorldId.ApplicationWorld
_UNSET = object()

KS_STYLE = {
    "ok": "background:#1b5e20; color:white;",
    "blocked": "background:#b71c1c; color:white;",
    "checking": "background:#e65100; color:white;",
}


# Profiles waiting to be destroyed (kept referenced until their pages are gone).
_GRAVEYARD: list[QWebEngineProfile] = []


def _bury_profile(profile: QWebEngineProfile) -> None:
    """Delete a profile only after its pages: detach it now, destroy it a bit later."""
    profile.setParent(None)
    _GRAVEYARD.append(profile)

    def destroy() -> None:
        _GRAVEYARD.remove(profile)
        profile.deleteLater()

    QTimer.singleShot(1500, destroy)


def _fmt(seconds: int) -> str:
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


class GuardedPage(QWebEnginePage):
    """A page that asks the window before every navigation and never touches the disk."""

    navigation_blocked = pyqtSignal(QUrl, str)

    def __init__(self, profile: QWebEngineProfile, window: "BrowserWindow") -> None:
        super().__init__(profile, window)
        self._window = window
        harden_page(self)

    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame: bool) -> bool:  # noqa: N802
        reason = self._window.navigation_veto(url, is_main_frame)
        if reason:
            if is_main_frame:
                self.navigation_blocked.emit(url, reason)
            return False
        return True

    def chooseFiles(self, mode, old_files, accepted_mime_types):  # noqa: N802 - Qt API
        # Never show the OS file dialog – files come only from the encrypted vault.
        return self._window.app.transfers.choose_files(self._window, mode)

    def createWindow(self, _type):  # noqa: N802 - pop-ups/new tabs open in the same view
        return self

    def javaScriptConsoleMessage(self, *_args) -> None:  # noqa: N802 - keep the console quiet
        pass


class BrowserWindow(QMainWindow):
    def __init__(self, app: "AppController") -> None:
        super().__init__()
        self.app = app
        self.profile: QWebEngineProfile | None = None
        self.page: GuardedPage | None = None
        self.tor_state = "checking"           # checking | ok | blocked
        self._tor_detail = ""
        self._control_ok = False
        self._started = False
        self._rotating = False
        self._locking = False
        self._current_country: str | None = None
        self._ip_info: IpInfo | None = None
        self._countries: dict[str, int] = {}
        self._allowed_http: set[str] = set()
        self._blocked_url: QUrl | None = None
        self._page_lang: str | None = None
        self._next_rotation = time.monotonic() + config.ROTATION_INTERVAL_MS / 1000

        self.resize(1280, 840)
        self._build_ui()
        self._new_session()
        self._build_timers()
        self.retranslate()
        self._set_tor_state("checking")
        self.check_tor()

    # ================================================================ UI
    def _build_ui(self) -> None:
        tb = QToolBar()
        tb.setMovable(False)
        tb.setFloatable(False)
        self.addToolBar(tb)
        self.toolbar = tb

        self.act_back = tb.addAction("◀", lambda: self.view.back())
        self.act_forward = tb.addAction("▶", lambda: self.view.forward())
        self.act_reload = tb.addAction("⟳", lambda: self.view.reload())
        self.act_home = tb.addAction("⌂", lambda: self.navigate(config.HOME_URL))

        self.address = QLineEdit()
        self.address.setClearButtonEnabled(True)
        self.address.returnPressed.connect(self.navigate)
        tb.addWidget(self.address)

        self.country_combo = QComboBox()
        self.country_combo.setMinimumWidth(190)
        self.country_combo.activated.connect(self._on_country_chosen)   # user action only
        tb.addWidget(self.country_combo)

        self.lock_box = QCheckBox()
        self.lock_box.setChecked(bool(self.app.settings.get("lock_country")))
        self.lock_box.toggled.connect(self._on_lock_toggled)
        tb.addWidget(self.lock_box)

        self.rotate_btn = QPushButton()
        self.rotate_btn.setStyleSheet("font-weight:bold; padding:4px 10px;")
        self.rotate_btn.clicked.connect(lambda: self.rotate_identity(reason="manual"))
        tb.addWidget(self.rotate_btn)

        tb2 = QToolBar()
        tb2.setMovable(False)
        self.addToolBarBreak()
        self.addToolBar(tb2)

        # The kill-switch indicator is deliberately big and coloured.
        self.ks_button = QPushButton()
        font = QFont()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 2)
        self.ks_button.setFont(font)
        self.ks_button.setMinimumHeight(34)
        self.ks_button.clicked.connect(self._explain_kill_switch)
        tb2.addWidget(self.ks_button)

        self.vault_btn = QPushButton()
        self.vault_btn.clicked.connect(lambda: self.app.transfers.open_panel(self))
        tb2.addWidget(self.vault_btn)

        self.translate_btn = QPushButton()
        self.translate_btn.clicked.connect(self.translate_page)
        tb2.addWidget(self.translate_btn)

        self.menu_btn = QToolButton()
        self.menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.menu = QMenu(self)
        self.menu.aboutToShow.connect(self._populate_menu)
        self.menu_btn.setMenu(self.menu)
        tb2.addWidget(self.menu_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb2.addWidget(spacer)

        self.panic_btn = QPushButton()
        self.panic_btn.setStyleSheet("background:#c62828; color:white; font-weight:bold; padding:4px 12px;")
        self.panic_btn.clicked.connect(self.app.panic)
        tb2.addWidget(self.panic_btn)

        self.logout_btn = QPushButton()
        self.logout_btn.clicked.connect(self.app.lock)
        tb2.addWidget(self.logout_btn)

        # ---- central area
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.ks_banner = QLabel()
        self.ks_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ks_banner.setStyleSheet("background:#b71c1c; color:white; font-size:15px; font-weight:bold; padding:8px;")
        self.ks_banner.hide()
        layout.addWidget(self.ks_banner)

        self.insecure_bar, self.insecure_label, insecure_buttons = self._make_bar("#fff3e0")
        self.insecure_continue = QPushButton()
        self.insecure_continue.clicked.connect(self._continue_insecure)
        insecure_buttons.addWidget(self.insecure_continue)
        layout.addWidget(self.insecure_bar)

        self.translate_bar, self.translate_label, tr_buttons = self._make_bar("#e3f2fd")
        self.tr_do_btn = QPushButton()
        self.tr_do_btn.clicked.connect(self.translate_page)
        self.tr_orig_btn = QPushButton()
        self.tr_orig_btn.clicked.connect(self.show_original)
        tr_buttons.addWidget(self.tr_do_btn)
        tr_buttons.addWidget(self.tr_orig_btn)
        layout.addWidget(self.translate_bar)

        self.stack = QStackedWidget()
        self.view = QWebEngineView()
        self.view.setAcceptDrops(False)
        self.stack.addWidget(self.view)
        self.blocked_screen = self._make_blocked_screen()
        self.stack.addWidget(self.blocked_screen)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.view.urlChanged.connect(self._on_url_changed)
        self.view.titleChanged.connect(self._on_title_changed)
        self.view.loadFinished.connect(self._on_load_finished)

        # ---- status bar
        sb = self.statusBar()
        self.ip_label = QLabel()
        self.country_label = QLabel()
        self.tor_label = QLabel()
        self.rotation_label = QLabel()
        self.idle_label = QLabel()
        self.mode_label = QLabel()
        for widget in (self.ip_label, self.country_label, self.tor_label,
                       self.rotation_label, self.idle_label, self.mode_label):
            widget.setStyleSheet("padding:0 8px;")
            sb.addPermanentWidget(widget)

        # ---- shortcuts
        QShortcut(QKeySequence("Ctrl+Shift+X"), self, self.app.panic,
                  context=Qt.ShortcutContext.ApplicationShortcut)
        QShortcut(QKeySequence("Ctrl+L"), self, lambda: (self.address.setFocus(), self.address.selectAll()))
        QShortcut(QKeySequence("F5"), self, lambda: self.view.reload())

    def _make_bar(self, color: str) -> tuple[QFrame, QLabel, QHBoxLayout]:
        bar = QFrame()
        bar.setStyleSheet(f"QFrame {{ background:{color}; }} QLabel {{ color:#222; }}")
        row = QHBoxLayout(bar)
        row.setContentsMargins(10, 4, 10, 4)
        label = QLabel()
        label.setWordWrap(True)
        row.addWidget(label, 1)
        buttons = QHBoxLayout()
        row.addLayout(buttons)
        close = QPushButton("✕")
        close.setFixedWidth(28)
        close.clicked.connect(bar.hide)
        row.addWidget(close)
        bar.hide()
        return bar, label, buttons

    def _make_blocked_screen(self) -> QWidget:
        screen = QWidget()
        screen.setStyleSheet("background:#1a0000;")
        layout = QVBoxLayout(screen)
        layout.addStretch()
        self.blocked_title = QLabel()
        self.blocked_title.setStyleSheet("color:#ff5252; font-size:28px; font-weight:bold;")
        self.blocked_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.blocked_body = QLabel()
        self.blocked_body.setStyleSheet("color:#ffcdd2; font-size:15px;")
        self.blocked_body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.blocked_body.setWordWrap(True)
        self.blocked_retry = QPushButton()
        self.blocked_retry.setStyleSheet("background:#ff5252; color:white; font-size:15px; padding:8px 24px;")
        self.blocked_retry.clicked.connect(self.check_tor)
        layout.addWidget(self.blocked_title)
        layout.addWidget(self.blocked_body)
        layout.addWidget(self.blocked_retry, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        return screen

    def _build_timers(self) -> None:
        self.rotate_timer = QTimer(self)
        self.rotate_timer.setInterval(config.ROTATION_INTERVAL_MS)
        self.rotate_timer.timeout.connect(lambda: self.rotate_identity(reason="auto"))
        self.rotate_timer.start()

        self.health_timer = QTimer(self)
        self.health_timer.setInterval(config.TOR_HEALTH_INTERVAL_MS)
        self.health_timer.timeout.connect(self.check_tor)
        self.health_timer.start()

        self.country_timer = QTimer(self)
        self.country_timer.setInterval(config.COUNTRY_REFRESH_INTERVAL_MS)
        self.country_timer.timeout.connect(self.load_countries)
        self.country_timer.start()

        self.tick_timer = QTimer(self)
        self.tick_timer.setInterval(1000)
        self.tick_timer.timeout.connect(self._tick)
        self.tick_timer.start()

    def retranslate(self) -> None:
        """Apply the current UI language to every visible text."""
        self.act_back.setToolTip(tr("back"))
        self.act_forward.setToolTip(tr("forward"))
        self.act_reload.setToolTip(tr("reload"))
        self.act_home.setToolTip(tr("home"))
        self.address.setPlaceholderText(tr("address_placeholder"))
        self.country_combo.setToolTip(tr("country_tip"))
        self.lock_box.setText(tr("lock_country"))
        self.lock_box.setToolTip(tr("lock_country_tip"))
        self.rotate_btn.setText(tr("rotate_now"))
        self.ks_button.setToolTip(tr("ks_tip"))
        self.vault_btn.setText(tr("vault_btn"))
        self.translate_btn.setText(tr("translate_btn"))
        self.menu_btn.setText(tr("menu_btn"))
        self.panic_btn.setText(tr("panic_btn"))
        self.panic_btn.setToolTip(tr("panic_tip"))
        self.logout_btn.setText(tr("logout_btn"))
        self.insecure_continue.setText(tr("insecure_continue"))
        self.tr_do_btn.setText(tr("tr_do"))
        self.tr_orig_btn.setText(tr("tr_original"))
        self.blocked_retry.setText(tr("ks_retry"))
        vault = self.app.vault
        self.mode_label.setText(tr("st_mode_user", name=vault.username) if vault else tr("st_mode_guest"))
        self._set_tor_state(self.tor_state)
        self._fill_country_combo()
        self._show_ip()
        self._on_title_changed(self.view.title())

    # ========================================================== session
    def _new_session(self) -> None:
        """Create a brand-new off-the-record profile and page, wiping the old one."""
        profile = QWebEngineProfile(self)          # no storage name => off-the-record
        harden_profile(profile)
        fingerprint.install(profile, self.app.settings["site_lang"])
        apply_security_level(profile.settings(), self.app.settings["security"])
        profile.downloadRequested.connect(self.app.transfers.handle_download)
        page = GuardedPage(profile, self)
        page.navigation_blocked.connect(self._on_navigation_blocked)

        old_page, old_profile = self.page, self.profile
        self.view.setPage(page)
        self.page, self.profile = page, profile

        if old_profile is not None:
            old_profile.cookieStore().deleteAllCookies()
            old_profile.clearHttpCache()
            old_profile.clearAllVisitedLinks()
        if old_page is not None:
            old_page.deleteLater()
        if old_profile is not None:
            _bury_profile(old_profile)
        self._allowed_http.clear()

    def wipe_session(self) -> None:
        self._new_session()

    def shutdown(self) -> None:
        """Called on lock/exit: stop everything and destroy the browsing session."""
        self._locking = True
        for timer in (self.rotate_timer, self.health_timer, self.country_timer, self.tick_timer):
            timer.stop()
        if self.page is not None:
            self.page.deleteLater()
        if self.profile is not None:
            self.profile.cookieStore().deleteAllCookies()
            self.profile.clearHttpCache()
            _bury_profile(self.profile)
        self.page = self.profile = None
        self.close()
        self.deleteLater()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        if not self._locking:
            self.app.quit()
        super().closeEvent(event)

    # ======================================================= navigation
    def navigation_veto(self, url: QUrl, is_main_frame: bool) -> str | None:
        scheme = url.scheme().lower()
        if scheme in ("about", "data", "blob"):
            return None
        if self.tor_state != "ok":
            return "killswitch"
        if scheme not in ("http", "https"):
            return "scheme"
        host = url.host().lower()
        if scheme == "http" and is_main_frame and not host.endswith(".onion") and host not in self._allowed_http:
            return "insecure"
        return None

    def navigate(self, text: str | None = None) -> None:
        text = (text if isinstance(text, str) else self.address.text()).strip()
        if not text:
            return
        if " " in text or ("." not in text and "://" not in text):
            url = QUrl(config.SEARCH_URL.format(query=quote_plus(text)))
        else:
            if "://" not in text:
                host = text.split("/")[0].lower()
                text = ("http://" if host.endswith(".onion") else "https://") + text
            url = QUrl(text)
        self.view.setUrl(url)

    def _on_navigation_blocked(self, url: QUrl, reason: str) -> None:
        if reason == "insecure":
            self._blocked_url = url
            self.insecure_label.setText(tr("insecure_text", host=url.host()))
            self.insecure_bar.show()
        elif reason == "scheme":
            self.app.notify(tr("blocked_scheme", scheme=url.scheme()))
        else:
            self._blocked_url = url

    def _continue_insecure(self) -> None:
        if self._blocked_url is not None:
            self._allowed_http.add(self._blocked_url.host().lower())
            self.insecure_bar.hide()
            self.view.setUrl(self._blocked_url)

    def _on_url_changed(self, url: QUrl) -> None:
        if url.scheme() not in ("", "about", "data", "blob"):
            self.address.setText(url.toString())
        self.act_back.setEnabled(self.view.history().canGoBack())
        self.act_forward.setEnabled(self.view.history().canGoForward())

    def _on_title_changed(self, title: str) -> None:
        self.setWindowTitle(f"{title} — {tr('app_title')}" if title and title != "about:blank" else tr("app_title"))

    # ======================================================= kill-switch
    def check_tor(self) -> None:
        run_async(self.app.tor.health, self._on_health)

    def _on_health(self, health: TorHealth) -> None:
        if self._locking:
            return
        self._control_ok = health.control_ok
        self._tor_detail = health.detail
        self._set_tor_state("ok" if health.safe_to_browse else "blocked")

    def _set_tor_state(self, state: str) -> None:
        previous, self.tor_state = self.tor_state, state
        self.ks_button.setText(tr({"ok": "ks_protected", "blocked": "ks_blocked", "checking": "ks_checking"}[state]))
        self.ks_button.setStyleSheet(KS_STYLE[state] + "padding:4px 14px; border-radius:6px;")
        if state == "ok":
            self.ks_banner.hide()
            self.stack.setCurrentWidget(self.view)
            self.tor_label.setText(tr("st_tor_ok") if self._control_ok else tr("st_tor_no_control"))
            self.rotate_btn.setEnabled(self._control_ok and not self._rotating)
            self.country_combo.setEnabled(self._control_ok)
            if not self._started:
                self._started = True
                self.navigate(config.HOME_URL)
                self.refresh_ip()
                self.load_countries()
            elif previous == "blocked" and self._blocked_url is not None:
                self.view.setUrl(self._blocked_url)
        else:
            if self.page is not None:
                self.page.triggerAction(QWebEnginePage.WebAction.Stop)
            self.stack.setCurrentWidget(self.blocked_screen)
            self.tor_label.setText(tr("st_tor_down") if state == "blocked" else tr("ks_checking"))
            self.blocked_title.setText(tr("ks_blocked_title") if state == "blocked" else tr("ks_checking"))
            self.blocked_body.setText(tr("ks_blocked_body", detail=self._tor_detail or "…"))
            if state == "blocked":
                self.ks_banner.setText(tr("ks_blocked_title"))
                self.ks_banner.show()
            self.rotate_btn.setEnabled(False)

    def _explain_kill_switch(self) -> None:
        QMessageBox.information(self, "Kill-Switch", tr("ks_tip") + (f"\n\n{self._tor_detail}" if self._tor_detail else ""))
        self.check_tor()

    # ========================================================= identity
    def load_countries(self) -> None:
        if self._locking or not self._control_ok:
            return
        run_async(self.app.tor.exit_countries, self._on_countries, self._on_countries_failed)

    def _on_countries_failed(self, _exc: Exception) -> None:
        if self._locking:
            return
        # Tor may still be downloading relay descriptors: offer a static list and retry soon.
        if not self._countries:
            self._countries = {code: 0 for code in FALLBACK_EXIT_COUNTRIES}
            self._fill_country_combo()
        self.app.notify(tr("st_country_list_failed"))
        QTimer.singleShot(60_000, self.load_countries)

    def _on_countries(self, countries: dict[str, int]) -> None:
        if self._locking:
            return
        self._countries = countries
        self._fill_country_combo()

    def _fill_country_combo(self) -> None:
        pinned = self.app.settings.get("pinned_country")
        combo = self.country_combo
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(tr("country_random"), None)
        codes = set(self._countries) | ({pinned} if pinned else set())
        for code in sorted(codes, key=lambda c: country_name(c)):
            count = self._countries.get(code)
            combo.addItem(f"{country_name(code)} ({count})" if count else country_name(code), code)
        index = combo.findData(pinned) if pinned else 0
        combo.setCurrentIndex(max(index, 0))
        combo.blockSignals(False)

    def _on_country_chosen(self, index: int) -> None:
        code = self.country_combo.itemData(index)
        self.app.settings["pinned_country"] = code
        self.app.save_settings()
        self.rotate_identity(explicit=code, reason="country")

    def _on_lock_toggled(self, checked: bool) -> None:
        self.app.settings["lock_country"] = checked
        self.app.save_settings()

    def rotate_identity(self, explicit=_UNSET, reason: str = "manual") -> None:
        """Change Tor circuit/country and wipe all browsing state."""
        if self._rotating or self.tor_state != "ok" or not self._control_ok:
            return
        self._rotating = True
        self.rotate_btn.setEnabled(False)
        self.statusBar().showMessage(tr("st_rotating"))
        pinned = self.app.settings.get("pinned_country")
        lock = self.lock_box.isChecked()
        current = self._current_country
        tor = self.app.tor

        def work() -> str | None:
            if explicit is not _UNSET and explicit:
                target = explicit
            elif lock and pinned and reason != "country":
                target = pinned                       # same country, new IP
            else:
                try:
                    target = tor.random_exit_country(exclude=current)  # a *different* country
                except TorControlError:
                    target = None                     # no GeoIP in Tor: plain NEWNYM
            return tor.new_identity(target)

        def done(target: str | None) -> None:
            self._rotating = False
            if self._locking:
                return
            if not (lock and pinned) and explicit is _UNSET:
                # Automatic/manual change without a lock: the menu shows "random" again.
                self.app.settings["pinned_country"] = None
                self.country_combo.setCurrentIndex(0)
            url = self.view.url()
            self._new_session()                       # cookies + cache + storage gone
            if url.isValid() and url.toString() not in ("", "about:blank"):
                self.view.setUrl(url)
            self._next_rotation = time.monotonic() + config.ROTATION_INTERVAL_MS / 1000
            self.rotate_timer.start()                 # restart the 10-minute countdown
            self.rotate_btn.setEnabled(True)
            self.statusBar().showMessage(tr("st_rotated"), 6000)
            self.refresh_ip()

        def failed(exc: Exception) -> None:
            self._rotating = False
            if self._locking:
                return
            self.rotate_btn.setEnabled(True)
            self.statusBar().showMessage(tr("st_rotate_failed", error=exc), 10000)

        run_async(work, done, failed)

    def refresh_ip(self) -> None:
        self._ip_info = None
        self.ip_label.setText(tr("st_fetching_ip"))
        self.country_label.setText("")
        run_async(lambda: fetch_ip_info(self.app.tor), self._on_ip, lambda _exc: self._on_ip(None))

    def _on_ip(self, info: IpInfo | None) -> None:
        if self._locking:
            return
        self._ip_info = info
        if info is not None:
            self._current_country = info.country_code
        self._show_ip()

    def _show_ip(self) -> None:
        info = self._ip_info
        if info is None:
            if self.ip_label.text() != tr("st_fetching_ip"):
                self.ip_label.setText(tr("st_ip_unknown"))
            return
        self.ip_label.setText(tr("st_ip", ip=info.ip))
        name = country_name(info.country_code) if info.country_code else (info.country_name or "?")
        self.country_label.setText(tr("st_country", country=name))

    def _tick(self) -> None:
        remaining = max(0, int(self._next_rotation - time.monotonic()))
        self.rotation_label.setText(tr("st_next_rotation", time=_fmt(remaining)))
        self.idle_label.setText(tr("st_idle", time=_fmt(self.app.idle.remaining_seconds())))

    # ====================================================== translation
    def _run_js(self, code: str, callback) -> None:
        if self.page is not None:
            self.page.runJavaScript(code, APP_WORLD, callback)

    def _on_load_finished(self, ok: bool) -> None:
        self.translate_bar.hide()
        if ok:
            self.insecure_bar.hide()
        self._page_lang = None
        if not ok or self.app.settings["tr_mode"] == "off":
            return
        page = self.page
        self._detect_language(lambda lang: self._maybe_offer_translation(page, lang))

    def _detect_language(self, callback) -> None:
        def got_sample(sample) -> None:
            if not sample:
                callback(None)
                return
            run_async(lambda: detect_language(sample[0], sample[1]), callback, lambda _e: callback(None))

        self._run_js(JS_SOURCE + "\nwindow.__cbT.sample();", got_sample)

    def _maybe_offer_translation(self, page, lang: str | None) -> None:
        if page is not self.page or lang is None:
            return
        self._page_lang = lang
        if lang == language():
            return
        if self.app.settings["tr_mode"] == "always":
            self.translate_page()
        else:
            self.translate_label.setText(tr("tr_offer", lang=language_name(lang), target=language_name(language())))
            self.translate_bar.show()

    def translate_page(self) -> None:
        if self._page_lang is None:
            self._detect_language(self._translate_from)
        else:
            self._translate_from(self._page_lang)

    def _translate_from(self, src: str | None) -> None:
        target = language()
        src = src or "en"
        if src == target:
            self.app.notify(tr("tr_same_lang"))
            return
        page, engine_name = self.page, self.app.settings["tr_engine"]
        if engine_name == "argos" and not ArgosEngine.available():
            QMessageBox.information(self, tr("translate_btn"), tr("models_need_argos"))
            return

        def got_texts(texts) -> None:
            if page is not self.page or not texts:
                return
            unique = list(dict.fromkeys(t for t in texts if t))
            self.statusBar().showMessage(tr("tr_running", total=len(unique)))
            engine = engine_for(engine_name)

            def done(translated: list[str]) -> None:
                if page is not self.page:
                    return
                mapping = dict(zip(unique, translated))
                result = [mapping.get(t, "") for t in texts]
                direction = "rtl" if target == "he" else "ltr"
                self._run_js(f"window.__cbT.apply({json.dumps(result, ensure_ascii=False)}, '{direction}');",
                             lambda _r: None)
                self.translate_bar.hide()
                self.statusBar().showMessage(tr("tr_done"), 5000)

            def failed(exc: Exception) -> None:
                if isinstance(exc, MissingModel):
                    self.statusBar().showMessage(tr("tr_no_model", src=exc.src, dst=exc.dst), 12000)
                elif isinstance(exc, GoogleBlocked):
                    self.statusBar().showMessage(tr("tr_google_blocked"), 12000)
                else:
                    self.statusBar().showMessage(tr("tr_failed", error=exc), 10000)

            run_async(lambda: engine.translate(unique, src, target), done, failed)

        self._run_js(JS_SOURCE + "\nwindow.__cbT.collect(1500);", got_texts)

    def show_original(self) -> None:
        self._run_js(JS_SOURCE + "\nwindow.__cbT.restore();", lambda _r: None)

    # ============================================================= menu
    def _populate_menu(self) -> None:
        menu = self.menu
        menu.clear()
        settings = self.app.settings

        def radio_group(title: str, key: str, options: list[tuple[str, str]], on_change) -> None:
            sub = menu.addMenu(title)
            group = QActionGroup(sub)
            for value, label in options:
                action = QAction(label, sub, checkable=True)
                action.setChecked(settings.get(key) == value)
                action.triggered.connect(lambda _c=False, v=value: on_change(v))
                group.addAction(action)
                sub.addAction(action)

        radio_group(tr("menu_ui_lang"), "ui_lang", [("he", tr("lang_he")), ("en", tr("lang_en"))],
                    self.app.set_ui_language)
        radio_group(tr("menu_site_lang"), "site_lang", [("en", tr("site_lang_en")), ("he", tr("site_lang_he"))],
                    self._set_site_language)
        radio_group(tr("menu_security"), "security",
                    [("standard", tr("sec_standard")), ("safer", tr("sec_safer")), ("safest", tr("sec_safest"))],
                    self._set_security)
        menu.addSeparator()
        radio_group(tr("menu_translate_mode"), "tr_mode",
                    [("off", tr("tmode_off")), ("ask", tr("tmode_ask")), ("always", tr("tmode_always"))],
                    lambda v: self._set_setting("tr_mode", v))
        radio_group(tr("menu_translate_engine"), "tr_engine",
                    [("argos", tr("engine_argos")), ("google", tr("engine_google"))],
                    lambda v: self._set_setting("tr_engine", v))
        menu.addAction(tr("menu_install_models"), self._install_models)
        menu.addSeparator()

        bookmarks = menu.addMenu(tr("menu_bookmarks"))
        if self.app.vault is None:
            bookmarks.addAction(tr("bm_guest")).setEnabled(False)
        else:
            bookmarks.addAction(tr("bm_add"), self._add_bookmark)
            bookmarks.addSeparator()
            items = self.app.vault.data.get("bookmarks", [])
            if not items:
                bookmarks.addAction(tr("bm_empty")).setEnabled(False)
            for bm in items:
                bookmarks.addAction(bm["title"][:60] or bm["url"], lambda u=bm["url"]: self.navigate(u))

        if self.app.vault is not None:
            if self.app.drive is None:
                menu.addAction(tr("menu_drive_link"), lambda: self.app.link_drive(self))
            else:
                menu.addAction(tr("menu_drive_unlink"), self.app.unlink_drive)
        menu.addSeparator()
        menu.addAction(tr("menu_about"), lambda: QMessageBox.about(self, tr("app_title"), tr("about_text")))

    def _set_setting(self, key: str, value) -> None:
        self.app.settings[key] = value
        self.app.save_settings()

    def _set_site_language(self, value: str) -> None:
        self._set_setting("site_lang", value)
        if self.profile is not None:
            fingerprint.install(self.profile, value)
            self.view.reload()

    def _set_security(self, value: str) -> None:
        self._set_setting("security", value)
        if self.profile is not None:
            apply_security_level(self.profile.settings(), value)
            self.view.reload()

    def _add_bookmark(self) -> None:
        vault = self.app.vault
        url = self.view.url().toString()
        if vault is None or not url or url == "about:blank":
            return
        vault.data.setdefault("bookmarks", []).append({"title": self.view.title(), "url": url})
        self.app.save_settings()

    def _install_models(self) -> None:
        if not ArgosEngine.available():
            QMessageBox.information(self, tr("menu_install_models"), tr("models_need_argos"))
            return
        self.statusBar().showMessage(tr("models_installing"))
        run_async(ArgosEngine.install_models,
                  lambda pairs: self.statusBar().showMessage(tr("models_installed", pairs=", ".join(pairs)), 10000),
                  lambda exc: self.statusBar().showMessage(tr("models_failed", error=exc), 10000))
