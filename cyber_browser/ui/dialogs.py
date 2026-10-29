"""Login, account creation (with authenticator setup) and re-authentication dialogs."""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QStackedWidget, QTabWidget, QVBoxLayout, QWidget,
)

from cyber_browser.auth import totp
from cyber_browser.auth.crypto_vault import (
    InvalidCredentials, LoginThrottle, UserVault, VaultExists, WeakPassword,
    check_digits_password, check_letters_password,
)
from cyber_browser.core.workers import run_async
from cyber_browser.i18n.strings import language, set_language, tr


def _password_field(digits: bool = False) -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    if digits:
        field.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)
    return field


def _error_label() -> QLabel:
    label = QLabel()
    label.setStyleSheet("color:#d32f2f; font-weight:bold;")
    label.setWordWrap(True)
    return label


class QrWidget(QWidget):
    """Draws a QR code from a boolean matrix (no image libraries required)."""

    def __init__(self, data: str, size: int = 220) -> None:
        super().__init__()
        self._matrix = totp.qr_matrix(data)
        self.setFixedSize(size, size)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("white"))
        cells = len(self._matrix)
        cell = self.width() / cells
        for y, row in enumerate(self._matrix):
            for x, dark in enumerate(row):
                if dark:
                    painter.fillRect(QRectF(x * cell, y * cell, cell + 0.5, cell + 0.5), QColor("black"))


class LoginDialog(QDialog):
    """Guest / login / create. After ``exec()`` check ``self.vault`` (None = guest)."""

    def __init__(self, on_language_changed) -> None:
        super().__init__()
        self.vault: UserVault | None = None
        self._throttle = LoginThrottle()
        self._on_language_changed = on_language_changed
        self._totp_secret: str | None = None
        self.setMinimumWidth(520)
        self._root = QVBoxLayout(self)
        self._content: QWidget | None = None
        self._build()

    # ------------------------------------------------------------- layout
    def _build(self) -> None:
        if self._content is not None:
            self._content.deleteLater()
        self.setWindowTitle(tr("login_title"))
        self._content = QWidget()
        layout = QVBoxLayout(self._content)
        layout.setContentsMargins(0, 0, 0, 0)

        lang_row = QHBoxLayout()
        lang_row.addWidget(QLabel(tr("ui_language")))
        self._lang_combo = QComboBox()
        self._lang_combo.addItem(tr("lang_he"), "he")
        self._lang_combo.addItem(tr("lang_en"), "en")
        self._lang_combo.setCurrentIndex(0 if language() == "he" else 1)
        self._lang_combo.currentIndexChanged.connect(self._change_language)
        lang_row.addWidget(self._lang_combo)
        lang_row.addStretch()
        layout.addLayout(lang_row)

        tabs = QTabWidget()
        tabs.addTab(self._guest_tab(), tr("tab_guest"))
        tabs.addTab(self._login_tab(), tr("tab_login"))
        tabs.addTab(self._create_tab(), tr("tab_create"))
        layout.addWidget(tabs)
        self._root.addWidget(self._content)

    def _change_language(self) -> None:
        set_language(self._lang_combo.currentData())
        self._on_language_changed()
        self._build()

    def _guest_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        info = QLabel(tr("guest_info"))
        info.setWordWrap(True)
        layout.addWidget(info)
        btn = QPushButton(tr("guest_enter"))
        btn.setMinimumHeight(40)
        btn.clicked.connect(self._enter_guest)
        layout.addWidget(btn)
        layout.addStretch()
        return tab

    def _login_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        self._l_user = QLineEdit()
        self._l_letters = _password_field()
        self._l_digits = _password_field(digits=True)
        self._l_code = QLineEdit()
        self._l_code.setMaxLength(6)
        self._l_error = _error_label()
        self._l_btn = QPushButton(tr("login_btn"))
        self._l_btn.clicked.connect(self._login)
        self._l_code.returnPressed.connect(self._login)
        form.addRow(tr("username"), self._l_user)
        form.addRow(tr("letters_pwd"), self._l_letters)
        form.addRow(tr("digits_pwd"), self._l_digits)
        form.addRow(tr("totp_code"), self._l_code)
        form.addRow(self._l_error)
        form.addRow(self._l_btn)
        return tab

    def _create_tab(self) -> QWidget:
        self._c_stack = QStackedWidget()

        page1 = QWidget()
        form = QFormLayout(page1)
        self._c_user = QLineEdit()
        self._c_letters = _password_field()
        self._c_letters2 = _password_field()
        self._c_digits = _password_field(digits=True)
        self._c_digits2 = _password_field(digits=True)
        rules = QLabel(tr("pwd_rules"))
        rules.setWordWrap(True)
        rules.setStyleSheet("color:#555;")
        self._c_error = _error_label()
        next_btn = QPushButton(tr("next_btn"))
        next_btn.clicked.connect(self._create_next)
        form.addRow(tr("username"), self._c_user)
        form.addRow(tr("letters_pwd"), self._c_letters)
        form.addRow(tr("letters_pwd_confirm"), self._c_letters2)
        form.addRow(tr("digits_pwd"), self._c_digits)
        form.addRow(tr("digits_pwd_confirm"), self._c_digits2)
        form.addRow(rules)
        form.addRow(self._c_error)
        form.addRow(next_btn)

        self._c_totp_page = QWidget()
        self._c_stack.addWidget(page1)
        self._c_stack.addWidget(self._c_totp_page)
        return self._c_stack

    # ------------------------------------------------------------ actions
    def _enter_guest(self) -> None:
        self.vault = None
        self.accept()

    def _login(self) -> None:
        user = self._l_user.text().strip()
        if not user:
            self._l_error.setText(tr("err_empty_username"))
            return
        wait = self._throttle.wait_seconds(user)
        if wait:
            self._l_error.setText(tr("err_wait", seconds=wait))
            return
        letters, digits, code = self._l_letters.text(), self._l_digits.text(), self._l_code.text()
        self._busy(self._l_btn, self._l_error)

        def done(vault: UserVault) -> None:
            if not totp.verify(vault.data.get("totp_secret", ""), code):
                vault.lock()
                self._throttle.record_failure(user)
                self._fail(self._l_btn, self._l_error, tr("err_totp"))
                return
            self._throttle.record_success(user)
            self.vault = vault
            self.accept()

        def failed(exc: Exception) -> None:
            self._throttle.record_failure(user)
            msg = tr("err_bad_credentials") if isinstance(exc, InvalidCredentials) else str(exc)
            self._fail(self._l_btn, self._l_error, msg)

        run_async(lambda: UserVault.open(user, letters, digits), done, failed)

    def _create_next(self) -> None:
        user = self._c_user.text().strip()
        letters, digits = self._c_letters.text(), self._c_digits.text()
        try:
            if not user:
                raise WeakPassword("err_empty_username")
            check_letters_password(letters)
            check_digits_password(digits)
            if letters != self._c_letters2.text() or digits != self._c_digits2.text():
                raise WeakPassword("err_mismatch")
            if UserVault.exists(user):
                raise WeakPassword("err_user_exists")
        except WeakPassword as exc:
            self._c_error.setText(tr(exc.args[0]))
            return
        self._c_error.clear()
        self._show_totp_setup(user, letters, digits)

    def _show_totp_setup(self, user: str, letters: str, digits: str) -> None:
        self._totp_secret = totp.new_secret()
        page = QWidget()
        layout = QVBoxLayout(page)
        title = QLabel(f"<b>{tr('totp_setup_title')}</b>")
        info = QLabel(tr("totp_setup_info"))
        info.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(info)
        layout.addWidget(QrWidget(totp.provisioning_uri(self._totp_secret, user)),
                         alignment=Qt.AlignmentFlag.AlignHCenter)
        secret = QLineEdit(self._totp_secret)
        secret.setReadOnly(True)
        row = QFormLayout()
        row.addRow(tr("totp_secret_label"), secret)
        code = QLineEdit()
        code.setMaxLength(6)
        row.addRow(tr("totp_code"), code)
        layout.addLayout(row)
        error = _error_label()
        layout.addWidget(error)
        btn = QPushButton(tr("create_btn"))
        layout.addWidget(btn)

        def create() -> None:
            if not totp.verify(self._totp_secret or "", code.text()):
                error.setText(tr("err_totp"))
                return
            self._busy(btn, error)
            initial = {"totp_secret": self._totp_secret, "settings": {"ui_lang": language()}}

            def done(vault: UserVault) -> None:
                self.vault = vault
                self.accept()

            def failed(exc: Exception) -> None:
                key = "err_user_exists" if isinstance(exc, VaultExists) else None
                self._fail(btn, error, tr(key) if key else str(exc))

            run_async(lambda: UserVault.create(user, letters, digits, initial), done, failed)

        btn.clicked.connect(create)
        code.returnPressed.connect(create)
        old = self._c_stack.widget(1)
        self._c_stack.removeWidget(old)
        old.deleteLater()
        self._c_stack.addWidget(page)
        self._c_stack.setCurrentIndex(1)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _busy(btn: QPushButton, label: QLabel) -> None:
        btn.setEnabled(False)
        label.setStyleSheet("color:#555;")
        label.setText(tr("working"))

    @staticmethod
    def _fail(btn: QPushButton, label: QLabel, message: str) -> None:
        btn.setEnabled(True)
        label.setStyleSheet("color:#d32f2f; font-weight:bold;")
        label.setText(message)


class ReauthDialog(QDialog):
    """Both passwords + authenticator code before any vault transfer."""

    def __init__(self, vault: UserVault, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vault = vault
        self.setWindowTitle(tr("reauth_title"))
        self.setMinimumWidth(420)
        form = QFormLayout(self)
        info = QLabel(tr("reauth_info"))
        info.setWordWrap(True)
        form.addRow(info)
        self._letters = _password_field()
        self._digits = _password_field(digits=True)
        self._code = QLineEdit()
        self._code.setMaxLength(6)
        self._error = _error_label()
        form.addRow(tr("letters_pwd"), self._letters)
        form.addRow(tr("digits_pwd"), self._digits)
        form.addRow(tr("totp_code"), self._code)
        form.addRow(self._error)
        buttons = QHBoxLayout()
        self._ok = QPushButton(tr("ok"))
        cancel = QPushButton(tr("cancel"))
        buttons.addWidget(self._ok)
        buttons.addWidget(cancel)
        form.addRow(buttons)
        self._ok.clicked.connect(self._check)
        self._code.returnPressed.connect(self._check)
        cancel.clicked.connect(self.reject)

    def _check(self) -> None:
        letters, digits, code = self._letters.text(), self._digits.text(), self._code.text()
        LoginDialog._busy(self._ok, self._error)

        def done(ok: bool) -> None:
            if ok and totp.verify(self._vault.data.get("totp_secret", ""), code):
                self.accept()
            else:
                LoginDialog._fail(self._ok, self._error, tr("err_bad_credentials"))

        run_async(lambda: self._vault.verify(letters, digits), done,
                  lambda exc: LoginDialog._fail(self._ok, self._error, str(exc)))
