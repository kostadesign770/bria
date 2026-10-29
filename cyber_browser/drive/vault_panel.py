"""The "File vault" window: list, import, export, delete – and the upload picker
shown when a website asks for a file."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QAbstractItemView, QDialog, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from cyber_browser import config
from cyber_browser.core.workers import run_async
from cyber_browser.drive.drive_client import VaultFile
from cyber_browser.i18n.strings import tr

if TYPE_CHECKING:
    from cyber_browser.app import AppController


def human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class VaultPanel(QDialog):
    def __init__(self, app: "AppController", parent: QWidget | None = None,
                 picker: bool = False, multi: bool = False) -> None:
        super().__init__(parent)
        self.app = app
        self.picker = picker
        self.selected: list[VaultFile] = []
        self._files: list[VaultFile] = []
        self.setWindowTitle(tr("vault_picker_title") if picker else tr("vault_title"))
        self.resize(720, 440)

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([tr("col_name"), tr("col_size"), tr("col_date")])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection if multi
                                    else QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        self.status = QLabel(tr("vault_loading"))
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        self._buttons: list[QPushButton] = []

        def add(key: str, slot) -> QPushButton:
            btn = QPushButton(tr(key))
            btn.clicked.connect(slot)
            buttons.addWidget(btn)
            self._buttons.append(btn)
            return btn

        add("vault_refresh", self.refresh)
        if config.ALLOW_LOCAL_IMPORT_EXPORT:
            add("vault_import", self._import)
            if not picker:
                add("vault_export", self._export)
        if not picker:
            add("vault_delete", self._delete)
        buttons.addStretch()
        if picker:
            add("vault_select", self._choose).setDefault(True)
        close = QPushButton(tr("cancel") if picker else tr("close"))
        close.clicked.connect(self.reject)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self.refresh()

    # ------------------------------------------------------------ helpers
    def _set_busy(self, busy: bool, text: str = "") -> None:
        for btn in self._buttons:
            btn.setEnabled(not busy)
        if text:
            self.status.setText(text)

    def _error(self, exc: Exception) -> None:
        self._set_busy(False, tr("vault_error", error=exc))

    def _selected_files(self) -> list[VaultFile]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self._files[r] for r in rows if r < len(self._files)]

    def _after_op(self) -> None:
        self.app.persist_drive_token()
        self.refresh()

    # ------------------------------------------------------------ actions
    def refresh(self) -> None:
        drive = self.app.drive
        if drive is None:
            return
        self._set_busy(True, tr("vault_loading"))

        def done(files: list[VaultFile]) -> None:
            self._files = files
            self.table.setRowCount(len(files))
            for row, f in enumerate(files):
                self.table.setItem(row, 0, QTableWidgetItem(f.name))
                self.table.setItem(row, 1, QTableWidgetItem(human_size(f.size)))
                self.table.setItem(row, 2, QTableWidgetItem(f.created))
            self._set_busy(False, tr("vault_ready", count=len(files)))

        run_async(drive.list_files, done, self._error)

    def _import(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, tr("vault_import"))
        if not paths:
            return
        drive = self.app.drive
        limit = config.MAX_TRANSFER_MB * 1024 * 1024
        for p in paths:
            if Path(p).stat().st_size > limit:
                QMessageBox.warning(self, tr("vault_title"), tr("dl_too_big", mb=config.MAX_TRANSFER_MB))
                return
        self._set_busy(True, tr("dl_saving", name=", ".join(Path(p).name for p in paths)))

        def work() -> None:
            for p in paths:
                path = Path(p)
                mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                drive.upload(path.name, mime, path.read_bytes())

        run_async(work, lambda _: self._after_op(), self._error)

    def _export(self) -> None:
        files = self._selected_files()
        if not files:
            return
        target, _ = QFileDialog.getSaveFileName(self, tr("vault_export"), files[0].name)
        if not target:
            return
        drive = self.app.drive
        self._set_busy(True, tr("vault_loading"))
        run_async(lambda: Path(target).write_bytes(drive.download(files[0])),
                  lambda _: self._set_busy(False, tr("vault_ready", count=len(self._files))), self._error)

    def _delete(self) -> None:
        files = self._selected_files()
        if not files:
            return
        names = ", ".join(f.name for f in files)
        if QMessageBox.question(self, tr("vault_delete"), tr("vault_confirm_delete", name=names)) \
                != QMessageBox.StandardButton.Yes:
            return
        drive = self.app.drive
        self._set_busy(True, tr("vault_loading"))
        run_async(lambda: [drive.delete(f) for f in files], lambda _: self._after_op(), self._error)

    def _choose(self) -> None:
        self.selected = self._selected_files()
        if self.selected:
            self.accept()
