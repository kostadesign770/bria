"""Routes every download and upload through the encrypted Google Drive vault.

* Website download  -> re-auth -> temp file -> encrypt -> Drive -> temp wiped.
* Website upload    -> re-auth -> vault picker -> decrypt into secure temp -> page.
* Guests, or users without a linked Drive: blocked, nothing touches the disk.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEventLoop, QObject, Qt
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest, QWebEnginePage
from PyQt6.QtWidgets import QMessageBox, QProgressDialog, QWidget

from cyber_browser import config
from cyber_browser.core.workers import run_async
from cyber_browser.drive.vault_panel import VaultPanel
from cyber_browser.i18n.strings import tr

if TYPE_CHECKING:
    from cyber_browser.app import AppController

DS = QWebEngineDownloadRequest.DownloadState


class TransferManager(QObject):
    def __init__(self, app: "AppController") -> None:
        super().__init__()
        self.app = app
        self._active: list[QWebEngineDownloadRequest] = []
        self.busy = False          # True while a nested event loop is running

    # ------------------------------------------------------------- gating
    def ensure_ready(self, parent: QWidget | None) -> bool:
        """User signed in + Drive linked + fresh re-authentication."""
        if self.app.vault is None:
            QMessageBox.warning(parent, tr("dl_blocked_title"), tr("dl_blocked_guest"))
            return False
        if self.app.drive is None:
            QMessageBox.warning(parent, tr("dl_blocked_title"), tr("dl_no_drive"))
            return False
        return self.app.ensure_reauth(parent)

    def open_panel(self, parent: QWidget | None) -> None:
        if self.ensure_ready(parent):
            VaultPanel(self.app, parent).exec()

    # ---------------------------------------------------------- downloads
    def handle_download(self, request: QWebEngineDownloadRequest) -> None:
        parent = self.app.window
        if request.isSavePageDownload():
            request.cancel()
            self.app.notify(tr("dl_page_blocked"))
            return
        if request.totalBytes() > config.MAX_TRANSFER_MB * 1024 * 1024:
            request.cancel()
            self.app.notify(tr("dl_too_big", mb=config.MAX_TRANSFER_MB))
            return
        if not self.ensure_ready(parent):
            request.cancel()
            return

        name = Path(request.suggestedFileName() or request.downloadFileName() or "download").name
        mime = request.mimeType() or "application/octet-stream"
        folder = self.app.temp.new_dir()
        request.setDownloadDirectory(str(folder))
        request.setDownloadFileName(uuid.uuid4().hex)   # meaningless name on disk
        self._active.append(request)

        def on_bytes() -> None:
            if request.receivedBytes() > config.MAX_TRANSFER_MB * 1024 * 1024:
                request.cancel()
                self.app.notify(tr("dl_too_big", mb=config.MAX_TRANSFER_MB))

        def on_finished() -> None:
            if request in self._active:
                self._active.remove(request)
            path = Path(request.downloadDirectory()) / request.downloadFileName()
            if request.state() != DS.DownloadCompleted:
                self.app.temp.wipe(folder)
                return
            try:
                content = path.read_bytes()
            finally:
                self.app.temp.wipe(folder)
            self._upload(name, mime, content)

        request.receivedBytesChanged.connect(on_bytes)
        request.isFinishedChanged.connect(on_finished)
        request.accept()
        self.app.notify(tr("dl_saving", name=name))

    def _upload(self, name: str, mime: str, content: bytes) -> None:
        drive = self.app.drive
        if drive is None:
            return
        run_async(lambda: drive.upload(name, mime, content),
                  lambda _: (self.app.persist_drive_token(), self.app.notify(tr("dl_saved", name=name))),
                  lambda exc: self.app.notify(tr("dl_failed", error=exc)))

    # ------------------------------------------------------------ uploads
    def choose_files(self, parent: QWidget | None, mode: QWebEnginePage.FileSelectionMode) -> list[str]:
        if mode == QWebEnginePage.FileSelectionMode.UploadFolder or not self.ensure_ready(parent):
            return []
        multi = mode == QWebEnginePage.FileSelectionMode.FileSelectOpenMultiple
        panel = VaultPanel(self.app, parent, picker=True, multi=multi)
        if panel.exec() != VaultPanel.DialogCode.Accepted or not panel.selected:
            return []

        drive = self.app.drive
        files = panel.selected
        loop = QEventLoop()
        outcome: dict[str, object] = {}
        progress = QProgressDialog(tr("up_preparing"), None, 0, 0, parent)
        progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        progress.show()

        def finish(key: str, value: object) -> None:
            outcome[key] = value
            loop.quit()

        run_async(lambda: [(f.name, drive.download(f)) for f in files],
                  lambda r: finish("ok", r), lambda e: finish("error", e))
        self.busy = True
        try:
            loop.exec()
        finally:
            self.busy = False
            progress.close()
        if "error" in outcome:
            self.app.notify(tr("vault_error", error=outcome["error"]))
            return []
        self.app.persist_drive_token()
        # Decrypted copies live in the secure temp area and are wiped later.
        return [str(self.app.temp.write(name, content)) for name, content in outcome["ok"]]
