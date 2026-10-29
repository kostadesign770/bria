"""Local-disk isolation.

* ``DropBlocker``  – files dragged from Explorer onto the browser are rejected.
* ``SecureTempArea`` – the only place decrypted vault files ever touch the disk
  (needed because Chromium uploads from a file path). Files are overwritten with
  zeros before deletion and removed after use, on lock, on exit and after
  ``TEMP_FILE_MAX_AGE_S``.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from PyQt6.QtCore import QEvent, QObject

from cyber_browser import config


class DropBlocker(QObject):
    """Application event filter that swallows every drag/drop carrying files."""

    _TYPES = {QEvent.Type.DragEnter, QEvent.Type.DragMove, QEvent.Type.Drop}

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802 - Qt API
        if event.type() in self._TYPES:
            mime = event.mimeData()
            if mime is not None and (mime.hasUrls() or mime.hasImage()):
                event.ignore()
                return True
        return False


def _wipe_file(path: Path) -> None:
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            chunk = b"\0" * min(size, 1 << 20) if size else b""
            written = 0
            while written < size:
                written += fh.write(chunk[: size - written])
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


class SecureTempArea:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="cbv_"))

    def new_dir(self) -> Path:
        path = self.root / uuid.uuid4().hex
        path.mkdir()
        return path

    def write(self, name: str, content: bytes) -> Path:
        safe = Path(name).name or "file"
        path = self.new_dir() / safe
        path.write_bytes(content)
        return path

    def wipe(self, path: Path) -> None:
        path = Path(path)
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    _wipe_file(child)
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            _wipe_file(path)

    def cleanup_old(self) -> None:
        cutoff = time.time() - config.TEMP_FILE_MAX_AGE_S
        for child in self.root.iterdir() if self.root.exists() else []:
            try:
                if child.stat().st_mtime < cutoff:
                    self.wipe(child)
            except OSError:
                pass

    def wipe_all(self) -> None:
        if self.root.exists():
            for child in list(self.root.iterdir()):
                self.wipe(child)

    def destroy(self) -> None:
        self.wipe_all()
        shutil.rmtree(self.root, ignore_errors=True)
