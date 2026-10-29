"""Drive vault client against an in-memory fake of the Drive REST API.

Verifies that Google would only ever receive ciphertext and random file names.
"""

from __future__ import annotations

import json
import os
import re

from cyber_browser.drive.drive_client import DriveVault, FOLDER_MIME

TOKEN = json.dumps({"token": "t", "refresh_token": "r", "client_id": "c", "client_secret": "s",
                    "token_uri": "https://oauth2.googleapis.com/token"})


class FakeResponse:
    def __init__(self, status: int = 200, payload=None, content: bytes = b"") -> None:
        self.status_code, self._payload, self.content, self.text = status, payload, content, ""

    def json(self):
        return self._payload


class FakeDrive:
    """Just enough of files.list / create / get?alt=media / delete."""

    def __init__(self) -> None:
        self.files: dict[str, dict] = {}
        self.raw_uploads: list[bytes] = []

    def get(self, url, params=None, timeout=None):
        if url.endswith("/files"):
            q = params["q"]
            if FOLDER_MIME in q:
                found = [{"id": i} for i, f in self.files.items() if f.get("mimeType") == FOLDER_MIME]
                return FakeResponse(payload={"files": found})
            parent = re.search(r"'([^']+)' in parents", q).group(1)
            items = [{"id": i, "description": f["description"], "size": str(len(f["blob"])),
                      "createdTime": "2026-10-29T12:00:00Z"}
                     for i, f in self.files.items() if parent in f.get("parents", [])]
            return FakeResponse(payload={"files": items})
        file_id = url.rsplit("/", 1)[1]
        return FakeResponse(content=self.files[file_id]["blob"])

    def post(self, url, json=None, params=None, data=None, headers=None, timeout=None):
        new_id = f"id{len(self.files)}"
        if json is not None:                                   # folder creation
            self.files[new_id] = dict(json)
            return FakeResponse(payload={"id": new_id})
        self.raw_uploads.append(data)
        boundary = headers["Content-Type"].split("boundary=")[1].encode()
        parts = data.split(b"--" + boundary)
        meta = __import__("json").loads(parts[1].split(b"\r\n\r\n", 1)[1].strip())
        blob = parts[2].split(b"\r\n\r\n", 1)[1][:-2]
        self.files[new_id] = {**meta, "blob": blob}
        return FakeResponse(payload={"id": new_id})

    def delete(self, url, timeout=None):
        self.files.pop(url.rsplit("/", 1)[1])
        return FakeResponse(204)


def make_vault() -> tuple[DriveVault, FakeDrive]:
    vault = DriveVault(TOKEN, os.urandom(32))
    fake = FakeDrive()
    vault._session = fake
    return vault, fake


def test_upload_list_download_delete_roundtrip():
    vault, fake = make_vault()
    secret = b"my private document contents"
    vault.upload("חוזה סודי.pdf", "application/pdf", secret)

    raw = fake.raw_uploads[0]
    assert secret not in raw
    assert "חוזה".encode() not in raw and b"pdf" not in raw.split(b"\r\n\r\n", 2)[1]
    stored = next(f for f in fake.files.values() if "blob" in f)
    assert re.fullmatch(r"[0-9a-f]{32}\.cbv", stored["name"])          # random name on Drive

    [item] = vault.list_files()
    assert item.name == "חוזה סודי.pdf" and item.mime == "application/pdf" and item.size == len(secret)
    assert vault.download(item) == secret
    vault.delete(item)
    assert vault.list_files() == []


def test_other_key_cannot_read():
    vault, fake = make_vault()
    vault.upload("a.txt", "text/plain", b"hello")
    other = DriveVault(TOKEN, os.urandom(32))
    other._session = fake
    [item] = other.list_files()
    assert item.name == "?"                                            # name not decryptable
