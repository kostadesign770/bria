"""Google Drive vault – the only gateway for files in and out of the browser.

* OAuth scope ``drive.file``: the app can see *only* the files it created
  itself, never the rest of the user's Drive.
* Every file is encrypted locally (AES-256-GCM with the vault's ``file_key``)
  before upload. The Drive file name is random; the real name is stored
  encrypted in the description. Google only ever sees ciphertext.
* All API traffic (including token refresh) goes through Tor.
  The one-time browser sign-in cannot: Google blocks sign-ins from Tor exits.
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

import requests
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2.credentials import Credentials

from cyber_browser import config
from cyber_browser.auth.crypto_vault import FILE_AAD, NAME_AAD, decrypt_bytes, encrypt_bytes

SCOPES = ["https://www.googleapis.com/auth/drive.file"]
API = "https://www.googleapis.com/drive/v3"
UPLOAD_API = "https://www.googleapis.com/upload/drive/v3"
FOLDER_MIME = "application/vnd.google-apps.folder"


class DriveError(Exception):
    pass


@dataclass
class VaultFile:
    id: str
    name: str
    mime: str
    size: int
    created: str


def authorize(client_secrets: Path) -> str:
    """Interactive one-time consent in the system browser. Returns token JSON."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets), scopes=SCOPES)
    # The token exchange itself goes through Tor.
    flow.oauth2session.proxies = config.tor_proxies()
    creds = flow.run_local_server(port=0, open_browser=True, prompt="consent",
                                  authorization_prompt_message="", success_message=
                                  "Cyber Browser: Google Drive linked. You can close this tab.")
    return creds.to_json()


class DriveVault:
    def __init__(self, token_json: str, file_key: bytes) -> None:
        self._creds = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
        self._file_key = file_key
        self._folder_id: str | None = None
        refresh_session = requests.Session()
        refresh_session.proxies = config.tor_proxies()
        self._session = AuthorizedSession(self._creds, auth_request=Request(session=refresh_session))
        self._session.proxies = config.tor_proxies()
        self._session.headers["User-Agent"] = config.USER_AGENT

    def token_json(self) -> str:
        """Current token (may have been refreshed) – persist it back into the vault."""
        return self._creds.to_json()

    # -------------------------------------------------------------- helpers
    def _check(self, resp: requests.Response) -> requests.Response:
        if resp.status_code >= 400:
            raise DriveError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    def _folder(self) -> str:
        if self._folder_id:
            return self._folder_id
        query = f"name = '{config.DRIVE_FOLDER_NAME}' and mimeType = '{FOLDER_MIME}' and trashed = false"
        found = self._check(self._session.get(f"{API}/files", params={"q": query, "fields": "files(id)"},
                                              timeout=60)).json().get("files", [])
        if found:
            self._folder_id = found[0]["id"]
        else:
            meta = {"name": config.DRIVE_FOLDER_NAME, "mimeType": FOLDER_MIME}
            self._folder_id = self._check(self._session.post(f"{API}/files", json=meta,
                                                             params={"fields": "id"}, timeout=60)).json()["id"]
        return self._folder_id

    def _encrypt_meta(self, name: str, mime: str) -> str:
        raw = json.dumps({"n": name, "m": mime}).encode("utf-8")
        return base64.b64encode(encrypt_bytes(self._file_key, raw, NAME_AAD)).decode("ascii")

    def _decrypt_meta(self, description: str) -> tuple[str, str]:
        try:
            raw = decrypt_bytes(self._file_key, base64.b64decode(description), NAME_AAD)
            meta = json.loads(raw)
            return meta["n"], meta.get("m") or "application/octet-stream"
        except Exception:  # noqa: BLE001 - foreign/corrupted file
            return "?", "application/octet-stream"

    # ---------------------------------------------------------------- API
    def list_files(self) -> list[VaultFile]:
        params = {
            "q": f"'{self._folder()}' in parents and trashed = false",
            "fields": "files(id,description,size,createdTime)",
            "orderBy": "createdTime desc",
            "pageSize": 1000,
        }
        files = self._check(self._session.get(f"{API}/files", params=params, timeout=60)).json().get("files", [])
        result = []
        for f in files:
            name, mime = self._decrypt_meta(f.get("description", ""))
            # Stored size includes 28 bytes of nonce + tag.
            result.append(VaultFile(f["id"], name, mime, max(0, int(f.get("size", 0)) - 28),
                                    f.get("createdTime", "")[:16].replace("T", " ")))
        return result

    def upload(self, name: str, mime: str, content: bytes) -> str:
        if len(content) > config.MAX_TRANSFER_MB * 1024 * 1024:
            raise DriveError("too big")
        blob = encrypt_bytes(self._file_key, content, FILE_AAD)
        meta = {"name": f"{uuid.uuid4().hex}.cbv", "parents": [self._folder()],
                "description": self._encrypt_meta(name, mime or "application/octet-stream")}
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
                f"{json.dumps(meta)}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
                ).encode("utf-8") + blob + f"\r\n--{boundary}--".encode("ascii")
        resp = self._session.post(f"{UPLOAD_API}/files", params={"uploadType": "multipart", "fields": "id"},
                                  data=body, headers={"Content-Type": f"multipart/related; boundary={boundary}"},
                                  timeout=600)
        return self._check(resp).json()["id"]

    def download(self, file: VaultFile) -> bytes:
        resp = self._session.get(f"{API}/files/{file.id}", params={"alt": "media"}, timeout=600)
        return decrypt_bytes(self._file_key, self._check(resp).content, FILE_AAD)

    def delete(self, file: VaultFile) -> None:
        self._check(self._session.delete(f"{API}/files/{file.id}", timeout=60))
