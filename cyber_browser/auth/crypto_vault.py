"""Encrypted per-user vault with two independent encryption layers.

File layout (``<sha256(username)>.cbv``)::

    b"CBV1" | uint16 header length | header JSON | ciphertext

The header holds the salts, the Argon2id parameters and both nonces. It is
authenticated (used as AEAD associated data) by both layers, so tampering with
it makes decryption fail.

Encryption::

    letters password --Argon2id(salt_1)--> key_1 --> AES-256-GCM        (inner layer)
    digits  password --Argon2id(salt_2)--> key_2 --> ChaCha20-Poly1305  (outer layer)

Both passwords are required; each must be at least ``MIN_PASSWORD_LENGTH``
characters. The vault also stores a random 256-bit ``file_key`` that encrypts
every file sent to Google Drive, so Google only ever sees ciphertext.

This module has no Qt dependency so it can be unit-tested on its own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
import unicodedata
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from cyber_browser import config

MAGIC = b"CBV1"
FILE_AAD = b"cyber-browser-drive-file-v1"
NAME_AAD = b"cyber-browser-drive-name-v1"
_DIGITS_RE = re.compile(r"[0-9]+")


class VaultError(Exception):
    """Base class for vault problems."""


class InvalidCredentials(VaultError):
    """Wrong username/passwords (deliberately indistinguishable)."""


class VaultExists(VaultError):
    """A vault for this username already exists."""


class WeakPassword(VaultError):
    """A password does not satisfy the policy. ``args[0]`` is an i18n key."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters (stored in the file so they can evolve)."""

    time_cost: int = 3
    memory_cost: int = 64 * 1024   # KiB -> 64 MiB
    parallelism: int = 4


DEFAULT_KDF = KdfParams()


# --------------------------------------------------------------------------- #
# Password policy
# --------------------------------------------------------------------------- #
def check_letters_password(password: str) -> None:
    """Letters only (any alphabet, e.g. Hebrew or English), >= 10 characters."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        raise WeakPassword("err_letters_short")
    if not all(ch.isalpha() for ch in password):
        raise WeakPassword("err_letters_only")


def check_digits_password(password: str) -> None:
    """Digits 0-9 only, >= 10 characters."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        raise WeakPassword("err_digits_short")
    if not _DIGITS_RE.fullmatch(password):
        raise WeakPassword("err_digits_only")


def normalize_username(username: str) -> str:
    return unicodedata.normalize("NFKC", username).strip().casefold()


def _normalize_secret(secret: str) -> bytes:
    # NFKC so the same password typed on different keyboards derives the same key.
    return unicodedata.normalize("NFKC", secret).encode("utf-8")


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #
def derive_key(secret: str, salt: bytes, params: KdfParams) -> bytes:
    """Argon2id -> 32-byte key."""
    return hash_secret_raw(
        secret=_normalize_secret(secret),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_bytes(key: bytes, data: bytes, aad: bytes) -> bytes:
    """AES-256-GCM, output = nonce(12) | ciphertext+tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise VaultError("corrupted or foreign file") from exc


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #
class UserVault:
    """An unlocked vault. Keys live only in this object and are dropped by ``lock()``."""

    kdf_params: KdfParams = DEFAULT_KDF

    def __init__(self, path: Path, username: str, data: dict[str, Any],
                 key_letters: bytes, key_digits: bytes, salts: tuple[bytes, bytes],
                 params: KdfParams) -> None:
        self.path = path
        self.username = username
        self.data = data
        self._key_letters: bytes | None = key_letters
        self._key_digits: bytes | None = key_digits
        self._salts = salts
        self._params = params

    # ---------------------------------------------------------------- paths
    @staticmethod
    def vaults_dir() -> Path:
        path = config.data_dir() / "vaults"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @classmethod
    def path_for(cls, username: str) -> Path:
        # The file name does not reveal the username.
        digest = hashlib.sha256(b"cbv-user:" + normalize_username(username).encode()).hexdigest()
        return cls.vaults_dir() / f"{digest}.cbv"

    @classmethod
    def exists(cls, username: str) -> bool:
        return cls.path_for(username).exists()

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, username: str, letters: str, digits: str,
               initial: dict[str, Any] | None = None) -> "UserVault":
        username = username.strip()
        if not username:
            raise VaultError("empty username")
        check_letters_password(letters)
        check_digits_password(digits)
        path = cls.path_for(username)
        if path.exists():
            raise VaultExists(username)

        params = cls.kdf_params
        salts = (os.urandom(16), os.urandom(16))
        data: dict[str, Any] = {
            "username": username,
            "created": int(time.time()),
            "file_key": _b64e(os.urandom(32)),
            "settings": {},
            "bookmarks": [],
        }
        data.update(initial or {})
        vault = cls(path, username, data,
                    derive_key(letters, salts[0], params),
                    derive_key(digits, salts[1], params),
                    salts, params)
        vault.save()
        return vault

    @classmethod
    def open(cls, username: str, letters: str, digits: str) -> "UserVault":
        path = cls.path_for(username)
        if not path.exists():
            # Burn the same CPU as a real attempt so timing doesn't reveal existence.
            derive_key(letters, b"\0" * 16, cls.kdf_params)
            derive_key(digits, b"\0" * 16, cls.kdf_params)
            raise InvalidCredentials()

        header, header_raw, ciphertext = cls._read_file(path)
        try:
            params = KdfParams(**header["kdf"])
            salts = (_b64d(header["salt_letters"]), _b64d(header["salt_digits"]))
            nonces = (_b64d(header["nonce_inner"]), _b64d(header["nonce_outer"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultError("corrupted vault file") from exc
        key_letters = derive_key(letters, salts[0], params)
        key_digits = derive_key(digits, salts[1], params)
        aad = MAGIC + header_raw
        try:
            inner = ChaCha20Poly1305(key_digits).decrypt(nonces[1], ciphertext, aad)
            plaintext = AESGCM(key_letters).decrypt(nonces[0], inner, aad)
        except InvalidTag as exc:
            raise InvalidCredentials() from exc
        data = json.loads(plaintext.decode("utf-8"))
        return cls(path, data.get("username", username), data, key_letters, key_digits, salts, params)

    def save(self) -> None:
        """Re-encrypt and atomically replace the vault file (fresh nonces every time)."""
        if self._key_letters is None or self._key_digits is None:
            raise VaultError("vault is locked")
        header = {
            "v": 1,
            "kdf": asdict(self._params),
            "salt_letters": _b64e(self._salts[0]),
            "salt_digits": _b64e(self._salts[1]),
            "nonce_inner": _b64e(os.urandom(12)),
            "nonce_outer": _b64e(os.urandom(12)),
        }
        header_raw = json.dumps(header, sort_keys=True).encode("utf-8")
        aad = MAGIC + header_raw
        plaintext = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
        inner = AESGCM(self._key_letters).encrypt(_b64d(header["nonce_inner"]), plaintext, aad)
        outer = ChaCha20Poly1305(self._key_digits).encrypt(_b64d(header["nonce_outer"]), inner, aad)

        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "wb") as fh:
            fh.write(MAGIC + struct.pack(">H", len(header_raw)) + header_raw + outer)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def verify(self, letters: str, digits: str) -> bool:
        """Re-check both passwords against the unlocked vault (used for re-auth)."""
        if self._key_letters is None or self._key_digits is None:
            return False
        ok_l = hmac.compare_digest(derive_key(letters, self._salts[0], self._params), self._key_letters)
        ok_d = hmac.compare_digest(derive_key(digits, self._salts[1], self._params), self._key_digits)
        return ok_l and ok_d

    def lock(self) -> None:
        """Forget keys and decrypted data. (Python can't guarantee RAM is zeroed,
        but we drop every reference so the memory can be reclaimed.)"""
        self._key_letters = None
        self._key_digits = None
        self.data = {}

    @property
    def is_locked(self) -> bool:
        return self._key_letters is None

    @property
    def file_key(self) -> bytes:
        return _b64d(self.data["file_key"])

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _read_file(path: Path) -> tuple[dict[str, Any], bytes, bytes]:
        raw = path.read_bytes()
        if raw[:4] != MAGIC or len(raw) < 6:
            raise VaultError("not a vault file")
        (hlen,) = struct.unpack(">H", raw[4:6])
        header_raw = raw[6:6 + hlen]
        try:
            header = json.loads(header_raw)
        except ValueError as exc:
            raise VaultError("corrupted vault file") from exc
        return header, header_raw, raw[6 + hlen:]


# --------------------------------------------------------------------------- #
# Brute-force throttling
# --------------------------------------------------------------------------- #
class LoginThrottle:
    """Exponential back-off per username, persisted so restarting doesn't reset it."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (config.data_dir() / "throttle.json")

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _store(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data), "utf-8")

    @staticmethod
    def _key(username: str) -> str:
        return hashlib.sha256(b"cbv-throttle:" + normalize_username(username).encode()).hexdigest()

    def wait_seconds(self, username: str) -> int:
        entry = self._load().get(self._key(username))
        if not entry or entry["fails"] < 3:
            return 0
        delay = min(2 ** (entry["fails"] - 2), config.MAX_LOGIN_DELAY_S)
        return max(0, int(entry["last"] + delay - time.time()))

    def record_failure(self, username: str) -> None:
        data = self._load()
        entry = data.setdefault(self._key(username), {"fails": 0, "last": 0})
        entry["fails"] += 1
        entry["last"] = time.time()
        self._store(data)

    def record_success(self, username: str) -> None:
        data = self._load()
        if data.pop(self._key(username), None) is not None:
            self._store(data)
