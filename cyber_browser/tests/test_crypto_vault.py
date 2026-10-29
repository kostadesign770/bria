"""Unit tests for the two-layer vault, password policy, throttling and file encryption.

Run from the repository root:  python -m pytest cyber_browser/tests -q
"""

from __future__ import annotations

import os

import pytest

from cyber_browser.auth import crypto_vault as cv
from cyber_browser.auth import totp

LETTERS = "abcdefghijKL"
DIGITS = "0123456789012"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBER_BROWSER_HOME", str(tmp_path))
    # Cheap KDF parameters so the tests run fast; production uses 64 MiB.
    monkeypatch.setattr(cv.UserVault, "kdf_params", cv.KdfParams(time_cost=1, memory_cost=8 * 1024, parallelism=1))
    return tmp_path


def test_password_policy():
    cv.check_letters_password("אבגדהוזחטיכ")          # Hebrew letters are fine
    cv.check_digits_password("1234567890")
    for bad, check in [("abc", cv.check_letters_password), ("abcdefghij1", cv.check_letters_password),
                       ("123456789", cv.check_digits_password), ("12345678901a", cv.check_digits_password),
                       ("１２３４５６７８９０", cv.check_digits_password)]:  # full-width digits rejected
        with pytest.raises(cv.WeakPassword):
            check(bad)


def test_create_open_roundtrip():
    vault = cv.UserVault.create("Dana", LETTERS, DIGITS, {"totp_secret": "X"})
    vault.data["bookmarks"].append({"title": "t", "url": "https://example.org"})
    vault.save()
    reopened = cv.UserVault.open("dana", LETTERS, DIGITS)       # username is case-insensitive
    assert reopened.data["bookmarks"][0]["url"] == "https://example.org"
    assert reopened.data["totp_secret"] == "X"
    assert len(reopened.file_key) == 32


def test_file_does_not_contain_plaintext_or_username():
    vault = cv.UserVault.create("secret-user", LETTERS, DIGITS, {"note": "top-secret-note"})
    raw = vault.path.read_bytes()
    assert b"top-secret-note" not in raw
    assert b"secret-user" not in raw and "secret-user" not in vault.path.name


@pytest.mark.parametrize("letters,digits", [(LETTERS + "x", DIGITS), (LETTERS, DIGITS + "1"),
                                             ("zzzzzzzzzzzz", "9999999999")])
def test_each_password_is_required(letters, digits):
    cv.UserVault.create("u", LETTERS, DIGITS)
    with pytest.raises(cv.InvalidCredentials):
        cv.UserVault.open("u", letters, digits)


def test_unknown_user_is_indistinguishable():
    with pytest.raises(cv.InvalidCredentials):
        cv.UserVault.open("nobody", LETTERS, DIGITS)


def test_tampered_header_is_rejected():
    vault = cv.UserVault.create("u", LETTERS, DIGITS)
    raw = bytearray(vault.path.read_bytes())
    raw[20] ^= 0x01                                   # flip a bit inside the header
    vault.path.write_bytes(bytes(raw))
    with pytest.raises((cv.InvalidCredentials, cv.VaultError, ValueError)):
        cv.UserVault.open("u", LETTERS, DIGITS)


def test_duplicate_user():
    cv.UserVault.create("u", LETTERS, DIGITS)
    with pytest.raises(cv.VaultExists):
        cv.UserVault.create("U", LETTERS, DIGITS)


def test_verify_and_lock():
    vault = cv.UserVault.create("u", LETTERS, DIGITS)
    assert vault.verify(LETTERS, DIGITS)
    assert not vault.verify(LETTERS, "1111111111")
    vault.lock()
    assert vault.is_locked and vault.data == {}
    assert not vault.verify(LETTERS, DIGITS)


def test_file_blob_encryption():
    key = os.urandom(32)
    blob = cv.encrypt_bytes(key, b"hello", cv.FILE_AAD)
    assert b"hello" not in blob
    assert cv.decrypt_bytes(key, blob, cv.FILE_AAD) == b"hello"
    with pytest.raises(cv.VaultError):
        cv.decrypt_bytes(os.urandom(32), blob, cv.FILE_AAD)
    with pytest.raises(cv.VaultError):
        cv.decrypt_bytes(key, blob, cv.NAME_AAD)       # wrong context


def test_throttle(isolated_home):
    throttle = cv.LoginThrottle(isolated_home / "t.json")
    for _ in range(2):
        throttle.record_failure("u")
    assert throttle.wait_seconds("u") == 0
    for _ in range(3):
        throttle.record_failure("u")
    assert throttle.wait_seconds("u") > 0
    throttle.record_success("u")
    assert throttle.wait_seconds("u") == 0


def test_totp():
    import pyotp

    secret = totp.new_secret()
    assert totp.verify(secret, pyotp.TOTP(secret).now())
    assert not totp.verify(secret, "000000") or pyotp.TOTP(secret).now() == "000000"
    assert totp.qr_matrix(totp.provisioning_uri(secret, "u"))
