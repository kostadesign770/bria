"""Time-based one-time passwords (Google Authenticator / Microsoft Authenticator).

The TOTP secret is stored *inside* the encrypted vault. It adds a "something you
have" factor to every interactive login and re-authentication.
"""

from __future__ import annotations

import pyotp

from cyber_browser import config


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=config.APP_DISPLAY_NAME)


def verify(secret: str, code: str) -> bool:
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return False
    # valid_window=1 tolerates +-30 s of clock drift between PC and phone.
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_matrix(data: str) -> list[list[bool]]:
    """QR code as a boolean matrix (drawn with QPainter, so no Pillow needed)."""
    import qrcode

    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.get_matrix()
