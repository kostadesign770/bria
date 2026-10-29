"""Ask Tor *why* a .onion address failed.

Chromium turns every SOCKS failure into a generic "site can't be reached".
Tor, with ``ExtendedErrors`` on the SocksPort, answers with a precise reply code
(descriptor not found, introduction failed, bad address, ...). This module
repeats the SOCKS5 CONNECT itself and returns that code.
"""

from __future__ import annotations

import socket

from cyber_browser import config

# Reply code -> i18n key
REASONS = {
    0x01: "onion_err_general",
    0x04: "onion_err_unreachable",
    0x05: "onion_err_refused",
    0x06: "onion_err_timeout",
    0xF0: "onion_err_not_found",
    0xF1: "onion_err_bad_descriptor",
    0xF2: "onion_err_intro_failed",
    0xF3: "onion_err_rendezvous_failed",
    0xF4: "onion_err_auth_missing",
    0xF5: "onion_err_auth_wrong",
    0xF6: "onion_err_bad_address",
    0xF7: "onion_err_intro_timeout",
}


def probe(host: str, port: int = 80, timeout: float = 90) -> int:
    """SOCKS5 CONNECT to ``host`` through Tor. Returns the reply code (0 = reachable)."""
    name = host.encode("idna")
    with socket.create_connection((config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT), timeout=timeout) as sock:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            return 0x01
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
        reply = sock.recv(4)
        return reply[1] if len(reply) >= 2 else 0x01


def reason_key(code: int) -> str | None:
    return None if code == 0 else REASONS.get(code, "onion_err_general")
