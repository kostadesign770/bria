"""Talks to Tor's ControlPort (9051) with *stem*.

Responsibilities
* ``new_identity(country)``  – optionally pin an exit country, then ``SIGNAL NEWNYM``;
* ``exit_countries()``       – live list of countries that currently have exit relays;
* ``health()``               – used by the kill-switch (SOCKS reachable + circuit built);
* ``country_of(ip)``         – offline GeoIP lookup inside Tor (no third-party API).

All methods are blocking and thread-safe; call them through ``run_async``.
"""

from __future__ import annotations

import os
import random
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass

from stem import Signal
from stem.control import Controller

from cyber_browser import config


# Countries that reliably host many exit relays – used until the live list is available.
FALLBACK_EXIT_COUNTRIES = ("us", "de", "nl", "fr", "se", "ch", "ca", "fi", "ro", "pl", "at", "no", "lu", "gb")


class TorControlError(Exception):
    """ControlPort unreachable, authentication failed, or Tor refused a command."""


@dataclass
class TorHealth:
    socks_ok: bool
    control_ok: bool
    circuit_ok: bool
    detail: str = ""

    @property
    def safe_to_browse(self) -> bool:
        # Without the control port we can't see circuits; a working SOCKS
        # handshake is then the best signal we have.
        return self.socks_ok and (self.circuit_ok or not self.control_ok)


class TorController:
    def __init__(self, host: str = config.TOR_SOCKS_HOST,
                 control_port: int = config.TOR_CONTROL_PORT,
                 socks_port: int = config.TOR_SOCKS_PORT) -> None:
        self.host = host
        self.control_port = control_port
        self.socks_port = socks_port
        self._ctrl: Controller | None = None
        self._lock = threading.RLock()
        self._country_cache: dict[str, int] = {}

    # ----------------------------------------------------------- connection
    def _controller(self) -> Controller:
        if self._ctrl is not None and self._ctrl.is_alive():
            return self._ctrl
        self.close()
        try:
            ctrl = Controller.from_port(address=self.host, port=self.control_port)
            # Cookie authentication is attempted automatically; a password is
            # only used if the user configured HashedControlPassword.
            ctrl.authenticate(password=os.environ.get(config.TOR_CONTROL_PASSWORD_ENV))
        except Exception as exc:  # noqa: BLE001 - stem raises many types
            raise TorControlError(str(exc) or exc.__class__.__name__) from exc
        self._ctrl = ctrl
        return ctrl

    def close(self) -> None:
        with self._lock:
            if self._ctrl is not None:
                try:
                    self._ctrl.close()
                except Exception:  # noqa: BLE001
                    pass
                self._ctrl = None

    # -------------------------------------------------------------- identity
    def new_identity(self, country: str | None) -> str | None:
        """Pin ``country`` (ISO code, e.g. ``"de"``) or clear the pin, then NEWNYM.

        Returns the country that was requested (``None`` = random exit).
        """
        with self._lock:
            ctrl = self._controller()
            try:
                if country:
                    ctrl.set_options({"ExitNodes": "{%s}" % country.lower(), "StrictNodes": "1"})
                else:
                    ctrl.reset_conf("ExitNodes", "StrictNodes")
                # Tor rate-limits NEWNYM (about once every 10 s); wait instead of failing.
                wait = ctrl.get_newnym_wait()
                if wait > 0:
                    time.sleep(min(wait, 15))
                ctrl.signal(Signal.NEWNYM)
            except Exception as exc:  # noqa: BLE001
                raise TorControlError(str(exc)) from exc
            # Give Tor a moment to start building the fresh circuit.
            time.sleep(1.5)
        return country.lower() if country else None

    def random_exit_country(self, exclude: str | None = None, min_relays: int = 5) -> str | None:
        """Pick a random country (different from ``exclude``) that has enough exits."""
        try:
            countries = self._country_cache or self.exit_countries()
        except TorControlError:
            countries = {code: min_relays for code in FALLBACK_EXIT_COUNTRIES}
        candidates = [c for c, n in countries.items() if n >= min_relays and c != (exclude or "").lower()]
        return random.choice(candidates) if candidates else None

    def exit_countries(self) -> dict[str, int]:
        """``{country_code: number_of_exit_relays}`` from the live consensus."""
        with self._lock:
            ctrl = self._controller()
            try:
                exits = [
                    status.address
                    for status in ctrl.get_network_statuses()
                    if "Exit" in status.flags and "BadExit" not in status.flags
                    and "Running" in status.flags and "Valid" in status.flags
                ]
                counts: Counter[str] = Counter()
                for i in range(0, len(exits), 200):
                    batch = [f"ip-to-country/{ip}" for ip in exits[i:i + 200]]
                    for code in ctrl.get_info(batch).values():
                        if code and code != "??":
                            counts[code.lower()] += 1
            except Exception as exc:  # noqa: BLE001 - e.g. Tor built without GeoIP
                raise TorControlError(str(exc)) from exc
        self._country_cache = dict(counts)
        return self._country_cache

    def country_of(self, ip: str) -> str | None:
        with self._lock:
            try:
                code = self._controller().get_info(f"ip-to-country/{ip}")
            except Exception:  # noqa: BLE001
                return None
        return None if not code or code == "??" else code.lower()

    # ---------------------------------------------------------------- health
    def health(self) -> TorHealth:
        socks_ok = self._socks_handshake()
        control_ok = circuit_ok = False
        detail = ""
        with self._lock:
            try:
                ctrl = self._controller()
                control_ok = True
                circuit_ok = ctrl.get_info("status/circuit-established") == "1"
                if not circuit_ok:
                    detail = ctrl.get_info("status/bootstrap-phase", "")
            except Exception as exc:  # noqa: BLE001
                detail = str(exc)
                self._ctrl = None
        if not socks_ok:
            detail = f"SOCKS {self.host}:{self.socks_port} unreachable"
        return TorHealth(socks_ok, control_ok, circuit_ok, detail)

    def _socks_handshake(self) -> bool:
        """Minimal SOCKS5 greeting – proves something is speaking SOCKS on 9050."""
        try:
            with socket.create_connection((self.host, self.socks_port), timeout=3) as sock:
                sock.sendall(b"\x05\x01\x00")
                return sock.recv(2) == b"\x05\x00"
        except OSError:
            return False
