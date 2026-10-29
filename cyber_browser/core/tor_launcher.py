"""Start the Tor binary that ships inside the portable build.

If something already answers SOCKS on 9050 (a Tor service the user installed),
it is used as-is. Otherwise, when a bundled Tor exists next to the program, it is
started with a generated torrc (ControlPort + cookie auth + GeoIP) and stopped
when the browser exits. ``__OwningControllerProcess`` makes Tor quit by itself
even if the browser crashes.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

from cyber_browser import config
from cyber_browser.core.tor_controller import TorController

log = logging.getLogger(__name__)

BUNDLE_ENV = "CYBER_TOR_BUNDLE"


def bundle_dir() -> Path | None:
    """``tor_bundle`` folder next to the executable (PyInstaller) or set via env."""
    if os.environ.get(BUNDLE_ENV):
        candidates = [Path(os.environ[BUNDLE_ENV])]
    else:
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        candidates = [base / "tor_bundle", Path(sys.executable).parent / "tor_bundle"]
    return next((c for c in candidates if c.is_dir()), None)


def _find(root: Path, name: str) -> Path | None:
    return next((p for p in sorted(root.rglob(name)) if p.is_file()), None)


class TorLauncher:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None

    def ensure_running(self) -> bool:
        """Returns True if Tor is (now) available or being started."""
        if TorController()._socks_handshake():
            return True
        root = bundle_dir()
        if root is None:
            return False
        exe = _find(root, "tor.exe" if sys.platform == "win32" else "tor")
        if exe is None:
            log.warning("bundled Tor not found in %s", root)
            return False

        state = config.data_dir() / "tor"
        state.mkdir(parents=True, exist_ok=True)
        lines = [
            # ExtendedErrors: precise SOCKS reply codes for .onion failures (see onion_probe.py)
            f"SocksPort {config.TOR_SOCKS_HOST}:{config.TOR_SOCKS_PORT} ExtendedErrors",
            f"ControlPort {config.TOR_SOCKS_HOST}:{config.TOR_CONTROL_PORT}",
            "CookieAuthentication 1",
            f"DataDirectory {state / 'state'}",
            f"__OwningControllerProcess {os.getpid()}",
            "Log notice file " + str(state / "tor.log"),
        ]
        for option, filename in (("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")):
            path = _find(root, filename)
            if path is not None:
                lines.append(f"{option} {path}")
        torrc = state / "torrc"
        torrc.write_text("\n".join(lines) + "\n", "utf-8")

        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self.process = subprocess.Popen([str(exe), "-f", str(torrc)], cwd=str(exe.parent),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        creationflags=flags)
        log.info("started bundled Tor (pid %s)", self.process.pid)
        return True

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
