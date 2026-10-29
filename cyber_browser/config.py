"""Central configuration: ports, timers, paths and network constants.

Everything that a user might want to tweak lives here so the rest of the
code never hard-codes a magic number.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "CyberBrowser"
APP_DISPLAY_NAME = "Cyber Browser"

# --------------------------------------------------------------------------- #
# Tor
# --------------------------------------------------------------------------- #
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
# If torrc uses HashedControlPassword, put the plain password in this env var.
# With CookieAuthentication (the default we recommend) leave it unset.
TOR_CONTROL_PASSWORD_ENV = "CYBER_TOR_PASSWORD"

# --------------------------------------------------------------------------- #
# Timers (milliseconds)
# --------------------------------------------------------------------------- #
ROTATION_INTERVAL_MS = 10 * 60 * 1000      # automatic country/IP change
IDLE_LOCK_MS = 5 * 60 * 1000               # auto-logout without activity
CLIPBOARD_CLEAR_MS = 60 * 1000             # wipe clipboard after copying
TOR_HEALTH_INTERVAL_MS = 15 * 1000         # kill-switch health probe
COUNTRY_REFRESH_INTERVAL_MS = 30 * 60 * 1000
TEMP_FILE_MAX_AGE_S = 10 * 60              # uploaded files are wiped after this

# After a successful re-authentication, vault transfers are allowed without
# asking again for this many seconds.
REAUTH_GRACE_SECONDS = 120

# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
MIN_PASSWORD_LENGTH = 10       # applies to BOTH the letters and the digits password
MAX_LOGIN_DELAY_S = 300        # cap for the exponential back-off after failures

# --------------------------------------------------------------------------- #
# Browsing
# --------------------------------------------------------------------------- #
HOME_URL = "https://check.torproject.org/"
SEARCH_URL = "https://html.duckduckgo.com/html/?q={query}"

# A common, generic Windows/Chrome user agent so we blend into the crowd.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

# The language *websites* see (Accept-Language + navigator.language).
# English is the most common value on Tor and therefore the least identifying.
SITE_LANGUAGES = {
    "en": ("en-US,en;q=0.9", "en-US", ["en-US", "en"]),
    "he": ("he-IL,he;q=0.9,en;q=0.5", "he-IL", ["he-IL", "he", "en"]),
}
DEFAULT_SITE_LANGUAGE = "en"

# --------------------------------------------------------------------------- #
# Google Drive vault
# --------------------------------------------------------------------------- #
DRIVE_FOLDER_NAME = "CyberBrowser Vault"
MAX_TRANSFER_MB = 200
# Allow moving files between the vault and the local disk from the vault panel
# (always behind re-authentication). Web pages can never touch the local disk.
ALLOW_LOCAL_IMPORT_EXPORT = True


def data_dir() -> Path:
    """Per-user application directory (vaults, credentials.json, throttle data)."""
    override = os.environ.get("CYBER_BROWSER_HOME")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def google_client_secrets_path() -> Path:
    """Where the OAuth client file downloaded from Google Cloud must be placed."""
    return data_dir() / "credentials.json"


def tor_proxies() -> dict[str, str]:
    """`requests` proxy mapping. ``socks5h`` = DNS is resolved by Tor (no leaks)."""
    url = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    return {"http": url, "https": url}


def chromium_flags() -> list[str]:
    """Command-line switches handed to the embedded Chromium engine.

    * every request goes through Tor's SOCKS5 port, including DNS (``.onion`` works);
    * nothing is resolved locally, so a misconfiguration fails closed;
    * WebRTC may not open UDP sockets outside the proxy (no real-IP leak);
    * Chromium's own background "phone home" traffic is switched off.
    """
    return [
        f"--proxy-server=socks5://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {TOR_SOCKS_HOST}",
        "--proxy-bypass-list=<-loopback>",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-breakpad",
        "--no-pings",
        "--disable-features=WebRtcHideLocalIpsWithMdns,MediaRouter,DnsOverHttps,"
        "AutofillServerCommunication,InterestFeedContentSuggestions",
    ]
