"""Find the current exit IP and its country, *through Tor*.

1. ``check.torproject.org/api/ip`` gives the exit IP and confirms it is a Tor exit.
2. The country is looked up inside Tor's own GeoIP database (nothing leaves the PC).
3. Fallbacks: ipwho.is, ipapi.co, icanhazip – all queried through Tor as well.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from cyber_browser import config
from cyber_browser.core.tor_controller import TorController


@dataclass
class IpInfo:
    ip: str
    country_code: str | None = None
    country_name: str | None = None
    is_tor: bool | None = None


def _session() -> requests.Session:
    session = requests.Session()
    session.proxies = config.tor_proxies()
    session.headers["User-Agent"] = config.USER_AGENT
    return session


def fetch_ip_info(tor: TorController | None = None, timeout: float = 25) -> IpInfo:
    session = _session()
    info: IpInfo | None = None

    try:
        data = session.get("https://check.torproject.org/api/ip", timeout=timeout).json()
        info = IpInfo(ip=data["IP"], is_tor=bool(data.get("IsTor")))
    except (requests.RequestException, ValueError, KeyError):
        pass

    if info is None:
        for url in ("https://ipwho.is/", "https://ipapi.co/json/"):
            try:
                data = session.get(url, timeout=timeout).json()
                info = IpInfo(ip=data["ip"], country_code=(data.get("country_code") or "").lower() or None,
                              country_name=data.get("country") or data.get("country_name"))
                break
            except (requests.RequestException, ValueError, KeyError):
                continue

    if info is None:
        # Last resort: plain-text IP only.
        ip = session.get("https://icanhazip.com/", timeout=timeout).text.strip()
        info = IpInfo(ip=ip)

    if info.country_code is None and tor is not None:
        info.country_code = tor.country_of(info.ip)
    if info.country_code is None:
        try:
            data = session.get(f"https://ipwho.is/{info.ip}", timeout=timeout).json()
            info.country_code = (data.get("country_code") or "").lower() or None
            info.country_name = data.get("country")
        except (requests.RequestException, ValueError):
            pass
    return info
