"""Download the newest stable Tor Expert Bundle for Windows into ``build/tor_bundle``.

Used by the GitHub Actions build; the bundle is verified against the
sha256sums file published next to it on dist.torproject.org.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

BASE = "https://dist.torproject.org/torbrowser/"
TARGET = Path(sys.argv[1] if len(sys.argv) > 1 else "build/tor_bundle")


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def main() -> None:
    listing = get(BASE).decode()
    versions = sorted({v for v in re.findall(r'href="(\d+(?:\.\d+)+)/"', listing)},
                      key=lambda v: [int(x) for x in v.split(".")], reverse=True)
    for version in versions:
        name = f"tor-expert-bundle-windows-x86_64-{version}.tar.gz"
        try:
            data = get(f"{BASE}{version}/{name}")
        except Exception:  # noqa: BLE001 - not published for this version, try the next
            continue
        expected = None
        for sums_file in ("sha256sums-signed-build.txt", "sha256sums-unsigned-build.txt"):
            try:
                sums = get(f"{BASE}{version}/{sums_file}").decode()
            except Exception:  # noqa: BLE001
                continue
            expected = next((line.split()[0] for line in sums.splitlines()
                             if line.strip().endswith(name)), None)
            if expected:
                break
        actual = hashlib.sha256(data).hexdigest()
        if expected != actual:
            raise SystemExit(f"checksum mismatch for {name}: {actual} != {expected}")
        TARGET.mkdir(parents=True, exist_ok=True)
        archive = TARGET.parent / name
        archive.write_bytes(data)
        with tarfile.open(archive) as tar:
            tar.extractall(TARGET, filter="data")
        print(f"Tor Expert Bundle {version} -> {TARGET} (sha256 {actual})")
        return
    raise SystemExit("no Tor Expert Bundle found")


if __name__ == "__main__":
    main()
