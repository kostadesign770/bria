"""Page translation engines.

* ``ArgosEngine``  – offline (argostranslate). Page text never leaves the computer.
  Models are downloaded once, through Tor.
* ``GoogleEngine`` – Google Translate's public endpoint, queried through Tor.
  Better quality, but the page text is sent to Google.

Both expose ``translate(texts, src, dst) -> list[str]`` and are blocking
(run them with ``run_async``).
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Callable

import requests

from cyber_browser import config

log = logging.getLogger(__name__)

JS_SOURCE = (Path(__file__).with_name("translate_page.js")).read_text("utf-8")


class TranslationError(Exception):
    pass


class GoogleBlocked(TranslationError):
    """Google answered 429/403 (rate limit / CAPTCHA) – common on Tor exit IPs."""


class MissingModel(TranslationError):
    def __init__(self, src: str, dst: str) -> None:
        super().__init__(f"{src}->{dst}")
        self.src, self.dst = src, dst


def normalize_lang(code: str | None) -> str | None:
    if not code:
        return None
    code = code.strip().lower().replace("_", "-").split("-")[0]
    return {"iw": "he", "zh": "zh"}.get(code, code) or None


def detect_language(declared: str | None, sample_text: str) -> str | None:
    """Prefer statistical detection on the text; fall back to the <html lang> attribute."""
    sample_text = (sample_text or "").strip()
    if len(sample_text) >= 40:
        try:
            from langdetect import DetectorFactory, detect

            DetectorFactory.seed = 0
            return normalize_lang(detect(sample_text))
        except Exception:  # noqa: BLE001 - langdetect raises on odd input
            pass
    return normalize_lang(declared)


def _tor_session() -> requests.Session:
    session = requests.Session()
    session.proxies = config.tor_proxies()
    session.headers["User-Agent"] = config.USER_AGENT
    return session


class GoogleEngine:
    URL = "https://translate.googleapis.com/translate_a/single"

    def translate(self, texts: list[str], src: str, dst: str,
                  progress: Callable[[int], None] | None = None) -> list[str]:
        session = _tor_session()
        out: list[str] = []
        batch: list[str] = []
        size = 0

        def flush() -> None:
            nonlocal batch, size
            if batch:
                out.extend(self._translate_batch(session, batch, src, dst))
                if progress:
                    progress(len(out))
            batch, size = [], 0

        for text in texts:
            text = text.replace("\n", " ")
            if size + len(text) > 3500:
                flush()
            batch.append(text)
            size += len(text) + 1
        flush()
        return out

    def _translate_batch(self, session: requests.Session, batch: list[str], src: str, dst: str) -> list[str]:
        resp = session.post(self.URL, params={"client": "gtx", "sl": src or "auto", "tl": dst, "dt": "t"},
                            data={"q": "\n".join(batch)}, timeout=40)
        if resp.status_code in (403, 429):
            raise GoogleBlocked(f"HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise TranslationError(f"HTTP {resp.status_code}")
        segments = resp.json()[0] or []
        joined = "".join(seg[0] for seg in segments if seg and seg[0])
        lines = joined.split("\n")
        if len(lines) == len(batch):
            return [line.strip() for line in lines]
        if len(batch) == 1:
            return [joined.strip()]
        # Google merged or split lines: fall back to one request per text.
        return [self._translate_batch(session, [t], src, dst)[0] for t in batch]


class ArgosEngine:
    @staticmethod
    def available() -> bool:
        try:
            import argostranslate.translate  # noqa: F401
        except ImportError:
            return False
        return True

    def translate(self, texts: list[str], src: str, dst: str,
                  progress: Callable[[int], None] | None = None) -> list[str]:
        import argostranslate.translate as at

        languages = {lang.code: lang for lang in at.get_installed_languages()}
        if src not in languages or dst not in languages:
            raise MissingModel(src, dst)
        translation = languages[src].get_translation(languages[dst])  # pivots via English if needed
        if translation is None:
            raise MissingModel(src, dst)
        out = []
        for i, text in enumerate(texts, 1):
            out.append(translation.translate(text))
            if progress and i % 10 == 0:
                progress(i)
        return out

    @staticmethod
    def install_models(pairs: tuple[tuple[str, str], ...] = (("he", "en"), ("en", "he"))) -> list[str]:
        """Download model packages through Tor and install them."""
        import argostranslate.package as ap
        import argostranslate.settings as asettings

        session = _tor_session()
        index = session.get(asettings.remote_package_index, timeout=60).json()
        installed: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            for src, dst in pairs:
                entry = next((p for p in index if p.get("from_code") == src and p.get("to_code") == dst), None)
                if entry is None:
                    continue
                url = entry["links"][0]
                target = Path(tmp) / f"{src}_{dst}.argosmodel"
                with session.get(url, stream=True, timeout=120) as resp:
                    resp.raise_for_status()
                    with open(target, "wb") as fh:
                        for chunk in resp.iter_content(1 << 16):
                            fh.write(chunk)
                ap.install_from_path(str(target))
                installed.append(f"{src}→{dst}")
        if not installed:
            raise TranslationError(json.dumps(pairs))
        return installed


def engine_for(name: str) -> GoogleEngine | ArgosEngine:
    return GoogleEngine() if name == "google" else ArgosEngine()
