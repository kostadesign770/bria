"""JavaScript injected into every page *before* its own scripts run.

It reduces what a site can learn about the machine:
* ``navigator.language(s)`` match the chosen site language;
* time zone reported as UTC;
* fixed hardware values (CPU count, memory, platform);
* WebRTC, media devices, battery, sensors, USB/Bluetooth/Serial/HID removed;
* canvas read-outs get per-identity noise, so canvas fingerprints change on
  every country switch.

Limits: this is best-effort hardening in a Chromium engine, not the full
uniformity of Tor Browser. Web Workers are not covered.
"""

from __future__ import annotations

import json
import secrets

from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineScript

from cyber_browser import config

_TEMPLATE = r"""
(() => {
  const LANG = __LANG__, LANGS = __LANGS__, SEED = __SEED__;
  const def = (obj, prop, value) => {
    try { Object.defineProperty(obj, prop, { get: () => value, configurable: true }); } catch (e) {}
  };
  const N = Navigator.prototype;
  def(N, 'language', LANG);
  def(N, 'languages', Object.freeze(LANGS.slice()));
  def(N, 'hardwareConcurrency', 4);
  def(N, 'deviceMemory', 8);
  def(N, 'platform', 'Win32');
  def(N, 'doNotTrack', null);
  for (const p of ['mediaDevices', 'getBattery', 'usb', 'bluetooth', 'serial', 'hid', 'xr',
                   'geolocation', 'getUserMedia', 'webkitGetUserMedia', 'getDisplayMedia']) {
    def(N, p, undefined);
  }
  for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel',
                   'RTCSessionDescription', 'RTCIceCandidate', 'MediaStreamTrack',
                   'Accelerometer', 'Gyroscope', 'Magnetometer', 'AbsoluteOrientationSensor',
                   'RelativeOrientationSensor', 'LinearAccelerationSensor', 'GravitySensor',
                   'AmbientLightSensor', 'DeviceMotionEvent', 'DeviceOrientationEvent']) {
    try { Object.defineProperty(window, k, { value: undefined, configurable: true }); } catch (e) {}
  }

  // Time zone -> UTC
  const ro = Intl.DateTimeFormat.prototype.resolvedOptions;
  Intl.DateTimeFormat.prototype.resolvedOptions = function () {
    const r = ro.call(this); r.timeZone = 'UTC'; return r;
  };
  Date.prototype.getTimezoneOffset = function () { return 0; };

  // Canvas noise (deterministic per identity, flips low bits of a few pixels)
  let s = SEED >>> 0;
  const rnd = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return (s >>> 0) / 4294967296; };
  const noisify = (data) => {
    for (let i = 0; i < data.length; i += 4 * (1 + Math.floor(rnd() * 64))) data[i] ^= 1;
    return data;
  };
  const gid = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...a) {
    const img = gid.apply(this, a); noisify(img.data); return img;
  };
  const wrap = (name) => {
    const orig = HTMLCanvasElement.prototype[name];
    HTMLCanvasElement.prototype[name] = function (...a) {
      // Work on a copy so the visible canvas is never modified.
      try {
        if (this.width && this.height) {
          const copy = document.createElement('canvas');
          copy.width = this.width; copy.height = this.height;
          const cx = copy.getContext('2d');
          cx.drawImage(this, 0, 0);
          const img = gid.call(cx, 0, 0, copy.width, copy.height);
          noisify(img.data);
          cx.putImageData(img, 0, 0);
          return orig.apply(copy, a);
        }
      } catch (e) {}
      return orig.apply(this, a);
    };
  };
  wrap('toDataURL'); wrap('toBlob');
})();
"""


def build_script(site_language: str) -> QWebEngineScript:
    _, lang, langs = config.SITE_LANGUAGES.get(site_language, config.SITE_LANGUAGES["en"])
    source = (_TEMPLATE
              .replace("__LANG__", json.dumps(lang))
              .replace("__LANGS__", json.dumps(langs))
              .replace("__SEED__", str(secrets.randbits(31) or 1)))
    script = QWebEngineScript()
    script.setName("cyber-fingerprint-shield")
    script.setSourceCode(source)
    script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
    script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
    script.setRunsOnSubFrames(True)
    return script


def install(profile: QWebEngineProfile, site_language: str) -> None:
    """(Re)install the shield and the matching Accept-Language header."""
    accept, _, _ = config.SITE_LANGUAGES.get(site_language, config.SITE_LANGUAGES["en"])
    profile.setHttpAcceptLanguage(accept)
    profile.setHttpUserAgent(config.USER_AGENT)
    scripts = profile.scripts()
    for old in scripts.find("cyber-fingerprint-shield"):
        scripts.remove(old)
    scripts.insert(build_script(site_language))
