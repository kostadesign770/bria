"""Deny every sensitive permission and apply the security level.

Camera, microphone, screen sharing, geolocation, notifications, clipboard
reading, mouse lock, local fonts and the File System Access API are refused
automatically – the user is never even asked, so a mis-click can't leak anything.
"""

from __future__ import annotations

import logging

from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings

log = logging.getLogger(__name__)

SECURITY_LEVELS = ("standard", "safer", "safest")
A = QWebEngineSettings.WebAttribute


def harden_page(page: QWebEnginePage) -> None:
    """Connect deny-all handlers to every permission signal the Qt version offers."""
    if hasattr(page, "permissionRequested"):           # Qt >= 6.8
        page.permissionRequested.connect(lambda permission: permission.deny())
    else:                                              # older Qt
        page.featurePermissionRequested.connect(
            lambda origin, feature: page.setFeaturePermission(
                origin, feature, QWebEnginePage.PermissionPolicy.PermissionDeniedByUser))
    if hasattr(page, "desktopMediaRequested"):         # screen/window sharing picker
        page.desktopMediaRequested.connect(lambda request: request.cancel())
    if hasattr(page, "fileSystemAccessRequested"):     # showOpenFilePicker & co.
        page.fileSystemAccessRequested.connect(lambda request: request.reject())


def harden_profile(profile: QWebEngineProfile) -> None:
    """Profile-wide privacy defaults (the profile is already off-the-record)."""
    profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
    profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
    if hasattr(profile, "setPersistentPermissionsPolicy"):
        profile.setPersistentPermissionsPolicy(
            QWebEngineProfile.PersistentPermissionsPolicy.AskEveryTime)
    if hasattr(profile, "setPushServiceEnabled"):
        profile.setPushServiceEnabled(False)
    profile.setSpellCheckEnabled(False)
    # Block third-party cookies (trackers embedded in other sites).
    profile.cookieStore().setCookieFilter(lambda request: not request.thirdParty)


def apply_security_level(settings: QWebEngineSettings, level: str) -> None:
    """Standard / Safer / Safest – modelled on Tor Browser's security slider."""
    # Always-on hardening regardless of level.
    for attr, value in (
        (A.JavascriptCanAccessClipboard, False),
        (A.JavascriptCanPaste, False),
        (A.ScreenCaptureEnabled, False),
        (A.WebRTCPublicInterfacesOnly, True),
        (A.AllowGeolocationOnInsecureOrigins, False),
        (A.AllowRunningInsecureContent, False),
        (A.LocalContentCanAccessRemoteUrls, False),
        (A.LocalContentCanAccessFileUrls, False),
        (A.DnsPrefetchEnabled, False),
        (A.HyperlinkAuditingEnabled, False),
        (A.PluginsEnabled, False),
        (A.NavigateOnDropEnabled, False),
        (A.PlaybackRequiresUserGesture, True),
        (A.AllowWindowActivationFromJavaScript, False),
        (A.XSSAuditingEnabled, True),
    ):
        settings.setAttribute(attr, value)

    safer = level in ("safer", "safest")
    safest = level == "safest"
    settings.setAttribute(A.JavascriptEnabled, not safest)
    settings.setAttribute(A.WebGLEnabled, not safer)
    settings.setAttribute(A.Accelerated2dCanvasEnabled, not safer)
    settings.setAttribute(A.JavascriptCanOpenWindows, not safer)
    settings.setAttribute(A.PdfViewerEnabled, not safest)
    if hasattr(A, "ReadingFromCanvasEnabled"):
        settings.setAttribute(A.ReadingFromCanvasEnabled, not safest)
