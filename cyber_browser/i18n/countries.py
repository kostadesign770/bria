"""Country names for the exit-country selector (Hebrew / English)."""

from __future__ import annotations

from cyber_browser.i18n.strings import language

# code: (Hebrew, English)
COUNTRIES: dict[str, tuple[str, str]] = {
    "us": ("ארצות הברית", "United States"), "de": ("גרמניה", "Germany"),
    "nl": ("הולנד", "Netherlands"), "fr": ("צרפת", "France"),
    "gb": ("בריטניה", "United Kingdom"), "se": ("שוודיה", "Sweden"),
    "ch": ("שווייץ", "Switzerland"), "ca": ("קנדה", "Canada"),
    "fi": ("פינלנד", "Finland"), "ro": ("רומניה", "Romania"),
    "pl": ("פולין", "Poland"), "at": ("אוסטריה", "Austria"),
    "no": ("נורווגיה", "Norway"), "lu": ("לוקסמבורג", "Luxembourg"),
    "cz": ("צ'כיה", "Czechia"), "es": ("ספרד", "Spain"),
    "it": ("איטליה", "Italy"), "bg": ("בולגריה", "Bulgaria"),
    "dk": ("דנמרק", "Denmark"), "is": ("איסלנד", "Iceland"),
    "ie": ("אירלנד", "Ireland"), "lt": ("ליטא", "Lithuania"),
    "lv": ("לטביה", "Latvia"), "ee": ("אסטוניה", "Estonia"),
    "be": ("בלגיה", "Belgium"), "pt": ("פורטוגל", "Portugal"),
    "ua": ("אוקראינה", "Ukraine"), "md": ("מולדובה", "Moldova"),
    "ru": ("רוסיה", "Russia"), "sg": ("סינגפור", "Singapore"),
    "jp": ("יפן", "Japan"), "hk": ("הונג קונג", "Hong Kong"),
    "au": ("אוסטרליה", "Australia"), "nz": ("ניו זילנד", "New Zealand"),
    "br": ("ברזיל", "Brazil"), "ar": ("ארגנטינה", "Argentina"),
    "in": ("הודו", "India"), "za": ("דרום אפריקה", "South Africa"),
    "il": ("ישראל", "Israel"), "tr": ("טורקיה", "Turkey"),
    "gr": ("יוון", "Greece"), "hu": ("הונגריה", "Hungary"),
    "sk": ("סלובקיה", "Slovakia"), "si": ("סלובניה", "Slovenia"),
    "hr": ("קרואטיה", "Croatia"), "rs": ("סרביה", "Serbia"),
    "cy": ("קפריסין", "Cyprus"), "mt": ("מלטה", "Malta"),
    "kr": ("דרום קוריאה", "South Korea"), "tw": ("טייוואן", "Taiwan"),
    "th": ("תאילנד", "Thailand"), "my": ("מלזיה", "Malaysia"),
    "id": ("אינדונזיה", "Indonesia"), "vn": ("וייטנאם", "Vietnam"),
    "mx": ("מקסיקו", "Mexico"), "cl": ("צ'ילה", "Chile"),
    "co": ("קולומביה", "Colombia"), "kz": ("קזחסטן", "Kazakhstan"),
    "am": ("ארמניה", "Armenia"), "ge": ("גאורגיה", "Georgia"),
    "sc": ("סיישל", "Seychelles"), "pa": ("פנמה", "Panama"),
    "cr": ("קוסטה ריקה", "Costa Rica"), "uy": ("אורוגוואי", "Uruguay"),
    "by": ("בלארוס", "Belarus"), "li": ("ליכטנשטיין", "Liechtenstein"),
    "ae": ("איחוד האמירויות", "United Arab Emirates"), "al": ("אלבניה", "Albania"),
    "ba": ("בוסניה והרצגובינה", "Bosnia and Herzegovina"), "mk": ("מקדוניה הצפונית", "North Macedonia"),
}


def country_name(code: str | None) -> str:
    if not code:
        return "?"
    code = code.lower()
    names = COUNTRIES.get(code)
    if names:
        return names[0] if language() == "he" else names[1]
    try:
        from PyQt6.QtCore import QLocale

        territory = QLocale.codeToTerritory(code.upper())
        if territory != QLocale.Country.AnyCountry:
            return QLocale.territoryToString(territory)
    except Exception:  # noqa: BLE001
        pass
    return code.upper()
