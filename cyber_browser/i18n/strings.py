"""User-interface strings in Hebrew and English.

The first language is taken from the operating system (``QLocale.system()``);
the user can switch at any time from the menu or the login screen.
Hebrew automatically turns the whole UI right-to-left.
"""

from __future__ import annotations

from typing import Callable

SUPPORTED = ("he", "en")

STRINGS: dict[str, dict[str, str]] = {
    # ------------------------------------------------------------ general
    "app_title": {"he": "Cyber Browser – דפדפן פרטי", "en": "Cyber Browser – Private Browser"},
    "lang_he": {"he": "עברית", "en": "עברית (Hebrew)"},
    "lang_en": {"he": "English (אנגלית)", "en": "English"},
    "ok": {"he": "אישור", "en": "OK"},
    "cancel": {"he": "ביטול", "en": "Cancel"},
    "close": {"he": "סגור", "en": "Close"},
    "working": {"he": "מעבד… (גזירת מפתחות מאובטחת)", "en": "Working… (secure key derivation)"},
    "ui_language": {"he": "שפת הממשק:", "en": "Interface language:"},

    # -------------------------------------------------------------- login
    "login_title": {"he": "כניסה לדפדפן", "en": "Sign in"},
    "tab_guest": {"he": "אורח", "en": "Guest"},
    "tab_login": {"he": "כניסת משתמש", "en": "User login"},
    "tab_create": {"he": "יצירת משתמש", "en": "Create user"},
    "guest_info": {
        "he": "מצב אורח: שום דבר לא נשמר – אין היסטוריה, אין עוגיות, אין קבצים.\n"
              "הורדה והעלאה של קבצים חסומות לחלוטין במצב זה.",
        "en": "Guest mode: nothing is saved – no history, no cookies, no files.\n"
              "Downloading and uploading files is completely blocked in this mode.",
    },
    "guest_enter": {"he": "כניסה כאורח", "en": "Enter as guest"},
    "username": {"he": "שם משתמש", "en": "Username"},
    "letters_pwd": {"he": "סיסמת אותיות (אותיות בלבד, 10+)", "en": "Letters password (letters only, 10+)"},
    "digits_pwd": {"he": "סיסמת ספרות (ספרות בלבד, 10+)", "en": "Digits password (digits only, 10+)"},
    "letters_pwd_confirm": {"he": "אימות סיסמת אותיות", "en": "Confirm letters password"},
    "digits_pwd_confirm": {"he": "אימות סיסמת ספרות", "en": "Confirm digits password"},
    "totp_code": {"he": "קוד מאפליקציית האימות (6 ספרות)", "en": "Authenticator code (6 digits)"},
    "login_btn": {"he": "כניסה", "en": "Sign in"},
    "create_btn": {"he": "צור משתמש", "en": "Create user"},
    "next_btn": {"he": "המשך", "en": "Next"},
    "pwd_rules": {
        "he": "הכספת מוצפנת בשתי שכבות: AES-256-GCM (מסיסמת האותיות) ו-ChaCha20-Poly1305 (מסיסמת הספרות).\n"
              "אין דרך לשחזר סיסמה שנשכחה – בלי שתיהן ובלי הטלפון, הנתונים אבודים.",
        "en": "The vault is encrypted twice: AES-256-GCM (letters password) and ChaCha20-Poly1305 "
              "(digits password).\nForgotten passwords cannot be recovered – without both and your phone the data is lost.",
    },
    "err_letters_short": {"he": "סיסמת האותיות חייבת לכלול לפחות 10 תווים.", "en": "The letters password needs at least 10 characters."},
    "err_letters_only": {"he": "סיסמת האותיות יכולה להכיל אותיות בלבד.", "en": "The letters password may contain letters only."},
    "err_digits_short": {"he": "סיסמת הספרות חייבת לכלול לפחות 10 ספרות.", "en": "The digits password needs at least 10 digits."},
    "err_digits_only": {"he": "סיסמת הספרות יכולה להכיל ספרות בלבד.", "en": "The digits password may contain digits only."},
    "err_mismatch": {"he": "האימות אינו תואם לסיסמה.", "en": "The confirmation does not match."},
    "err_user_exists": {"he": "שם המשתמש כבר קיים.", "en": "This username already exists."},
    "err_bad_credentials": {"he": "פרטי הכניסה שגויים.", "en": "Wrong credentials."},
    "err_wait": {"he": "יותר מדי ניסיונות כושלים. נסה שוב בעוד {seconds} שניות.",
                 "en": "Too many failed attempts. Try again in {seconds} seconds."},
    "err_empty_username": {"he": "יש להזין שם משתמש.", "en": "Please enter a username."},
    "err_totp": {"he": "קוד האימות שגוי.", "en": "Wrong authenticator code."},
    "totp_setup_title": {"he": "הגדרת אימות דו-שלבי", "en": "Two-factor setup"},
    "totp_setup_info": {
        "he": "סרוק את הקוד באפליקציית אימות (Google Authenticator / Microsoft Authenticator)\n"
              "והזן את הקוד בן 6 הספרות כדי לסיים. שמור את המפתח הטקסטואלי במקום בטוח.",
        "en": "Scan the code with an authenticator app (Google Authenticator / Microsoft Authenticator)\n"
              "and enter the 6-digit code to finish. Keep the text key somewhere safe.",
    },
    "totp_secret_label": {"he": "מפתח גיבוי:", "en": "Backup key:"},

    # ------------------------------------------------------------- re-auth
    "reauth_title": {"he": "אימות מחדש נדרש", "en": "Re-authentication required"},
    "reauth_info": {"he": "העברת קבצים דורשת את שתי הסיסמאות ואת קוד האימות.",
                    "en": "File transfers require both passwords and the authenticator code."},

    # ------------------------------------------------------------- toolbar
    "back": {"he": "אחורה", "en": "Back"},
    "forward": {"he": "קדימה", "en": "Forward"},
    "reload": {"he": "רענון", "en": "Reload"},
    "home": {"he": "דף הבית", "en": "Home"},
    "address_placeholder": {"he": "הקלד כתובת, כתובת ‎.onion או חיפוש ולחץ Enter",
                            "en": "Type an address, a .onion address or a search and press Enter"},
    "rotate_now": {"he": "החלף מדינה עכשיו", "en": "Change country now"},
    "country_random": {"he": "🎲 מדינה אקראית", "en": "🎲 Random country"},
    "country_tip": {"he": "בחר מדינת יציאה. ללא פעולה – הדפדפן מחליף לבד כל 10 דקות.",
                    "en": "Choose an exit country. Without action the browser switches by itself every 10 minutes."},
    "lock_country": {"he": "🔒 נעל מדינה", "en": "🔒 Lock country"},
    "lock_country_tip": {"he": "ההחלפה האוטומטית תחליף IP אבל תישאר באותה מדינה.",
                         "en": "Automatic rotation changes the IP but stays in the same country."},
    "ks_protected": {"he": "🛡️ KILL-SWITCH: מוגן", "en": "🛡️ KILL-SWITCH: PROTECTED"},
    "ks_blocked": {"he": "⛔ KILL-SWITCH: גלישה חסומה", "en": "⛔ KILL-SWITCH: BROWSING BLOCKED"},
    "ks_checking": {"he": "⏳ KILL-SWITCH: בודק את Tor…", "en": "⏳ KILL-SWITCH: checking Tor…"},
    "ks_tip": {
        "he": "מתג ההשבתה פעיל תמיד: אם Tor לא מחובר, אף בקשה לא יוצאת מהמחשב.",
        "en": "The kill-switch is always on: if Tor is not connected, no request leaves this computer.",
    },
    "ks_blocked_title": {"he": "⛔ הגלישה נחסמה – אין חיבור ל-Tor", "en": "⛔ Browsing blocked – no Tor connection"},
    "ks_blocked_body": {
        "he": "כדי להגן על הזהות שלך, הדפדפן לא שולח אף בקשה כש-Tor לא זמין.\n"
              "ודא ששירות Tor פועל (פורט 9050) וחכה כמה שניות. פרטים: {detail}",
        "en": "To protect your identity the browser sends nothing while Tor is unavailable.\n"
              "Make sure the Tor service is running (port 9050) and wait a few seconds. Details: {detail}",
    },
    "ks_retry": {"he": "בדוק שוב", "en": "Check again"},
    "vault_btn": {"he": "📁 כספת קבצים", "en": "📁 File vault"},
    "translate_btn": {"he": "🌐 תרגם", "en": "🌐 Translate"},
    "panic_btn": {"he": "🚨 פאניקה", "en": "🚨 Panic"},
    "panic_tip": {"he": "מחיקה מיידית של הכל ונעילה (Ctrl+Shift+X)", "en": "Wipe everything and lock now (Ctrl+Shift+X)"},
    "logout_btn": {"he": "🔒 נעל", "en": "🔒 Lock"},
    "menu_btn": {"he": "⚙ הגדרות", "en": "⚙ Settings"},

    # ---------------------------------------------------------------- menu
    "menu_ui_lang": {"he": "שפת הממשק", "en": "Interface language"},
    "menu_site_lang": {"he": "השפה שאתרים רואים", "en": "Language websites see"},
    "site_lang_en": {"he": "אנגלית (מומלץ – הכי פחות מזהה)", "en": "English (recommended – least identifying)"},
    "site_lang_he": {"he": "עברית", "en": "Hebrew"},
    "menu_security": {"he": "רמת אבטחה", "en": "Security level"},
    "sec_standard": {"he": "רגיל", "en": "Standard"},
    "sec_safer": {"he": "בטוח יותר (ללא WebGL, ללא חלונות קופצים)", "en": "Safer (no WebGL, no pop-ups)"},
    "sec_safest": {"he": "מקסימלי (JavaScript כבוי)", "en": "Safest (JavaScript off)"},
    "menu_translate_engine": {"he": "מנוע תרגום", "en": "Translation engine"},
    "engine_argos": {"he": "Argos – מקומי, פרטי (מומלץ)", "en": "Argos – offline, private (recommended)"},
    "engine_google": {"he": "Google דרך Tor – מקוון", "en": "Google via Tor – online"},
    "menu_translate_mode": {"he": "תרגום אוטומטי", "en": "Automatic translation"},
    "tmode_off": {"he": "כבוי", "en": "Off"},
    "tmode_ask": {"he": "הצע לתרגם", "en": "Offer to translate"},
    "tmode_always": {"he": "תרגם תמיד", "en": "Always translate"},
    "menu_install_models": {"he": "הורד מודלי תרגום (עברית↔אנגלית)", "en": "Download translation models (Hebrew↔English)"},
    "menu_drive_link": {"he": "חבר Google Drive לכספת", "en": "Link Google Drive vault"},
    "menu_drive_unlink": {"he": "נתק את Google Drive", "en": "Unlink Google Drive"},
    "menu_bookmarks": {"he": "סימניות", "en": "Bookmarks"},
    "bm_add": {"he": "➕ הוסף את הדף הנוכחי", "en": "➕ Bookmark this page"},
    "bm_empty": {"he": "(אין סימניות)", "en": "(no bookmarks)"},
    "bm_guest": {"he": "סימניות זמינות רק למשתמש מחובר", "en": "Bookmarks require a user account"},
    "menu_about": {"he": "אודות", "en": "About"},
    "about_text": {
        "he": "Cyber Browser – כל התעבורה עוברת דרך Tor (SOCKS5 127.0.0.1:9050).\n"
              "החלפת מדינה אוטומטית כל 10 דקות, מחיקת עוגיות ו-cache בכל החלפה,\n"
              "חסימת מצלמה/מיקרופון/שיתוף מסך, הסתרת החלון מצילומי מסך (Windows),\n"
              "כספת קבצים מוצפנת ב-Google Drive ונעילה אוטומטית אחרי 5 דקות.",
        "en": "Cyber Browser – all traffic goes through Tor (SOCKS5 127.0.0.1:9050).\n"
              "Automatic country change every 10 minutes, cookies and cache wiped on every change,\n"
              "camera/microphone/screen-sharing blocked, window hidden from screenshots (Windows),\n"
              "encrypted Google Drive file vault and auto-lock after 5 minutes.",
    },

    # -------------------------------------------------------------- status
    "st_ip": {"he": "🌐 IP: {ip}", "en": "🌐 IP: {ip}"},
    "st_country": {"he": "📍 {country}", "en": "📍 {country}"},
    "st_ip_unknown": {"he": "🌐 IP: לא ידוע", "en": "🌐 IP: unknown"},
    "st_fetching_ip": {"he": "🌐 בודק IP…", "en": "🌐 Checking IP…"},
    "st_tor_ok": {"he": "🧅 Tor: מחובר", "en": "🧅 Tor: connected"},
    "st_tor_no_control": {"he": "🧅 Tor: מחובר (ללא ControlPort – אין החלפת מדינה)",
                          "en": "🧅 Tor: connected (no ControlPort – no country switching)"},
    "st_tor_down": {"he": "🧅 Tor: מנותק", "en": "🧅 Tor: disconnected"},
    "st_next_rotation": {"he": "🔄 החלפה בעוד {time}", "en": "🔄 Next change in {time}"},
    "st_idle": {"he": "⏱ נעילה בעוד {time}", "en": "⏱ Locks in {time}"},
    "st_mode_guest": {"he": "👤 אורח", "en": "👤 Guest"},
    "st_mode_user": {"he": "👤 {name}", "en": "👤 {name}"},
    "st_rotating": {"he": "🔄 מחליף מדינה ומנקה עוגיות ו-cache…", "en": "🔄 Changing country and wiping cookies & cache…"},
    "st_rotated": {"he": "✅ זהות חדשה – עוגיות ו-cache נמחקו", "en": "✅ New identity – cookies & cache wiped"},
    "st_rotate_failed": {"he": "❌ החלפת המדינה נכשלה: {error}", "en": "❌ Country change failed: {error}"},
    "st_country_list_failed": {"he": "לא ניתן לטעון את רשימת המדינות מ-Tor", "en": "Could not load the country list from Tor"},

    # --------------------------------------------------------------- bars
    "insecure_text": {"he": "⚠️ האתר {host} אינו מוצפן (http). חסמנו אותו כדי למנוע ציתות בצומת היציאה.",
                      "en": "⚠️ {host} is not encrypted (http). It was blocked to prevent exit-node snooping."},
    "onion_retry": {"he": "נסה שוב", "en": "Retry"},
    "onion_checking": {"he": "🧅 האתר {host} לא נטען – בודק מול Tor מה הסיבה…", "en": "🧅 {host} did not load – asking Tor why…"},
    "onion_now_ok": {"he": "🧅 Tor מצליח להגיע לאתר עכשיו – לחץ \"נסה שוב\". (אתרי onion איטיים בחיבור הראשון.)",
                     "en": "🧅 Tor can reach the site now – press \"Retry\". (.onion sites are slow on the first connection.)"},
    "onion_err_general": {"he": "🧅 Tor לא הצליח להתחבר לאתר ה-onion.", "en": "🧅 Tor could not connect to the .onion site."},
    "onion_err_unreachable": {"he": "🧅 האתר לא זמין כרגע (Tor לא הגיע אליו). ייתכן שהוא כבוי.", "en": "🧅 The site is unreachable right now (it may be offline)."},
    "onion_err_refused": {"he": "🧅 אתר ה-onion דחה את החיבור (השירות פועל אבל לא בפורט הזה).", "en": "🧅 The .onion site refused the connection (wrong port?)."},
    "onion_err_timeout": {"he": "🧅 תם הזמן להתחברות לאתר. נסה שוב בעוד רגע.", "en": "🧅 The connection timed out. Try again in a moment."},
    "onion_err_not_found": {"he": "🧅 האתר לא נמצא ברשת Tor: הוא כבוי, נסגר, או שהכתובת שגויה.", "en": "🧅 Site not found on the Tor network: it is offline, gone, or the address is wrong."},
    "onion_err_bad_descriptor": {"he": "🧅 המידע שהאתר פרסם ב-Tor פגום.", "en": "🧅 The site published an invalid descriptor."},
    "onion_err_intro_failed": {"he": "🧅 האתר קיים אבל לא ענה (כשל בשלב ההיכרות). נסה שוב.", "en": "🧅 The site exists but did not answer (introduction failed). Try again."},
    "onion_err_rendezvous_failed": {"he": "🧅 האתר קיים אבל החיבור אליו נכשל (rendezvous). נסה שוב.", "en": "🧅 The site exists but the connection failed (rendezvous). Try again."},
    "onion_err_auth_missing": {"he": "🧅 האתר פרטי ודורש מפתח הרשאה (client authorization).", "en": "🧅 This is a private site that needs a client-authorization key."},
    "onion_err_auth_wrong": {"he": "🧅 מפתח ההרשאה לאתר הפרטי שגוי.", "en": "🧅 The client-authorization key for this private site is wrong."},
    "onion_err_bad_address": {"he": "🧅 כתובת ה-onion לא תקינה. כתובת חוקית היא 56 תווים לפני .onion (כתובות ישנות בנות 16 תווים כבר לא עובדות).",
                              "en": "🧅 Invalid .onion address. Valid addresses have 56 characters before .onion (old 16-character addresses no longer work)."},
    "onion_err_intro_timeout": {"he": "🧅 האתר לא ענה בזמן. ייתכן שהוא עמוס או כבוי. נסה שוב.", "en": "🧅 The site did not answer in time (busy or offline). Try again."},
    "insecure_continue": {"he": "המשך בכל זאת (לסשן הזה)", "en": "Continue anyway (this session)"},
    "blocked_scheme": {"he": "⛔ סוג הכתובת {scheme}: חסום בדפדפן הזה.", "en": "⛔ {scheme}: addresses are blocked in this browser."},
    "tr_offer": {"he": "הדף בשפה: {lang}. לתרגם ל{target}?", "en": "This page is in {lang}. Translate to {target}?"},
    "tr_do": {"he": "תרגם", "en": "Translate"},
    "tr_original": {"he": "הצג מקור", "en": "Show original"},
    "tr_running": {"he": "🌐 מתרגם {total} קטעי טקסט…", "en": "🌐 Translating {total} text blocks…"},
    "tr_done": {"he": "🌐 הדף תורגם", "en": "🌐 Page translated"},
    "tr_failed": {"he": "❌ התרגום נכשל: {error}", "en": "❌ Translation failed: {error}"},
    "tr_no_model": {"he": "אין מודל תרגום מקומי עבור {src}→{dst}. הורד מודלים מתפריט ההגדרות או עבור ל-Google.",
                    "en": "No offline model for {src}→{dst}. Download models from Settings or switch to Google."},
    "tr_google_blocked": {"he": "Google חסמה את הבקשה מכתובת ה-IP הזו (429/CAPTCHA). החלף מדינה ונסה שוב, או עבור למנוע Argos המקומי.",
                          "en": "Google blocked the request from this IP (429/CAPTCHA). Change country and retry, or switch to the offline Argos engine."},
    "tr_same_lang": {"he": "הדף כבר בשפת הממשק.", "en": "The page is already in the interface language."},
    "models_installing": {"he": "מוריד מודלי תרגום דרך Tor… (עשוי לקחת כמה דקות)",
                          "en": "Downloading translation models through Tor… (may take a few minutes)"},
    "models_installed": {"he": "✅ מודלי התרגום הותקנו: {pairs}", "en": "✅ Translation models installed: {pairs}"},
    "models_failed": {"he": "❌ הורדת המודלים נכשלה: {error}", "en": "❌ Model download failed: {error}"},
    "models_need_argos": {"he": "יש להתקין קודם: pip install argostranslate", "en": "Install first: pip install argostranslate"},

    # ---------------------------------------------------------- transfers
    "dl_blocked_title": {"he": "העברת קבצים חסומה", "en": "File transfer blocked"},
    "dl_blocked_guest": {
        "he": "במצב אורח אי אפשר להוריד או להעלות קבצים.\nהיכנס כמשתמש וחבר את Google Drive כדי להשתמש בכספת המוצפנת.",
        "en": "Guests cannot download or upload files.\nSign in as a user and link Google Drive to use the encrypted vault.",
    },
    "dl_no_drive": {"he": "הקבצים עוברים רק דרך כספת Google Drive. חבר את Drive מתפריט ההגדרות.",
                    "en": "Files only move through the Google Drive vault. Link Drive from the Settings menu."},
    "dl_saving": {"he": "⬆️ מצפין ושומר בכספת: {name}", "en": "⬆️ Encrypting and saving to vault: {name}"},
    "dl_saved": {"he": "✅ נשמר בכספת: {name}", "en": "✅ Saved to vault: {name}"},
    "dl_failed": {"he": "❌ השמירה בכספת נכשלה: {error}", "en": "❌ Saving to the vault failed: {error}"},
    "dl_too_big": {"he": "הקובץ גדול מ-{mb}MB ולא נשמר.", "en": "The file is larger than {mb}MB and was not saved."},
    "dl_page_blocked": {"he": "שמירת דפים חסומה.", "en": "Saving pages is blocked."},
    "up_preparing": {"he": "מפענח קבצים מהכספת…", "en": "Decrypting files from the vault…"},

    # ------------------------------------------------------------ vault UI
    "vault_title": {"he": "כספת קבצים מוצפנת (Google Drive)", "en": "Encrypted file vault (Google Drive)"},
    "vault_picker_title": {"he": "בחר קבצים מהכספת להעלאה לאתר", "en": "Choose vault files to upload to the site"},
    "col_name": {"he": "שם", "en": "Name"},
    "col_size": {"he": "גודל", "en": "Size"},
    "col_date": {"he": "תאריך", "en": "Date"},
    "vault_refresh": {"he": "🔄 רענן", "en": "🔄 Refresh"},
    "vault_import": {"he": "⬆️ הכנס קובץ מהמחשב", "en": "⬆️ Import from computer"},
    "vault_export": {"he": "⬇️ הוצא קובץ למחשב", "en": "⬇️ Export to computer"},
    "vault_delete": {"he": "🗑 מחק", "en": "🗑 Delete"},
    "vault_select": {"he": "העלה לאתר", "en": "Upload to site"},
    "vault_loading": {"he": "טוען…", "en": "Loading…"},
    "vault_ready": {"he": "{count} קבצים בכספת. התוכן מוצפן – Google רואה רק מידע מוצפן.",
                    "en": "{count} files in the vault. Content is encrypted – Google only sees ciphertext."},
    "vault_confirm_delete": {"he": "למחוק לצמיתות את {name}?", "en": "Permanently delete {name}?"},
    "vault_need_user": {"he": "הכספת זמינה רק למשתמש מחובר.", "en": "The vault is only available to signed-in users."},
    "vault_error": {"he": "❌ שגיאה: {error}", "en": "❌ Error: {error}"},
    "drive_no_credentials": {
        "he": "לא נמצא קובץ OAuth של Google.\nהורד את credentials.json מ-Google Cloud Console ושמור אותו כאן:\n{path}",
        "en": "Google OAuth client file not found.\nDownload credentials.json from the Google Cloud Console and save it here:\n{path}",
    },
    "drive_linking": {
        "he": "דפדפן המערכת ייפתח לאישור הגישה ל-Google Drive.\n"
              "שים לב: שלב ההתחברות הזה בלבד עובר מחוץ ל-Tor (Google חוסמת התחברות מ-Tor).",
        "en": "Your system browser will open to approve Google Drive access.\n"
              "Note: this sign-in step alone happens outside Tor (Google blocks sign-ins from Tor).",
    },
    "drive_linked": {"he": "✅ Google Drive חובר לכספת.", "en": "✅ Google Drive linked to the vault."},
    "drive_link_failed": {"he": "❌ חיבור Drive נכשל: {error}", "en": "❌ Linking Drive failed: {error}"},
    "drive_unlinked": {"he": "Google Drive נותק.", "en": "Google Drive unlinked."},
}

_lang = "en"
_listeners: list[Callable[[str], None]] = []


def set_language(lang: str) -> None:
    global _lang
    _lang = lang if lang in SUPPORTED else "en"
    for listener in list(_listeners):
        listener(_lang)


def language() -> str:
    return _lang


def on_language_changed(callback: Callable[[str], None]) -> None:
    _listeners.append(callback)


def remove_listener(callback: Callable[[str], None]) -> None:
    if callback in _listeners:
        _listeners.remove(callback)


def system_language() -> str:
    """Hebrew if the OS is set to Hebrew, otherwise English."""
    from PyQt6.QtCore import QLocale

    name = QLocale.system().name().lower()   # e.g. "he_il", "en_us"
    return "he" if name.startswith(("he", "iw")) else "en"


def tr(key: str, **kwargs: object) -> str:
    entry = STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(_lang) or entry["en"]
    return text.format(**kwargs) if kwargs else text


_LANGUAGE_NAMES_HE = {
    "en": "אנגלית", "he": "עברית", "ar": "ערבית", "ru": "רוסית", "fr": "צרפתית", "de": "גרמנית",
    "es": "ספרדית", "it": "איטלקית", "pt": "פורטוגזית", "zh": "סינית", "ja": "יפנית", "ko": "קוריאנית",
    "tr": "טורקית", "nl": "הולנדית", "pl": "פולנית", "uk": "אוקראינית", "fa": "פרסית", "hi": "הינדי",
    "el": "יוונית", "sv": "שוודית", "ro": "רומנית", "hu": "הונגרית", "cs": "צ'כית", "am": "אמהרית",
}


def language_name(code: str) -> str:
    """Name of a page language in the current UI language (e.g. "en" -> "אנגלית" / "English")."""
    if _lang == "he" and code in _LANGUAGE_NAMES_HE:
        return _LANGUAGE_NAMES_HE[code]
    from PyQt6.QtCore import QLocale

    name = QLocale.languageToString(QLocale(code).language())
    return name if name and name != "C" else code


def is_rtl() -> bool:
    return _lang == "he"
