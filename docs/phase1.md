# Phase 1 — Threat Intelligence Source

## משימה 1.1 — בחירת Feed ראשון

**Feed נבחר:** [FortiGuard PSIRT](https://www.fortiguard.com/psirt) (Fortinet Product Security Incident Response Team)

**סוג IOC:** לא IOC קלאסי (IP/URL/hash) — זהו feed של **מודיעין פגיעויות (vulnerability intel)**: advisories על CVE-ים ופגיעויות שנפתרו במוצרי Fortinet. כל רשומה כוללת:
- מזהה advisory (`FG-IR-YY-NNN`)
- כותרת/תיאור הפגיעות
- CVSSv3 Score
- קישור ל-advisory המלא (`https://fortiguard.fortinet.com/psirt/FG-IR-...`)
- תאריך פרסום/עדכון

**גישה / פורמטים זמינים:**
| פורמט | URL | הערות |
|---|---|---|
| RSS/XML (PSIRT Advisories) | `https://filestore.fortinet.com/fortiguard/rss/ir.xml` | **הפיד שנבחר** — ללא API key, מתעדכן שוטף |
| דף HTML (רשימה + פילטרים) | `https://www.fortiguard.com/psirt` | דורש User-Agent של דפדפן — curl עם UA ברירת מחדל נחסם ע"י ה-WAF שלהם עצמו (הוחזר 500 "Web Page Blocked") |
| דף advisory בודד | `https://fortiguard.fortinet.com/psirt/FG-IR-YY-NNN` | HTML פר-advisory, לא feed |

**API key:** לא נדרש לפיד ה-RSS.

**הערה טכנית חשובה:** גישה עם `curl` ללא `-A` (User-Agent) לדף ה-HTML `fortiguard.com/psirt` נחסמת ע"י ה-Web Filter של Fortinet עצמם (החזירו HTTP 500 עם עמוד "Web Page Blocked"). הפתרון היה להשתמש ב-RSS feed הרשמי (`ir.xml`) שנמצא תחת `fortiguard.com/rss-feeds`, שם אין את הבעיה הזו.

## משימה 1.2 — הורדה ידנית

זרימה: `Feed (ir.xml) → curl → Raw Data`

```bash
curl -s -o data/raw/fortiguard_psirt.xml "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
```

תוצאה: HTTP 200, קובץ XML תקין (~36KB) עם עשרות advisories, כולל כותרת, CVSS score, ותיאור לכל אחד.

קובצי raw נשמרים תחת `data/raw/`:
- `fortiguard_psirt.xml` — הפיד הנבחר לשלב 1

## המרה לפורמט MISP Custom Feed

הסקריפט [`scripts/xml_to_misp_feed.py`](../scripts/xml_to_misp_feed.py) ממיר את ה-XML הגולמי לפורמט [MISP Feed](https://www.misp-project.org/feeds/) תקני:

```bash
python scripts/xml_to_misp_feed.py
```

פלט: `data/misp_feed/`
- `manifest.json` — מיפוי `event-uuid → מטא-דאטה` (info, date, threat_level_id, analysis, tags) לכל 50 ה-advisories
- `<event-uuid>.json` — אירוע MISP מלא (`{"Event": {...}}`) לכל advisory, עם:
  - **Attribute** מסוג `link` (קישור ל-advisory), `text` (תיאור), `float` (CVSSv3 score), ו-`vulnerability` (CVE, אם צוין ב-advisory)
  - **Tag**: `source:fortiguard-psirt`, `fortiguard:advisory="FG-IR-YY-NNN"`, `cvss-score:"X.X"`
  - `threat_level_id` נגזר מ-CVSS (≥9 → High, ≥7 → Medium, אחרת Low)

**איך מוסיפים את זה כ-Feed ב-MISP:**
1. להגיש את `data/misp_feed/` דרך שרת HTTP (סטטי) — לדוגמה `python -m http.server` בתוך התיקייה.
2. ב-MISP: `Sync Actions → Feeds → Add Feed`, לבחור `Source format: MISP Feed`, ולהצביע ל-URL של השרת (או לנתיב local אם ה-Feed מוגדר כ-`Local` ולא `Network`).
3. `Fetch and store all feed data` / `Cache all feed metadata` כדי לייבא את ה-events.

UUID-ים נגזרים דטרמיניסטית (`uuid5` על ה-`guid`), כך שהרצה חוזרת של הסקריפט מייצרת אותם UUID-ים ולא כפילויות.
