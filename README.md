# MISP Threat Intel Feed Ingestion

Pulls indicators and advisories from public CTI sources and converts them
into [MISP Feed](https://www.misp-project.org/feeds/) JSON, ready to be
served over HTTP and imported into MISP.

## Quick start

```bash
python scripts/run_feeds.py
```

Runs every source listed in [`scripts/sources.csv`](scripts/sources.csv)
and writes MISP events to `data/misp_feed/<source>/`.

Run a subset:

```bash
python scripts/run_feeds.py --only cisa-kev,nvd-recent
```

## Sources

| name | source | parser |
|---|---|---|
| `cisa-kev` | CISA Known Exploited Vulnerabilities catalog | generic |
| `nvd-recent` | NVD CVE API 2.0 (recently published CVEs) | dedicated (`nvd_to_misp.py`) |
| `govil-cve-advisories` | Israel National Cyber Directorate CVE advisories | dedicated (`govil_cve_to_misp.py`) |
| `ipsum-level3` | IPsum malicious IP blocklist | generic |
| `fortiguard-psirt` | Fortinet PSIRT advisories (RSS) | generic |
| `hp-security-bulletins` | HP security bulletins (RSS) | generic |

Add a new source that's plain RSS/JSON/CSV/text: just add a row to
`sources.csv` with `parser=generic` — no code change needed. A source
that needs special handling (auth, pagination, deeply nested JSON, a
JS-rendered page with no visible feed) needs a small dedicated script
exposing a `convert(...)` function, registered in `run_feeds.py`'s
`PARSERS` dict. See `scripts/nvd_to_misp.py` or `scripts/govil_cve_to_misp.py`
for examples of that pattern.

## Importing into MISP

**Manual, one-off:**
1. Serve the output folder over HTTP:
   ```bash
   cd data/misp_feed/<source>
   python -m http.server 8000
   ```
2. In MISP: **Sync Actions → Feeds → Add Feed**, Source format `MISP Feed`,
   URL pointing at that server (the folder itself, not a specific file —
   MISP requests `<url>/manifest.json`).
3. **Fetch and store all feed data** to import.

**Automated, scheduled:** see [`deploy/systemd/`](deploy/systemd/) — a
GitHub-scheduled sync that pulls `sources.csv` from GitHub every 3 days,
regenerates every source, and uses the MISP API to create/fetch each Feed
automatically (no manual clicks). `scripts/sync_github_to_misp.py` is the
entry point.

Now: `scripts/sync_github_to_misp.py` does all of it — pulls
`sources.csv` straight from GitHub, regenerates every source, and talks
to MISP's API directly to create (or reuse) each Feed and trigger the
fetch. Verified end-to-end with mocks: both "feed doesn't exist yet →
create it" and "feed already exists → just re-fetch, no duplicate" paths
work correctly.

MISP Auth Keys are only ever shown in full once, at creation time — if
you've lost one, generate a new one (**Administration → List Auth Keys →
+ Add authentication key**) rather than trying to recover the old value.

### Verifying data actually landed in MISP

A Feed existing doesn't mean its data was imported - check both:

1. **The Feed itself was registered:** **Sync Actions → Feeds** - look for
   it Enabled/Caching-enabled with the right URL (e.g.
   `http://172.17.0.1:8000/www-cisa-gov/`).
2. **The events were actually pulled in:** **Event Actions → List Events**,
   filter by Org (`CISA`, `NVD`, `gov.il-CERT-IL`, ...) or by tag
   (`source:www-cisa-gov`). A registered-but-empty feed usually means
   `fetch_feed()` triggered but the pull itself failed - check
   **Administration → Jobs** on the MISP side.

Quick event-count check from the command line instead of the UI:
```bash
curl -s -H "Authorization: <your MISP_API_KEY>" -H "Accept: application/json" \
  "https://127.0.0.1/events/index" -k | python3 -c "import json,sys; print(len(json.load(sys.stdin)), 'events total')"
```

## Project layout

```
scripts/
  run_feeds.py             CSV-driven dispatcher (manual/local entry point)
  sync_github_to_misp.py   scheduled entry point: pulls sources.csv from
                           GitHub, regenerates feeds, syncs into MISP via API
  sources.csv              source list: name,url,parser
  feed_to_misp.py          generic RSS/JSON/CSV/text -> MISP feed converter
  nvd_to_misp.py           dedicated NVD CVE API converter
  govil_cve_to_misp.py     dedicated gov.il CVE advisories converter

deploy/systemd/
  systemd units for the scheduled sync + the persistent feed HTTP server.
  See its own README for install steps.

Integration/misp-ti-integration/
  A structured collector -> validator -> normalizer pipeline (in progress)
  for API sources needing auth, built around an internal IOC model rather
  than the CSV-feed approach above. See its own README for details.

docs/
  phase1.md                source-selection notes

data/
  raw/                      raw fetched responses (gitignored)
  misp_feed/                generated MISP Feed output (gitignored)
```

## File-by-file guide

### `scripts/`

- **`feed_to_misp.py`** — the generic converter, used for any source that
  doesn't need special handling. Given a URL, it fetches the content,
  auto-detects the format (RSS/XML, JSON, CSV, or plain text), and if the
  URL turns out to be an HTML landing page rather than a real feed, it
  scans the page for RSS `<link>` tags or "download JSON/CSV" links to
  find the actual feed underneath. It then extracts IOCs — flattening
  top-level fields for structured formats, or regex-scanning for
  IPs/domains/URLs/hashes/emails/CVEs in RSS and free text — and writes a
  proper MISP Feed folder (`manifest.json` + one JSON file per event,
  deterministic UUIDs so re-runs don't duplicate). Limits: only flattens
  top-level JSON keys (fails on deeply nested structures like NVD's), and
  can't execute JavaScript (fails on client-rendered SPA pages).

- **`nvd_to_misp.py`** — dedicated converter for the NVD CVE API 2.0.
  Exists because NVD nests everything useful (description, CVSS score,
  references) under a `cve: {...}` wrapper and inside lists, which the
  generic converter can't reach. Paginates through NVD's API for a given
  date range, pulls the best available CVSS score (prefers v3.1, falls
  back to v3.0 then v2), and builds one MISP event per CVE with
  `vulnerability`/`text`/`float`/`weakness`/`link` attributes.

- **`govil_cve_to_misp.py`** — dedicated converter for Israel's National
  Cyber Directorate CVE advisories. Exists because that page is a
  Cloudflare-protected Angular single-page app with no visible feed — the
  real data API (`POST /en/api/DynamicCollector`) and its page-specific
  `DynamicTemplateID` had to be found by reading the page's JS bundle.
  Also works around a WAF that fingerprints and blocks Python's
  `urllib`/`requests` after one call by shelling out to `curl` instead.

- **`run_feeds.py`** — the CSV-driven dispatcher and the main manual entry
  point. Reads `sources.csv`, and for each row calls the right converter
  based on its `parser` column (`generic`, `nvd`, or `govil-cve`). One
  source failing doesn't stop the others — each is isolated, and a
  summary table prints at the end. Supports `--only name1,name2` to run a
  subset.

- **`sync_github_to_misp.py`** — the scheduled automation entry point.
  Downloads `sources.csv` straight from GitHub (so a `git push` to that
  file is what changes what gets ingested), runs every source through
  the same dispatcher logic as `run_feeds.py`, then talks to the MISP API
  directly (via PyMISP's `feeds()`/`add_feed()`/`fetch_feed()`) to
  create a Feed if one doesn't exist yet (matched by URL, so re-runs
  don't create duplicates) or reuse an existing one, and triggers the
  fetch — no manual "Add Feed"/"Fetch and store" clicks needed. This is
  what `deploy/systemd/misp-github-sync.timer` runs every 3 days.

- **`sources.csv`** — not code, but the config every converter above
  reads: `name,url,parser` per row.

### `deploy/systemd/`

Not Python, but part of the automation: `misp-feeds-http.service` keeps
`data/misp_feed/` served over HTTP continuously; `misp-github-sync.timer`
fires `misp-github-sync.service` (which just runs `sync_github_to_misp.py`)
every 3 days. See that folder's own README for install steps.

### `Integration/misp-ti-integration/`

A separate, more structured pipeline (in progress) built around an
internal IOC model, currently wired up for URLhaus specifically rather
than the CSV/multi-source approach above:

- **`models/ioc.py`** — the internal `IOC` dataclass every stage below
  operates on: value, type, source, first/last seen, confidence,
  description, malware, tags, reference.
- **`collectors/base.py`** — the `ThreatIntelCollector` abstract
  interface (just a `fetch()` method) any new source's collector
  implements.
- **`collectors/urlhaus.py`** — queries the URLhaus API for recent
  malicious URLs. Handles auth (`Auth-Key` header), timeouts, and
  distinct errors for 401/429/connection failures.
- **`parsers/urlhaus_parser.py`** — converts URLhaus's raw JSON response
  into a list of `IOC` objects.
- **`validators/ioc_validator.py`** — rejects malformed IOCs (bad IPs,
  invalid hash lengths, broken URLs/domains). Private-IP filtering is a
  config flag, not hardcoded — a private IP isn't inherently malicious or
  inherently noise.
- **`normalizers/ioc_normalizer.py`** — makes equivalent values consistent
  (e.g. `HTTP://Example.COM` and `http://example.com` normalize the
  same) without ever modifying hashes, and without mutating the original
  IOC.
- **`deduplication/deduplicator.py`** — drops repeat IOCs by
  (type, normalized value); first occurrence wins.
- **`misp/event_builder.py`** — maps IOC types to MISP attribute types
  (`ip` → `ip-dst`, `md5`/`sha1`/`sha256`, etc.) and builds a proper MISP
  Event dict from a list of IOCs.
- **`misp/client.py`** — thin PyMISP wrapper: connectivity test and event
  push, with a **dry-run mode that's the default** and never touches the
  network on the write side.
- **`main.py`** — wires the whole chain together: collect → parse →
  validate → normalize → dedup → build event → push. Dry run unless you
  pass `--live` (and even then, refuses to run without `MISP_URL`/
  `MISP_API_KEY` set).
- **`tests/`** — one test file per stage above (38 tests total), all
  using mocked data so they never require a real URLhaus key or MISP
  instance to run.

## Requirements

`scripts/run_feeds.py` and the individual converters are standard-library
only (`urllib`/`subprocess`, no external deps beyond `curl` on PATH).
`scripts/sync_github_to_misp.py` needs `pymisp` and `python-dotenv` — see
the root [`requirements.txt`](requirements.txt) (`pip install -r
requirements.txt`). `Integration/misp-ti-integration/` has its own,
separate `requirements.txt` (`requests`, `pymisp`, `pytest`).
