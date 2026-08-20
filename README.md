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

## Requirements

`scripts/run_feeds.py` and the individual converters are standard-library
only (`urllib`/`subprocess`, no external deps beyond `curl` on PATH).
`scripts/sync_github_to_misp.py` needs `pymisp` and `python-dotenv` — see
the root [`requirements.txt`](requirements.txt) (`pip install -r
requirements.txt`). `Integration/misp-ti-integration/` has its own,
separate `requirements.txt` (`requests`, `pymisp`, `pytest`).
