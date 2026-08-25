# MISP Threat Intel Feed Ingestion

Pulls indicators and advisories from public CTI sources and converts them
into [MISP Feed](https://www.misp-project.org/feeds/) JSON, ready to be
served over HTTP and imported into MISP.

## Quick start

```bash
python scripts/feed_to_misp.py "<url>" --org "SomeName"
```

Fetches a single URL, auto-detects its format, and writes MISP events to
`data/misp_feed/<slug>/`. This is the standalone, one-off way to convert
any RSS/JSON/CSV/text feed.

For the CSV-driven scheduled pipeline (multiple sources, auto-registers
Feeds in MISP), see [`scripts/sync_github_to_misp.py`](#importing-into-misp)
below.

## Sources

| name | source | parser |
|---|---|---|
| `cisa-kev` | CISA Known Exploited Vulnerabilities catalog | generic |
| `ipsum-level3` | IPsum malicious IP blocklist | generic |
| `fortiguard-psirt` | Fortinet PSIRT advisories (RSS) | generic |
| `hp-security-bulletins` | HP security bulletins (RSS) | generic |
| `threatfox-abuse-ch` | abuse.ch ThreatFox API | dedicated (`threatfox_to_misp.py`) |

Add a new source that's plain RSS/JSON/CSV/text: just add a row to
`sources.csv` with `parser=generic` — no code change needed. A source
that needs special handling (auth, pagination, a JS-rendered page with
no visible feed) needs a small dedicated script exposing a `convert(...)`
function, registered in `sync_github_to_misp.py`'s `PARSERS` dict. See
`scripts/threatfox_to_misp.py` for an example of that pattern.

NVD and Israel's gov.il CVE advisories were previously supported via
dedicated scripts (`nvd_to_misp.py`, `govil_cve_to_misp.py`) but those
were removed to keep the pipeline to just the generic converter plus
one dedicated example. Re-adding either would mean rebuilding that
dedicated-script logic from scratch — both sources need it: NVD nests
everything under a `cve: {...}` wrapper the generic converter can't
reach, and gov.il is a JS-rendered SPA behind a WAF with no visible feed.

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

**Automated, scheduled:** see [`deploy/systemd/`](deploy/systemd/) — two
timers: a full sync every 3 days regardless (so existing sources keep
picking up new IOCs), plus a lightweight check every 5 minutes that only
downloads `sources.csv` itself and triggers a full sync if it actually
changed — so a new row in the CSV gets picked up fast without re-fetching
every source's actual data on every 5-minute tick. Both paths use the
MISP API to create/fetch each Feed automatically (no manual clicks).
`scripts/sync_github_to_misp.py` (full sync) and
`scripts/check_sources_csv_changed.py` (change detector) are the entry
points.

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
   filter by Org (`CISA`, `Abuse.ch - ThreatFox`, ...) or by tag
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
  feed_to_misp.py          generic RSS/JSON/CSV/text -> MISP feed converter
                           (also the standalone one-off entry point)
  threatfox_to_misp.py     dedicated abuse.ch ThreatFox API converter
  sync_github_to_misp.py   CSV-driven, scheduled entry point: pulls
                           sources.csv from GitHub, dispatches each row to
                           the right converter, syncs into MISP via API
  check_sources_csv_changed.py  cheap poll that triggers sync_github_to_misp.py
                           only when sources.csv actually changed
  sources.csv              source list: name,url,parser

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

- **`threatfox_to_misp.py`** — dedicated converter for abuse.ch's
  ThreatFox. Exists because ThreatFox's `/browse/` page looks like it has
  real data in a browser, but that table is populated client-side
  (DataTables JS) — the raw HTML has none of it, which is why the
  generic converter previously captured literal `<!doctype html>` as
  junk. Uses ThreatFox's real API instead (`POST
  https://threatfox-api.abuse.ch/api/v1/`, `Auth-Key` header — same free
  abuse.ch key as URLhaus), with correct `ioc_type` → MISP attribute
  mapping including the `ip:port` → MISP's composite `ip-dst|port` type.

- **`sync_github_to_misp.py`** — the CSV-driven, scheduled automation
  entry point. Downloads `sources.csv` straight from GitHub (so a `git
  push` to that file is what changes what gets ingested), and for each
  row dispatches to the right converter based on its `parser` column
  (`generic` or `threatfox` — its own small `PARSERS` dict, defined in
  this file). One source failing doesn't stop the others — each is
  isolated, and a summary table prints at the end. It also talks to the
  MISP API directly (via PyMISP's `feeds()`/`add_feed()`/`fetch_feed()`)
  to create a Feed if one doesn't exist yet (matched by URL, so re-runs
  don't create duplicates) or reuse an existing one, and triggers the
  fetch — no manual "Add Feed"/"Fetch and store" clicks needed. This is
  the expensive full run (hits every source); `deploy/systemd/misp-github-sync.timer`
  runs it unconditionally every 3 days.

- **`check_sources_csv_changed.py`** — a cheap, frequent poll. Downloads
  just `sources.csv` (a few KB, no rate-limit concern) and compares its
  hash against the last-seen value in `.state/sources_csv.sha256`. If
  unchanged, exits immediately. If changed, imports and runs
  `sync_github_to_misp.py`'s full sync. This is what lets a new CSV row
  get picked up within minutes without re-fetching every source's actual
  data on every 5-minute tick — `deploy/systemd/misp-csv-watch.timer`
  runs it every 5 minutes.

- **`sources.csv`** — not code, but the config every converter above
  reads: `name,url,parser` per row.

### `deploy/systemd/`

Not Python, but part of the automation: `misp-feeds-http.service` keeps
`data/misp_feed/` served over HTTP continuously; `misp-github-sync.timer`
runs the full sync every 3 days regardless; `misp-csv-watch.timer` checks
every 5 minutes for a CSV change and triggers a full sync only when one's
detected. See that folder's own README for install steps.

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

## Troubleshooting

If MISP shows feeds as "Not cached" or feed data isn't landing as
events, three unrelated issues have come up in practice — the HTTP
server crash-looping on a bad `WorkingDirectory`, scripts run from the
wrong directory writing data to the wrong path, and `sources.csv`
reverting to a junk-producing state — each with diagnose/fix/verify
commands, plus how to pull MISP's real error message out of the
container's log file when the web UI's Jobs/Audit Logs aren't enough.
See [`deploy/systemd/README.md`](deploy/systemd/README.md#troubleshooting)
for the reference guide, or
[`docs/incident-2026-08-24-feed-sync.md`](docs/incident-2026-08-24-feed-sync.md)
for the full incident writeup of the day all three issues were found.

## Requirements

`feed_to_misp.py` and `threatfox_to_misp.py` are standard-library only
(`urllib`, no external deps).
`scripts/sync_github_to_misp.py` needs `pymisp` and `python-dotenv` — see
the root [`requirements.txt`](requirements.txt) (`pip install -r
requirements.txt`). `Integration/misp-ti-integration/` has its own,
separate `requirements.txt` (`requests`, `pymisp`, `pytest`).
