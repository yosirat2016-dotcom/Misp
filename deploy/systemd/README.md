# Automated feed ingestion (Kali / systemd)

GitHub is the single source of truth: pushing a change to
`scripts/sources.csv` on the `main` branch is what changes what gets
ingested. There is no local file-watch - everything runs on a schedule
and always pulls the CSV fresh from GitHub.

Five systemd units:

- **`misp-feeds-http.service`** - long-running. Serves `data/misp_feed/`
  over HTTP on port 8000 so MISP can always reach it. Restarts on failure.
- **`misp-github-sync.service`** - one-shot. Downloads `sources.csv` from
  GitHub, regenerates every source's feed files, then uses the MISP API
  to create (if it doesn't exist yet) and fetch each Feed - no manual
  "Add Feed" / "Fetch and store" clicks needed. This is the expensive
  part - it hits every source, including rate-limited/WAF-protected ones
  like NVD and gov.il.
- **`misp-github-sync.timer`** - fires `misp-github-sync.service`
  unconditionally every 3 days (plus once ~10 minutes after boot), so
  existing sources still pick up new IOCs even if `sources.csv` never
  changes.
- **`misp-csv-watch.service`** - one-shot. Downloads just `sources.csv`
  (a few KB, no rate-limit concern) and compares its hash against the
  last-seen value in `.state/sources_csv.sha256`. If unchanged, exits
  immediately. If changed, triggers `misp-github-sync.service`'s full
  run so a new row gets picked up fast.
- **`misp-csv-watch.timer`** - fires `misp-csv-watch.service` every
  5 minutes. Safe to run this often specifically *because* it only
  downloads the small CSV each time, not the actual feeds - the
  expensive/rate-limited work only happens when something actually
  changed.

## Prerequisites

1. Install the Python dependencies (`pymisp`, `python-dotenv`):
   ```bash
   pip3 install -r requirements.txt
   ```
2. Create `.env` at the repo root from `.env.example` and fill in:
   - `MISP_URL` / `MISP_API_KEY` - a MISP Auth Key (User profile -> Auth Keys)
   - `FEED_SERVE_BASE_URL` - the Docker bridge gateway IP if MISP runs in
     Docker (find it with `ip addr show docker0 | grep "inet "`), since
     `127.0.0.1` inside MISP's container means the container itself, not
     the Kali host running the HTTP server
   - `GITHUB_SOURCES_CSV_URL` - defaults to this repo's raw `sources.csv`
     on `main`; change only if you fork/rename the repo

## Install (on Kali, where the repo is cloned)

1. Edit `WorkingDirectory=` in all `.service`/`.timer` files if your
   clone isn't at `/home/rata/Desktop/Misp`.

2. Copy the units in and reload:
   ```bash
   sudo cp deploy/systemd/misp-feeds-http.service /etc/systemd/system/
   sudo cp deploy/systemd/misp-github-sync.service /etc/systemd/system/
   sudo cp deploy/systemd/misp-github-sync.timer /etc/systemd/system/
   sudo cp deploy/systemd/misp-csv-watch.service /etc/systemd/system/
   sudo cp deploy/systemd/misp-csv-watch.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Enable and start:
   ```bash
   sudo systemctl enable --now misp-feeds-http.service
   sudo systemctl enable --now misp-github-sync.timer
   sudo systemctl enable --now misp-csv-watch.timer
   ```

## Verify

```bash
# HTTP server is up
systemctl status misp-feeds-http.service
curl http://127.0.0.1:8000/

# Timers are scheduled
systemctl list-timers misp-github-sync.timer misp-csv-watch.timer

# Trigger a full sync manually to test everything end to end
sudo systemctl start misp-github-sync.service
journalctl -u misp-github-sync.service -n 80 --no-pager

# Trigger the CSV watcher manually - first run should always report
# "changed" (no prior state) and trigger a full sync; run it again
# immediately after and it should report "unchanged"
sudo systemctl start misp-csv-watch.service
journalctl -u misp-csv-watch.service -n 20 --no-pager
```

A successful manual run should print a per-source summary ending in
something like:
```
=== Summary ===
  ok       cisa-kev      1671 events -> http://172.17.0.1:8000/www-cisa-gov/ (created, fetch triggered (feed id 108))
```

Then check MISP's Event List for the new/updated events.

## Migrating from the old local-watch setup

If you previously installed `misp-feeds-watch.path` / `misp-feeds-run.*`
(the local-CSV-edit trigger), disable and remove those - they've been
replaced by the GitHub-scheduled sync above:
```bash
sudo systemctl disable --now misp-feeds-watch.path misp-feeds-run.timer
sudo rm /etc/systemd/system/misp-feeds-watch.path /etc/systemd/system/misp-feeds-run.service /etc/systemd/system/misp-feeds-run.timer
sudo systemctl daemon-reload
```

## Notes

- `misp-github-sync.service` creates a MISP Feed per source (matched by
  URL, so re-runs are idempotent - it won't create duplicates) and calls
  `fetch_feed()` on it every run, which is the API equivalent of clicking
  "Fetch and store all feed data." This writes real events into MISP -
  there's no dry-run mode for this script, unlike `main.py` in
  `Integration/misp-ti-integration/`.
- One source failing (bad URL, MISP rejects the feed, network hiccup)
  doesn't stop the others - each is isolated and reported in the summary.
- `misp-csv-watch.service` intentionally never touches NVD/gov.il/etc.
  directly - it only ever downloads `sources.csv` itself. The 5-minute
  cadence is safe *because* of that; do not repoint it at anything more
  expensive.
- `.state/sources_csv.sha256` is per-machine and gitignored - deleting it
  (or running on a fresh clone) makes the next `misp-csv-watch` tick
  treat the CSV as "changed" and trigger one full sync, which is expected.
- Logs: `logs/sync_github_to_misp.log` and `logs/csv_watch.log` (both
  appended, not rotated).
