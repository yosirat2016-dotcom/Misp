# Summary: why feed data wasn't reaching MISP, and how it got fixed

Three separate, unrelated bugs were stacked on top of each other. Here's
each one, how we found it, and the exact fix.

## Problem 1: The HTTP server (`misp-feeds-http.service`) wasn't running

**Symptom:** MISP showed `curl error 7 'Could not connect to server': Failed to connect to 172.17.0.1 port 8000`

**Diagnosis:**
```bash
systemctl status misp-feeds-http.service
```
Output showed `Active: activating (auto-restart) ... Process: ... status=200/CHDIR` — the service kept crash-looping because its `WorkingDirectory=` pointed at a path that didn't exist (`/home/rata/Desktop/Misp/...`, missing the `MISP/` folder your actual clone has: `/home/rata/Desktop/MISP/Misp/...`).

**Check that confirmed it:**
```bash
sudo cat /etc/systemd/system/misp-feeds-http.service | grep WorkingDirectory
```

**Fix:** corrected the path in the repo's `deploy/systemd/*.service` files, then on Kali:
```bash
cd /home/rata/Desktop/MISP/Misp
git pull
sudo cp deploy/systemd/misp-feeds-http.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart misp-feeds-http.service
```

**Verification:**
```bash
systemctl status misp-feeds-http.service   # must show "active (running)"
curl http://127.0.0.1:8000/                # must return an HTML directory listing, not a connection error
```

## Problem 2: `sync_github_to_misp.py` was being run from the wrong directory

**Symptom:** after fixing Problem 1, the server was running but serving an **empty** directory — no feed folders at all.

**Diagnosis:**
```bash
ls -la /home/rata/Desktop/MISP/Misp/data/misp_feed/          # empty
ls -la /home/rata/Desktop/MISP/Misp/scripts/data/misp_feed/  # all the real data was here instead
```
The script writes output to the *relative* path `data/misp_feed/`. Running it from inside `scripts/` created `scripts/data/misp_feed/` — a different location than where the HTTP server (and the Feed URLs already configured in MISP) expect it.

**Fix:** always run it from the repo root, not from `scripts/`:
```bash
cd /home/rata/Desktop/MISP/Misp
python3 scripts/sync_github_to_misp.py
```

## Problem 3: `sources.csv` kept getting reverted to a broken state directly on GitHub (happened 4 times)

**Symptom:** sources that were fixed and verified working (`nvd-recent`, `govil-cve-advisories`) kept reverting to `parser=generic`, and 12-13 unresearched placeholder rows kept getting flipped from a safe inert value (`needs-research`) to `generic` — which actually executes them and scrapes junk data (analytics/tracking noise from JS-rendered homepages) into real MISP events.

**Diagnosis:** comparing git history each time:
```bash
git fetch origin
git log origin/main --oneline -5
git show origin/main:scripts/sources.csv
```

**Fix, applied repeatedly:** restore the last known-good version and push:
```bash
git checkout <last-good-commit-hash> -- scripts/sources.csv
git add scripts/sources.csv
git commit -m "..."
git push
```

The two rules that matter going forward:
- `nvd-recent` must use `parser=nvd` (not `generic` — NVD's JSON is too deeply nested, generic produces 0 real attributes)
- `govil-cve-advisories` must use `parser=govil-cve` (not `generic` — gov.il is a JS-rendered page with a WAF, generic can't reach the real data)
- The 12-13 placeholder rows must stay `needs-research` until each one's real API endpoint is individually verified — every one of them was tested and confirmed to produce junk under `generic`

## After the 4th regression actually reached live MISP, manual cleanup was needed

Since Problem 1 and 2 were fixed by the time the CSV broke a 4th time, that regression *did* get fetched into MISP for real:
- Deleted 9 junk Feed entries in MISP (Sync Actions → Feeds) that had been auto-created for the placeholder sources
- Checked **Event List** for any junk events that made it in under those sources' tags/orgs, deleted any found
- Re-ran `sync_github_to_misp.py` after the CSV fix to regenerate correct data for `nvd-recent` and `govil-cve-advisories`, which had gotten corrupted (0 attributes / wrong slug) during that run

## Digging into the actual MISP error message (useful for future debugging)

MISP's Jobs list only shows a generic `"Job failed. See error log for more details"` — the real error isn't in the web UI's Audit Logs or Application Logs. It's inside the container's filesystem:
```bash
docker ps -a                                                              # find the container name
docker exec misp-docker-misp-core-1 tail -n 100 /var/www/MISP/app/tmp/logs/error.log
```
That's what actually revealed the `curl error 7` / `404` messages driving this whole investigation.
