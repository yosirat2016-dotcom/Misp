# Automated feed ingestion (Kali / systemd)

Two independent triggers, both running `scripts/run_feeds.py`:

- **`misp-feeds-watch.path`** — fires the moment `scripts/sources.csv` is
  modified (e.g. you add a new source row), running all sources.
- **`misp-feeds-run.timer`** — fires every 3 days regardless, so existing
  sources pick up new IOCs even if the CSV never changes.

Both trigger the same **`misp-feeds-run.service`**, which just runs
`python3 scripts/run_feeds.py` and appends output to `logs/run_feeds.log`.

## Install (on Kali, where the repo is cloned)

1. Edit the `WorkingDirectory=` line in `misp-feeds-run.service` if your
   clone isn't at `/home/rata/Desktop/Misp` - update the path to match.

2. Copy the unit files into systemd's directory and reload:
   ```bash
   sudo cp deploy/systemd/misp-feeds-run.service /etc/systemd/system/
   sudo cp deploy/systemd/misp-feeds-watch.path /etc/systemd/system/
   sudo cp deploy/systemd/misp-feeds-run.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Enable and start both triggers:
   ```bash
   sudo systemctl enable --now misp-feeds-watch.path
   sudo systemctl enable --now misp-feeds-run.timer
   ```

## Verify

```bash
# Confirm both triggers are active
systemctl status misp-feeds-watch.path
systemctl status misp-feeds-run.timer

# See when the timer will next fire
systemctl list-timers misp-feeds-run.timer

# Trigger a run manually to test the service itself works
sudo systemctl start misp-feeds-run.service
journalctl -u misp-feeds-run.service -n 50 --no-pager

# Test the file-watch: touch the CSV and watch it fire
touch scripts/sources.csv
journalctl -u misp-feeds-run.service -f
```

## Notes

- This only regenerates the local `data/misp_feed/<source>/` folders.
  MISP still needs to pull from them - either click **Fetch and store all
  feed data** in the MISP UI after each run, or set up MISP's own feed
  auto-fetch (a separate, MISP-side scheduling mechanism, not covered here).
- `misp-feeds-run.service` runs as whatever user owns the systemd service
  invocation (root, if installed as shown). Adjust with a `User=` line in
  the `.service` file if you want it to run as a non-root user instead.
- Logs land in `logs/run_feeds.log` (appended, not rotated - consider
  `logrotate` if this runs for a long time unattended).
