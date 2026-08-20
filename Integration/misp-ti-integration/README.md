# MISP TI Integration

Pulls IOCs from a third-party CTI source, validates/normalizes/dedupes them,
and imports them into MISP as events.

## Status

MVP in progress. Current stage: CTI collector (URLhaus) only — no parsing,
validation, or MISP push yet.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
pip install -r requirements.txt
cp .env.example .env     # fill in CTI_API_KEY (and MISP_URL/MISP_API_KEY later)
```

Get a free URLhaus Auth-Key at https://auth.abuse.ch/.

## Run the collector (manual test)

```bash
python -m collectors.urlhaus
```
