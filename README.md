---
title: Smart Energy Monitor
emoji: ⚡
colorFrom: green
colorTo: yellow
sdk: docker
app_port: 5000
pinned: false
---

# Smart Energy Monitor

A Flask + Flask-SocketIO web application that monitors 20 simulated smart
meters in a home. It generates live readings, detects threshold violations
(over-voltage, under-voltage, over-current, high power, temperature, device
offline), flags power anomalies with a rolling z-score, sends optional email
alerts, and produces daily/weekly/monthly energy & cost reports with CSV export.

## Architecture

The device simulator (`simulator.py`) generates realistic readings and sends
each one as JSON over HTTP to the backend's `/api/reading` endpoint. The
backend stores the reading, runs the alert engine and anomaly detection,
broadcasts new readings/alerts to all dashboard clients over WebSocket, and a
backend monitor thread flags devices that stop reporting. By default the
simulator runs embedded inside `app.py`; to run it as a separate process, set
`EMBEDDED_SIMULATOR=0` on the server and start `python simulator.py`.

## Features

- Live dashboard with WebSocket updates (readings + alerts stream in real time)
- 20 virtual smart meters with realistic load profiles and occasional spikes
- Configurable alert thresholds (global defaults + per-device overrides)
- ML-style anomaly detection (rolling z-score over each device's power history)
- Energy / cost reports bucketed daily, weekly, monthly + CSV export
- Device usage ranking, trends, and an interactive floor map
- User accounts with password hashing and brute-force login lockout

## Run locally

```bash
pip install -r requirements.txt
python app.py                 # -> http://localhost:5000
# or with Docker
docker compose up --build
```

Run the simulator as a separate process (optional):

```bash
EMBEDDED_SIMULATOR=0 python app.py   # backend, no built-in simulator
python simulator.py                  # standalone simulator process
```

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | `change-me-in-production` | Session signing key |
| `ENERGY_RATE` | `0.80` | Price per kWh (Ghana Cedis) |
| `CURRENCY_SYMBOL` | `GH₵` | Currency display |
| `SIM_INTERVAL` | `3` | Seconds between simulated readings |
| `RETENTION_DAYS` | `30` | Reading retention window |
| `SMTP_HOST/USER/PASSWORD` | (empty) | SMTP server for email alerts |
| `PORT` | `5000` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `SIMULATOR_SERVER_URL` | `http://127.0.0.1:5000` | Backend URL the simulator POSTs readings to |
| `EMBEDDED_SIMULATOR` | `1` | `1` = run simulator in-process, `0` = use `simulator.py` |

## Tests

```bash
python -m pytest test_app.py
```
