# SirenUA Threat Monitor Server

FastAPI-based threat monitoring server for Ukraine's air raid threats. It parses public Telegram channels (like official Ukrainian Air Force channel) using a web scraper and exposes a REST API for the SirenUA iOS application.

## Features

- **FastAPI API**: Exposes endpoints to retrieve real-time regional threat statuses.
- **Telegram Web Scraper**: Automatically scrapes public web-preview versions of major Telegram channels every 20 seconds. No API credentials or interactive phone logins required!
- **Fallback / Mock Mode**: Contains mock scenarios (e.g., MiG-31K takeoff, massive cruise missile attack, Shahed drone threat) for localized testing and simulation.
- **Docker Support**: Containerized using a slim Python environment.
- **One-click Render Deployment**: Ready to deploy directly to [Render](https://render.com/).

## API Endpoints

- `GET /` — Service status, mode, and scraping connection status.
- `GET /api/threats` — Current threat level (`none`, `low`, `medium`, `high`, `critical`), threat type (`drone`, `missile`, `ballistic`, `aviation`, `artillery`), and details for all regions of Ukraine.
- `POST /api/threats/mock` — Manually set threat for testing (Mock mode only).
- `POST /api/threats/scenario` — Launch simulation scenarios (`mig_takeoff`, `shaheds_south`, `cruise_missiles_west`, `massive_attack`, `ballistic_kharkiv`, `clear`).
- `POST /api/threats/clear` — Clear all threat levels.

## Docker Setup

Build the image:
```bash
docker build -t sirenua-threat-monitor .
```

Run the container:
```bash
docker run -p 8085:8085 -e LIVE_MODE=true sirenua-threat-monitor
```

## Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the server in mock/scenario mode:
   ```bash
   python server.py
   ```

3. Start the server in live Telegram monitoring mode:
   ```bash
   python server.py --live
   # OR set environment variable LIVE_MODE=true
   ```
