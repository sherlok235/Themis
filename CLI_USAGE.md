# PoWS — How to Run

There are **two ways** to run PoWS. Use ONE of them, not both.

---

## MODE A — Local Python (recommended for development)

No Docker needed. Runs everything as local Python processes.

### Step 1 — Start all services

```bash
cd pows/
./start.sh
```

Leave this terminal open. You should see all 6 services go green:

```
✓ Dashboard ready on :3000
✓ Demo targets ready on :8080
✓ Validator-1 ready on :9001
✓ Validator-2 ready on :9002
✓ Validator-3 ready on :9003
✓ Coordinator ready on :8000
```

### Step 2 — Open the dashboard

→ http://localhost:3000

Click **"Normal site (Scenario 1)"** or **"Injected site (Scenario 2)"**

### Step 3 — Or use the CLI (second terminal)

```bash
cd pows/

# Validate the normal demo site
python3 demo.py http://localhost:8080/normal.html

# Validate the injected (tampered) demo site
python3 demo.py http://localhost:8080/injected.html

# Validate any external URL
python3 demo.py https://example.com

# Run both demo scenarios automatically
python3 demo.py
```

### Stop everything

```bash
./stop.sh
```

### Check what is running

```bash
./status.sh
```

---

## MODE B — Docker Compose

Runs everything in isolated containers. Useful for deployment.

### Start

```bash
cd pows/

# First time or after code changes — force full rebuild:
docker compose build --no-cache && docker compose up

# Subsequent runs (no code changes):
docker compose up
```

### Open the dashboard

→ http://localhost:3000

### CLI against Docker

```bash
# The coordinator is on localhost:8000 in both modes
python3 demo.py http://localhost:8080/normal.html
```

### Stop

```bash
docker compose down
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `NS_ERROR_UNKNOWN_HOST` | Run `./stop.sh` then `./start.sh` — stale old process running |
| `Cannot reach localhost:8000` | Run `./start.sh` first (Mode A) or `docker compose up` (Mode B) |
| `ModuleNotFoundError` | Make sure you are inside the `pows/` folder |
| Port already in use | `./stop.sh` clears all PoWS ports |
| Docker build fails | Run `docker compose build --no-cache` to skip cached broken layers |
| `./start.sh` crashes immediately | Run `./status.sh` — another instance may already be running |

---

## Ports

| Service | Port |
|---------|------|
| Dashboard UI | 3000 |
| Demo target server | 8080 |
| Coordinator API | 8000 |
| Validator 1 | 9001 |
| Validator 2 | 9002 |
| Validator 3 | 9003 |
