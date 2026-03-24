# ⬡ PoWS — Proof-of-Web-State AKA(Themis)

**Independent website fingerprinting and certification using Firefox (Gecko engine)**

A PoC validator system that proves what a website delivered and rendered — independently, across 3 validators — achieving cryptographic consensus.

---

## 🏗 Architecture

```
┌────────────────────────────────────────────────────────────┐
│                           CLIENT                           │
│                    Dashboard  :3000                        │
└───────────────────────┬────────────────────────────────────┘
                        │ HTTP
            ┌───────────▼────────────┐
            │    COORDINATOR :8000   │
            │  2-of-3 Consensus      │
            └────┬────────┬────────┬─┘
                 │        │        │
        ┌────────▼─┐ ┌────▼────┐ ┌▼────────┐
        │Validator1│ │Valid. 2 │ │Valid. 3 │
        │  :9001   │ │  :9002  │ │  :9003  │
        │ Firefox  │ │ Firefox │ │ Firefox │
        │  Gecko   │ │  Gecko  │ │  Gecko  │
        └──────────┘ └─────────┘ └─────────┘
                 All use Playwright + Firefox
```

### What Each Validator Captures

| Signal | Method |
|--------|--------|
| DNS IP | `socket.gethostbyname()` |
| TLS fingerprint | `ssl` cert DER → SHA256 |
| HTTP status | Playwright response |
| DOM hash | `outerHTML` → normalize → SHA256 |
| Layout hash | `getBoundingClientRect()` + `getComputedStyle()` → SHA256 |
| Screenshot hash | PNG perceptual hash |
| Resource Merkle root | SHA256 of all JS/CSS/HTML → Merkle tree |
| Final fingerprint | SHA256(dom + layout + tls + merkle) |

### Consensus

3 validators run independently. Coordinator checks:
- `2-of-3` identical fingerprints → **✅ CERTIFIED**
- Disagreement → **🚨 MISMATCH DETECTED** with diff

---

## 🚀 Quick Start

### Option A — Docker Compose (recommended, only CLI)

```bash
docker compose up --build
```

Then open:
- **Dashboard**: http://localhost:3000
- **Coordinator API**: http://localhost:8000
- **Demo targets**: http://localhost:8080/normal.html and http://localhost:8080/injected.html

### Option B — Local Python (no Docker), Not working  out of the  box,  may need  some  fixes.

```bash
# Install Python deps
pip install playwright requests

# Install Firefox browser
playwright install firefox

# Start demo target server
cd demo_targets && python3 -m http.server 8080 &

# Start coordinator
cd coordinator && python3 coordinator.py &

# Start 3 validators
PORT=9001 VALIDATOR_ID=validator-1 python3 validator/validator.py &
PORT=9002 VALIDATOR_ID=validator-2 python3 validator/validator.py &
PORT=9003 VALIDATOR_ID=validator-3 python3 validator/validator.py &

# Open dashboard
cd dashboard && python3 -m http.server 3000
```

Visit http://localhost:3000

---

## 📡 API Endpoints

### Coordinator

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/validate` | POST | Start validation, returns result |
| `/history` | GET | Last 20 validations |
| `/health` | GET | Health check |

### Example

```bash
curl -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Validator (direct)

```bash
curl -X POST http://localhost:9001/validate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 📁 Project Structure

```
pows/
├── docker-compose.yml
├── demo.py                  # CLI demo script
├── validator/
│   ├── Dockerfile
│   └── validator.py         # Firefox/Gecko fingerprinting engine
├── coordinator/
│   ├── Dockerfile
│   └── coordinator.py       # 2-of-3 consensus logic
├── dashboard/
│   └── index.html           # Full-stack demo dashboard (single file)
└── demo_targets/
    ├── normal.html           # Legitimate banking site
    └── injected.html         # Tampered: CSS injection + phishing form + exfil script
```

---

## 🔐 Fingerprint Components

```
final_fingerprint = SHA256(
  DOM_HASH           // normalized outerHTML
  + LAYOUT_HASH      // bounding rects + computed styles
  + TLS_HASH         // TLS cert DER
  + MERKLE_ROOT      // all JS/CSS/HTML resources
)
```

**DOM Normalization** removes:
- ISO timestamps
- Unix timestamps  
- Random IDs / nonces
- Session tokens in URLs
- Tag order snapshot.

---

## ⛓ Blockchain Notarization

The `evidence_hash` is suitable for submission to any L1.
The dashboard has a mock "Notarize on Sui Testnet" button ( not functional yet).

For real notarization:
```javascript
// Sui Move (simplified)
public entry fun notarize(evidence_hash: vector<u8>, ctx: &mut TxContext) {
    let cert = EvidenceCert { hash: evidence_hash, timestamp: tx_context::epoch(ctx) };
    transfer::share_object(cert);
}
```

---

## 🔮 Scaling Path (Post-PoC)

- [ ] Geographic validator distribution
- [ ] Validator staking / slashing for anti-collusion
- [ ] Real-time streaming results via WebSocket
- [ ] IPFS evidence storage
- [ ] Full Sui/ETH smart contract integration
- [ ] Diff visualization for detected changes
