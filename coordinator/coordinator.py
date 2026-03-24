"""
PoWS - Proof-of-Web-State Coordinator Server
Orchestrates 3 Firefox validators and computes consensus.

API docs: http://localhost:8000/docs
OpenAPI:  http://localhost:8000/openapi.json
"""

import json
import os
import sys
import time
import threading
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from consensus import sha256, compute_consensus

VALIDATORS = [
    {"id": "validator-1", "url": os.environ.get("VALIDATOR_1_URL", "http://localhost:9001")},
    {"id": "validator-2", "url": os.environ.get("VALIDATOR_2_URL", "http://localhost:9002")},
    {"id": "validator-3", "url": os.environ.get("VALIDATOR_3_URL", "http://localhost:9003")},
]

CONSENSUS_THRESHOLD = 2
validation_history: list[dict] = []
_lock = threading.Lock()


# ── OpenAPI spec ──────────────────────────────────────────────────────────────

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "PoWS — Proof-of-Web-State API",
        "version": "1.0.0",
        "description": (
            "Independent website fingerprinting and certification using Firefox (Gecko engine). "
            "3 validators independently load a URL, fingerprint the DOM, layout, resources, TLS, "
            "and screenshot. 2-of-3 consensus = CERTIFIED."
        ),
    },
    "servers": [{"url": "http://localhost:8000", "description": "Local coordinator"}],
    "paths": {
        "/health": {
            "get": {
                "summary": "Health check",
                "operationId": "health",
                "tags": ["System"],
                "responses": {"200": {"description": "Coordinator is healthy",
                    "content": {"application/json": {"schema": {"type": "object",
                        "properties": {
                            "status": {"type": "string", "example": "ok"},
                            "validators": {"type": "integer", "example": 3},
                            "mode": {"type": "string", "example": "local"},
                            "uptime_validations": {"type": "integer", "example": 5},
                        }}}}}}
            }
        },
        "/validators": {
            "get": {
                "summary": "List validators and health",
                "operationId": "listValidators",
                "tags": ["System"],
                "responses": {"200": {"description": "Validator list",
                    "content": {"application/json": {"schema": {"type": "object",
                        "properties": {"validators": {"type": "array", "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "url": {"type": "string"},
                                "healthy": {"type": "boolean"},
                            }
                        }}}}}}}}
            }
        },
        "/validate": {
            "post": {
                "summary": "Validate a URL",
                "description": (
                    "Sends URL to all 3 Firefox (Gecko) validators in parallel. "
                    "Each validator loads the page with a real browser and computes: "
                    "DOM hash, layout hash, resource Merkle root, TLS fingerprint, screenshot hash. "
                    "The coordinator checks 2-of-3 consensus and returns the result. "
                    "Takes 20-60 seconds."
                ),
                "operationId": "validate",
                "tags": ["Validation"],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": {"type": "string", "format": "uri",
                                    "example": "https://example.com"},
                            "strict": {"type": "boolean", "default": False,
                                       "description": "Require 3/3 agreement instead of 2/3"}
                        }
                    }}}
                },
                "responses": {
                    "200": {"description": "Validation result",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ValidationResult"}}}},
                    "400": {"description": "Missing or invalid URL"},
                    "408": {"description": "Validation timed out"},
                }
            }
        },
        "/history": {
            "get": {
                "summary": "Last 20 validation results",
                "operationId": "history",
                "tags": ["Validation"],
                "responses": {"200": {"description": "History list",
                    "content": {"application/json": {"schema": {"type": "object",
                        "properties": {"history": {"type": "array",
                            "items": {"$ref": "#/components/schemas/ValidationResult"}}}}}}}}
            }
        },
        "/result/{id}": {
            "get": {
                "summary": "Get validation by ID",
                "operationId": "getResult",
                "tags": ["Validation"],
                "parameters": [{"name": "id", "in": "path", "required": True,
                    "schema": {"type": "string"}, "example": "a3f9b12c4d1e"}],
                "responses": {
                    "200": {"description": "Validation result",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ValidationResult"}}}},
                    "404": {"description": "Not found"},
                }
            }
        },
    },
    "components": {
        "schemas": {
            "ValidatorResult": {
                "type": "object",
                "properties": {
                    "validator_id": {"type": "string", "example": "validator-1"},
                    "url": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "http_status": {"type": "integer", "example": 200},
                    "dns_ip": {"type": "string", "example": "93.184.216.34"},
                    "dom_hash": {"type": "string"},
                    "layout_hash": {"type": "string"},
                    "resource_merkle_root": {"type": "string"},
                    "tls_hash": {"type": "string"},
                    "screenshot_hash": {"type": "string"},
                    "final_fingerprint": {"type": "string"},
                    "resources": {"type": "array", "items": {"type": "object"}},
                    "har_summary": {"type": "object"},
                    "error": {"type": "string", "nullable": True},
                }
            },
            "Consensus": {
                "type": "object",
                "properties": {
                    "certified": {"type": "boolean"},
                    "verdict": {"type": "string", "example": "✅ CERTIFIED"},
                    "dominant_fingerprint": {"type": "string"},
                    "agreement_count": {"type": "integer"},
                    "total_validators": {"type": "integer"},
                    "threshold": {"type": "integer"},
                    "mismatches": {"type": "array", "items": {"type": "object"}},
                    "evidence_hash": {"type": "string",
                        "description": "Submit to blockchain for notarization"},
                }
            },
            "ValidationResult": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "example": "a3f9b12c4d1e"},
                    "url": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "validators": {"type": "array",
                        "items": {"$ref": "#/components/schemas/ValidatorResult"}},
                    "consensus": {"$ref": "#/components/schemas/Consensus"},
                }
            }
        }
    },
    "tags": [
        {"name": "Validation", "description": "Submit URLs for validation"},
        {"name": "System", "description": "Health and system info"},
    ]
}

SWAGGER_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>PoWS API Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
  <style>
    body { margin: 0; background: #050b0f; }
    .swagger-ui .topbar { background: #0a1520; border-bottom: 1px solid #1a3a5c; }
    .swagger-ui .topbar .download-url-wrapper { display: none; }
    .swagger-ui .topbar-wrapper .link::before {
      content: "\u2B21 PoWS API";
      font-family: monospace; font-size: 18px; font-weight: 700;
      color: #00d4ff; letter-spacing: 2px;
    }
    .swagger-ui .topbar-wrapper img { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout",
      deepLinking: true,
      defaultModelsExpandDepth: 2,
      tryItOutEnabled: true,
    });
  </script>
</body>
</html>"""


# ── URL translation ───────────────────────────────────────────────────────────

def is_running_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def translate_url_for_validators(url: str) -> str:
    """
    In Docker mode, rewrite localhost URLs to Docker service name demo-server.
    In local mode (./start.sh), pass through unchanged.
    """
    if not is_running_in_docker():
        return url
    try:
        parsed = urlparse(url)
        if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            translated = url.replace(f"{parsed.hostname}:{port}", f"demo-server:{port}") \
                            .replace(f"{parsed.hostname}/", "demo-server/") \
                            .replace(f"{parsed.hostname}", "demo-server")
            print(f"[coordinator] localhost → demo-server: {url} → {translated}")
            return translated
    except Exception as e:
        print(f"[coordinator] translate error: {e}")
    return url


# ── Validator communication ───────────────────────────────────────────────────

def post_json(url: str, payload: dict, timeout: int = 60) -> Optional[dict]:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def ask_validator(validator: dict, url: str) -> dict:
    print(f"[coordinator] {validator['id']} ← {url}")
    result = post_json(f"{validator['url']}/validate", {"url": url}, timeout=60)
    result["_validator_url"] = validator["url"]
    return result


def check_validator_health(validator: dict) -> bool:
    try:
        req = urllib.request.Request(f"{validator['url']}/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


# ── Core validation ───────────────────────────────────────────────────────────

def run_validation(url: str, job_id: str = None, threshold: int = None,
                   url_b: str = None) -> dict:
    """
    Validate url with all validators.
    If url_b is provided, one randomly chosen validator receives url_b instead
    of url — simulating a tampered/rogue node. Consensus will fail because
    1-of-3 validators saw a different page.
    """
    import random
    url = translate_url_for_validators(url)
    if url_b:
        url_b = translate_url_for_validators(url_b)
    if job_id is None:
        job_id = sha256(url + str(time.time()))[:12]
    if threshold is None:
        threshold = CONSENSUS_THRESHOLD

    # Pick a random validator index to receive url_b
    rogue_idx = random.randint(0, len(VALIDATORS) - 1) if url_b else None
    if rogue_idx is not None:
        print(f"[coordinator] split-test: rogue validator = {VALIDATORS[rogue_idx]['id']}")

    validator_results = [None, None, None]
    threads = []

    def run(idx, validator):
        target = url_b if (url_b and idx == rogue_idx) else url
        validator_results[idx] = ask_validator(validator, target)

    for i, v in enumerate(VALIDATORS):
        t = threading.Thread(target=run, args=(i, v))
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=180)

    results = [r for r in validator_results if r is not None]
    consensus = compute_consensus(results, threshold=threshold)

    record = {
        "id": job_id,
        "url": url,
        "url_b": url_b,
        "rogue_validator": VALIDATORS[rogue_idx]["id"] if rogue_idx is not None else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "validators": results,
        "consensus": consensus,
        "mode": "split" if url_b else "standard",
    }

    with _lock:
        validation_history.append(record)

    print(f"[coordinator] {url} → {consensus['verdict']}")
    return record


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, data: dict):
        self._send(code, json.dumps(data, indent=2).encode(), "application/json")

    def _send_html(self, code: int, html: str):
        self._send(code, html.encode(), "text/html; charset=utf-8")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/docs", "/docs/"):
            self._send_html(200, SWAGGER_HTML)
        elif path in ("/openapi.json", "/openapi"):
            self._send_json(200, OPENAPI_SPEC)
        elif path == "/health":
            self._send_json(200, {
                "status": "ok",
                "validators": len(VALIDATORS),
                "mode": "docker" if is_running_in_docker() else "local",
                "uptime_validations": len(validation_history),
            })
        elif path == "/validators":
            self._send_json(200, {"validators": [
                {"id": v["id"], "url": v["url"], "healthy": check_validator_health(v)}
                for v in VALIDATORS
            ]})
        elif path == "/history":
            with _lock:
                self._send_json(200, {"history": validation_history[-20:]})
        elif path.startswith("/result/"):
            rid = path.split("/result/")[1]
            with _lock:
                found = next((r for r in validation_history if r["id"] == rid), None)
            self._send_json(200 if found else 404,
                            found or {"error": "not found"})
        elif path == "/":
            self._send_json(200, {
                "service": "PoWS Coordinator",
                "version": "1.0.0",
                "docs": "http://localhost:8000/docs",
                "openapi": "http://localhost:8000/openapi.json",
                "endpoints": {
                    "POST /validate":      "Validate a URL with 3 Firefox validators",
                    "GET  /history":       "Last 20 validation results",
                    "GET  /result/{id}":   "Get result by ID",
                    "GET  /validators":    "List validators and health",
                    "GET  /health":        "Health check",
                    "GET  /docs":          "Swagger UI",
                    "GET  /openapi.json":  "OpenAPI 3.0 spec",
                }
            })
        else:
            self._send_json(404, {"error": "not found",
                                  "hint": "See /docs for API documentation"})

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/validate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            url = body.get("url", "").strip()
            if not url:
                self._send_json(400, {"error": "url required"})
                return

            strict = body.get("strict", False)
            url_b  = body.get("url_b", None)
            if url_b:
                url_b = url_b.strip()
            threshold = 3 if strict else CONSENSUS_THRESHOLD
            job_id = sha256(url + str(time.time()))[:12]

            def bg(jid=job_id, target_url=url, thr=threshold, ub=url_b):
                run_validation(target_url, job_id=jid, threshold=thr, url_b=ub)

            threading.Thread(target=bg, daemon=True, name="bg").start()

            # Poll for this specific job_id — now set from the start, no race condition
            for _ in range(360):
                time.sleep(0.5)
                with _lock:
                    found = next(
                        (r for r in validation_history if r.get("id") == job_id), None)
                if found:
                    self._send_json(200, found)
                    return
            self._send_json(408, {"error": "timeout", "url": url})
        else:
            self._send_json(404, {"error": "not found",
                                  "hint": "See /docs for API documentation"})


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", "8000"))
    mode = "docker" if is_running_in_docker() else "local"
    print(f"[coordinator] Starting on port {PORT} (mode: {mode})")
    print(f"[coordinator] Validators: {[v['url'] for v in VALIDATORS]}")
    print(f"[coordinator] Swagger UI → http://localhost:{PORT}/docs")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
