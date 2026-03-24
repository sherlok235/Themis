"""
PoWS - Proof-of-Web-State Validator Node
Uses Firefox (Gecko engine) via Playwright to fingerprint websites.
"""

import asyncio
import hashlib
import json
import os
import re
import time
import base64
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page, Response

VALIDATOR_ID = os.environ.get("VALIDATOR_ID", "validator-1")
COORDINATOR_URL = os.environ.get("COORDINATOR_URL", "http://coordinator:8000")
PORT = int(os.environ.get("PORT", "9001"))


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def normalize_dom(html: str) -> str:
    """Remove dynamic/random elements so hash is deterministic."""
    # Remove timestamps (ISO format, unix, etc.)
    html = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d+Z]*', 'TIMESTAMP', html)
    html = re.sub(r'\b1[0-9]{9}\b', 'UNIXTIME', html)
    # Remove random IDs / nonces
    html = re.sub(r'(?:id|nonce|csrf)="[a-f0-9-]{8,}"', 'id="NORMALIZED"', html, flags=re.IGNORECASE)
    # Remove session tokens in URLs
    html = re.sub(r'(?:token|session|sid)=[A-Za-z0-9_\-]{8,}', 'token=NORMALIZED', html)
    # Normalize whitespace
    html = re.sub(r'\s+', ' ', html).strip()
    return html


def build_merkle_root(hashes: list[str]) -> str:
    """Simple binary merkle tree over resource hashes."""
    if not hashes:
        return sha256("empty")
    nodes = [bytes.fromhex(h) for h in hashes]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(nodes[i] + nodes[i + 1]).digest()
            for i in range(0, len(nodes), 2)
        ]
    return nodes[0].hex()


def perceptual_hash_screenshot(png_bytes: bytes) -> str:
    """
    Simple pHash-like fingerprint from screenshot bytes.
    Without PIL we do a block-average over raw PNG data.
    """
    # Use SHA256 of sampled bytes as proxy perceptual hash
    sample = png_bytes[::max(1, len(png_bytes) // 256)]
    return sha256(bytes(sample))[:16]


async def validate_url(url: str) -> dict:
    """Core validation: launch Firefox, collect all signals, produce fingerprint."""
    result = {
        "validator_id": VALIDATOR_ID,
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dom_hash": None,
        "layout_hash": None,
        "tls_hash": None,
        "dns_ip": None,
        "screenshot_hash": None,
        "http_status": None,
        "resource_merkle_root": None,
        "resources": [],
        "har_summary": {},
        "error": None,
        "final_fingerprint": None,
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        # ── DNS resolution ───────────────────────────────────────────────────
        try:
            dns_ip = socket.gethostbyname(hostname)
            result["dns_ip"] = dns_ip
        except Exception:
            result["dns_ip"] = "unresolved"

        # ── TLS fingerprint ──────────────────────────────────────────────────
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
                    cert_der = s.getpeercert(binary_form=True)
                    result["tls_hash"] = sha256(cert_der)
            except Exception:
                result["tls_hash"] = sha256(f"no-tls-{hostname}")
        else:
            result["tls_hash"] = sha256("http-no-tls")

        # ── Browser launch (Firefox / Gecko) ─────────────────────────────────
        async with async_playwright() as p:
            browser = await p.firefox.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            )
            page = await context.new_page()

            # Intercept all network requests
            resource_hashes = []
            request_log = []

            async def on_response(response: Response):
                try:
                    status = response.status
                    req_url = response.url
                    headers = dict(response.headers)
                    body = await response.body()
                    body_hash = sha256(body)
                    resource_hashes.append(body_hash)
                    request_log.append({
                        "url": req_url,
                        "status": status,
                        "size": len(body),
                        "hash": body_hash,
                        "content_type": headers.get("content-type", ""),
                    })
                    # Record main page HTTP status (handle trailing slash variants)
                    req_clean = req_url.rstrip("/")
                    url_clean = url.rstrip("/")
                    if req_clean == url_clean:
                        result["http_status"] = status
                except Exception:
                    pass

            page.on("response", on_response)

            # Navigate
            # "domcontentloaded" fires as soon as HTML is parsed — does not wait
            # for external fonts/CDN which can hang indefinitely on local servers.
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            if response:
                result["http_status"] = response.status  # always capture from goto response

            await asyncio.sleep(0.3)  # settle JS

            # ── DOM fingerprint ──────────────────────────────────────────────
            raw_html = await page.evaluate("() => document.documentElement.outerHTML")
            normalized = normalize_dom(raw_html)
            result["dom_hash"] = sha256(normalized)

            # ── Layout fingerprint (bounding rects + computed styles) ────────
            layout_data = await page.evaluate("""() => {
                const selectors = ['button', 'input', 'a', 'h1', 'h2', 'nav', 'form'];
                const items = [];
                for (const sel of selectors) {
                    const els = Array.from(document.querySelectorAll(sel)).slice(0, 10);
                    for (const el of els) {
                        const r = el.getBoundingClientRect();
                        const s = window.getComputedStyle(el);
                        items.push({
                            tag: sel,
                            x: Math.round(r.x), y: Math.round(r.y),
                            w: Math.round(r.width), h: Math.round(r.height),
                            font: s.fontFamily,
                            color: s.color,
                            bg: s.backgroundColor,
                            display: s.display,
                        });
                    }
                }
                return items;
            }""")
            result["layout_hash"] = sha256(json.dumps(layout_data, sort_keys=True))

            # ── Screenshot perceptual hash ────────────────────────────────────
            png_bytes = await page.screenshot(full_page=False)
            result["screenshot_hash"] = perceptual_hash_screenshot(png_bytes)

            # ── Resources & Merkle root ───────────────────────────────────────
            result["resources"] = request_log[:50]  # cap for PoC
            result["resource_merkle_root"] = build_merkle_root(resource_hashes)

            # ── HAR summary ───────────────────────────────────────────────────
            result["har_summary"] = {
                "total_requests": len(request_log),
                "total_bytes": sum(r["size"] for r in request_log),
                "status_codes": {},
            }
            for r in request_log:
                sc = str(r["status"])
                result["har_summary"]["status_codes"][sc] = \
                    result["har_summary"]["status_codes"].get(sc, 0) + 1

            await browser.close()

        # ── Final composite fingerprint ───────────────────────────────────────
        result["final_fingerprint"] = sha256(
            result["dom_hash"] +
            result["layout_hash"] +
            result["tls_hash"] +
            result["resource_merkle_root"]
        )

    except Exception as e:
        result["error"] = str(e)
        # Generate a failure fingerprint so coordinator still gets a result
        result["final_fingerprint"] = sha256(f"error:{e}:{url}")

    return result


# ── HTTP server so coordinator can request validation ─────────────────────────

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

pending_results = {}


def _do_validate_sync(url: str) -> dict:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(validate_url(url))
    loop.close()
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default logs

    def do_POST(self):
        if self.path == "/validate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            url = body.get("url", "")
            print(f"[{VALIDATOR_ID}] Validating: {url}")
            result = _do_validate_sync(url)
            print(f"[{VALIDATOR_ID}] Done. fingerprint={result.get('final_fingerprint', 'N/A')[:16]}…")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')


if __name__ == "__main__":
    print(f"[{VALIDATOR_ID}] Starting on port {PORT}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
