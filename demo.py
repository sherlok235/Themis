#!/usr/bin/env python3
"""
PoWS — Proof-of-Web-State  CLI
================================
Talks to the coordinator (which runs all 3 Firefox validators) and prints results.

USAGE
-----
  # Validate any URL
  python3 demo.py https://example.com

  # Split tamper test — V1+V2 get URL1, V3 gets URL2 — should detect mismatch
  python3 demo.py http://localhost:8080/normal.html http://localhost:8080/injected.html

  # Run both demo scenarios automatically (no URL needed)
  python3 demo.py

  # Strict mode — require all 3 validators to agree (3/3 instead of 2/3)
  python3 demo.py --strict http://localhost:8080/normal.html

  # Strict + split tamper test
  python3 demo.py --strict http://localhost:8080/normal.html http://localhost:8080/injected.html

PRE-REQUISITES
--------------
  Start everything first:
    ./start.sh

  Then in a second terminal:
    python3 demo.py http://localhost:8080/normal.html
"""

import json
import sys
import hashlib
import urllib.request
import urllib.error

# ── colours ──────────────────────────────────────────────────────────────────
CYAN   = '\033[96m'
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
DIM    = '\033[2m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

COORDINATOR_PORT = 8000


# ── helpers ───────────────────────────────────────────────────────────────────

def post_json(url: str, payload: dict, timeout: int = 180) -> dict:
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data,
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {"error": f"Cannot reach {url} — {e.reason}. Is ./start.sh running?"}
    except Exception as e:
        return {"error": str(e)}


def translate_url(url: str) -> str:
    """
    The coordinator handles Docker translation server-side.
    demo.py always sends the URL exactly as given by the user.
    """
    return url


def banner(text: str, color: str = CYAN):
    line = '─' * 62
    print(f"\n{color}{BOLD}{line}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{line}{RESET}")


def print_validator(r: dict, rogue_id: str = None):
    ok = r.get('http_status') == 200
    vid = r.get('validator_id', '?')
    is_rogue = rogue_id and vid == rogue_id
    rogue_tag = f" {YELLOW}⚠ ROGUE — received injected URL{RESET}" if is_rogue else ""
    print(f"\n{CYAN}▸ {vid}{RESET}{rogue_tag}")
    print(f"  URL          : {r.get('url','?')}")
    print(f"  HTTP status  : {GREEN if ok else RED}{r.get('http_status','?')}{RESET}")
    print(f"  DNS IP       : {r.get('dns_ip','?')}")
    print(f"  DOM hash     : {YELLOW}{r.get('dom_hash','N/A')}{RESET}")
    print(f"  Layout hash  : {YELLOW}{r.get('layout_hash','N/A')}{RESET}")
    print(f"  Merkle root  : {YELLOW}{r.get('resource_merkle_root','N/A')}{RESET}")
    print(f"  Screenshot Φ : {r.get('screenshot_hash','N/A')}")
    print(f"  TLS hash     : {DIM}{str(r.get('tls_hash','N/A'))[:40]}…{RESET}")
    print(f"  Resources    : {len(r.get('resources', []))} captured")
    if r.get('error'):
        print(f"  {RED}ERROR: {r['error']}{RESET}")


def run_scenario(url: str, label: str, strict: bool = False, url_b: str = None):
    banner(f"SCENARIO: {label}", CYAN)
    print(f"{DIM}  Target : {url}{RESET}")
    if url_b:
        print(f"{DIM}  Target B (validator-3): {url_b}{RESET}")
    mode_str = "strict (3/3)" if strict else "standard (2/3)"
    if url_b:
        mode_str += " · SPLIT (V1+V2 vs V3)"
    print(f"{DIM}  Mode   : {mode_str}{RESET}")
    print(f"\n{DIM}  Contacting coordinator → 3 Firefox validators…{RESET}")
    print(f"{DIM}  Loading page with Firefox, please wait…{RESET}")

    import threading
    done_event = threading.Event()

    def spinner():
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        elapsed = 0
        while not done_event.is_set():
            print(f"\r  {CYAN}{frames[i % len(frames)]}{RESET} {elapsed}s elapsed…", end="", flush=True)
            done_event.wait(timeout=0.5)
            i += 1
            elapsed += 1
        print(f"\r  {GREEN}✓{RESET} Done{' ' * 20}")

    spin_thread = threading.Thread(target=spinner, daemon=True)
    spin_thread.start()

    payload = {"url": translate_url(url), "strict": strict}
    if url_b:
        payload["url_b"] = translate_url(url_b)

    result = post_json(f"http://localhost:{COORDINATOR_PORT}/validate", payload)

    done_event.set()
    spin_thread.join()

    if result.get("error"):
        print(f"\n{RED}  ✗  {result['error']}{RESET}\n")
        return

    validators = result.get("validators", [])
    consensus  = result.get("consensus", {})

    rogue_id = result.get("rogue_validator")
    for v in validators:
        print_validator(v, rogue_id=rogue_id)

    # Fingerprint grouping
    print(f"\n{DIM}  Fingerprint groups:{RESET}")
    fp_map: dict = {}
    for v in validators:
        fp = v.get('final_fingerprint') or ''
        fp_map.setdefault(fp, []).append(v.get('validator_id', '?'))
    for fp, ids in fp_map.items():
        short = fp[:40] + '…' if fp else 'N/A'
        print(f"    {len(ids)}/{len(validators)}: {', '.join(ids)}  →  {short}")

    # Verdict
    print(f"\n{'═' * 62}")
    certified = consensus.get('certified', False)
    if certified:
        print(f"\n  {GREEN}{BOLD}✅  CERTIFIED{RESET}")
        print(f"  {GREEN}Agreement  : {consensus.get('agreement_count','?')}/{consensus.get('total_validators','?')} validators{RESET}")
        fp = consensus.get('dominant_fingerprint') or ''
        print(f"  {GREEN}Fingerprint: {fp[:40]}…{RESET}")
    else:
        print(f"\n  {RED}{BOLD}🚨  MISMATCH DETECTED — NOT CERTIFIED{RESET}")
        print(f"  {RED}Agreement  : {consensus.get('agreement_count','?')}/{consensus.get('total_validators','?')} validators{RESET}")
        for m in consensus.get('mismatches', []):
            field = m.get('field','?').replace('_', ' ').upper()
            print(f"\n  {RED}⚠  {field} DIFFERS:{RESET}")
            print(f"     {m.get('validator_a','?')} : {m.get('hash_a','?')}")
            print(f"     {m.get('validator_b','?')} : {m.get('hash_b','?')}")

    rogue = result.get("rogue_validator")
    if rogue:
        print(f"  Rogue node    : {YELLOW}{rogue}{RESET} (received injected URL)")
    print(f"\n  Evidence hash : {YELLOW}{consensus.get('evidence_hash','N/A')}{RESET}")
    print(f"{'═' * 62}\n")


def main():
    args = sys.argv[1:]

    if args and args[0] in ('-h', '--help'):
        print(__doc__)
        return

    # Parse --strict flag
    strict = '--strict' in args
    args   = [a for a in args if a != '--strict']

    if not args:
        # No URL → run both demo scenarios
        banner("PoWS — Proof-of-Web-State · Full Demo", CYAN)
        print(f"{DIM}  Engine     : Firefox (Gecko) via Playwright{RESET}")
        print(f"{DIM}  Validators : 3 independent nodes, consensus 2-of-3{RESET}")
        run_scenario("http://localhost:8080/normal.html",
                     "NORMAL WEBSITE  — validators should AGREE")
        run_scenario("http://localhost:8080/injected.html",
                     "INJECTED WEBSITE — validators should DETECT MISMATCH")
        banner("Demo complete", GREEN)
        return

    if len(args) == 2:
        # Two URLs: V1+V2 validate url, V3 validates url_b — split tamper test
        run_scenario(args[0], f"SPLIT TEST: {args[0]}  vs  {args[1]}",
                     strict=strict, url_b=args[1])
    else:
        for url in args:
            run_scenario(url, f"CUSTOM: {url}", strict=strict)


if __name__ == '__main__':
    main()
