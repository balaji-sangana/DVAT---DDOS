#!/usr/bin/env python3
# ============================================================
# DVAT – Defensive Vulnerability Assessment Tool
# Author  : Balaji Sangana
# Version : 3.3.0
# Mode    : Blue Team / Defensive Security
# ============================================================
# ⚠ Authorized testing only
# ============================================================

import argparse
import time
import sys
import requests
from statistics import mean
from collections import Counter
import matplotlib.pyplot as plt

VERSION = "1.0.0"

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------
def banner():
    print(f"""
=============°==============================================
  ██████╗ ██╗   ██╗ █████╗ ████████╗
  ██╔══██╗██║   ██║██╔══██╗╚══██╔══╝
  ██║  ██║██║   ██║███████║   ██║
  ██║  ██║╚██╗ ██╔╝██╔══██║   ██║
  ██████╔╝ ╚████╔╝ ██║  ██║   ██║
  ╚═════╝   ╚═══╝  ╚═╝  ╚═╝   ╚═╝
============================================================
DVAT – Defensive Domain & URL Testing Tool
Version : {VERSION} 
Author  : Balaji Sangana
 Mode   : Blue-Team / Defensive Security
------------------------------------------------------------
 ⚠ Authorized testing only. Misuse is illegal.
------------------------------------------------------------
""")

# ------------------------------------------------------------
# Examples
# ------------------------------------------------------------
def show_examples():
    print("""
DVAT EXAMPLES
=============

# Full URL (GET)
python dvat.py --url https://example.com/login

# Full URL (POST)
python dvat.py --url https://example.com/api/login \\
  --method POST --data '{"user":"test","pass":"test"}'

# Domain + Port
python dvat.py --domain example.com --port 8080

# Domain + Port + Path
python dvat.py --domain example.com --port 443 --path /login

# Multiple Paths
python dvat.py --domain example.com --port 443 --paths-file paths.txt

# Burp Request Replay
python dvat.py --domain example.com --port 443 --request-file request.txt

# Increase Stress Rate
python dvat.py --url https://example.com --rate 20

⚠ Authorized testing only
""")
    sys.exit(0)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def load_paths(path, paths_file):
    if paths_file:
        with open(paths_file) as f:
            return [p.strip() for p in f if p.strip()]
    return [path] if path else ["/"]

def load_headers(file):
    headers = {}
    if not file:
        return headers
    with open(file) as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def load_tokens(file):
    if not file:
        return []
    with open(file) as f:
        return [t.strip() for t in f if t.strip()]

def rotate_auth(headers, tokens, index):
    if not tokens:
        return headers
    h = headers.copy()
    h["Authorization"] = f"Bearer {tokens[index % len(tokens)]}"
    return h

# ------------------------------------------------------------
# Burp Request Parser
# ------------------------------------------------------------
def burp_to_request(file):
    with open(file) as f:
        lines = f.read().splitlines()

    method, path, _ = lines[0].split()
    headers, body = {}, None

    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            if not k.lower().startswith(("content-length", "accept-encoding")):
                headers[k.strip()] = v.strip()
        i += 1

    if i + 1 < len(lines):
        body = "\n".join(lines[i + 1:])

    return {"method": method, "headers": headers, "body": body, "path": path}

# ------------------------------------------------------------
# WAF Detection
# ------------------------------------------------------------
def detect_waf(headers):
    h = {k.lower(): v.lower() for k, v in headers.items()}
    waf = set()

    if "cf-ray" in h or "cloudflare" in h.get("server", ""):
        waf.add("Cloudflare")
    if "x-amzn-requestid" in h or "cloudfront" in h.get("via", ""):
        waf.add("AWS WAF / CloudFront")
    if any("akamai" in k for k in h):
        waf.add("Akamai")
    if "x-iinfo" in h or "incap_ses" in h:
        waf.add("Imperva")

    return waf

# ------------------------------------------------------------
# Phase Runner
# ------------------------------------------------------------
def run_phase(req, duration, rate, tokens, label):
    lat, events, wafs = [], Counter(), set()
    start, sent = time.time(), 0
    print(f"[▶] {label} phase")

    while time.time() - start < duration:
        try:
            headers = rotate_auth(req["headers"], tokens, sent)
            t1 = time.time()
            r = requests.request(
                req["method"],
                req["url"],
                headers=headers,
                data=req["body"],
                timeout=5,
                allow_redirects=False
            )
            lat.append(time.time() - t1)
            sent += 1
            wafs |= detect_waf(r.headers)

            if r.status_code == 429:
                events["RATE_LIMIT"] += 1
            elif r.status_code == 403:
                events["WAF_BLOCK"] += 1
            elif r.status_code >= 500:
                events["SERVER_ERROR"] += 1
            elif r.status_code >= 400:
                events["CLIENT_ERROR"] += 1
            else:
                events["ALLOWED"] += 1

            time.sleep(1 / rate)

        except requests.exceptions.Timeout:
            events["TIMEOUT"] += 1
        except requests.exceptions.RequestException:
            events["ERROR"] += 1

    return {
        "avg_latency": mean(lat) if lat else 0,
        "latencies": lat,
        "events": events,
        "waf": wafs
    }

# ------------------------------------------------------------
# Risk Score
# ------------------------------------------------------------
def risk_score(base, stress):
    score = 0
    if stress["events"].get("RATE_LIMIT", 0) > 0:
        score += 40
    if stress["events"].get("WAF_BLOCK", 0) > 0:
        score += 40
    if stress["events"].get("TIMEOUT", 0) > base["events"].get("TIMEOUT", 0):
        score += 30
    if base["avg_latency"] and stress["avg_latency"] > base["avg_latency"] * 2:
        score += 20
    return min(score, 100)

# ------------------------------------------------------------
# Timeline Plot
# ------------------------------------------------------------
def plot_timeline(lat, name):
    if not lat:
        return
    plt.figure()
    plt.plot(lat)
    plt.xlabel("Request #")
    plt.ylabel("Latency (s)")
    plt.title(f"Latency Timeline – {name}")
    plt.grid(True)
    plt.savefig(f"latency_{name}.png")
    plt.close()

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="DVAT – Defensive URL / Domain Vulnerability Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--examples", action="store_true", help="Show usage examples")

    parser.add_argument("--url", help="Full URL (http/https)")
    parser.add_argument("--domain", help="Domain or IP")
    parser.add_argument("--port", type=int, help="Port number")
    parser.add_argument("--path", help="Single path")
    parser.add_argument("--paths-file", help="Multiple paths file")

    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--data", help="POST body")
    parser.add_argument("--headers-file", help="Headers file")
    parser.add_argument("--request-file", help="Burp raw HTTP request")
    parser.add_argument("--tokens-file", help="Auth tokens")

    parser.add_argument("--baseline-duration", type=int, default=10)
    parser.add_argument("--baseline-rate", type=int, default=2)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--rate", type=int, default=10)

    args = parser.parse_args()

    if args.version:
        print(f"DVAT version {VERSION}")
        sys.exit(0)

    if args.examples:
        show_examples()

    if not args.url and not (args.domain and args.port):
        print("[!] Use --url OR --domain + --port")
        sys.exit(1)

    paths = load_paths(args.path, args.paths_file)
    tokens = load_tokens(args.tokens_file)

    if args.request_file:
        base_req = burp_to_request(args.request_file)
    else:
        headers = load_headers(args.headers_file)
        if args.method == "POST" and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        base_req = {
            "method": args.method,
            "headers": headers,
            "body": args.data,
            "path": args.path or "/"
        }

    if args.url:
        targets = [args.url]
    else:
        scheme = "https" if args.port == 443 else "http"
        targets = [f"{scheme}://{args.domain}:{args.port}{p}" for p in paths]

    secure = 0
    for i, url in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Testing {url}")
        req = base_req.copy()
        req["url"] = url

        base = run_phase(req, args.baseline_duration, args.baseline_rate, tokens, "BASELINE")
        stress = run_phase(req, args.duration, args.rate, tokens, "STRESS")

        plot_timeline(stress["latencies"], f"target_{i}")

        dom = stress["events"].most_common(1)[0][0] if stress["events"] else "UNKNOWN"
        risk = risk_score(base, stress)

        print("\n--- RESULT ---")
        print("Dominant Event :", dom)
        print("WAF Detected   :", ", ".join(stress["waf"]) or "None")
        print("Risk Score    :", risk, "/100")

        if dom in ["RATE_LIMIT", "WAF_BLOCK", "TIMEOUT"]:
            print("[✔] NOT VULNERABLE")
            secure += 1
        else:
            print("[❌] POTENTIALLY VULNERABLE")

    print("\n========== OVERALL ==========")
    print(f"Protected : {secure}/{len(targets)}")

if __name__ == "__main__":
    main()
