# 🛡️ DVAT – Defensive Vulnerability Assessment Tool

**DVAT (Defensive Vulnerability Assessment Tool)** is a **Blue-Team focused security testing tool** designed to evaluate whether a web application or API is **protected against high-rate traffic, denial-of-service conditions, and abusive request patterns**.

DVAT does **not exploit vulnerabilities**. Instead, it **observes defensive behavior** such as rate limiting, request blocking, throttling, and silent drops to determine whether an endpoint is **protected or potentially vulnerable**.

> ⚠️ **Authorized testing only. Misuse is illegal.**

---

## ✨ Key Features

### 🔍 Defensive Traffic Analysis
- Baseline vs Stress testing  
- Detects defensive responses:
  - `RATE_LIMIT` (HTTP 429)
  - `WAF_BLOCK` (HTTP 403)
  - `TIMEOUT` (silent drop / throttling)
- Latency spike detection  
- Per-endpoint **risk score (0–100)**  

### 🌐 Target Support
- Full URL testing
  ```bash
  --url https://example.com/search?q=test
- Domain + port testing
  ```bash
  --domain example.com --port 8080
- Multiple paths per domain
- Query parameter support

### 🔐 Request Handling

- GET and POST methods
- Custom headers support
- POST body support (JSON / form)
- Burp Suite raw HTTP request replay
- Auth-safe token rotation

### 🧠 WAF Fingerprinting

Detects common providers via response headers:
- Cloudflare
- AWS WAF / CloudFront
- Akamai
- Imperva

📊 Evidence Generation

- Latency timeline charts (latency_*.png)
- Clear verdict per endpoint
- Overall protection summary
