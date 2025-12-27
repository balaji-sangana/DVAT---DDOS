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

### 🧰 Requirements

- Python 3.8+

- Required libraries:
  - requests
  - matplotlib

- Install dependencies
  ```bash
  pip install requests matplotlib

### ⚙️ Usage
🔹 Show help
```bash
   python3 dvat.py --help
```
🔹 Show examples
```bash
python3 dvat.py --examples
```
🔹 Show version
```bash
python3 dvat.py --version
```
###🧪 Usage Examples
1️⃣ Test a full URL (GET)
```bash
python3 dvat.py --url http://127.0.0.1:8080
```
2️⃣ Test a POST endpoint
```bash
python3 dvat.py \
  --url https://example.com/api/login \
  --method POST \
  --data '{"username":"test","password":"test"}'
```
3️⃣ Test domain + port
```bash
python3 dvat.py --domain example.com --port 8080
```
4️⃣ Test multiple paths
```bash
python3 dvat.py \
  --domain example.com \
  --port 443 \
  --paths-file paths.txt
```
paths.txt
```bash
 /login
 /api/search
```
5️⃣ Replay Burp Suite request
```bash
python3 dvat.py \
  --domain example.com \
  --port 443 \
  --request-file request.txt
```
6️⃣ Auth token rotation
```bash
python3 dvat.py \
  --url https://example.com/api \
  --tokens-file tokens.txt
```
### 📊 Sample Output
```bash
[1/1] Testing https://example.com/search?q=test
[▶] BASELINE phase
[▶] STRESS phase

--- RESULT ---
Dominant Event : TIMEOUT
WAF Detected   : Cloudflare
Risk Score     : 70 /100
[✔] NOT VULNERABLE

========== OVERALL ==========
Protected : 1/1
```
### 🧠 Verdict Logic
- Dominant Event	Meaning	Verdict
- ALLOWED	No defensive control triggered	❌ Potentially Vulnerable
- RATE_LIMIT	Rate limiting detected	✔ Not Vulnerable
- WAF_BLOCK	Requests blocked by WAF	✔ Not Vulnerable
- TIMEOUT	Silent throttling / drop	✔ Not Vulnerable
### 📈 Risk Score Calculation
Condition	Score
- Rate limiting detected	+40
- WAF blocking detected	+40
- TIMEOUT increase under stress	+30
- Latency > 2× baseline	+20
- Max score	100
🚫 What DVAT Does NOT Do
❌ No exploitation
❌ No payload fuzzing
❌ No firewall bypass
❌ No evasion techniques
❌ No amplification attacks

#### DVAT is strictly defensive and observational.

### 🧾 Use Cases

- SOC / Blue-Team validation
- WAF effectiveness testing
- DoS resilience assessment
- Security audits & compliance checks
- Pre-production hardening

### 📜 License

This project is licensed under the MIT License.

### 🔮 Future Enhancements

- PDF / JSON report generation
- Confidence scoring (High / Medium / Low)
- Flask web dashboard
- CI/CD integration mode
- Cookie-based authentication support
- CVSS-style scoring model

---
