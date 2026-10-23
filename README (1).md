# Automated Web Scanner: Security Headers and CORS Auditor

**Project type:** Educational cybersecurity project  
**Author:** Anurag Basu  
**Bootcamp:** IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares

## 1. Overview
This Python command-line tool performs a basic review of HTTP security response headers and selected CORS response headers for a website. It checks for six commonly discussed headers and displays their values when present. It can optionally save a JSON report.

## 2. Scope and responsible use
Run this tool only against a website you own or have explicit permission to test. It sends a normal HTTP GET request and does not attempt exploitation, brute force, crawling, or intrusive testing. A missing header is a review item, not proof of a vulnerability. The tool is not a substitute for a professional security assessment.

## 3. Features
- Accepts a URL with or without `https://`.
- Reports HTTP status and final URL after redirects.
- Checks `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Displays `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.
- Optionally writes a JSON report.

## 4. Technology
- Python 3.9+
- `requests` library
- Standard libraries: `argparse`, `json`, `datetime`, and `urllib.parse`

## 5. Setup
1. Install Python 3.9 or newer.
2. Open a terminal in this folder.
3. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

## 6. Run
Basic:
```bash
python AnuragBasu_AutomatedWebScanner.py https://example.com
```
Save a JSON report:
```bash
python AnuragBasu_AutomatedWebScanner.py https://example.com --json report.json
```
Replace the sample URL with a target you own or are authorized to test. `example.com` is a reserved example domain and is useful for a basic demonstration.

## 7. Output
The program prints the target, check time, HTTP status, final URL, header presence and values, selected CORS response headers, and cautionary notes. Network errors are displayed without crashing the program.

## 8. Limitations
- Only response headers visible on one GET request are inspected.
- Some headers may be configured at a CDN, proxy, application, or route level.
- CORS behaviour can depend on request origin, methods, and preflight responses; this tool does not perform a full CORS test.
- A header being present does not guarantee correct configuration.
- Network errors, redirects, authentication, or bot protections can affect results.

## 9. Future improvements
- Add a user-supplied `Origin` option and carefully controlled OPTIONS preflight checks.
- Export a formatted HTML/PDF report.
- Add unit tests and a sample test server.
- Add severity guidance reviewed against current security guidance.

## 10. References
- Python documentation: https://docs.python.org/3/
- Requests documentation: https://requests.readthedocs.io/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/

## Dataset
This project audits live HTTP response headers and does not require a training dataset.
