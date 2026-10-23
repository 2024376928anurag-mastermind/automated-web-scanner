"""
Automated Web Scanner — Educational Security Header and CORS Auditor
Use only on websites you own or have explicit permission to test.
This tool performs basic HTTP checks; it is not a penetration tester.
"""
import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps browsers enforce HTTPS after a secure visit.",
    "Content-Security-Policy": "Helps reduce certain content-injection risks.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Can help prevent clickjacking in older browser controls.",
    "Referrer-Policy": "Controls referrer information sent with requests.",
    "Permissions-Policy": "Controls access to selected browser features.",
}

def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please provide a URL.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return raw_url

def audit(url: str, timeout: float = 10.0) -> dict:
    result = {
        "url": url,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "http_status": None,
        "final_url": None,
        "https": urlparse(url).scheme == "https",
        "security_headers": {},
        "cors": {},
        "notes": [
            "This is a basic configuration check, not a complete security assessment.",
            "A missing header is a review item, not proof of a vulnerability.",
        ],
    }
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Educational-Automated-Web-Scanner/1.0"},
        )
        result["http_status"] = response.status_code
        result["final_url"] = response.url
        headers = response.headers

        for name, description in SECURITY_HEADERS.items():
            value = headers.get(name)
            result["security_headers"][name] = {
                "present": value is not None,
                "value": value or "",
                "description": description,
            }

        allow_origin = headers.get("Access-Control-Allow-Origin")
        allow_credentials = headers.get("Access-Control-Allow-Credentials")
        result["cors"] = {
            "access_control_allow_origin": allow_origin,
            "access_control_allow_credentials": allow_credentials,
            "review": (
                "Wildcard origin with credentials enabled needs careful review."
                if allow_origin == "*" and str(allow_credentials).lower() == "true"
                else "Review CORS policy in the context of the application."
            ),
        }
    except requests.RequestException as exc:
        result["error"] = f"Request failed: {exc}"
    return result

def print_report(report: dict) -> None:
    print("\n" + "=" * 66)
    print("AUTOMATED WEB SCANNER — BASIC AUDIT REPORT")
    print("=" * 66)
    print("Target:", report["url"])
    print("Checked (UTC):", report["checked_at_utc"])
    if report.get("error"):
        print(report["error"])
        return
    print("HTTP status:", report["http_status"])
    print("Final URL:", report["final_url"])
    print("HTTPS in input URL:", "Yes" if report["https"] else "No")
    print("\nSecurity headers:")
    for name, item in report["security_headers"].items():
        state = "PRESENT" if item["present"] else "MISSING — REVIEW"
        print(f"- {name}: {state}")
        if item["value"]:
            print(f"  Value: {item['value']}")
    print("\nCORS headers:")
    print("Access-Control-Allow-Origin:", report["cors"].get("access_control_allow_origin") or "Not present")
    print("Access-Control-Allow-Credentials:", report["cors"].get("access_control_allow_credentials") or "Not present")
    print("Review:", report["cors"].get("review", "No CORS information available."))
    print("\nNotes:")
    for note in report["notes"]:
        print("-", note)

def main():
    parser = argparse.ArgumentParser(description="Basic security header and CORS auditor.")
    parser.add_argument("url", nargs="?", help="Website URL you own or have permission to test")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path", help="Optional path to save machine-readable JSON report")
    args = parser.parse_args()

    raw_url = args.url or input("Enter an authorized website URL: ")
    try:
        url = normalize_url(raw_url)
    except ValueError as exc:
        parser.error(str(exc))

    if urlparse(url).scheme != "https":
        print("WARNING: URL does not use HTTPS. Only scan targets you are authorized to test.")
    report = audit(url, timeout=args.timeout)
    print_report(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")

if __name__ == "__main__":
    main()
