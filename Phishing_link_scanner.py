# phishing_link_scanner_interactive.py
import tldextract
import Levenshtein as lv
from urllib.parse import urlparse
import ipaddress
import re

# small whitelist you can expand or load from file
legitimate_domains = ['examples.com', 'google.com', 'facebook.com', 'youtube.com']

SUSPICIOUS_KEYWORDS = [
    'secure', 'account', 'update', 'login', 'verify', 'confirm', 'bank', 'reset'
]

def extract_domain_parts(url):
    e = tldextract.extract(url)
    # e.subdomain, e.domain, e.suffix
    return e.subdomain, e.domain, e.suffix

def is_misspelled_domain(domain, legitimate_domains, threshold=0.9):
    for legit in legitimate_domains:
        # compare only the registered name (without suffix)
        sim = lv.ratio(domain, legit.split('.')[0])
        if sim >= threshold:
            return True
    return False

def heuristic_score(url):
    """
    Return a numeric score where higher means more suspicious.
    You can tune the weights below to change sensitivity.
    """
    score = 0.0
    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return score

    # 1) credential injection (user:pass@host)
    if parsed.username or parsed.password or '@' in url:
        score += 2.0

    # 2) IP address used as hostname
    try:
        ipaddress.ip_address(hostname)
        score += 2.5
    except Exception:
        pass

    # 3) many subdomains (depth)
    labels = hostname.split('.')
    if len(labels) >= 4:  # e.g., a.b.c.domain.com
        score += 1.0
    if len(labels) >= 6:
        score += 1.0

    # 4) hyphens and digits in domain (common in typosquats)
    # check registered domain (second-level + suffix)
    sub, domain, suffix = extract_domain_parts(url)
    registered = f"{domain}.{suffix}" if suffix else domain

    hyphen_count = domain.count('-')
    if hyphen_count >= 1:
        score += 0.8 * hyphen_count
    if any(ch.isdigit() for ch in domain):
        score += 0.8

    # 5) suspicious keywords anywhere in host/path
    host_and_path = hostname + parsed.path
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in host_and_path:
            score += 1.5

    # 6) very long domain or URL length
    if len(domain) > 20:
        score += 0.8
    if len(url) > 200:
        score += 0.8

    # 7) many query parameters (not always malicious but often used)
    if parsed.query and parsed.query.count('&') >= 4:
        score += 0.5

    return score

def is_phishing_url(url, legitimate_domains, typo_threshold=0.9, heuristic_threshold=2.0):
    subdomain, domain, suffix = extract_domain_parts(url)
    hostname = f"{domain}.{suffix}".lower() if suffix else domain.lower()

    # 1) legitimate domain check
    if hostname in legitimate_domains:
        print(f"[SAFE]   {url} -> registered domain '{hostname}' is known-good")
        return False

    # 2) brand in subdomain trick (e.g., google.security-update.com)
    for legit in legitimate_domains:
        legit_name = legit.split('.')[0]
        if legit_name in subdomain and hostname != legit:
            print(f"[PHISH]  {url} -> contains brand '{legit_name}' in subdomain but registered domain is '{hostname}'")
            return True

    # 3) misspelling check (typosquatting)
    if is_misspelled_domain(domain, legitimate_domains, threshold=typo_threshold):
        print(f"[PHISH]  {url} -> domain '{domain}' looks similar to a legit domain")
        return True

    # 4) heuristic fallback (works for any arbitrary URL)
    score = heuristic_score(url)
    if score >= heuristic_threshold:
        print(f"[PHISH]  {url} -> heuristic score {score:.2f} >= {heuristic_threshold}")
        return True

    # otherwise unknown / probably safe
    print(f"[UNKNOWN]{url} -> heuristic score {score:.2f} (below threshold {heuristic_threshold})")
    return False

if __name__ == "__main__":
    print("🔍 Phishing Link Scanner (interactive). Enter one URL per line; type 'done' to finish.")
    urls = []
    while True:
        u = input("URL: ").strip()
        if not u:
            continue
        if u.lower() == 'done':
            break
        urls.append(u)

    if not urls:
        print("No URLs entered. Exiting.")
    else:
        print("\n--- SCANNING RESULTS ---\n")
        for u in urls:
            is_phishing_url(u, legitimate_domains, typo_threshold=0.85, heuristic_threshold=2.0)
