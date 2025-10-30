import tldextract
import Levenshtein as lv
from urllib.parse import urlparse
from difflib import SequenceMatcher

legitimate_domains = ['examples.com', 'google.com', 'facebook.com']

test_urls = [
    'http://example.co',
    'http://examp1e.com',
    'https://www.google.security-update.com',
    'http://faceb00k.com/login',
    'https://google.com'
]

def get_registered_domain(hostname):
    parts = hostname.split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return hostname

def is_misspelled_domain(registered_domain, legitimate_domains, threshold=0.9):
    for legit in legitimate_domains:
        sim = SequenceMatcher(None, registered_domain, legit).ratio()
        if sim >= threshold:
            return True
    return False

def is_phishing_url(url, legitimate_domains, threshold=0.9):
    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return False
    registered = get_registered_domain(hostname)
    
    # Exact match -> safe
    if registered in legitimate_domains:
        print(f"[SAFE]   {url}  -> registered domain '{registered}' is known-good")
        return False
    
    # Brand-as-subdomain trick (e.g., google.security-update.com)
    for legit in legitimate_domains:
        if legit.split('.')[0] in hostname and registered != legit:
            print(f"[PHISH]  {url}  -> contains legitimate brand '{legit}' in hostname '{hostname}' but registered domain is '{registered}'")
            return True
    
    # Misspelling / typosquat on registered domain
    if is_misspelled_domain(registered, legitimate_domains, threshold):
        print(f"[PHISH]  {url}  -> registered domain '{registered}' is similar to a legit domain")
        return True
    
    print(f"[UNKNOWN]{url} -> registered domain '{registered}' not in list and not similar enough (ratio<{threshold})")
    return False

# Run checks
for url in test_urls:
    is_phishing_url(url, legitimate_domains, threshold=0.85)  # tweak threshold as needed
