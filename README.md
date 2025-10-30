# Phishing-Link-Scanner

# 🕵️‍♂️ Phishing Link Scanner

A simple yet effective **phishing URL detector** written in Python.  
It checks for:
- Misspelled domains (e.g., `gooogle.com`)
- Subdomain impersonation (e.g., `google.security-update.com`)
- Known legitimate domains (e.g., `google.com`)

---

## ⚙️ Installation


1. git clone https://github.com/<your-username>/phishing-link-scanner.git
2. cd phishing-link-scanner
3. pip install -r requirements.txt
4. python phishing_link_scanner.py

## Uses Levenshtein distance to detect typosquatting.
Extracts domain parts using tldextract.
Detects brand-based subdomain impersonation.
