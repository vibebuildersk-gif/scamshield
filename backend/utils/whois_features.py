import whois
from datetime import datetime
import tldextract
import socket

# Use a custom socket timeout handler so a frozen registry server doesn't crash your app.py frontend!
socket.setdefaulttimeout(5.0)

def extract_whois_features(url):
    """
    Extracts domain intelligence features, specifically focusing on
    domain age and registrar information, which are critical for
    detecting short-lived phishing domains.
    """
    features = {
        "DomainAgeDays": 0,  # Zero-Day Trap Fix: Treat missing WHOIS as 0 Days Old (maximum risk)
        "IsDomainHidden": 0,
        "Registrar": "Unknown"
    }

    try:
        ext = tldextract.extract(url)
        # WHOIS only works on the root domain (e.g., 'web.app', not 'subdomain.web.app')
        base_domain = f"{ext.domain}.{ext.suffix}"
        
        w = whois.whois(base_domain)

        # Handle Creation Date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is not None:
                now = datetime.now(creation_date.tzinfo)
            else:
                now = datetime.now()
            age = (now - creation_date).days
            features["DomainAgeDays"] = max(0, age)
        
        # Handle Registrar
        if w.registrar:
            features["Registrar"] = str(w.registrar)
        
        # Check for privacy protection / hidden whois
        privacy_keywords = ['privacy', 'redacted', 'hidden', 'proxy', 'protect', 'domains by proxy', 'whoisguard']
        
        raw_data = str(w).lower()
        if any(keyword in raw_data for keyword in privacy_keywords):
            features["IsDomainHidden"] = 1

    except Exception as e:
        # If whois fails (e.g., domain doesn't exist or whois blocked), 
        # it returns default values (age -1 implies suspicious/unknown)
        pass

    return features

if __name__ == "__main__":
    test_url = input("Enter URL for WHOIS check: ")
    res = extract_whois_features(test_url)
    print("\n========== WHOIS INTELLIGENCE ==========")
    for k, v in res.items():
        print(f"{k:20}: {v}")
