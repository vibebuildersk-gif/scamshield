import os
import sys

from utils.whois_features import extract_whois_features
from utils.html_features import extract_html_features
from utils.browser import visit_website
from utils.behavior_analyzer import analyze_behavior

def test_url(url):
    print("=" * 60)
    print(f"🕵️  STARTING ADVANCED SECURITY SCAN FOR: {url}")
    print("=" * 60)
    
    # 1. Domain Intelligence (WHOIS)
    print("\n[1/3] Running WHOIS Domain Intelligence...")
    whois_data = extract_whois_features(url)
    for k, v in whois_data.items():
        print(f"  -> {k}: {v}")
        
    if whois_data.get("DomainAgeDays") != -1 and whois_data.get("DomainAgeDays", 999) < 30:
        print("  ⚠️  WARNING: Domain is very young (less than 30 days old)!")

    # 2. Browser Rendering & Clickjacking
    print("\n[2/3] Launching Playwright Browser (Checking for Clickjacking)...")
    browser_data = visit_website(url)
    
    if not browser_data:
        print("  ❌ Failed to load website in browser.")
        return
        
    print(f"  -> Title: {browser_data['title']}")
    print(f"  -> Screenshot Saved: {browser_data['screenshot']}")
    print(f"  -> Clickjacking / Overlay Detected: {browser_data['has_clickjacking']}")
    
    if browser_data.get("has_clickjacking"):
        print("  ⚠️  CRITICAL WARNING: Invisible clickjacking overlay detected!")

    # 3. Data Theft Form Detection
    print("\n[3/3] Scanning HTML for Data Theft (Credit Cards/SSN)...")
    html_data = extract_html_features(url)
    
    print(f"  -> Suspicious Bank/Data Fields: {bool(html_data.get('HasBankDataFields'))}")
    print(f"  -> Suspicious Form Action (External): {bool(html_data.get('HasSuspiciousFormAction'))}")
    
    if html_data.get("HasBankDataFields"):
        print("  ⚠️  WARNING: Page is asking for sensitive financial/personal data!")
    if html_data.get("HasSuspiciousFormAction"):
        print("  ⚠️  CRITICAL WARNING: Form submits data to a highly suspicious third-party!")
        
    # 4. Browser Behavior Analysis (Phase 2)
    print("\n[4/4] Phase 2: Running Deep Browser Behavior Analysis...")
    behavior = analyze_behavior(url)
    
    for k, v in behavior.items():
        if v:
            # Highlight true detections in yellow/red conceptually
            print(f"  -> {k}: True ⚠️")
        else:
            print(f"  -> {k}: False")
    
    if behavior.get("auto_redirects") or behavior.get("redirect_chain_length") > 1:
        print("  ⚠️  WARNING: Suspicious redirects detected!")
    if behavior.get("hidden_forms") or behavior.get("invisible_iframes"):
        print("  ⚠️  CRITICAL WARNING: Hidden elements designed to steal data detected!")
        
    print("\n" + "=" * 60)
    print("✅ SCAN COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    target = input("Enter a URL to scan: ")
    test_url(target)
