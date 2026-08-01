import pandas as pd
import os
import sys

from utils.url_features import extract_url_features
from utils.html_features import extract_html_features
from utils.whois_features import extract_whois_features
from utils.behavior_analyzer import analyze_behavior

CSV_PATH = r"C:\Users\khang\OneDrive\Desktop\5th sem mini projects\5th sem mini project ml model\dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_PATH = "Advanced_Phishing_Dataset.csv"
TARGET_SAMPLES = 30000  # 30,000 legitimate, 30,000 phishing (60,000 Total)

def process_url(url):
    print(f"\n[Scraping] {url}")
    # 1. Base URL features
    url_f = extract_url_features(url)
    
    # 2. WHOIS
    whois_f = extract_whois_features(url)
    
    # 3. HTML (requests)
    html_f = extract_html_features(url)
    
    # 4. Behavior (Playwright)
    behavior_f = analyze_behavior(url)
    
    # Combine all
    combined = {}
    combined.update(url_f)
    combined.update(whois_f)
    combined.update(html_f)
    combined.update(behavior_f)
    return combined

if __name__ == "__main__":
    print(f"Loading dataset from: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)
    
    # We drop NAs and Shuffle the dataset randomly
    df = df.dropna(subset=['URL', 'label'])
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    results = []
    
    phishing_count = 0
    legit_count = 0
    
    print(f"Goal: {TARGET_SAMPLES} Phishing URLs, {TARGET_SAMPLES} Legitimate URLs")
    
    for index, row in df.iterrows():
        if phishing_count >= TARGET_SAMPLES and legit_count >= TARGET_SAMPLES:
            break
            
        url = row['URL']
        label = row['label']
        
        if label == 1 and phishing_count >= TARGET_SAMPLES:
            continue
        if label == 0 and legit_count >= TARGET_SAMPLES:
            continue
            
        try:
            # We enforce https prefix if missing just to ensure playwright works
            if not url.startswith("http"):
                url = "https://" + url
                
            features = process_url(url)
            
            # Convert booleans to 1/0 for Machine Learning
            for k, v in features.items():
                if isinstance(v, bool):
                    features[k] = int(v)
            
            features['label'] = label
            features['URL'] = url
            results.append(features)
            
            if label == 1:
                phishing_count += 1
                print(f"[+] Phishing grabbed ({phishing_count}/{TARGET_SAMPLES})")
            else:
                legit_count += 1
                print(f"[+] Legit grabbed ({legit_count}/{TARGET_SAMPLES})")
                
            # Save intermediate progress so we don't lose data if we stop it early
            temp_df = pd.DataFrame(results)
            temp_df.to_csv(OUTPUT_PATH, index=False)
            
        except Exception as e:
            print(f"[-] Failed to process {url}: {e}")
            
    print("\n==============================================")
    print("✅ Dataset generation complete!")
    print(f"✅ Saved completely to {OUTPUT_PATH}")
    print("==============================================")
