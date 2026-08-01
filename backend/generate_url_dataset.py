import pandas as pd
from utils.url_features import extract_url_features
import time

CSV_PATH = r"C:\Users\khang\OneDrive\Desktop\5th sem mini projects\5th sem mini project ml model\dataset\PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_PATH = "Aligned_URL_Dataset.csv"
TARGET_SAMPLES = 50000  # Generate a large dataset instantly

print(f"Loading original dataset...")
df = pd.read_csv(CSV_PATH)
df = df.dropna(subset=['URL', 'label']).sample(frac=1, random_state=42).reset_index(drop=True)

results = []
phishing_count = 0
legit_count = 0

start_time = time.time()
print("Extracting aligned URL features...")

for index, row in df.iterrows():
    if phishing_count >= TARGET_SAMPLES and legit_count >= TARGET_SAMPLES:
        break
        
    url = row['URL']
    label = row['label']
    
    # Balance dataset
    if label == 0 and phishing_count >= TARGET_SAMPLES:
        continue
    if label == 1 and legit_count >= TARGET_SAMPLES:
        continue
        
    try:
        # Enforce https prefix if missing just like app.py does
        if not url.startswith("http"):
            url = "https://" + url
            
        features = extract_url_features(url)
        
        # Copy HTML features from the original dataset so we can train on them!
        html_feature_keys = [
            "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
            "HasDescription", "HasFavicon", "HasTitle", "HasCopyrightInfo",
            "NoOfPopup", "NoOfiFrame", "IsResponsive", "NoOfImage",
            "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
            "HasBankDataFields", "HasSuspiciousFormAction"
        ]
        
        for hk in html_feature_keys:
            # Some features might not be in the original dataset exactly as named, so we use .get with default 0
            features[hk] = row.get(hk, 0)
            
        features['label'] = label
        results.append(features)
        
        if label == 0:
            phishing_count += 1
        else:
            legit_count += 1
            
    except Exception:
        continue

end_time = time.time()
aligned_df = pd.DataFrame(results)
aligned_df.to_csv(OUTPUT_PATH, index=False)
print(f"Generated {len(aligned_df)} perfectly aligned samples in {end_time - start_time:.2f} seconds!")
print(f"Saved to {OUTPUT_PATH}")
