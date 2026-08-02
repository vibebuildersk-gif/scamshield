from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import os

# Fix Playwright on Render: force it to look in the local project directory for Chromium
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"

from utils.url_features import extract_url_features
from utils.html_features import extract_html_features
from utils.whois_features import extract_whois_features
from utils.behavior_analyzer import analyze_behavior

app = FastAPI(title="Advanced Phishing Detection API")

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

MODEL_PATH = os.path.join(BASE_DIR, "models", "advanced_rf_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "advanced_feature_names.pkl")

# Load model globally
model = None
feature_names = None

@app.on_event("startup")
def load_model():
    global model, feature_names
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
        model = joblib.load(MODEL_PATH)
        feature_names = joblib.load(FEATURES_PATH)
    else:
        print("WARNING: Advanced ML Model not found! Run train_advanced.py first.")

class ScanRequest(BaseModel):
    url: str

@app.post("/api/scan-qr")
async def scan_qr_code(file: UploadFile = File(...)):
    contents = await file.read()
    from utils.qr_analyzer import decode_qr_image, analyze_qr_string
    
    # 1. Decode Image
    payload = decode_qr_image(contents)
    if not payload:
        return {"error": "Could not detect or decode a QR code in the provided image.", "risk_level": "Unknown"}
        
    # 2. Analyze Payload
    analysis_results = analyze_qr_string(payload)
    return analysis_results


@app.post("/api/scan")
def scan_url(req: ScanRequest):
    url = req.url
    if not url.startswith("http"):
        url = "https://" + url
        
    print(f"Scanning: {url}")
    
    from utils.urlscan_api import submit_to_urlscan, poll_urlscan_result, _get_fallback_data
    from utils.virustotal_api import check_virustotal
    from utils.ocr_analyzer import generate_ocr_summary
    import concurrent.futures
    
    # Submit to URLScan immediately
    uid = submit_to_urlscan(url)
    
    # Run ML/Behavior Extraction and URLScan polling concurrently
    with concurrent.futures.ThreadPoolExecutor() as executor:
        behavior_future = executor.submit(analyze_behavior, url)
        if uid:
            urlscan_future = executor.submit(poll_urlscan_result, uid)
            
        behavior_results = behavior_future.result()
        urlscan_data = urlscan_future.result() if uid else _get_fallback_data()

    # Fallback to VirusTotal if URLScan failed
    vt_data = None
    if urlscan_data.get("asn_name") == "API Timeout" or not uid:
        print("[Fallback] URLScan failed, querying VirusTotal...")
        vt_data = check_virustotal(url)

    # 1. Extract all features exactly like we did in generate_dataset.py
    features = {}
    html_content = behavior_results.pop("_raw_html", None)
    final_url = behavior_results.pop("_final_url", url)
    
    features.update(extract_url_features(final_url))
    features.update(extract_whois_features(final_url))
    features.update(extract_html_features(final_url, html=html_content))
    features.update(behavior_results)
    
    # Convert booleans to 1/0
    for k, v in features.items():
        if isinstance(v, bool):
            features[k] = int(v)
            
    # OCR Generation
    ocr_summary = None
    if not features.get("is_site_dead"):
        print("[OCR] Site is alive, generating visual description...")
        ocr_summary = generate_ocr_summary()
            
    if model is None or feature_names is None:
        # Return just the extracted features if model isn't built yet
        return {
            "prediction": "Unknown (Model Not Trained)",
            "confidence": 0,
            "raw_features": features
        }
        
    # Align features with the exact columns the ML model expects
    final_features = {}
    for fn in feature_names:
        final_features[fn] = features.get(fn, 0)
        
    df = pd.DataFrame([final_features])
    
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    
    # Overfitting Fix: High Authority Baseline Override
    if features.get("IsHighAuthority", 0) == 1:
        prediction = 0
        probability = [1.0, 0.0]
        
    phishing_prob = probability[1]
    
    # --- Extract your telemetry inputs ---
    domain_age = features.get("DomainAgeDays", -1)
    has_password_field = features.get("HasPasswordField", 0) == 1
    has_bank_fields = features.get("HasBankDataFields", 0) == 1
    suspicious_action = features.get("HasSuspiciousFormAction", 0) == 1
    
    # --- The Safe-Shield Decision Layer ---
    # Only give a "free pass" if the site isn't actively harvesting highly critical credentials
    is_actively_harvesting = has_password_field or has_bank_fields or suspicious_action
    
    # Free Cloud-Host Abuse Filter
    free_hosts = [
        '.web.app', 
        '.firebaseapp.com', 
        '.vercel.app', 
        '.netlify.app', 
        '.github.io', 
        '.herokuapp.com',
        '.xsph.ru',
        '.sprinthost.ru'
    ]
    is_free_host = any(free_host in url.lower() for free_host in free_hosts)
    
    # Phase 2.5: Visual Screenshot Engine
    from utils.visual_analysis import calculate_visual_similarity
    screenshot_path = features.get("_screenshot_path", "")
    is_spoofing, brand_name, sim_pct = calculate_visual_similarity(screenshot_path)
    
    # If it is a free host but visually unique and not harvesting
    if is_free_host and not is_spoofing and not is_actively_harvesting:
        phishing_prob = max(0.05, phishing_prob - 0.50) # Deflate false alarms safely!
    
    if domain_age > 365 and not is_actively_harvesting and not is_free_host:
        # Trigger 1: Is it a heavily restricted institutional domain registry? (.ac.in, .edu, .gov)
        if any(trusted_tld in url.lower() for trusted_tld in ['.ac.in', '.edu', '.gov.in', '.gov']):
            phishing_prob = phishing_prob * 0.10  # Slash confidence by 90%
        
        # Trigger 2: Standard old domain with minor frontend anomalies (like IIT Bombay's hidden elements)
        else:
            phishing_prob = phishing_prob * 0.35  # Slash confidence by 65%
            
    # Recalculate final verdict based on the adjusted probability threshold (0.50)
    prediction = 1 if phishing_prob >= 0.50 else 0
    probability = [1.0 - phishing_prob, phishing_prob]
        
    # ML Override Logic (Cloud Intelligence is Ground Truth)
    api_is_malicious = False
    api_is_clean = False
    
    if vt_data:
        if vt_data["is_malicious"]:
            api_is_malicious = True
        elif vt_data["overall_score"] != "API Timeout":
            api_is_clean = True
    else:
        if urlscan_data["is_malicious"]:
            api_is_malicious = True
        elif urlscan_data["asn_name"] != "API Timeout":
            api_is_clean = True
            
    if api_is_malicious:
        prediction = 1
        probability = [0.01, 0.99]
    elif api_is_clean:
        prediction = 0
        probability = [0.99, 0.01]

    confidence = max(probability) * 100
    
    return {
        "prediction": "Legitimate" if prediction == 0 else "Phishing",
        "confidence": round(confidence, 2),
        "phishing_probability": round(probability[1] * 100, 2),
        "legitimate_probability": round(probability[0] * 100, 2),
        "raw_features": features,
        "urlscan": urlscan_data,
        "virustotal": vt_data,
        "ocr_summary": ocr_summary,
        "screenshot_url": features.get("cloudinary_url") or urlscan_data.get("screenshot_url", "")
    }

if __name__ == "__main__":
    import uvicorn
    import os
    # Run server locally or via cloud provider port
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
