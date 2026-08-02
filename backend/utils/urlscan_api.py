import requests
import time

URLSCAN_API_KEY = "019fbd12-747f-740e-b884-10dfbb54b605"
SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/{}/"

def submit_to_urlscan(url):
    """
    Submits a URL to URLScan.io and returns the UUID for polling.
    """
    headers = {
        'API-Key': URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        "url": url,
        "visibility": "public"
    }
    
    try:
        response = requests.post(SUBMIT_URL, headers=headers, json=data)
        if response.status_code == 200:
            return response.json().get('uuid')
        elif response.status_code == 429:
            print("[URLScan] Rate limited (429) during submission.")
            return None
        elif response.status_code == 400:
            print(f"[URLScan] Bad request (400) during submission: {response.text}")
            return None
        else:
            print(f"[URLScan] Submission error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"[URLScan Error] {e}")
        return None

def poll_urlscan_result(uuid):
    """
    Polls the result endpoint until it's ready, with a 2-second sleep to avoid 429 errors.
    Returns the structured intelligence data.
    """
    if not uuid:
        return _get_fallback_data()

    headers = {'API-Key': URLSCAN_API_KEY}
    url = RESULT_URL.format(uuid)
    
    max_retries = 15
    
    for i in range(max_retries):
        try:
            time.sleep(2)  # Pro-tip spacing
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return _parse_urlscan_data(data)
            elif response.status_code == 404:
                # Still processing
                continue
            elif response.status_code == 429:
                print("[URLScan] Rate limited (429) during polling.")
                time.sleep(5)
                continue
            else:
                print(f"[URLScan] Polling error: {response.status_code}")
                return _get_fallback_data()
                
        except Exception as e:
            print(f"[URLScan Polling Error] {e}")
            break
            
    return _get_fallback_data()

def _parse_urlscan_data(data):
    """
    Extracts the most critical threat intelligence from the massive URLScan JSON.
    """
    page = data.get("page", {})
    verdicts = data.get("verdicts", {})
    
    # Extract ASN and Country
    asn_name = page.get("asnname", "Unknown ASN")
    country = page.get("country", "Unknown Country")
    
    # Overall Verdict
    overall_score = verdicts.get("overall", {}).get("score", 0)
    is_malicious = verdicts.get("overall", {}).get("malicious", False)
    
    # Brand Impersonation
    brands = verdicts.get("urlscan", {}).get("brands", [])
    impersonated_brand = brands[0] if brands else "None Detected"
    
    # Extract HTTP Security Headers (Clickjacking detection)
    security_headers_missing = True
    try:
        # urlscan puts response headers in data.requests
        requests_list = data.get("data", {}).get("requests", [])
        if requests_list:
            headers = requests_list[0].get("response", {}).get("response", {}).get("headers", {})
            if "x-frame-options" in headers or "content-security-policy" in headers:
                security_headers_missing = False
    except:
        pass

    return {
        "asn_name": asn_name,
        "country": country,
        "overall_score": overall_score,
        "is_malicious": is_malicious,
        "impersonated_brand": impersonated_brand,
        "security_headers_missing": security_headers_missing,
        "report_url": data.get("task", {}).get("reportURL", "#"),
        "screenshot_url": data.get("task", {}).get("screenshotURL", f"https://urlscan.io/screenshots/{data.get('task', {}).get('uuid', '')}.png") if data.get("task", {}).get("uuid") else ""
    }

def _get_fallback_data():
    return {
        "asn_name": "API Timeout",
        "country": "Unknown",
        "overall_score": 0,
        "is_malicious": False,
        "impersonated_brand": "Unknown",
        "security_headers_missing": False,
        "report_url": "#",
        "screenshot_url": ""
    }

if __name__ == "__main__":
    # Test script
    test_url = "https://chatgpt.com/"
    print(f"Submitting {test_url} to URLScan...")
    uid = submit_to_urlscan(test_url)
    if uid:
        print(f"Got UUID: {uid}. Waiting for results...")
        res = poll_urlscan_result(uid)
        print("Final Results:")
        for k, v in res.items():
            print(f"{k}: {v}")
    else:
        print("Submission failed.")
