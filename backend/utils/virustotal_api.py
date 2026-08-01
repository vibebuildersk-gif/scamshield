import requests
import base64
import time

VT_API_KEY = "89eb538dd8541f61e4ba0e6d542701e9061c388507caf5f17b7de7d22d4afa5e"

def check_virustotal(url):
    """
    Queries VirusTotal for a URL. 
    First tries to get an existing report (very fast). 
    If not found, submits a new scan and polls.
    """
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    # 1. Try to get existing report
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if res.status_code == 200:
            data = res.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return _parse_stats(stats)
        elif res.status_code == 404:
            # 2. Submit new scan
            submit_data = {"url": url}
            headers["content-type"] = "application/x-www-form-urlencoded"
            submit_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=submit_data)
            
            if submit_res.status_code == 200:
                analysis_id = submit_res.json().get("data", {}).get("id")
                return poll_virustotal(analysis_id)
            else:
                print(f"[VirusTotal] Submit Error: {submit_res.status_code}")
                return _fallback()
        else:
            print(f"[VirusTotal] Fetch Error: {res.status_code}")
            return _fallback()
            
    except Exception as e:
        print(f"[VirusTotal Exception] {e}")
        return _fallback()

def poll_virustotal(analysis_id):
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    for _ in range(5):
        time.sleep(3)
        res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if res.status_code == 200:
            data = res.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                return _parse_stats(stats)
    return _fallback()

def _parse_stats(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    
    total = malicious + suspicious + harmless + undetected
    is_malicious = (malicious + suspicious) > 0
    
    return {
        "used_vt": True,
        "is_malicious": is_malicious,
        "malicious_votes": malicious + suspicious,
        "total_votes": total,
        "overall_score": f"{malicious + suspicious}/{total}"
    }

def _fallback():
    return {
        "used_vt": True,
        "is_malicious": False,
        "malicious_votes": 0,
        "total_votes": 0,
        "overall_score": "API Timeout"
    }

if __name__ == "__main__":
    print(check_virustotal("https://chatgpt.com"))
