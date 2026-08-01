import requests
import os

OCR_API_KEY = "K86004914088957"
OCR_URL = "https://api.ocr.space/parse/image"

def generate_ocr_summary():
    """
    Reads the Playwright screenshot, sends it to OCR.space, and generates a smart description.
    """
    image_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "scrapes", "current_target.png")
    
    if not os.path.exists(image_path):
        return None
        
    try:
        with open(image_path, 'rb') as f:
            payload = {
                'apikey': OCR_API_KEY,
                'language': 'eng',
                'isOverlayRequired': False
            }
            # Timeout is slightly higher for free tier APIs
            res = requests.post(OCR_URL, files={'filename': f}, data=payload, timeout=20)
            
            if res.status_code == 200:
                data = res.json()
                if not data.get("IsErroredOnProcessing"):
                    parsed_results = data.get("ParsedResults", [])
                    if parsed_results:
                        text_lower = parsed_results[0].get("ParsedText", "").lower()
                        original_text = parsed_results[0].get("ParsedText", "")
                        
                        # Clean the text snippet (remove newlines and extra spaces)
                        import re
                        clean_text = re.sub(r'\s+', ' ', original_text).strip()
                        snippet = clean_text[:130] if len(clean_text) > 130 else clean_text
                        
                        if len(snippet) < 5:
                            return "The website contains very little or no readable text."
                            
                        # Generate a smart summary based on keywords
                        prefix = "General content detected:"
                        if any(word in text_lower for word in ['password', 'login', 'sign in', 'log in', 'forgot']):
                            prefix = "Login Page Detected:"
                        elif any(word in text_lower for word in ['credit card', 'payment', 'checkout', 'buy']):
                            prefix = "Payment/Checkout Page Detected:"
                        elif any(word in text_lower for word in ['verify', 'confirm your identity', 'account locked']):
                            prefix = "Verification/Alert Page Detected:"
                            
                        return f"{prefix} '{snippet}...'"
                else:
                    print(f"[OCR] API Processing Error: {data.get('ErrorMessage')}")
            else:
                print(f"[OCR] HTTP Error: {res.status_code}")
                
    except Exception as e:
        print(f"[OCR] Exception: {e}")
        
    return None

if __name__ == "__main__":
    print(generate_ocr_summary())
