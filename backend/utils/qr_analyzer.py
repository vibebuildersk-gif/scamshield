import re
import idna
from urllib.parse import urlparse
import cv2
import numpy as np
import zxingcpp

def decode_qr_image(image_bytes):
    """
    Decodes a QR code from raw image bytes.
    Returns the string payload or None if no QR code is found.
    """
    # Convert bytes to numpy array for cv2
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img is None:
        return None
        
    barcode = zxingcpp.read_barcode(img)
    if barcode:
        return barcode.text
        
    return None

from urllib.parse import urlparse, parse_qs

def analyze_qr_string(payload):
    """
    Analyzes a QR code string payload for various threats.
    Returns a dictionary of boolean flags, a list of warning messages, and payment details.
    """
    warnings = []
    flags = {
        "is_reverse_payment": False,
        "is_intent_hijacking": False,
        "is_unicode_spoofing": False,
        "is_suspicious": False
    }
    
    payload_lower = payload.lower()
    
    # 1. Payment QR Detection
    payment_indicators = ['upi://pay', '000201', 'paypal.me', 'paytm', 'phonepe', 'gpay', 'bharatqr', 'upi://']
    is_payment_qr = any(ind in payload_lower for ind in payment_indicators)
    
    payment_details = {}
    
    if is_payment_qr:
        # Extract UPI details if present
        if 'upi://pay' in payload_lower or 'upi://' in payload_lower:
            try:
                parsed = urlparse(payload)
                query_params = parse_qs(parsed.query)
                payment_details['payee_name'] = query_params.get('pn', [''])[0]
                payment_details['payee_vpa'] = query_params.get('pa', [''])[0]
                payment_details['amount'] = query_params.get('am', [''])[0]
                payment_details['mcc'] = query_params.get('mc', [''])[0]
            except Exception:
                pass
    else:
        # It's NOT a payment QR
        content_type = "Text/Unknown"
        if payload_lower.startswith("http"): content_type = "Website Link"
        elif payload.startswith("WIFI:"): content_type = "WiFi Connection Request"
        elif payload.startswith("SMSTO:"): content_type = "SMS Draft"
        elif payload.startswith("TEL:"): content_type = "Phone Call"
        
        warnings.append(f"NON-PAYMENT QR ALERT: This is NOT a payment QR code. If you scanned this expecting to pay someone, you are being scammed. This QR code actually contains a [{content_type}].")
    
    # 2. The Reverse Payment Scam (Request Fraud)
    if "am=" in payload_lower or any(phrase in payload_lower for phrase in ["receive money", "request money", "pay to"]):
        flags["is_reverse_payment"] = True
        warnings.append("Reverse Payment Alert: This QR code initiates a money request. Scanning a QR code ALWAYS deducts money from your account. You never need to scan to receive money.")
        
    # 4. Intent Hijacking & App Spoofing
    if payload.startswith("WIFI:"):
        flags["is_intent_hijacking"] = True
        warnings.append("Intent Hijacking: This QR code attempts to connect your device to a Wi-Fi network automatically. This could be a rogue hotspot.")
    elif payload.startswith("SMSTO:"):
        flags["is_intent_hijacking"] = True
        warnings.append("Intent Hijacking: This QR code attempts to draft an SMS message, potentially to a premium-rate number.")
    elif payload.startswith("TEL:"):
        flags["is_intent_hijacking"] = True
        warnings.append("Intent Hijacking: This QR code attempts to initiate a phone call, potentially to a scam number.")
        
    if "play.google.com/store/apps" not in payload_lower and "apps.apple.com" not in payload_lower:
        if "apk" in payload_lower and "download" in payload_lower:
            flags["is_intent_hijacking"] = True
            warnings.append("App Spoofing: This QR code redirects to download an APK file outside of official app stores. High risk of malware/spyware.")

    # 5. Unicode Spoofing (Homograph Attacks)
    if payload_lower.startswith("http://") or payload_lower.startswith("https://"):
        parsed = urlparse(payload)
        domain = parsed.netloc
        try:
            punycode_domain = idna.encode(domain).decode('utf-8')
            if punycode_domain != domain:
                if punycode_domain.startswith("xn--"):
                    flags["is_unicode_spoofing"] = True
                    warnings.append(f"Unicode Spoofing (Homograph Attack): The domain uses lookalike characters from different alphabets to mimic a legitimate site. Real domain layout: {punycode_domain}")
        except idna.IDNAError:
            flags["is_unicode_spoofing"] = True
            warnings.append("Unicode Spoofing Alert: The domain contains invalid or malformed international characters.")

    # Calculate Risk Score (0-100%)
    risk_score = 0
    if not is_payment_qr:
        risk_score = 85  # High baseline if it's not a payment QR but scanned in a payment context
    
    if flags["is_reverse_payment"]: risk_score = max(risk_score, 95)
    if flags["is_intent_hijacking"]: risk_score = max(risk_score, 90)
    if flags["is_unicode_spoofing"]: risk_score = max(risk_score, 99)
    
    if is_payment_qr and risk_score == 0 and payment_details.get('amount') and not payment_details.get('mcc'):
        # Dynamic QR without MCC (P2P instead of P2M)
        risk_score = 40
        warnings.append("Caution: This is a Person-to-Person (P2P) payment request, not a verified Merchant. Verify the recipient name carefully.")
        
    if risk_score >= 50:
        flags["is_suspicious"] = True

    return {
        "payload": payload,
        "is_payment_qr": is_payment_qr,
        "payment_details": payment_details,
        "flags": flags,
        "warnings": warnings,
        "risk_score": risk_score,
        "risk_level": "High" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low"
    }
