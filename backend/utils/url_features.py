from urllib.parse import urlparse, unquote
from collections import Counter
import tldextract
import math
import re


TRUSTED_TLDS = {
    "com": 1.00,
    "org": 0.95,
    "edu": 0.98,
    "gov": 0.99,
    "net": 0.90,
    "io": 0.85,
    "co": 0.80,
    "in": 0.88,
}

BRAND_KEYWORDS = [
    "google",
    "amazon",
    "facebook",
    "paypal",
    "apple",
    "microsoft",
    "instagram",
    "github",
    "linkedin",
    "twitter",
    "netflix",
    "bank",
    "login",
    "secure",
    "verify",
]

AUTHORITY_ALLOWLIST = [
    "github.com",
    "codesandbox.io",
    "vercel.app",
    "glitch.me",
    "html5test.co",
]



def calculate_entropy(text):
    if not text:
        return 0

    counter = Counter(text)
    entropy = 0

    for count in counter.values():
        p = count / len(text)
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def longest_character_run(text):
    if not text:
        return 0

    longest = 1
    current = 1

    for i in range(1, len(text)):
        if text[i].isalnum() == text[i - 1].isalnum():
            current += 1
            longest = max(longest, current)
        else:
            current = 1

    return round(longest / len(text), 4)


def similarity_score(url):
    url = url.lower()

    for brand in BRAND_KEYWORDS:
        if brand in url:
            return 100

    return 0


def extract_url_features(url):

    # ANTI-OVERFITTING: Strip scheme and 'www.' to prevent the model from hyper-fixating on them
    # because the PhiUSIIL dataset has a massive bias where 100% of legitimate URLs have 'www.'
    clean_url = url.lower().replace("https://", "").replace("http://", "")
    if clean_url.startswith("www."):
        clean_url = clean_url[4:]
        
    # We still need the original parsed URL for some TLD extraction, but we use clean_url for character counts
    parsed = urlparse(url if "://" in url else "https://" + url)
    decoded = unquote(clean_url)

    ext = tldextract.extract(clean_url)

    domain = ext.domain
    suffix = ext.suffix

    letters = sum(c.isalpha() for c in decoded)
    digits = sum(c.isdigit() for c in decoded)
    special = sum(not c.isalnum() for c in decoded)

    features = {}

    # -------------------------------------------------
    # Basic Features
    # -------------------------------------------------

    features["URLLength"] = len(decoded)
    features["DomainLength"] = len(domain)
    features["SubDomainLength"] = len(ext.subdomain) if ext.subdomain else 0

    features["IsDomainIP"] = int(
        bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parsed.hostname or ""))
    )
    
    # High Authority baseline check
    root_domain = f"{domain}.{suffix}".lower()
    features["IsHighAuthority"] = int(root_domain in AUTHORITY_ALLOWLIST)

    features["TLDLength"] = len(suffix)

    features["NoOfSubDomain"] = (
        len(ext.subdomain.split("."))
        if ext.subdomain
        else 0
    )

    features["IsHTTPS"] = int(parsed.scheme == "https")

    # -------------------------------------------------
    # Character Counts
    # -------------------------------------------------

    features["NoOfLettersInURL"] = letters
    features["NoOfDegitsInURL"] = digits

    features["LetterRatioInURL"] = round(
        letters / len(decoded),
        4
    ) if decoded else 0

    features["DegitRatioInURL"] = round(
        digits / len(decoded),
        4
    ) if decoded else 0

    features["NoOfEqualsInURL"] = decoded.count("=")
    features["NoOfQMarkInURL"] = decoded.count("?")
    features["NoOfAmpersandInURL"] = decoded.count("&")

    features["NoOfOtherSpecialCharsInURL"] = len(
        re.findall(r"[!@#$%^*(){}\[\];:,<>/~`|\\]", decoded)
    )

    features["SpacialCharRatioInURL"] = round(
        special / len(decoded),
        4
    ) if decoded else 0

    # -------------------------------------------------
    # Obfuscation
    # -------------------------------------------------

    obfuscated = decoded.count("%") + decoded.count("@")

    features["HasObfuscation"] = int(
        "%" in decoded
        or "@" in decoded
        or "//" in decoded[8:]
    )

    features["NoOfObfuscatedChar"] = obfuscated

    features["ObfuscationRatio"] = round(
        obfuscated / len(decoded),
        4
    ) if decoded else 0

    # -------------------------------------------------
    # Advanced URL Features
    # -------------------------------------------------

    features["HasPunycode"] = int("xn--" in parsed.netloc.lower())

    # Check for Cloud/Dynamic DNS abuse
    cloud_dns = ["amazonaws.com", "appspot.com", "duckdns.org", "herokuapp.com", "firebaseapp.com", "azurewebsites.net"]
    features["IsCloudOrDynamicDNS"] = int(any(c in parsed.netloc.lower() for c in cloud_dns))

    # Smarter Brand Similarity & Contextual Co-occurrence
    features["URLSimilarityIndex"] = 0
    decoded_lower = decoded.lower()
    domain_lower = domain.lower()
    
    # Check 1: Brand masked in path or subdomain
    for brand in BRAND_KEYWORDS:
        if brand in decoded_lower and brand != domain_lower:
            features["URLSimilarityIndex"] = 100
            break
            
    # Check 2: Contextual Co-occurrence (e.g., "free" + "bank")
    if features["URLSimilarityIndex"] == 0:
        sensitive_words = ["login", "verify", "account", "bank", "wallet", "secure"]
        if "free" in decoded_lower and any(s in decoded_lower for s in sensitive_words):
            features["URLSimilarityIndex"] = 100

    features["CharContinuationRate"] = longest_character_run(decoded)

    features["URLCharProb"] = calculate_entropy(decoded)

    features["TLDLegitimateProb"] = TRUSTED_TLDS.get(
        suffix.lower(),
        0.40
    )

    return features


if __name__ == "__main__":

    url = input("Enter URL: ")

    data = extract_url_features(url)

    print("\nExtracted URL Features\n")

    for key, value in data.items():
        print(f"{key:30}: {value}")