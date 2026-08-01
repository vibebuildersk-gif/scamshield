import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    )
}


def extract_html_features(url, html=None):
    features = {}

    try:
        if html is None:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=10,
                allow_redirects=True
            )
            html = response.text

        soup = BeautifulSoup(html, "lxml")

    except Exception:
        return {
            "NoOfImage": 0,
            "NoOfCSS": 0,
            "NoOfJS": 0,
            "NoOfSelfRef": 0,
            "NoOfEmptyRef": 0,
            "NoOfExternalRef": 0,
            "HasSubmitButton": 0,
            "HasHiddenFields": 0,
            "HasPasswordField": 0,
            "HasDescription": 0,
            "HasFavicon": 0,
            "HasTitle": 0,
            "HasCopyrightInfo": 0,
            "NoOfPopup": 0,
            "NoOfiFrame": 0,
            "LineOfCode": 0,
            "LargestLineLength": 0,
            "IsResponsive": 0,
            "HasBankDataFields": 0,
            "HasSuspiciousFormAction": 0,
        }

    domain = urlparse(url).netloc

    # ---------------------------------------------------
    # Images
    # ---------------------------------------------------

    features["NoOfImage"] = len(soup.find_all("img"))

    # ---------------------------------------------------
    # CSS
    # ---------------------------------------------------

    features["NoOfCSS"] = len(
        soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower())
    )

    # ---------------------------------------------------
    # JavaScript
    # ---------------------------------------------------

    features["NoOfJS"] = len(soup.find_all("script"))

    # ---------------------------------------------------
    # Links
    # ---------------------------------------------------

    self_ref = 0
    external = 0
    empty = 0

    for tag in soup.find_all("a", href=True):

        href = tag["href"].strip()

        if href == "" or href == "#":
            empty += 1
            continue

        absolute = urljoin(url, href)

        if urlparse(absolute).netloc == domain:
            self_ref += 1
        else:
            external += 1

    features["NoOfSelfRef"] = self_ref
    features["NoOfExternalRef"] = external
    features["NoOfEmptyRef"] = empty

    # ---------------------------------------------------
    # Forms
    # ---------------------------------------------------

    features["HasSubmitButton"] = int(
        soup.find("input", {"type": "submit"}) is not None
        or soup.find("button", {"type": "submit"}) is not None
    )

    features["HasPasswordField"] = int(
        soup.find("input", {"type": "password"}) is not None
    )

    features["HasHiddenFields"] = int(
        soup.find("input", {"type": "hidden"}) is not None
    )

    # ---------------------------------------------------
    # Data Theft / Advanced Form Analysis
    # ---------------------------------------------------

    # Check for fields asking for credit cards, SSN, bank details
    suspicious_input_names = [
        "cc", "creditcard", "cardnumber", "cvv", "cvc", "exp",
        "ssn", "socialsecurity", "routing", "accountnumber",
        "bank", "pin"
    ]
    
    has_bank_data = False
    for inp in soup.find_all("input"):
        name = inp.get("name", "").lower()
        id_attr = inp.get("id", "").lower()
        placeholder = inp.get("placeholder", "").lower()
        
        if any(sus in name or sus in id_attr or sus in placeholder for sus in suspicious_input_names):
            has_bank_data = True
            break
            
    features["HasBankDataFields"] = int(has_bank_data)
    
    # Check for suspicious form actions (e.g., sending data to a free host or generic script)
    has_suspicious_action = False
    suspicious_domains = ["discord.com", "api.telegram.org", "pastebin.com", "000webhostapp.com"]
    for form in soup.find_all("form"):
        action = form.get("action", "").lower()
        
        # If action points to a suspicious third party
        if any(sus_domain in action for sus_domain in suspicious_domains):
            has_suspicious_action = True
            break
        
        # If action points to a php script on a completely different domain
        if action.startswith("http") and urlparse(action).netloc != domain:
            has_suspicious_action = True
            break
            
    features["HasSuspiciousFormAction"] = int(has_suspicious_action)

    # ---------------------------------------------------
    # Meta Description
    # ---------------------------------------------------

    features["HasDescription"] = int(
        soup.find("meta", attrs={"name": "description"}) is not None
    )

    # ---------------------------------------------------
    # Favicon
    # ---------------------------------------------------

    favicon = soup.find(
        "link",
        rel=lambda x: x and "icon" in x.lower()
    )

    features["HasFavicon"] = int(favicon is not None)

    # ---------------------------------------------------
    # Title
    # ---------------------------------------------------

    title = soup.find("title")

    features["HasTitle"] = int(
        title is not None and title.text.strip() != ""
    )

    # ---------------------------------------------------
    # Copyright
    # ---------------------------------------------------

    text = soup.get_text().lower()

    features["HasCopyrightInfo"] = int(
        "copyright" in text or "©" in text
    )

    # ---------------------------------------------------
    # Popup Detection
    # ---------------------------------------------------

    popup = 0

    scripts = soup.find_all("script")

    for script in scripts:

        content = script.text.lower()

        if (
            "alert(" in content
            or "confirm(" in content
            or "prompt(" in content
        ):
            popup += 1

    features["NoOfPopup"] = popup

    # ---------------------------------------------------
    # iframe
    # ---------------------------------------------------

    features["NoOfiFrame"] = len(
        soup.find_all("iframe")
    )

    # ---------------------------------------------------
    # Responsive
    # ---------------------------------------------------

    viewport = soup.find(
        "meta",
        attrs={"name": "viewport"}
    )

    features["IsResponsive"] = int(viewport is not None)

    # ---------------------------------------------------
    # Line statistics
    # ---------------------------------------------------

    lines = html.splitlines()

    features["LineOfCode"] = len(lines)

    if lines:
        features["LargestLineLength"] = max(
            len(line)
            for line in lines
        )
    else:
        features["LargestLineLength"] = 0

    return features


if __name__ == "__main__":

    url = input("Enter URL : ")

    data = extract_html_features(url)

    print()

    for key, value in data.items():
        print(f"{key:25}: {value}")