import os
import re
import traceback
import cloudinary
import cloudinary.uploader

from playwright.sync_api import sync_playwright

# Configure Cloudinary
cloudinary.config(
    cloud_name="dafsamoco",
    api_key="641631957764477",
    api_secret="9OllXoVtR0Iv1wmeDWp1GmLQngk",
    secure=True
)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
HTML_DIR = os.path.join(BASE_DIR, "html")

os.makedirs(SCREENSHOT_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)


def safe_filename(url):
    filename = re.sub(r"^https?://", "", url)
    filename = re.sub(r"[^a-zA-Z0-9]", "_", filename)
    return filename


def visit_website(url):

    filename = safe_filename(url)

    screenshot_path = os.path.join(
        SCREENSHOT_DIR,
        filename + ".png"
    )

    html_path = os.path.join(
        HTML_DIR,
        filename + ".html"
    )

    with sync_playwright() as p:

        browser = None

        try:

            browser = p.chromium.launch(
                channel="chrome",
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ]
            )

            page = browser.new_page(
                viewport={
                    "width": 1366,
                    "height": 768
                }
            )

            page.goto(
                url,
                wait_until="load",
                timeout=60000
            )

            page.wait_for_timeout(5000)

            page.screenshot(
                path=screenshot_path
            )
            
            # Upload screenshot to Cloudinary
            cloudinary_url = ""
            try:
                upload_result = cloudinary.uploader.upload(screenshot_path, folder="phishguard_scans")
                cloudinary_url = upload_result.get("secure_url", "")
            except Exception as e:
                print(f"Cloudinary upload failed: {e}")

            # Check for Clickjacking / Transparent Overlays
            has_clickjacking = page.evaluate('''
                () => {
                    let suspicious = false;
                    const elements = document.querySelectorAll('div, iframe');
                    for (let el of elements) {
                        const style = window.getComputedStyle(el);
                        const zIndex = parseInt(style.zIndex);
                        const opacity = parseFloat(style.opacity);
                        const position = style.position;
                        
                        if ((position === 'absolute' || position === 'fixed') && zIndex >= 99 && opacity <= 0.1) {
                            const rect = el.getBoundingClientRect();
                            if (rect.width > window.innerWidth * 0.5 && rect.height > window.innerHeight * 0.5) {
                                suspicious = true;
                                break;
                            }
                        }
                    }
                    return suspicious;
                }
            ''')

            html = page.content()

            with open(
                html_path,
                "w",
                encoding="utf-8"
            ) as f:
                f.write(html)

            result = {
                "title": page.title(),
                "final_url": page.url,
                "html": html,
                "html_file": html_path,
                "screenshot": screenshot_path,
                "cloudinary_url": cloudinary_url,
                "has_clickjacking": has_clickjacking
            }

            browser.close()

            return result

        except Exception:

            traceback.print_exc()

            if browser:
                browser.close()

            return None


if __name__ == "__main__":

    url = input("Enter URL : ")

    result = visit_website(url)

    print("\n========== RESULT ==========\n")

    print(result)