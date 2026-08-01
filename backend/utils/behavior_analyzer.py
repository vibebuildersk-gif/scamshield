from playwright.sync_api import sync_playwright

def analyze_behavior(url):
    """
    Actively monitors browser behavior to detect advanced phishing techniques
    that rely on dynamic redirects, popups, and hidden DOM elements.
    """
    import os
    import cloudinary
    import cloudinary.uploader
    
    cloudinary.config(
        cloud_name="dafsamoco",
        api_key="641631957764477",
        api_secret="9OllXoVtR0Iv1wmeDWp1GmLQngk",
        secure=True
    )
    
    # Delete stale screenshot from previous runs
    stale_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "scrapes", "current_target.png")
    if os.path.exists(stale_path):
        try:
            os.remove(stale_path)
        except Exception:
            pass

    results = {
        "is_site_dead": False,
        "dead_reason": None,
        "redirect_chain_length": 0,
        "auto_redirects": False,
        "has_popups": False,
        "has_downloads": False,
        
        "login_forms": False,
        "password_fields": False,
        "otp_fields": False,
        "credit_card_fields": False,
        "bank_fields": False,
        
        "hidden_forms": False,
        "hidden_buttons": False,
        "hidden_links": False,
        "invisible_iframes": False
    }

    redirect_urls = []

    def handle_request(req):
        if req.is_navigation_request() and req.redirected_from:
            redirect_urls.append(req.url)

    def handle_popup(popup):
        results["has_popups"] = True
        
    def handle_download(download):
        results["has_downloads"] = True

    try:
        with sync_playwright() as p:
            # Run invisible browser for cloud compatibility
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True
            )
            page = context.new_page()
            
            # Attach event listeners
            page.on("request", handle_request)
            page.on("popup", handle_popup)
            page.on("download", handle_download)
            
            # Load the page and wait for it to settle visually
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(5000) # Give Cloudflare/React 5 seconds to load
            except Exception as goto_err:
                print(f"[Behavior Analyzer] goto warning: {goto_err}")
                results["is_site_dead"] = True
                results["dead_reason"] = "DNS Error or Unreachable"
            
            # Phase 2.5: Visual Screenshot Engine
            import os
            page.set_viewport_size({"width": 1280, "height": 720})
            screenshot_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "scrapes", "current_target.png")
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            page.screenshot(path=screenshot_path)
            results["_screenshot_path"] = screenshot_path
            
            # Upload screenshot to Cloudinary
            cloudinary_url = ""
            try:
                upload_result = cloudinary.uploader.upload(screenshot_path, folder="phishguard_scans")
                cloudinary_url = upload_result.get("secure_url", "")
            except Exception as e:
                print(f"[Behavior Analyzer] Cloudinary upload failed: {e}")
                
            results["cloudinary_url"] = cloudinary_url
            
            # Evaluate Navigation
            results["redirect_chain_length"] = len(redirect_urls)
            
            # Fetch the fully rendered HTML for other extractors to use
            results["_raw_html"] = page.content()
            
            # If the final URL is totally different, flag it as auto redirect
            final_url = page.url
            results["_final_url"] = final_url
            
            if final_url != url:
                clean_final = final_url.rstrip("/").replace("https://", "http://").replace("www.", "")
                clean_initial = url.rstrip("/").replace("https://", "http://").replace("www.", "")
                if clean_final != clean_initial:
                    results["auto_redirects"] = True

            # JavaScript injection to inspect actual rendered state
            js_payload = """
            () => {
                const dom_results = {
                    login_forms: false,
                    password_fields: false,
                    otp_fields: false,
                    credit_card_fields: false,
                    bank_fields: false,
                    hidden_forms: false,
                    hidden_buttons: false,
                    hidden_links: false,
                    invisible_iframes: false
                };

                // Helper to check if an element is intentionally hidden
                const isHidden = (el) => {
                    const style = window.getComputedStyle(el);
                    return style.display === 'none' || 
                           style.visibility === 'hidden' || 
                           style.opacity === '0' ||
                           parseInt(style.left) < -900 ||
                           parseInt(style.top) < -900;
                };

                // 1. Check Forms
                const forms = document.querySelectorAll('form');
                for (let f of forms) {
                    if (isHidden(f)) dom_results.hidden_forms = true;
                    
                    const html = f.outerHTML.toLowerCase();
                    if (html.includes('login') || html.includes('sign in') || html.includes('auth')) {
                        dom_results.login_forms = true;
                    }
                }

                // 2. Check Buttons & Links
                const buttons = document.querySelectorAll('button');
                for (let b of buttons) {
                    if (isHidden(b)) dom_results.hidden_buttons = true;
                }
                const links = document.querySelectorAll('a');
                for (let l of links) {
                    if (isHidden(l)) dom_results.hidden_links = true;
                }

                // 3. Check Iframes
                const iframes = document.querySelectorAll('iframe');
                for (let iframe of iframes) {
                    if (isHidden(iframe)) dom_results.invisible_iframes = true;
                    // 1x1 tracking/malicious iframes
                    if (iframe.width === '1' || iframe.height === '1' || iframe.width === '0' || iframe.height === '0') {
                        dom_results.invisible_iframes = true;
                    }
                }

                // 4. Check Inputs (The real threat targets)
                const inputs = document.querySelectorAll('input');
                const otpKeywords = ['otp', 'verification', '2fa', 'code', 'token'];
                const ccKeywords = ['card', 'cc', 'cvv', 'cvc', 'expire', 'expiry', 'cardnumber'];
                const bankKeywords = ['account', 'routing', 'bank', 'ssn', 'social security'];

                for (let inp of inputs) {
                    const type = (inp.type || "").toLowerCase();
                    const name = (inp.name || "").toLowerCase();
                    const id = (inp.id || "").toLowerCase();
                    const ph = (inp.placeholder || "").toLowerCase();
                    
                    const combined = `${name} ${id} ${ph}`;

                    if (type === 'password') dom_results.password_fields = true;
                    
                    if (otpKeywords.some(k => combined.includes(k))) dom_results.otp_fields = true;
                    if (ccKeywords.some(k => combined.includes(k))) dom_results.credit_card_fields = true;
                    if (bankKeywords.some(k => combined.includes(k))) dom_results.bank_fields = true;
                }

                return dom_results;
            }
            """
            
            dom_results = page.evaluate(js_payload)
            
            # Merge dom results into main results
            for k, v in dom_results.items():
                results[k] = v
                
            browser.close()
            
    except Exception as e:
        print(f"[Behavior Analyzer Error] {e}")
        pass
            
    return results

if __name__ == "__main__":
    test = input("Enter URL for behavior analysis: ")
    res = analyze_behavior(test)
    for k, v in res.items():
        print(f"{k:25}: {v}")
