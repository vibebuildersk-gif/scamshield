document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const loadingState = document.getElementById('loading-state');
    const resultsState = document.getElementById('results-state');
    const verdictCard = document.getElementById('verdict-card');
    const verdictText = document.getElementById('verdict-text');
    const confidenceScore = document.getElementById('confidence-score');
    const telemetryGrid = document.getElementById('telemetry-grid');

    // The FastAPI Backend URL (Updated for Ngrok Tunneling)
    const API_URL = "https://proposable-joni-superornamentally.ngrok-free.dev/api/scan";

    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            alert("Please enter a URL to scan!");
            return;
        }

        // Disable button to prevent double-clicks
        scanBtn.disabled = true;
        scanBtn.style.opacity = '0.5';
        scanBtn.innerText = "ANALYZING...";

        // Reset UI
        resultsState.classList.add('hidden');
        loadingState.classList.remove('hidden');
        verdictCard.className = "verdict-card"; // Reset classes
        document.getElementById('http-warning').classList.add('hidden');
        telemetryGrid.innerHTML = '';

        try {
            // Make POST request to our FastAPI backend
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) throw new Error("Server returned an error. Is app.py running?");

            const data = await response.json();
            
            // Hide loading, show results
            loadingState.classList.add('hidden');
            resultsState.classList.remove('hidden');

            // Update Verdict
            verdictText.innerText = data.prediction.toUpperCase();
            confidenceScore.innerText = `${data.confidence}%`;

            if (data.prediction.toLowerCase() === 'phishing') {
                verdictCard.classList.add('danger');
            } else {
                verdictCard.classList.add('safe');
                // Check if it's missing SSL (IsHTTPS == 0) and unhide warning
                if (data.raw_features && (data.raw_features.IsHTTPS === 0 || data.raw_features.IsHTTPS === false)) {
                    document.getElementById('http-warning').classList.remove('hidden');
                }
            }

            // Handle OCR and Dead Site
            const deadWarning = document.getElementById('site-dead-warning');
            const ocrBox = document.getElementById('ocr-summary-box');
            const ocrText = document.getElementById('ocr-text');
            
            if (deadWarning) deadWarning.classList.add('hidden');
            if (ocrBox) ocrBox.classList.add('hidden');
            
            if (data.raw_features && data.raw_features.is_site_dead) {
                if (deadWarning) deadWarning.classList.remove('hidden');
            } else if (data.ocr_summary) {
                if (ocrText) ocrText.innerText = data.ocr_summary;
                if (ocrBox) ocrBox.classList.remove('hidden');
            }

            // Populate Behavioral Telemetry Grid
            // Pick a few interesting features to show off
            const keyFeatures = [
                { key: 'IsHTTPS', label: 'SSL/TLS Certificate' },
                { key: 'DomainAgeDays', label: 'Domain Age (Days)' },
                { key: 'login_forms', label: 'Login Forms Detected' },
                { key: 'hidden_buttons', label: 'Hidden Elements' },
                { key: 'invisible_iframes', label: 'Tracking Iframes' },
                { key: 'otp_fields', label: '2FA/OTP Fields' },
                { key: 'auto_redirects', label: 'Auto Redirects' }
            ];

            const raw = data.raw_features;

            keyFeatures.forEach(feature => {
                let value = raw[feature.key];
                
                if (feature.key === 'DomainAgeDays') {
                    value = (value !== undefined && value !== null) ? value : 'N/A';
                    if (value === 0) value = "0"; // Explicitly show 0 for Max Risk
                    else if (value < 0) value = "Hidden/Unknown";
                } else {
                    // Format boolean values nicely
                    if (value === 1 || value === true) value = "True";
                    if (value === 0 || value === false) value = "False";
                }
                
                // Special edge cases
                if (feature.key === 'IsHTTPS' && value === "True") value = "Valid";
                if (feature.key === 'IsHTTPS' && value === "False") value = "Missing";

                const metricDiv = document.createElement('div');
                metricDiv.className = 'metric';
                
                let valClass = "val";
                if (value === "True") valClass += " true";
                if (value === "False") valClass += " false";

                metricDiv.innerHTML = `
                    <span class="label">${feature.label}</span>
                    <span class="${valClass}">${value}</span>
                `;
                telemetryGrid.appendChild(metricDiv);
            });

            // Populate Cloud Intelligence Grid
            const urlscanGrid = document.getElementById('urlscan-grid');
            const cloudTitle = urlscanGrid.previousElementSibling; // The <h3> above it
            urlscanGrid.innerHTML = '';
            
            cloudTitle.classList.remove('hidden');
            urlscanGrid.classList.remove('hidden');
            
            if (data.virustotal) {
                cloudTitle.innerText = "🌍 Global Threat Intelligence";
                const scanFeatures = [
                    { label: 'Security Vendors Flagged', value: data.virustotal.overall_score },
                    { label: 'Global Consensus Verdict', value: data.virustotal.is_malicious ? "Malicious" : "Clean" }
                ];

                    scanFeatures.forEach(feature => {
                        let val = feature.value;
                        const metricDiv = document.createElement('div');
                        metricDiv.className = 'metric';
                        
                        let valClass = "val";
                        if (val === "Malicious" || val === "True" || (typeof val === 'string' && val !== "0" && val.includes("/"))) valClass += " true"; // Red
                        if (val === "Clean" || val === "False" || (typeof val === 'string' && val.startsWith("0/"))) valClass += " false"; // Green

                        metricDiv.innerHTML = `
                            <span class="label">${feature.label}</span>
                            <span class="${valClass}">${val}</span>
                        `;
                        urlscanGrid.appendChild(metricDiv);
                    });
                } else if (data.urlscan) {
                    cloudTitle.innerText = "🌍 Global Threat Intelligence";
                    const scanFeatures = [
                        { label: 'Hosting Provider (ASN)', value: data.urlscan.asn_name },
                        { label: 'Server Location', value: data.urlscan.country },
                        { label: 'Global Consensus Verdict', value: data.urlscan.is_malicious ? "Malicious" : "Clean" },
                        { label: 'Impersonated Brand', value: data.urlscan.impersonated_brand },
                        { label: 'Security Headers Missing', value: data.urlscan.security_headers_missing ? "True" : "False" }
                    ];

                    scanFeatures.forEach(feature => {
                        let val = feature.value;
                        const metricDiv = document.createElement('div');
                        metricDiv.className = 'metric';
                        
                        let valClass = "val";
                        if (val === "Malicious" || val === "True") valClass += " true"; // CSS .true is Red (Danger)
                        if (val === "Clean" || val === "False") valClass += " false"; // CSS .false is Green (Safe)

                        metricDiv.innerHTML = `
                            <span class="label">${feature.label}</span>
                            <span class="${valClass}">${val}</span>
                        `;
                        urlscanGrid.appendChild(metricDiv);
                    });
                }

            // Display Visual Snapshot
            const targetScreenshot = document.getElementById('target-screenshot');
            targetScreenshot.src = `https://proposable-joni-superornamentally.ngrok-free.dev/static/scrapes/current_target.png?t=${new Date().getTime()}`;
            targetScreenshot.classList.remove('hidden');

        } catch (error) {
            loadingState.classList.add('hidden');
            alert(`Connection Error: ${error.message}\nMake sure your FastAPI server is running with 'python app.py'!`);
        } finally {
            // Re-enable button
            scanBtn.disabled = false;
            scanBtn.style.opacity = '1';
            scanBtn.innerText = "ANALYZE TARGET";
        }
    });

    // Allow hitting Enter to scan
    urlInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });
});
