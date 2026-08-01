document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const loadingState = document.getElementById('loading-state');
    const resultsState = document.getElementById('results-state');
    const verdictCard = document.getElementById('verdict-card');
    const verdictText = document.getElementById('verdict-text');
    const confidenceScore = document.getElementById('confidence-score');
    const telemetryGrid = document.getElementById('telemetry-grid');

    // The FastAPI Backend URL (Updated for Render Cloud Deployment)
    const API_URL = "https://scamshield-xozi.onrender.com/api/scan";

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
            if (data.screenshot_url && data.screenshot_url !== "") {
                targetScreenshot.src = data.screenshot_url;
                targetScreenshot.classList.remove('hidden');
            } else {
                targetScreenshot.classList.add('hidden');
            }

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

    // --- Sidebar Navigation Logic ---
    const navLinkDetection = document.getElementById('nav-link-detection');
    const navQrChecker = document.getElementById('nav-qr-checker');
    const viewLinkDetection = document.getElementById('link-detection-view');
    const viewQrChecker = document.getElementById('qr-checker-view');

    navLinkDetection.addEventListener('click', () => {
        navLinkDetection.classList.add('active');
        navQrChecker.classList.remove('active');
        viewLinkDetection.classList.remove('hidden');
        viewQrChecker.classList.add('hidden');
    });

    navQrChecker.addEventListener('click', () => {
        navQrChecker.classList.add('active');
        navLinkDetection.classList.remove('active');
        viewQrChecker.classList.remove('hidden');
        viewLinkDetection.classList.add('hidden');
    });

    // --- QR Checker Logic ---
    const qrDropZone = document.getElementById('qr-drop-zone');
    const qrFileInput = document.getElementById('qr-file-input');
    const qrUploadBtn = document.getElementById('qr-upload-btn');
    const qrPreviewZone = document.getElementById('qr-preview-zone');
    const qrPreviewImage = document.getElementById('qr-preview-image');
    const qrAnalyzeBtn = document.getElementById('qr-analyze-btn');
    const qrResetBtn = document.getElementById('qr-reset-btn');
    
    const qrLoadingState = document.getElementById('qr-loading-state');
    const qrResultsState = document.getElementById('qr-results-state');
    const qrVerdictCard = document.getElementById('qr-verdict-card');
    const qrVerdictText = document.getElementById('qr-verdict-text');
    const qrPayloadText = document.getElementById('qr-payload-text');
    const qrWarningsContainer = document.getElementById('qr-warnings-container');

    const API_QR_URL = API_URL.replace("/api/scan", "/api/scan-qr");
    let currentUploadedFile = null;

    qrUploadBtn.addEventListener('click', () => qrFileInput.click());

    qrFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleQrPreview(e.target.files[0]);
        }
    });

    qrDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        qrDropZone.style.borderColor = 'var(--accent)';
    });

    qrDropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        qrDropZone.style.borderColor = 'var(--border)';
    });

    qrDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        qrDropZone.style.borderColor = 'var(--border)';
        if (e.dataTransfer.files.length > 0) {
            handleQrPreview(e.dataTransfer.files[0]);
        }
    });

    function handleQrPreview(file) {
        if (!file.type.startsWith('image/')) {
            alert('Please upload an image file.');
            return;
        }
        currentUploadedFile = file;
        
        const reader = new FileReader();
        reader.onload = function(e) {
            qrPreviewImage.src = e.target.result;
            qrDropZone.classList.add('hidden');
            qrPreviewZone.classList.remove('hidden');
            qrResultsState.classList.add('hidden');
        }
        reader.readAsDataURL(file);
    }
    
    qrResetBtn.addEventListener('click', () => {
        currentUploadedFile = null;
        qrFileInput.value = '';
        qrPreviewImage.src = '';
        qrPreviewZone.classList.add('hidden');
        qrResultsState.classList.add('hidden');
        qrDropZone.classList.remove('hidden');
    });

    qrAnalyzeBtn.addEventListener('click', async () => {
        if (!currentUploadedFile) return;

        // Reset UI
        qrResultsState.classList.add('hidden');
        qrPreviewZone.classList.add('hidden');
        qrLoadingState.classList.remove('hidden');
        qrVerdictCard.className = 'verdict-card';
        qrWarningsContainer.innerHTML = '';
        qrPayloadText.innerText = '';

        const formData = new FormData();
        formData.append('file', currentUploadedFile);

        try {
            const response = await fetch(API_QR_URL, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error("Server returned an error.");

            const data = await response.json();
            
            qrLoadingState.classList.add('hidden');
            qrResultsState.classList.remove('hidden');

            if (data.error) {
                qrVerdictText.innerText = "ERROR";
                qrVerdictCard.classList.add('danger');
                qrPayloadText.innerText = data.error;
                return;
            }

            qrPayloadText.innerHTML = `<strong>Raw Payload:</strong> <br><span style="word-break: break-all; color: rgba(255,255,255,0.7); font-size: 0.85rem;">${data.payload}</span>`;

            // Display Payment Details if it's a payment QR
            if (data.is_payment_qr && data.payment_details && Object.keys(data.payment_details).length > 0) {
                const pd = data.payment_details;
                let detailsHtml = `<div class="payment-details-box" style="margin-top: 1.5rem; padding: 1.5rem; background: rgba(102, 252, 241, 0.05); border: 1px solid var(--accent); border-radius: 12px; text-align: left; color: var(--text-light);">`;
                detailsHtml += `<h4 style="color: var(--accent); margin-bottom: 1rem; font-size: 1.1rem;">💳 Extracted Payment Details:</h4>`;
                if (pd.payee_name) detailsHtml += `<div style="margin-bottom: 0.5rem;"><strong>Payee Name:</strong> <span style="color: var(--safe); font-weight: bold;">${pd.payee_name}</span></div>`;
                if (pd.payee_vpa) detailsHtml += `<div style="margin-bottom: 0.5rem;"><strong>UPI ID:</strong> <span style="font-family: monospace;">${pd.payee_vpa}</span></div>`;
                if (pd.amount) detailsHtml += `<div style="margin-bottom: 0.5rem;"><strong>Requested Amount:</strong> <span style="color: var(--danger); font-weight: bold; font-size: 1.2rem;">₹${pd.amount}</span></div>`;
                if (pd.mcc) detailsHtml += `<div><strong>Merchant Code:</strong> ${pd.mcc} <span style="color: var(--safe); font-size: 0.8rem;">(Verified P2M)</span></div>`;
                else detailsHtml += `<div><strong>Merchant Code:</strong> None <span style="color: #ffcc00; font-size: 0.8rem;">(P2P Transfer)</span></div>`;
                detailsHtml += `</div>`;
                qrPayloadText.innerHTML += detailsHtml;
            }

            let verdictColorClass = 'safe';
            let verdictTextStr = 'SAFE';

            if (data.risk_score >= 70) {
                verdictColorClass = 'danger';
                verdictTextStr = `HIGH RISK (${data.risk_score}%)`;
            } else if (data.risk_score >= 40) {
                verdictColorClass = 'warning';
                verdictTextStr = `WARNING (${data.risk_score}%)`;
            } else {
                verdictTextStr = `SAFE (${data.risk_score}% Risk)`;
            }

            qrVerdictText.innerText = verdictTextStr;
            qrVerdictCard.classList.remove('safe', 'danger', 'warning');
            
            // Add inline styles for warning just in case CSS class is missing
            if (verdictColorClass === 'warning') {
                qrVerdictCard.style.borderColor = '#ffcc00';
                qrVerdictCard.style.boxShadow = '0 0 30px rgba(255, 204, 0, 0.15)';
                qrVerdictText.style.color = '#ffcc00';
            } else {
                qrVerdictCard.style.borderColor = '';
                qrVerdictCard.style.boxShadow = '';
                qrVerdictText.style.color = '';
            }
            
            qrVerdictCard.classList.add(verdictColorClass);

            if (data.warnings && data.warnings.length > 0) {
                data.warnings.forEach(warning => {
                    const warnDiv = document.createElement('div');
                    if (warning.includes("NON-PAYMENT QR ALERT")) {
                        warnDiv.className = 'warning-box danger-box';
                        warnDiv.innerHTML = `<span class="icon">🛑</span> <strong>Alert:</strong> ${warning}`;
                    } else if (warning.includes("Caution")) {
                        warnDiv.className = 'warning-box info-box';
                        warnDiv.style.borderColor = '#ffcc00';
                        warnDiv.style.backgroundColor = 'rgba(255, 204, 0, 0.05)';
                        warnDiv.style.color = '#ffeba3';
                        warnDiv.innerHTML = `<span class="icon">⚠️</span> <strong>Caution:</strong> ${warning}`;
                    } else {
                        warnDiv.className = 'warning-box danger-box';
                        warnDiv.innerHTML = `<span class="icon">⚠️</span> <strong>Alert:</strong> ${warning}`;
                    }
                    qrWarningsContainer.appendChild(warnDiv);
                });
            } else {
                const safeDiv = document.createElement('div');
                safeDiv.className = 'warning-box info-box';
                safeDiv.innerHTML = `<span class="icon">✅</span> <strong>Clean:</strong> No suspicious intent or formatting found in this payment QR code.`;
                qrWarningsContainer.appendChild(safeDiv);
            }
        } catch (error) {
            console.error(error);
            qrVerdictText.innerText = "ERROR";
            qrVerdictCard.classList.add('danger');
            qrPayloadText.innerText = "Failed to connect to the backend scanner API.";
            qrResultsState.classList.remove('hidden');
        } finally {
            qrLoadingState.classList.add('hidden');
            qrPreviewZone.classList.remove('hidden'); // Show preview again alongside results
            qrAnalyzeBtn.style.display = 'none'; // Hide analyze btn after analysis
            qrResetBtn.innerText = 'Upload Different Image'; 
        }
    });
    
    // reset button logic extension for post-analysis
    qrResetBtn.addEventListener('click', () => {
        qrAnalyzeBtn.style.display = 'inline-block';
        qrResetBtn.innerText = 'Upload Different Image';
    });
});
