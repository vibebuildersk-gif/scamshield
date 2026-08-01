document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const loadingState = document.getElementById('loading-state');
    const resultsState = document.getElementById('results-state');
    const verdictCard = document.getElementById('verdict-card');
    const verdictText = document.getElementById('verdict-text');
    const confidenceScore = document.getElementById('confidence-score');
    const telemetryGrid = document.getElementById('telemetry-grid');

    // The FastAPI Backend URL (Updated to Local WiFi IP for mobile testing)
    const API_URL = "http://192.168.31.61:8000/api/scan";

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

            // Display Visual Snapshot
            const targetScreenshot = document.getElementById('target-screenshot');
            targetScreenshot.src = `http://192.168.31.61:8000/static/scrapes/current_target.png?t=${new Date().getTime()}`;
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
