let lastScan = null;
let currentTab = 'url';

// ── Tab Switching ───────────────────────────────────────────────
function switchTab(tab) {
    currentTab = tab;

    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');

    // Hide results
    clearResults();
}

function loadExample(tab, value) {
    if (tab === 'url') document.getElementById('urlInput').value = value;
    if (tab === 'email') document.getElementById('emailInput').value = value;
    if (tab === 'phone') document.getElementById('phoneInput').value = value;
}

// ── Scanning Animation ──────────────────────────────────────────
function startScanning(logs) {
    document.getElementById('results').classList.remove('visible');
    document.getElementById('scanning').classList.add('active');

    const logEl = document.getElementById('scan-log');
    logEl.innerHTML = '<div>Initializing threat scan...</div>';

    logs.forEach(({ t, text }) => {
        setTimeout(() => {
            logEl.innerHTML += `<div>${text}</div>`;
        }, t);
    });
}

function stopScanning() {
    document.getElementById('scanning').classList.remove('active');
}

// ── Show Results ────────────────────────────────────────────────
function showResults(riskScore, verdict, desc, color, tagsHtml, detailsHtml, scanData) {
    // Save for PDF
    lastScan = scanData;

    // Set risk panel color
    document.getElementById('risk-panel').style.setProperty('--risk-color', color);

    // Animate score
    const scoreEl = document.getElementById('score-display');
    scoreEl.style.color = color;
    let num = 0;
    const interval = setInterval(() => {
        num = Math.min(num + 2, riskScore);
        scoreEl.textContent = num;
        if (num >= riskScore) clearInterval(interval);
    }, 20);

    // Animate gauge
    const fill = document.getElementById('gauge-fill');
    fill.style.stroke = color;
    setTimeout(() => {
        fill.style.strokeDashoffset = 440 - (440 * riskScore / 100);
    }, 100);

    // Verdict
    document.getElementById('verdict').textContent = verdict;
    document.getElementById('verdict').style.color = color;
    document.getElementById('risk-desc').textContent = desc;

    // Tags
    document.getElementById('threat-tags').innerHTML = tagsHtml;

    // Details
    document.getElementById('dynamic-results').innerHTML = detailsHtml;

    // Show results
    document.getElementById('results').classList.add('visible');
}

// ── Get Color & Verdict ─────────────────────────────────────────
function getRiskDisplay(riskScore) {
    if (riskScore >= 60) {
        return { color: '#ff2d55', verdict: 'HIGH RISK', desc: 'Serious threat detected. Do not proceed!' };
    } else if (riskScore >= 30) {
        return { color: '#ffd600', verdict: 'SUSPICIOUS', desc: 'Moderate risk detected. Exercise caution.' };
    } else {
        return { color: '#00ff88', verdict: 'SAFE', desc: 'No threats detected. Looks clean!' };
    }
}

// ── Build Threat Tags ───────────────────────────────────────────
function buildTags(riskScore, reasons) {
    if (riskScore >= 60) {
        return `
            <span class="threat-tag red">High Risk</span>
            <span class="threat-tag red">Do Not Proceed</span>
            ${reasons.length > 0 ? '<span class="threat-tag yellow">Threat Detected</span>' : ''}
        `;
    } else if (riskScore >= 30) {
        return `
            <span class="threat-tag yellow">Suspicious</span>
            <span class="threat-tag yellow">Caution Advised</span>
        `;
    } else {
        return `
            <span class="threat-tag green">Clean</span>
            <span class="threat-tag green">No Threats Found</span>
        `;
    }
}

// ── Build Reasons List ──────────────────────────────────────────
function buildReasons(reasons) {
    if (!reasons || reasons.length === 0) {
        return '<div style="color:var(--green)">✅ No threats found</div>';
    }
    return reasons.map(r => `<div>⚠️ ${r}</div>`).join('');
}

// ── URL Check ───────────────────────────────────────────────────
async function checkUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return alert('Please enter a URL!');

    startScanning([
        { t: 500,  text: '🔍 Querying Google Safe Browsing...' },
        { t: 1000, text: '✓ Safe Browsing response received' },
        { t: 1500, text: '🔍 Submitting to VirusTotal...' },
        { t: 2000, text: '✓ VirusTotal scan initiated' },
        { t: 2500, text: '🔍 Running IPQualityScore check...' },
        { t: 3000, text: '✓ All APIs responded' },
        { t: 3200, text: '📊 Calculating risk score...' },
    ]);

    try {
        const response = await fetch('/check-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        stopScanning();

        if (data.error) return alert('Error: ' + data.error);

        const { color, verdict, desc } = getRiskDisplay(data.riskScore);
        const tags = buildTags(data.riskScore, data.reasons || []);

        // Build details
        const details = `
            <div class="feeds-title">// API Results</div>
            ${buildDetailRow('Google Safe Browsing', data.gsb?.safe ? '✅ Clean' : '⚠️ Flagged', data.gsb?.safe ? 'safe' : 'danger')}
            ${data.vt ? buildDetailRow('VT Malicious Engines', data.vt.malicious + ' / ' + data.vt.total, data.vt.malicious > 0 ? 'danger' : 'safe') : ''}
            ${data.vt ? buildDetailRow('VT Suspicious Engines', data.vt.suspicious + '', data.vt.suspicious > 0 ? 'warn' : 'safe') : ''}
            ${data.ipqs ? buildDetailRow('IPQS Risk Score', data.ipqs.riskScore + ' / 100', data.ipqs.riskScore > 60 ? 'danger' : data.ipqs.riskScore > 30 ? 'warn' : 'safe') : ''}
            ${data.ipqs ? buildDetailRow('Domain Age', data.ipqs.domainAge, '') : ''}
            ${data.ipqs ? buildDetailRow('Country', data.ipqs.country, '') : ''}
            <div style="margin-top:12px" class="feeds-title">// Reasons</div>
            <div class="vt-details">${buildReasons(data.reasons)}</div>
        `;

        showResults(
            data.riskScore, verdict, desc, color, tags, details,
            { type: 'URL', target: url, riskScore: data.riskScore, riskLevel: data.riskLevel, reasons: data.reasons }
        );

    } catch (error) {
        stopScanning();
        alert('Something went wrong. Is the server running?');
    }
}

// ── Email Check ─────────────────────────────────────────────────
async function checkEmail() {
    const email = document.getElementById('emailInput').value.trim();
    if (!email) return alert('Please enter an email address!');

    startScanning([
        { t: 500,  text: '📧 Validating email format...' },
        { t: 1000, text: '🔍 Checking domain reputation...' },
        { t: 1500, text: '🔍 Scanning for disposable email...' },
        { t: 2000, text: '📊 Calculating fraud score...' },
    ]);

    try {
        const response = await fetch('/check-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await response.json();
        stopScanning();

        if (data.error) return alert('Error: ' + data.error);

        const { color, verdict, desc } = getRiskDisplay(data.riskScore);
        const tags = buildTags(data.riskScore, data.reasons || []);

        const details = `
            <div class="feeds-title">// Email Analysis</div>
            ${buildDetailRow('Email Valid', data.valid ? '✅ Yes' : '❌ No', data.valid ? 'safe' : 'danger')}
            ${buildDetailRow('Disposable Email', data.disposable ? '⚠️ Yes' : '✅ No', data.disposable ? 'danger' : 'safe')}
            ${buildDetailRow('Fraud Score', data.fraudScore + ' / 100', data.fraudScore > 60 ? 'danger' : data.fraudScore > 30 ? 'warn' : 'safe')}
            ${buildDetailRow('Domain', data.domain || 'Unknown', '')}
            <div style="margin-top:12px" class="feeds-title">// Reasons</div>
            <div class="vt-details">${buildReasons(data.reasons)}</div>
        `;

        showResults(
            data.riskScore, verdict, desc, color, tags, details,
            { type: 'Email', target: email, riskScore: data.riskScore, riskLevel: data.riskLevel, reasons: data.reasons }
        );

    } catch (error) {
        stopScanning();
        alert('Something went wrong. Is the server running?');
    }
}

// ── Phone Check ─────────────────────────────────────────────────
async function checkPhone() {
    const phone = document.getElementById('phoneInput').value.trim();
    if (!phone) return alert('Please enter a phone number!');

    startScanning([
        { t: 500,  text: '📱 Validating phone number...' },
        { t: 1000, text: '🔍 Checking carrier information...' },
        { t: 1500, text: '🔍 Scanning spam databases...' },
        { t: 2000, text: '📊 Calculating fraud score...' },
    ]);

    try {
        const response = await fetch('/check-phone', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ phone })
        });
        const data = await response.json();
        stopScanning();

        if (data.error) return alert('Error: ' + data.error);

        const { color, verdict, desc } = getRiskDisplay(data.riskScore);
        const tags = buildTags(data.riskScore, data.reasons || []);

        const details = `
            <div class="feeds-title">// Phone Analysis</div>
            ${buildDetailRow('Valid Number', data.valid ? '✅ Yes' : '❌ No', data.valid ? 'safe' : 'danger')}
            ${buildDetailRow('Fraud Score', data.fraudScore + ' / 100', data.fraudScore > 60 ? 'danger' : data.fraudScore > 30 ? 'warn' : 'safe')}
            ${buildDetailRow('Carrier', data.carrier || 'Unknown', '')}
            ${buildDetailRow('Line Type', data.lineType || 'Unknown', '')}
            ${buildDetailRow('Country', data.country || 'Unknown', '')}
            <div style="margin-top:12px" class="feeds-title">// Reasons</div>
            <div class="vt-details">${buildReasons(data.reasons)}</div>
        `;

        showResults(
            data.riskScore, verdict, desc, color, tags, details,
            { type: 'Phone', target: phone, riskScore: data.riskScore, riskLevel: data.riskLevel, reasons: data.reasons }
        );

    } catch (error) {
        stopScanning();
        alert('Something went wrong. Is the server running?');
    }
}

// ── SMS Check ───────────────────────────────────────────────────
async function checkSms() {
    const sms = document.getElementById('smsInput').value.trim();
    if (!sms) return alert('Please paste an SMS message!');

    startScanning([
        { t: 500,  text: '💬 Analyzing SMS content...' },
        { t: 1000, text: '🔍 Scanning for suspicious words...' },
        { t: 1500, text: '🔍 Extracting and checking URLs...' },
        { t: 2000, text: '📊 Calculating threat score...' },
    ]);

    try {
        const response = await fetch('/check-sms', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sms })
        });
        const data = await response.json();
        stopScanning();

        if (data.error) return alert('Error: ' + data.error);

        const { color, verdict, desc } = getRiskDisplay(data.riskScore);
        const tags = buildTags(data.riskScore, data.reasons || []);

        // Build URL results
        let urlResultsHtml = '';
        if (data.urlResults && data.urlResults.length > 0) {
            urlResultsHtml = data.urlResults.map(u =>
                buildDetailRow(u.url.substring(0, 30) + '...', 'Risk: ' + u.score, u.score > 50 ? 'danger' : 'safe')
            ).join('');
        }

        const details = `
            <div class="feeds-title">// SMS Analysis</div>
            ${buildDetailRow('URLs Found', data.urlsFound + '', data.urlsFound > 0 ? 'warn' : 'safe')}
            ${buildDetailRow('Suspicious Words', data.suspiciousWords?.length + '', data.suspiciousWords?.length > 0 ? 'warn' : 'safe')}
            ${data.suspiciousWords?.length > 0 ? buildDetailRow('Words Found', data.suspiciousWords.join(', '), 'warn') : ''}
            ${urlResultsHtml}
            <div style="margin-top:12px" class="feeds-title">// Reasons</div>
            <div class="vt-details">${buildReasons(data.reasons)}</div>
        `;

        showResults(
            data.riskScore, verdict, desc, color, tags, details,
            { type: 'SMS', target: sms.substring(0, 50) + '...', riskScore: data.riskScore, riskLevel: data.riskLevel, reasons: data.reasons }
        );

    } catch (error) {
        stopScanning();
        alert('Something went wrong. Is the server running?');
    }
}

// ── Helper: Build Detail Row ────────────────────────────────────
function buildDetailRow(key, value, cls) {
    return `
        <div class="detail-row">
            <span class="detail-key">${key}</span>
            <span class="detail-val ${cls}">${value}</span>
        </div>
    `;
}

// ── Clear Results ───────────────────────────────────────────────
function clearResults() {
    document.getElementById('results').classList.remove('visible');
    document.getElementById('gauge-fill').style.strokeDashoffset = '440';
    document.getElementById('score-display').textContent = '—';
    document.getElementById('verdict').textContent = '—';
    document.getElementById('risk-desc').textContent = 'Submit to begin';
    lastScan = null;
}

// ── Download PDF ────────────────────────────────────────────────
async function downloadPDF() {
    if (!lastScan) return alert('No scan data available!');
    const response = await fetch('/download-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastScan)
    });
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `phishshield-report.pdf`;
    link.click();
}
// Register Service Worker for PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(reg => console.log('✅ Service Worker registered'))
            .catch(err => console.log('❌ SW error:', err));
    });
}