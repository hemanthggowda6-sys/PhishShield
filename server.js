 const dns = require('node:dns');
 dns.setServers(['1.1.1.1', '8.8.8.8']);

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const mongoose = require('mongoose');
const Scan = require('./models/scan');
const app = express();
const PORT = process.env.PORT || 3000;

// ── Connect to MongoDB ──────────────────────────────────────────
if (process.env.MONGO_URI) {
    mongoose.connect(process.env.MONGO_URI)
        .then(() => console.log('✅ MongoDB connected!'))
        .catch(err => console.log('❌ MongoDB error:', err.message));
}

app.use(express.static('public'));
app.use(express.json());

// ── Google Safe Browsing ────────────────────────────────────────
async function checkGoogleSafeBrowsing(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
    if (!apiKey) return { safe: true, error: 'Missing key' };
    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                client: { clientId: "phishshield", clientVersion: "1.0.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            }
        );
        const matches = response.data.matches;
        return { safe: !matches || matches.length === 0 };
    } catch (error) {
        console.log('GSB error:', error.message);
        return { safe: true, error: error.message };
    }
}

// ── VirusTotal ──────────────────────────────────────────────────
async function checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return null;
    try {
        const submitResponse = await axios.post(
            'https://www.virustotal.com/api/v3/urls',
            new URLSearchParams({ url }),
            { headers: { 'x-apikey': apiKey } }
        );
        const scanId = submitResponse.data.data.id;
        await new Promise(resolve => setTimeout(resolve, 3000));
        const reportResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${scanId}`,
            { headers: { 'x-apikey': apiKey } }
        );
        const stats = reportResponse.data.data.attributes.stats;
        return {
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            harmless: stats.harmless,
            total: stats.malicious + stats.suspicious + stats.harmless + (stats.undetected || 0)
        };
    } catch (error) {
        console.log('VT error:', error.message);
        return null;
    }
}

// ── IPQualityScore URL ──────────────────────────────────────────
async function checkIPQS(url) {
    const apiKey = process.env.IPQS_API_KEY;
    if (!apiKey) return null;
    try {
        const encodedUrl = encodeURIComponent(url);
        const response = await axios.get(
            `https://www.ipqualityscore.com/api/json/url/${apiKey}/${encodedUrl}`
        );
        const data = response.data;
        return {
            phishing: data.phishing,
            malware: data.malware,
            suspicious: data.suspicious,
            riskScore: data.risk_score,
            spamming: data.spamming,
            domainAge: data.domain_age?.human || 'Unknown',
            country: data.country_code || 'Unknown'
        };
    } catch (error) {
        console.log('IPQS error:', error.message);
        return null;
    }
}
// ── Pattern Based Detection ─────────────────────────────────────
function analyzeUrlPatterns(url) {
    let score = 0;
    let reasons = [];

    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        const fullUrl = url.toLowerCase();

        // 1. Number substitutions (paypa1, amaz0n, g00gle)
        const numberSubs = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's'
        };
        const knownBrands = [
            'paypal', 'amazon', 'google', 'facebook', 'apple',
            'microsoft', 'netflix', 'instagram', 'whatsapp', 'twitter',
            'hdfc', 'icici', 'sbi', 'axis', 'kotak', 'paytm',
            'phonepe', 'gpay', 'flipkart', 'myntra', 'zomato'
        ];

        // Normalize domain by replacing numbers with letters
        let normalizedDomain = domain;
        Object.entries(numberSubs).forEach(([num, letter]) => {
            normalizedDomain = normalizedDomain.replaceAll(num, letter);
        });

        // Check if normalized domain contains a brand name
        const impersonatedBrand = knownBrands.find(brand =>
            normalizedDomain.includes(brand) && !domain.includes(brand)
        );
        if (impersonatedBrand) {
            score += 40;
            reasons.push(`Possible brand impersonation: ${impersonatedBrand}`);
        }

        // 2. Suspicious TLDs
        const suspiciousTlds = [
            '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
            '.ru', '.cn', '.pw', '.top', '.click', '.loan',
            '.work', '.party', '.download', '.racing'
        ];
        const hasSuspiciousTld = suspiciousTlds.some(tld => domain.endsWith(tld));
        if (hasSuspiciousTld) {
            score += 20;
            reasons.push('Suspicious domain extension detected');
        }

        // 3. Too many hyphens (secure-login-verify-account.com)
        const hyphenCount = (domain.match(/-/g) || []).length;
        if (hyphenCount >= 3) {
            score += 25;
            reasons.push(`Too many hyphens in domain (${hyphenCount})`);
        } else if (hyphenCount === 2) {
            score += 10;
        }

        // 4. Suspicious keywords in URL
        const suspiciousKeywords = [
            'login', 'signin', 'verify', 'secure', 'update',
            'confirm', 'account', 'banking', 'password', 'credential',
            'authenticate', 'validation', 'kyc', 'urgent', 'suspended'
        ];
        const foundKeywords = suspiciousKeywords.filter(k => fullUrl.includes(k));
        if (foundKeywords.length >= 2) {
            score += 20;
            reasons.push(`Suspicious keywords in URL: ${foundKeywords.slice(0,3).join(', ')}`);
        }

        // 5. Brand name + suspicious word combo
        const brandInDomain = knownBrands.find(brand => domain.includes(brand));
        if (brandInDomain && (domain.includes('-') || domain.includes('.'))) {
            const domainWithoutBrand = domain.replace(brandInDomain, '');
            if (domainWithoutBrand.length > 3) {
                score += 30;
                reasons.push(`Brand name "${brandInDomain}" used in suspicious domain`);
            }
        }

        // 6. Very long domain
        if (domain.length > 40) {
            score += 15;
            reasons.push('Unusually long domain name');
        }

        // 7. URL shorteners hiding destination
        const urlShorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
            'ow.ly', 'short.link', 'rb.gy', 'cutt.ly'
        ];
        if (urlShorteners.some(s => domain.includes(s))) {
            score += 15;
            reasons.push('URL shortener detected — destination hidden');
        }

        // 8. IP address instead of domain
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipPattern.test(domain)) {
            score += 35;
            reasons.push('IP address used instead of domain name');
        }

        // 9. Multiple subdomains
        const subdomainCount = domain.split('.').length - 2;
        if (subdomainCount >= 3) {
            score += 20;
            reasons.push(`Too many subdomains (${subdomainCount})`);
        }

        // 10. No HTTPS
        if (urlObj.protocol === 'http:') {
            score += 10;
            reasons.push('Not using secure HTTPS connection');
        }

    } catch (e) {
        score += 10;
        reasons.push('Invalid or malformed URL');
    }

    return { score: Math.min(score, 100), reasons };
}
// ── Calculate Risk Score ────────────────────────────────────────
function calculateRiskScore(gsbResult, vtResult, ipqsResult, patternResult) {
    let score = 0;
    let reasons = [];

    // Google Safe Browsing (weight: 40)
    if (!gsbResult.safe) {
        score += 40;
        reasons.push('Google Safe Browsing flagged this URL');
    }

    // VirusTotal (weight: 35)
    if (vtResult) {
        if (vtResult.malicious > 5) {
            score += 35;
            reasons.push(`${vtResult.malicious} antivirus engines flagged it`);
        } else if (vtResult.malicious > 0) {
            score += 20;
            reasons.push(`${vtResult.malicious} antivirus engines flagged it`);
        }
        if (vtResult.suspicious > 0) score += 5;
    }

    // IPQualityScore (weight: 25)
    if (ipqsResult) {
        if (ipqsResult.phishing) {
            score += 25;
            reasons.push('Detected as phishing by IPQualityScore');
        }
        if (ipqsResult.malware) {
            score += 20;
            reasons.push('Malware detected by IPQualityScore');
        }
        if (ipqsResult.suspicious) {
            score += 10;
            reasons.push('Marked suspicious by IPQualityScore');
        }
        if (ipqsResult.riskScore > 85) {
            score += 15;
            reasons.push('Very high IPQS risk score');
        } else if (ipqsResult.riskScore > 60) {
            score += 8;
        }
    }

    // Pattern Detection (weight: 30)
    if (patternResult && patternResult.score > 0) {
        score += Math.round(patternResult.score * 0.3);
        reasons.push(...patternResult.reasons);
    }

    return { score: Math.min(score, 100), reasons };
}

// ── Main URL Check Route ────────────────────────────────────────
app.post('/check-url', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Please enter a URL' });
    console.log(`🔍 Checking URL: ${url}`);

    const [gsbResult, vtResult, ipqsResult] = await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkVirusTotal(url),
        checkIPQS(url)
    ]);

    const patternResult = analyzeUrlPatterns(url);
    const { score: riskScore, reasons } = calculateRiskScore(gsbResult, vtResult, ipqsResult, patternResult);
    let riskLevel;
    if (riskScore < 30) riskLevel = 'Low';
    else if (riskScore < 60) riskLevel = 'Medium';
    else riskLevel = 'High';

    let message = riskScore >= 30
        ? '⚠️ UNSAFE: ' + reasons.join('. ')
        : '✅ SAFE: No threats detected.';

    // Save to MongoDB
    if (mongoose.connection.readyState === 1) {
        try {
            const scan = new Scan({
                url,
                riskScore,
                riskLevel,
                vtMalicious: vtResult ? vtResult.malicious : 0,
                vtTotal: vtResult ? vtResult.total : 0,
                googleFlagged: !gsbResult.safe
            });
            await scan.save();
            console.log('💾 Scan saved to MongoDB!');
        } catch (e) {
            console.log('DB save error:', e.message);
        }
    }

    res.json({
        message, riskScore, riskLevel,
        reasons, vt: vtResult,
        gsb: gsbResult, ipqs: ipqsResult
    });
});

// ── Email Check Route ───────────────────────────────────────────
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Please enter an email' });
    console.log(`📧 Checking email: ${email}`);

    const apiKey = process.env.IPQS_API_KEY;
    try {
        const response = await axios.get(
            `https://www.ipqualityscore.com/api/json/email/${apiKey}/${email}`
        );
        const data = response.data;

        let riskScore = 0;
        let reasons = [];

        if (data.disposable) {
            riskScore += 40;
            reasons.push('Disposable/temporary email address');
        }
        if (data.fraud_score > 85) {
            riskScore += 40;
            reasons.push('Very high fraud score');
        } else if (data.fraud_score > 60) {
            riskScore += 20;
            reasons.push('High fraud score');
        }
        if (!data.valid) {
            riskScore += 30;
            reasons.push('Invalid email address');
        }
        if (data.honeypot) {
            riskScore += 30;
            reasons.push('Known spam honeypot');
        }
        if (data.spam_trap_score === 'high') {
            riskScore += 20;
            reasons.push('Spam trap detected');
        }

        riskScore = Math.min(riskScore, 100);
        const riskLevel = riskScore < 30 ? 'Low' : riskScore < 60 ? 'Medium' : 'High';

        res.json({
            email, riskScore, riskLevel,
            valid: data.valid,
            disposable: data.disposable,
            fraudScore: data.fraud_score,
            domain: data.domain,
            reasons,
            message: riskScore >= 30
                ? '⚠️ SUSPICIOUS EMAIL: ' + reasons.join('. ')
                : '✅ EMAIL LOOKS SAFE'
        });
    } catch (error) {
        console.log('Email check error:', error.message);
        res.status(500).json({ error: 'Could not check email: ' + error.message });
    }
});

// ── Phone Check Route ───────────────────────────────────────────
// ── Phone Check Route ───────────────────────────────────────────
app.post('/check-phone', async (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Please enter a phone number' });
    console.log(`📱 Checking phone: ${phone}`);

    // Clean phone number
    const cleanPhone = phone.replace(/\s+/g, '').replace(/[^\d+]/g, '');

    try {
        // ── NumVerify for validation ────────────────────────────
        const numVerifyKey = process.env.NUMVERIFY_API_KEY;
        const numVerifyResponse = await axios.get(
            `http://apilayer.net/api/validate?access_key=${numVerifyKey}&number=${cleanPhone}&country_code=IN&format=1`
        );
        const numData = numVerifyResponse.data;
        console.log('NumVerify Response:', JSON.stringify(numData));

        // ── IPQS for fraud score ────────────────────────────────
        const ipqsKey = process.env.IPQS_API_KEY;
        let fraudScore = 0;
        let spammer = false;
        let risky = false;

        try {
            const ipqsResponse = await axios.get(
                `https://www.ipqualityscore.com/api/json/phone/${ipqsKey}/${cleanPhone}?strictness=1`
            );
            const ipqsData = ipqsResponse.data;
            if (ipqsData.success) {
                fraudScore = ipqsData.fraud_score || 0;
                spammer = ipqsData.spammer || false;
                risky = ipqsData.risky || false;
            }
        } catch (e) {
            console.log('IPQS skipped:', e.message);
        }

        let riskScore = 0;
        let reasons = [];

        // NumVerify results
        if (!numData.valid) {
            riskScore += 20;
            reasons.push('Invalid phone number format');
        }

        // Fraud score from IPQS
        if (fraudScore > 85) {
            riskScore += 50;
            reasons.push('Very high fraud score');
        } else if (fraudScore > 60) {
            riskScore += 30;
            reasons.push('High fraud score');
        }

        if (spammer) {
            riskScore += 40;
            reasons.push('Known spammer number');
        }

        if (risky) {
            riskScore += 20;
            reasons.push('Risky phone number');
        }

        riskScore = Math.min(riskScore, 100);
        const riskLevel = riskScore < 30 ? 'Low' : riskScore < 60 ? 'Medium' : 'High';

        res.json({
            phone: cleanPhone,
            riskScore,
            riskLevel,
            valid: numData.valid,
            fraudScore,
            carrier: numData.carrier || 'Unknown',
            lineType: numData.line_type || numData.type || 'Unknown',
            country: numData.country_name || numData.country_code || 'Unknown',
            location: numData.location || 'Unknown',
            reasons,
            message: riskScore >= 30
                ? '⚠️ SUSPICIOUS NUMBER: ' + reasons.join('. ')
                : '✅ PHONE NUMBER LOOKS SAFE'
        });

    } catch (error) {
        console.log('Phone check error:', error.message);
        res.status(500).json({ error: 'Could not check phone: ' + error.message });
    }
});

// ── SMS Check Route ─────────────────────────────────────────────
app.post('/check-sms', async (req, res) => {
    const { sms } = req.body;
    if (!sms) return res.status(400).json({ error: 'Please enter SMS text' });
    console.log(`💬 Checking SMS`);

    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = sms.match(urlRegex) || [];

    let riskScore = 0;
    let reasons = [];

    const suspiciousWords = [
        'won', 'winner', 'prize', 'claim', 'free', 'urgent',
        'verify', 'suspended', 'blocked', 'click here', 'limited time',
        'congratulations', 'selected', 'reward', 'otp', 'bank account',
        'credit card', 'password', 'login', 'confirm', 'kyc', 'aadhar',
        'pan card', 'lucky', 'cash prize', 'lakh', 'crore'
    ];

    const lowerSms = sms.toLowerCase();
    const foundWords = suspiciousWords.filter(word => lowerSms.includes(word));

    if (foundWords.length >= 3) {
        riskScore += 40;
        reasons.push(`Contains ${foundWords.length} suspicious words: ${foundWords.slice(0, 3).join(', ')}`);
    } else if (foundWords.length > 0) {
        riskScore += 15;
        reasons.push(`Contains suspicious words: ${foundWords.join(', ')}`);
    }

    // Check URLs in SMS
    let urlResults = [];
    for (const url of urls.slice(0, 3)) {
        const [gsb, ipqs] = await Promise.all([
            checkGoogleSafeBrowsing(url),
            checkIPQS(url)
        ]);
        const { score } = calculateRiskScore(gsb, null, ipqs);
        urlResults.push({ url, score });
        if (score > 50) {
            riskScore += 30;
            reasons.push(`Suspicious URL found: ${url}`);
        }
    }

    riskScore = Math.min(riskScore, 100);
    const riskLevel = riskScore < 30 ? 'Low' : riskScore < 60 ? 'Medium' : 'High';

    res.json({
        riskScore, riskLevel,
        urlsFound: urls.length,
        urlResults,
        suspiciousWords: foundWords,
        reasons,
        message: riskScore >= 30
            ? '⚠️ SUSPICIOUS SMS: ' + reasons.join('. ')
            : '✅ SMS LOOKS SAFE'
    });
});

// ── History Route ───────────────────────────────────────────────
app.get('/history', async (req, res) => {
    if (mongoose.connection.readyState !== 1) {
        return res.json({ error: 'Database not connected' });
    }
    try {
        const scans = await Scan.find().sort({ timestamp: -1 }).limit(20);
        res.json(scans);
    } catch (e) {
        res.json({ error: e.message });
    }
});

// ── PDF Route ───────────────────────────────────────────────────
app.post('/download-pdf', (req, res) => {
    const { type, target, riskScore, riskLevel, reasons } = req.body;
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=phishshield-report.pdf');
    doc.pipe(res);

    doc.fontSize(20).text('PhishShield Threat Report', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Type: ${type || 'URL'}`);
    doc.text(`Target: ${target}`);
    doc.text(`Risk Score: ${riskScore} / 100`);
    doc.text(`Risk Level: ${riskLevel}`);

    if (reasons && reasons.length > 0) {
        doc.moveDown();
        doc.text('Threat Reasons:');
        reasons.forEach(r => doc.text(`  • ${r}`));
    }

    doc.moveDown();
    doc.text(`Generated: ${new Date().toLocaleString()}`);
    doc.text('PhishShield - AI Threat Intelligence Analyzer');
    doc.end();
});

app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});