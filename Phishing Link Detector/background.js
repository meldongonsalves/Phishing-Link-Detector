// background.js — Service Worker
// Handles:
//   1. OpenPhish feed — loads confirmed phishing URLs into memory (no key needed)
//   2. PhishTank API  — per-URL lookup (free, needs API key from phishtank.org)
//   3. WHOIS domain age — free API, no key needed

// ─── CONFIG ───────────────────────────────────────────────────────────────────
// To enable PhishTank: register free at https://www.phishtank.com/api_register.php
// Then paste your key below. Leave empty to skip PhishTank and use OpenPhish only.
const PHISHTANK_API_KEY = '';


// VirusTotal API — free tier: 500 requests/day, 4 per minute
// Register free at https://www.virustotal.com/gui/join-us
// Paste your key below to enable. Works without a key — just skips VT check.
const VIRUSTOTAL_API_KEY = '';


// ─── DATABASE WHITELIST ───────────────────────────────────────────────────────
// Domains that must NEVER be flagged even if they appear in phishing databases.
const DATABASE_WHITELIST = new Set([
  'googleadservices.com','doubleclick.net','googlesyndication.com',
  'googletagmanager.com','googletagservices.com','google-analytics.com',
  'g.co','goo.gl','youtube.com','youtu.be','google.com','googleapis.com',
  'gstatic.com','googleusercontent.com','ggpht.com',
  'facebook.com','instagram.com','twitter.com','x.com',
  'microsoft.com','microsoftonline.com','live.com','outlook.com',
  'apple.com','icloud.com','amazon.com','amazon.co.uk',
  'taboola.com','outbrain.com','adsrvr.org','criteo.com','adnxs.com',
]);

function isDatabaseWhitelisted(domain) {
  domain = domain.replace(/^www\./, '');
  if (DATABASE_WHITELIST.has(domain)) return true;
  const parts = domain.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (DATABASE_WHITELIST.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

// ─── OPENPHISH FEED ───────────────────────────────────────────────────────────
// Public feed from GitHub mirror — updated regularly, no key required
// Contains ~30,000 confirmed active phishing URLs
const OPENPHISH_FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

let openPhishSet = new Set();      // confirmed phishing URLs from OpenPhish
let openPhishDomainSet = new Set(); // just domains for faster lookup
let feedLastLoaded = null;

async function loadOpenPhishFeed() {
  try {
    console.log('[PhishingDetector] Loading OpenPhish feed...');
    const response = await fetch(OPENPHISH_FEED_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    const urls = text.trim().split('\n').filter(u => u.startsWith('http'));

    openPhishSet = new Set(urls.map(u => u.trim().toLowerCase()));

    // Also extract domains for partial matching
    openPhishDomainSet = new Set();
    for (const url of openPhishSet) {
      try {
        const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
        openPhishDomainSet.add(hostname);
      } catch(e) {}
    }

    feedLastLoaded = Date.now();
    console.log(`[PhishingDetector] OpenPhish feed loaded: ${openPhishSet.size} URLs, ${openPhishDomainSet.size} domains`);
  } catch(err) {
    console.warn('[PhishingDetector] OpenPhish feed failed to load:', err.message);
  }
}

// Reload feed every 6 hours (matches OpenPhish update cadence)
loadOpenPhishFeed();
setInterval(loadOpenPhishFeed, 6 * 60 * 60 * 1000);

// ─── CACHES ───────────────────────────────────────────────────────────────────
const phishTankCache = {};
const virusTotalCache = {};
const whoisCache     = {};

// ─── MESSAGE HANDLER ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ── Database check (OpenPhish + PhishTank combined) ──────────────────────
  if (message.action === 'checkDatabase') {
    const url    = message.url.trim().toLowerCase();
    const domain = message.domain.toLowerCase().replace(/^www\./, '');

    // 0. Check database whitelist first — prevents false positives on Google ad domains etc.
    if (isDatabaseWhitelisted(domain)) {
      sendResponse({ success: true, isPhishing: false, source: 'Whitelist', detail: 'Domain is whitelisted' });
      return true;
    }

    // 1. Check OpenPhish feed first (instant, local)
    const inOpenPhish = openPhishSet.has(url) || openPhishDomainSet.has(domain);
    if (inOpenPhish) {
      sendResponse({
        success: true,
        isPhishing: true,
        source: 'OpenPhish',
        detail: 'Confirmed phishing URL in OpenPhish database (Cisco Talos verified)'
      });
      return true;
    }

    // 2. Check PhishTank if key is configured
    if (PHISHTANK_API_KEY) {
      if (phishTankCache[url] !== undefined) {
        sendResponse({ success: true, ...phishTankCache[url] });
        return true;
      }

      const formData = new URLSearchParams();
      formData.append('url', btoa(url)); // PhishTank expects base64-encoded URL
      formData.append('format', 'json');
      formData.append('app_key', PHISHTANK_API_KEY);

      fetch('https://checkurl.phishtank.com/checkurl/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'PhishingDetectorExtension/2.0'
        },
        body: formData.toString()
      })
      .then(r => r.json())
      .then(data => {
        const results = data?.results;
        const isPhishing = results?.in_database === true && results?.valid === 'y';
        const result = {
          success: true,
          isPhishing,
          source: 'PhishTank',
          detail: isPhishing
            ? `Confirmed phishing in PhishTank database (ID: ${results.phish_id})`
            : 'Not found in PhishTank database'
        };
        phishTankCache[url] = result;
        sendResponse(result);
      })
      .catch(() => {
        sendResponse({ success: true, isPhishing: false, source: 'PhishTank', detail: 'Lookup failed' });
      });
      return true;
    }


    // 3. VirusTotal check if key configured
    if (VIRUSTOTAL_API_KEY) {
      const urlBase64 = btoa(url).replace(/=/g, '');
      if (virusTotalCache[url] !== undefined) {
        sendResponse({ success: true, ...virusTotalCache[url] });
        return true;
      }
      fetch(`https://www.virustotal.com/api/v3/urls/${urlBase64}`, {
        headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
      })
      .then(r => r.json())
      .then(data => {
        const stats = data?.data?.attributes?.last_analysis_stats;
        const malicious = stats?.malicious || 0;
        const suspicious = stats?.suspicious || 0;
        const total = Object.values(stats || {}).reduce((a,b) => a+b, 0);
        const isPhishing = malicious >= 3;
        const result = {
          success: true,
          isPhishing,
          source: 'VirusTotal',
          detail: isPhishing
            ? `Flagged by ${malicious}/${total} VirusTotal engines`
            : `Clean on VirusTotal (${malicious} flags out of ${total} engines)`
        };
        virusTotalCache[url] = result;
        sendResponse(result);
      })
      .catch(() => {
        sendResponse({ success: true, isPhishing: false, source: 'VirusTotal', detail: 'Lookup failed' });
      });
      return true;
    }

    // No key — just report OpenPhish result (not found)
    sendResponse({
      success: true,
      isPhishing: false,
      source: 'OpenPhish',
      detail: openPhishSet.size > 0
        ? `Not found in OpenPhish database (${openPhishSet.size.toLocaleString()} URLs checked)`
        : 'OpenPhish feed not yet loaded'
    });
    return true;
  }

  // ── WHOIS domain age lookup ──────────────────────────────────────────────
  if (message.action === 'whoisLookup') {
    const domain = message.domain;
    if (whoisCache[domain]) {
      sendResponse({ success: true, data: whoisCache[domain], cached: true });
      return true;
    }

    fetch(`https://domaininfo.shreshtait.com/api/search/${domain}`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => {
        let ageDays = null, isNewDomain = false;
        if (data.creation_date) {
          ageDays = Math.floor((Date.now() - new Date(data.creation_date)) / 86400000);
          isNewDomain = ageDays < 180;
        }
        const result = {
          domain,
          creationDate: data.creation_date || null,
          registrar: data.registrar || null,
          ageDays,
          isNewDomain,
          ageLabel: ageDays !== null
            ? ageDays < 30   ? `${ageDays} days old — very new`
            : ageDays < 180  ? `${ageDays} days old — recently registered`
            : ageDays < 365  ? `${Math.floor(ageDays/30)} months old`
            : `${Math.floor(ageDays/365)} year(s) old`
            : 'Age unknown'
        };
        whoisCache[domain] = result;
        sendResponse({ success: true, data: result });
      })
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }



  // ── User report: "Report as Phishing" ───────────────────────────────────
  if (message.action === 'reportPhishing') {
    const domain = message.domain;
    chrome.storage.local.get(['userReportedDomains', 'reportMetadata'], (result) => {
      const reported = result.userReportedDomains || [];
      const metadata = result.reportMetadata || {};
      if (!reported.includes(domain)) {
        reported.push(domain);
        metadata[domain] = { date: new Date().toISOString(), visits: 0 };
        chrome.storage.local.set({ userReportedDomains: reported, reportMetadata: metadata }, () => {
          console.log(`[PhishingDetector] User reported: ${domain}`);
        });
      }
      sendResponse({ success: true, totalReported: reported.length });
    });
    return true;
  }

  // ── Increment visit count for reported domain ────────────────────────────
  if (message.action === 'incrementVisit') {
    const domain = message.domain;
    chrome.storage.local.get(['reportMetadata'], (result) => {
      const metadata = result.reportMetadata || {};
      if (metadata[domain]) {
        metadata[domain].visits = (metadata[domain].visits || 0) + 1;
        chrome.storage.local.set({ reportMetadata: metadata });
      }
    });
    return true;
  }

  // ── Check user reported domains ──────────────────────────────────────────
  if (message.action === 'getUserReports') {
    chrome.storage.local.get(['userReportedDomains'], (result) => {
      sendResponse({ domains: result.userReportedDomains || [] });
    });
    return true;
  }

  // ── Browser notification ─────────────────────────────────────────────────
  if (message.action === 'showNotification') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icon.png',
      title: message.title,
      message: message.message,
      priority: 2
    });
    return true;
  }

  // ── Feed status (for popup info) ─────────────────────────────────────────
  if (message.action === 'getFeedStatus') {
    sendResponse({
      openPhishCount: openPhishSet.size,
      openPhishDomains: openPhishDomainSet.size,
      feedLastLoaded,
      phishTankEnabled: !!PHISHTANK_API_KEY
    });
    return true;
  }
});
