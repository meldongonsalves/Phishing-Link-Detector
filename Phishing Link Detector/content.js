// content.js
// Detection pipeline:
//   1. Trusted whitelist  → skip entirely (no false positives)
//   2. OpenPhish/PhishTank database → instant confirmed flag
//   3. ML model + typosquatting + WHOIS → catches new/unknown threats

// On chatbot pages use lower threshold (0.6) — any phishing link in an AI response is high concern.
// On general pages (YouTube, Google etc.) raise to 0.82 to avoid flagging ad links and embeds.
const THRESHOLD_CHATBOT = 0.60;
const THRESHOLD_GENERAL = 0.82;

// Pages where we apply the higher threshold to reduce noise from ads/third-party links
const TRUSTED_HOST_PAGES = [
  'youtube.com','google.com','reddit.com','twitter.com','x.com',
  'facebook.com','instagram.com','linkedin.com','twitch.tv',
  'bbc.co.uk','bbc.com','cnn.com','theguardian.com','wikipedia.org'
];

const CHATBOT_DOMAINS = [
  'chat.openai.com','chatgpt.com','claude.ai',
  'gemini.google.com','perplexity.ai','poe.com',
  'copilot.microsoft.com','you.com'
];

const currentHost = window.location.hostname.toLowerCase();
const isOnChatbot = CHATBOT_DOMAINS.some(d => currentHost.includes(d));
const isOnTrustedPage = TRUSTED_HOST_PAGES.some(d => currentHost.includes(d));
// file:// pages are demo/test pages — use chatbot threshold
const isFilePage = window.location.protocol === 'file:';
const HIGH_RISK_THRESHOLD = (isOnChatbot || isFilePage) ? THRESHOLD_CHATBOT : (isOnTrustedPage ? THRESHOLD_GENERAL : 0.70);

function getChatbotName(host) {
  if (host.includes('openai.com') || host.includes('chatgpt.com')) return 'ChatGPT';
  if (host.includes('claude.ai'))   return 'Claude';
  if (host.includes('gemini'))      return 'Gemini';
  if (host.includes('perplexity'))  return 'Perplexity';
  if (host.includes('poe'))         return 'Poe';
  if (host.includes('copilot') || host.includes('bing')) return 'Copilot';
  return null;
}


// ─── USER REPORTED DOMAINS ────────────────────────────────────────────────────
let userReportedDomains = new Set();

// Load user reports from storage on startup
chrome.runtime.sendMessage({ action: 'getUserReports' }, (response) => {
  if (response?.domains) {
    userReportedDomains = new Set(response.domains);
  }
});

function isUserReported(hostname) {
  hostname = hostname.replace(/^www\./, '');
  return userReportedDomains.has(hostname);
}

let scanResults = {
  total: 0, flagged: 0, safe: 0, skipped: 0,
  dbConfirmed: 0,   // URLs confirmed phishing by database
  mlFlagged: 0,     // URLs flagged by ML only
  flaggedLinks: [],
  isChatbotPage: isOnChatbot,
  chatbotName: getChatbotName(currentHost)
};

// ─── TOOLTIP ──────────────────────────────────────────────────────────────────
const tooltipEl = (() => {
  const t = document.createElement('div');
  t.className = 'phishing-tooltip';
  t.style.display = 'none';
  document.body.appendChild(t);
  return t;
})();

function severityColor(s) {
  return s === 'high' ? '#ff3c5a' : s === 'medium' ? '#ffb547' : '#8b93b0';
}

function showTooltip(linkEl, score, reasons, whoisData, dbResult) {
  const pct = score >= 1 ? '100' : (score * 100).toFixed(0);
  const barColor = score > 0.8 ? '#ff3c5a' : '#ffb547';

  // Database badge
  const dbBadge = dbResult?.isPhishing
    ? `<div style="background:rgba(255,60,90,.15);border:1px solid rgba(255,60,90,.4);border-radius:4px;padding:4px 8px;font-size:10px;color:#ff3c5a;margin-bottom:8px;font-family:monospace;">
        🔴 Confirmed in ${dbResult.source} database
       </div>`
    : '';

  const whoisHtml = whoisData ? (() => {
    const c = whoisData.isNewDomain ? '#ff3c5a' : '#00e5a0';
    return `<div style="margin-top:8px;padding-top:7px;border-top:1px solid #1e2330;font-size:10px;">
      <span style="color:#555;text-transform:uppercase;letter-spacing:.06em;">WHOIS: </span>
      <span style="color:${c}">${whoisData.isNewDomain ? '⚠ ' : '✓ '}${whoisData.ageLabel}</span>
    </div>`;
  })() : '';

  const reasonsHtml = reasons.map(r => `
    <div style="display:flex;gap:7px;align-items:flex-start;margin-top:5px;">
      <span style="color:${severityColor(r.severity)};flex-shrink:0;font-size:9px;margin-top:2px;">▶</span>
      <span style="color:#ccc;font-size:11px;line-height:1.4">${r.text}</span>
    </div>`).join('');

  tooltipEl.innerHTML = `
    <div style="font-weight:800;font-size:13px;color:#ff3c5a;margin-bottom:5px;">⚠ Phishing Risk: ${pct}%</div>
    <div style="background:#111;border-radius:3px;height:5px;margin-bottom:10px;">
      <div style="width:${pct}%;background:${barColor};height:5px;border-radius:3px;"></div>
    </div>
    ${dbBadge}
    <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#555;margin-bottom:2px;">Why flagged:</div>
    ${reasonsHtml}
    ${whoisHtml}`;

  const rect = linkEl.getBoundingClientRect();
  const left = Math.min(window.scrollX + rect.left, window.scrollX + window.innerWidth - 300);
  tooltipEl.style.left = `${left}px`;
  tooltipEl.style.top = `${window.scrollY + rect.bottom + 6}px`;
  tooltipEl.style.display = 'block';
}

function hideTooltip() { tooltipEl.style.display = 'none'; }

// ─── BROWSER NOTIFICATION ─────────────────────────────────────────────────────
// Shows a Chrome notification when phishing links are found on a page.
// Only fires once per page load to avoid spamming the user.
let notificationShown = false;

function showPhishingNotification(count, dbConfirmed) {
  if (notificationShown) return;
  notificationShown = true;

  const isConfirmed = dbConfirmed > 0;
  const title = isConfirmed
    ? `⚠ Confirmed Phishing Links Detected`
    : `⚠ Suspicious Links Detected`;
  const message = isConfirmed
    ? `${dbConfirmed} link${dbConfirmed > 1 ? 's' : ''} on this page confirmed in phishing databases. Do not click unknown links.`
    : `${count} suspicious link${count > 1 ? 's' : ''} flagged by the ML model. Click the extension icon for details.`;

  chrome.runtime.sendMessage({
    action: 'showNotification',
    title,
    message
  });
}



// ─── BACKGROUND COMMUNICATION ─────────────────────────────────────────────────
function checkDatabase(url, domain) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ action: 'checkDatabase', url, domain }, response => {
        resolve(chrome.runtime.lastError ? null : response);
      });
    } catch(e) { resolve(null); }
  });
}

function fetchWhoisAge(domain) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ action: 'whoisLookup', domain }, response => {
        resolve(chrome.runtime.lastError || !response?.success ? null : response.data);
      });
    } catch(e) { resolve(null); }
  });
}

// ─── APPLY HIGHLIGHT ──────────────────────────────────────────────────────────
function highlightLink(url, score, reasons, whoisData, dbResult) {
  // Use direct href comparison instead of CSS.escape selector
  // CSS.escape can mangle URLs with dots/slashes causing querySelectorAll to miss elements
  document.querySelectorAll('a[href]').forEach(el => {
    if (el.href !== url) return;
    el.classList.add('phishing-high-risk');
    if (dbResult?.isPhishing) el.classList.add('phishing-confirmed');
    if (!el.dataset.phishingListened) {
      el.dataset.phishingListened = '1';
      el.addEventListener('mouseenter', () => showTooltip(el, score, reasons, whoisData, dbResult));
      el.addEventListener('mouseleave', hideTooltip);
    }
  });
}

// ─── MAIN SCANNER ─────────────────────────────────────────────────────────────
async function scanLinks() {
  const allLinks = document.querySelectorAll('a[href]');

  scanResults = {
    total: 0, flagged: 0, safe: 0, skipped: 0,
    dbConfirmed: 0, mlFlagged: 0,
    flaggedLinks: [],
    isChatbotPage: isOnChatbot,
    chatbotName: getChatbotName(currentHost)
  };

  const seenUrls = new Set();

  // Reset notification flag so it can fire again on rescan
  notificationShown = false;

  // Remove old highlights AND clear listener flags so ALL links get re-evaluated
  document.querySelectorAll('a[href]').forEach(el => {
    el.classList.remove('phishing-high-risk', 'phishing-confirmed');
    delete el.dataset.phishingListened;
  });

  const urlsToProcess = [];
  allLinks.forEach(link => {
    const url = link.href;
    if (!url || !url.startsWith('http')) return;
    if (seenUrls.has(url)) return;
    seenUrls.add(url);

    const features = extractFeatures(url);
    if (features === null) { scanResults.skipped++; return; }

    scanResults.total++;
    urlsToProcess.push({ url, features });
  });

  // Process all URLs in parallel
  await Promise.all(urlsToProcess.map(async ({ url, features }) => {
    let hostname;
    try { hostname = new URL(url).hostname.replace(/^www\./, ''); } catch(e) { return; }

    // Step 0: Check user-reported domains (highest priority)
    if (isUserReported(hostname)) {
      scanResults.flagged++;
      scanResults.dbConfirmed++;
      const reasons = [{ text: 'You previously reported this domain as phishing', severity: 'high' }];
      const item = { url, score: 1.0, reasons, whoisData: null, dbResult: { isPhishing: true, source: 'User Report' }, source: 'User Report' };
      scanResults.flaggedLinks.push(item);
      highlightLink(url, 1.0, reasons, null, { isPhishing: true, source: 'User Report' });
      return;
    }

    // Step 1: Check public phishing databases
    const dbResult = await checkDatabase(url, hostname);

    if (dbResult?.isPhishing) {
      // Confirmed by database — highest confidence, score = 1.0
      scanResults.flagged++;
      scanResults.dbConfirmed++;
      const reasons = [{
        text: `${dbResult.detail}`,
        severity: 'high'
      }];
      const item = { url, score: 1.0, reasons, whoisData: null, dbResult, source: dbResult.source };
      scanResults.flaggedLinks.push(item);
      highlightLink(url, 1.0, reasons, null, dbResult);
      return;
    }

    // Step 2: ML model + typosquatting
    const score = computePhishingProbability(features);
    const reasons = generateReasons(features, score);

    if (score >= HIGH_RISK_THRESHOLD) {
      scanResults.flagged++;
      scanResults.mlFlagged++;
      const item = { url, score, reasons, whoisData: null, dbResult, source: 'ML Model' };
      scanResults.flaggedLinks.push(item);
      highlightLink(url, score, reasons, null, dbResult);

      // Step 3: WHOIS age check (async, updates after initial flag)
      const whoisData = await fetchWhoisAge(hostname);
      if (whoisData) {
        item.whoisData = whoisData;
        if (whoisData.isNewDomain) {
          item.reasons.unshift({
            text: `Domain is only ${whoisData.ageLabel} — newly registered domains are a strong phishing indicator`,
            severity: 'high'
          });
        }
      }
    } else {
      scanResults.safe++;
    }
  }));


  // ── SCAN THE CURRENT PAGE'S OWN DOMAIN ──────────────────────────────────
  // This catches scam sites like bestadblocker.net where the scam is a popup
  // with no <a> links — we score the page domain itself
  try {
    const pageHostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
    if (!isTrustedDomain(pageHostname) && !isUserReported(pageHostname)) {
      const pageUrl = window.location.href;
      const pageFeatures = extractFeatures(pageUrl);
      if (pageFeatures) {
        const pageScore = computePhishingProbability(pageFeatures);
        // Use a slightly lower threshold for the page itself (0.55)
        // since we're on it, any signal matters more
        if (pageScore >= 0.55) {
          const pageReasons = generateReasons(pageFeatures, pageScore);
          pageReasons.unshift({
            text: 'This page\'s own domain was flagged — the site itself may be malicious, not just links on it',
            severity: 'high'
          });
          scanResults.flagged++;
          scanResults.mlFlagged++;
          const pageItem = {
            url: pageUrl,
            score: pageScore,
            reasons: pageReasons,
            whoisData: null,
            dbResult: null,
            source: 'Page Domain',
            isPageDomain: true
          };
          scanResults.flaggedLinks.unshift(pageItem); // put at top of list

          // WHOIS for the page domain too
          const pageWhois = await fetchWhoisAge(pageHostname);
          if (pageWhois) {
            pageItem.whoisData = pageWhois;
            if (pageWhois.isNewDomain) {
              pageItem.reasons.splice(1, 0, {
                text: `This domain is only ${pageWhois.ageLabel} — very recently registered`,
                severity: 'high'
              });
            }
          }
        }
      }
    }
  } catch(e) { /* page domain scan failed silently */ }

  // Fire browser notification if anything was flagged
  if (scanResults.flagged > 0) {
    showPhishingNotification(scanResults.flagged, scanResults.dbConfirmed);
  }
}

// ─── POPUP COMMUNICATION ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getResults') {
    sendResponse({ results: scanResults });
  } else if (message.action === 'rescan') {
    scanLinks().then(() => sendResponse({ results: scanResults }));
  }
  return true;
});

// Run
scanLinks();

// Signal ready
chrome.runtime.sendMessage({ action: 'contentScriptReady' }).catch(() => {});

// Watch for new content (chatbot streaming)
let scanTimer = null;
const observer = new MutationObserver(() => {
  clearTimeout(scanTimer);
  scanTimer = setTimeout(scanLinks, 800);
});
observer.observe(document.body, { childList: true, subtree: true });
