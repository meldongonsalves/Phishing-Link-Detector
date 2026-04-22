// popup.js

const statusBanner = document.getElementById('statusBanner');
const statusIcon   = document.getElementById('statusIcon');
const statusLabel  = document.getElementById('statusLabel');
const statusDesc   = document.getElementById('statusDesc');
const totalCount   = document.getElementById('totalCount');
const flaggedCount = document.getElementById('flaggedCount');
const safeCount    = document.getElementById('safeCount');
const linksList    = document.getElementById('linksList');
const listLabel    = document.getElementById('listLabel');
const modeBadge    = document.getElementById('modeBadge');
const rescanBtn    = document.getElementById('rescanBtn');
const feedStatus   = document.getElementById('feedStatus');

function getHost(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

function getHostAndPath(url) {
  try {
    const u = new URL(url);
    const path = u.pathname.length > 22 ? u.pathname.slice(0, 20) + '…' : u.pathname;
    return u.hostname + path;
  } catch { return url; }
}

// ── Feed status bar ────────────────────────────────────────────────────────────
function loadFeedStatus() {
  chrome.runtime.sendMessage({ action: 'getFeedStatus' }, (response) => {
    if (!response || !feedStatus) return;
    if (response.openPhishCount > 0) {
      feedStatus.textContent = `🔴 OpenPhish: ${response.openPhishCount.toLocaleString()} URLs loaded`;
      feedStatus.style.color = '#00e5a0';
    } else {
      feedStatus.textContent = '⏳ Loading phishing database…';
      feedStatus.style.color = '#4a5168';
    }
  });
}

// ── Mode badge ─────────────────────────────────────────────────────────────────
function renderBadge(isChatbot, name) {
  if (isChatbot && name) {
    modeBadge.innerHTML = `<div class="badge chatbot"><span class="dot"></span>Monitoring ${name} links</div>`;
  } else {
    modeBadge.innerHTML = `<div class="badge general">○ &nbsp;General page scan</div>`;
  }
}

// ── Render XAI reasons ─────────────────────────────────────────────────────────
function reasonsHTML(reasons) {
  if (!reasons || reasons.length === 0) {
    return '<div class="reason-row"><span class="reason-text">No specific pattern identified</span></div>';
  }
  return reasons.map(r => `
    <div class="reason-row">
      <span class="reason-dot ${r.severity}">▶</span>
      <span class="reason-text">${r.text}</span>
    </div>`).join('');
}

function whoisHTML(whoisData) {
  if (!whoisData) return '';
  const cls = whoisData.isNewDomain ? 'red' : 'green';
  const icon = whoisData.isNewDomain ? '⚠' : '✓';
  return `<div class="whois-block">
    <div class="whois-row">
      <span class="whois-label">WHOIS Age:</span>
      <span class="whois-value ${cls}">${icon} ${whoisData.ageLabel}</span>
    </div>
    ${whoisData.registrar ? `<div class="whois-row"><span class="whois-label">Registrar:</span><span class="whois-value">${whoisData.registrar.slice(0,35)}</span></div>` : ''}
  </div>`;
}

// ── Render results ─────────────────────────────────────────────────────────────
function renderResults(data) {
  const { total, flagged, safe, skipped, dbConfirmed, mlFlagged, flaggedLinks, isChatbotPage, chatbotName, url } = data;

  setupReportButton(getHost(url));
  totalCount.textContent   = total;
  flaggedCount.textContent = flagged;
  safeCount.textContent    = safe;
  statusLabel.classList.remove('scanning');
  renderBadge(isChatbotPage, chatbotName);

  if (flagged === 0) {
    statusBanner.className  = 'status safe';
    statusIcon.textContent  = '✅';
    statusLabel.textContent = 'Page Looks Safe';
    const note = skipped > 0 ? ` (${skipped} trusted domains skipped)` : '';
    statusDesc.textContent  = `${total} link${total !== 1 ? 's' : ''} analysed — none flagged${note}`;
  } else if (flagged <= 2) {
    statusBanner.className  = 'status warn';
    statusIcon.textContent  = '⚠️';
    statusLabel.textContent = 'Caution Advised';
    statusDesc.textContent  = `${flagged} suspicious link${flagged !== 1 ? 's' : ''} detected`;
  } else {
    statusBanner.className  = 'status danger';
    statusIcon.textContent  = '🚨';
    statusLabel.textContent = 'High Risk Page';
    // Check if the page domain itself was flagged
    const pageDomainFlagged = flaggedLinks?.some(l => l.isPageDomain);
    statusDesc.textContent = pageDomainFlagged
      ? `This page's domain is suspicious — do not enter any personal information`
      : `${flagged} phishing links found — do not click unknown links`;
  }

  if (!flaggedLinks || flaggedLinks.length === 0) {
    listLabel.textContent = 'FLAGGED LINKS';
    linksList.innerHTML   = '<div class="empty">✓ No suspicious links found</div>';
    return;
  }

  // Build source summary label
  const dbNote = dbConfirmed > 0 ? ` · ${dbConfirmed} database confirmed` : '';
  const mlNote = mlFlagged  > 0 ? ` · ${mlFlagged} ML detected` : '';
  listLabel.textContent = `FLAGGED LINKS${dbNote}${mlNote}`;

  linksList.innerHTML = flaggedLinks.map((item, idx) => {
    const pct  = item.score >= 1 ? '100' : (item.score * 100).toFixed(0);
    const disp = getHostAndPath(item.url);
    const pageBadge = item.isPageDomain ? '<span class="db-confirmed-badge" style="background:rgba(255,181,71,.15);border-color:rgba(255,181,71,.4);color:#ffb547">THIS PAGE</span>' : '';
    const dbBadge = item.dbResult?.isPhishing
      ? `<span class="db-confirmed-badge">${item.dbResult.source}</span>` : '';
    return `
      <div class="link-item" id="li-${idx}">
        <div class="link-row">
          <div class="link-dot${item.dbResult?.isPhishing ? ' confirmed' : ''}"></div>
          <div class="link-url" title="${item.url}">${item.isPageDomain ? "⚠ Current page domain" : disp}${pageBadge}${dbBadge}</div>
          <div class="link-score">${pct}%</div>
          <div class="link-arrow">▶</div>
        </div>
        <div class="reasons-panel">
          <div class="reasons-title">Why this was flagged:</div>
          ${reasonsHTML(item.reasons)}
          ${whoisHTML(item.whoisData)}
        </div>
      </div>`;
  }).join('');

  flaggedLinks.forEach((_, idx) => {
    const el = document.getElementById(`li-${idx}`);
    if (el) el.addEventListener('click', () => el.classList.toggle('expanded'));
  });
}

function showError(msg) {
  statusBanner.className  = 'status idle';
  statusIcon.textContent  = '❌';
  statusLabel.classList.remove('scanning');
  statusLabel.textContent = 'Cannot Scan';
  statusDesc.textContent  = msg;
  totalCount.textContent = flaggedCount.textContent = safeCount.textContent = '—';
  linksList.innerHTML = `<div class="empty">${msg}</div>`;
}

function resetUI() {
  statusBanner.className  = 'status idle';
  statusIcon.textContent  = '⏳';
  statusLabel.textContent = 'Scanning…';
  statusLabel.classList.add('scanning');
  statusDesc.textContent  = 'Checking databases & analysing links…';
  totalCount.textContent = flaggedCount.textContent = safeCount.textContent = '—';
  linksList.innerHTML = '<div class="empty">Loading…</div>';
  modeBadge.innerHTML = '';
}

function runScan() {
  resetUI();
  loadFeedStatus();
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) { showError('No active tab found'); return; }
  
    let attempts = 0;
    function tryGetResults() {
      attempts++;
      chrome.tabs.sendMessage(tab.id, { action: 'getResults' }, (response) => {
        if (chrome.runtime.lastError) {
          if (attempts <= 3) {
            chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ['featureExtractor.js', 'model.js', 'content.js']
            }, () => setTimeout(tryGetResults, 1000));
          } else {
            showError('Reload the page then try again');
          }
          return;
        }
        if (response?.results) {
          renderResults({ ...response.results, url: tab.url });
        } else {
          showError('No data yet — reload the page');
        }
      });
    }
    setTimeout(tryGetResults, 800);
  });
}

rescanBtn.addEventListener('click', () => {
  resetUI();
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { action: 'rescan' }, (response) => {
      if (chrome.runtime.lastError) { showError('Reload the page then try again'); return; }
      setTimeout(runScan, 2500);
    });
  });
});


// ── Report button ──────────────────────────────────────────────────────────────
const reportSection = document.getElementById('reportSection');
const reportBtn     = document.getElementById('reportBtn');
const reportLabel   = document.getElementById('reportLabel');

let currentPageHost = '';

function setupReportButton(host) {
  currentPageHost = host;
  if (!host || host === '—') return;

  // Check if already reported
  chrome.runtime.sendMessage({ action: 'getUserReports' }, (response) => {
    const reported = response?.domains || [];
    const clean = host.replace(/^www\./, '');

    reportSection.style.display = 'flex';

    if (reported.includes(clean)) {
      reportBtn.textContent = '✓ Reported';
      reportBtn.classList.add('reported');
      reportLabel.textContent = `${clean} is in your personal blocklist.`;
    } else {
      reportBtn.textContent = '🚩 Report';
      reportBtn.classList.remove('reported');
      reportLabel.textContent = `Suspicious page? Report ${clean} to your personal blocklist.`;
    }
  });
}

reportBtn.addEventListener('click', () => {
  if (reportBtn.classList.contains('reported')) return;
  const clean = currentPageHost.replace(/^www\./, '');
  chrome.runtime.sendMessage({ action: 'reportPhishing', domain: clean }, (response) => {
    if (response?.success) {
      reportBtn.textContent = '✓ Reported';
      reportBtn.classList.add('reported');
      reportLabel.textContent = `${clean} added to your personal blocklist. It will be flagged on future visits.`;
      // Re-run scan on current tab to immediately show it flagged
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { action: 'rescan' }, () => {});
        }
      });
    }
  });
});


// ── View Reports page ──────────────────────────────────────────────────────────
const viewReportsBtn = document.getElementById('viewReportsBtn');
if (viewReportsBtn) {
  viewReportsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('reports.html') });
  });
}

runScan();
