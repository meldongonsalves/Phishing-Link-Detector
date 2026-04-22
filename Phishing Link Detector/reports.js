let allReports = [];
    let sortBy = 'domain';
    let sortDir = 1;

    // ── Load data ─────────────────────────────────────────────────────────────
    function loadReports() {
      chrome.storage.local.get(null, (result) => {
        // Support both old format (just array) and new format (with metadata)
        const domains  = result.userReportedDomains || [];
        const metadata = result.reportMetadata || {};

        // Debug: log what's in storage
        console.log('[Reports] Storage contents:', result);
        console.log('[Reports] Domains found:', domains);

        allReports = domains.map(domain => ({
          domain,
          date:   metadata[domain]?.date   || null,
          visits: metadata[domain]?.visits || 0
        }));

        renderTable(allReports);
        updateStats();
      });
    }

    // ── Render table ──────────────────────────────────────────────────────────
    function renderTable(data) {
      const tbody = document.getElementById('tableBody');
      const exportBtn   = document.getElementById('exportBtn');
      const clearAllBtn = document.getElementById('clearAllBtn');

      exportBtn.disabled   = data.length === 0;
      clearAllBtn.disabled = data.length === 0;

      if (data.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="4">
              <div class="empty">
                <div class="empty-icon">✓</div>
                <div class="empty-title">No domains reported yet</div>
                <div class="empty-sub">
                  When you click the 🚩 Report button in the extension popup,<br/>
                  the domain will appear here with the date and visit count.
                </div>
              </div>
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = data.map(item => {
  

        return `
          <tr>
            <td>
              <div class="domain-cell">
                <div class="domain-dot"></div>
                <div class="domain-name">${item.domain}</div>
              </div>
            </td>
            <td>
              <button class="remove-btn" onclick="removeDomain('${item.domain}')">Remove</button>
            </td>
          </tr>`;
      }).join('');
    }

    // ── Update stats ──────────────────────────────────────────────────────────
    function updateStats() { /* stats bar removed */ }

    // ── Remove single domain ──────────────────────────────────────────────────
    function removeDomain(domain) {
      chrome.storage.local.get(['userReportedDomains', 'reportMetadata'], (result) => {
        const domains  = (result.userReportedDomains || []).filter(d => d !== domain);
        const metadata = result.reportMetadata || {};
        delete metadata[domain];

        chrome.storage.local.set({ userReportedDomains: domains, reportMetadata: metadata }, () => {
          allReports = allReports.filter(r => r.domain !== domain);
          applyFiltersAndSort();
          updateStats();
          showToast(`${domain} removed from blocklist`);
        });
      });
    }

    // ── Clear all ─────────────────────────────────────────────────────────────
    document.getElementById('clearAllBtn').addEventListener('click', () => {
      if (!confirm('Clear all reported domains? This cannot be undone.')) return;
      chrome.storage.local.set({ userReportedDomains: [], reportMetadata: {} }, () => {
        allReports = [];
        renderTable([]);
        updateStats();
        showToast('All reported domains cleared');
      });
    });

    // ── Export to CSV ─────────────────────────────────────────────────────────
    document.getElementById('exportBtn').addEventListener('click', () => {
      if (allReports.length === 0) return;

      const headers = ['Domain', 'Date Reported', 'Time Reported', 'Visits Blocked'];
      const rows = allReports.map(r => {
        const d = r.date !== 'Unknown' ? new Date(r.date) : null;
        return [
          r.domain,
          d ? d.toLocaleDateString('en-GB') : '—',
          d ? d.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' }) : '—',
          r.visits || 0
        ];
      });

      const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `phishing-blocklist-${new Date().toISOString().slice(0,10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Exported to CSV successfully');
    });

    // ── Search ────────────────────────────────────────────────────────────────
    document.getElementById('searchInput').addEventListener('input', applyFiltersAndSort);

    function applyFiltersAndSort() {
      const query = document.getElementById('searchInput').value.toLowerCase().trim();
      let filtered = query
        ? allReports.filter(r => r.domain.toLowerCase().includes(query))
        : [...allReports];

      filtered.sort((a, b) => {
        let av, bv;
        if (sortBy === 'domain')  { av = a.domain; bv = b.domain; }
        if (sortBy === 'date')    { av = new Date(a.date || 0); bv = new Date(b.date || 0); }
        if (sortBy === 'visits')  { av = a.visits || 0; bv = b.visits || 0; }
        if (av < bv) return -1 * sortDir;
        if (av > bv) return  1 * sortDir;
        return 0;
      });

      renderTable(filtered);
    }

    // ── Sorting ───────────────────────────────────────────────────────────────
    document.getElementById('sortDomain').addEventListener('click', () => {
      sortDir *= -1;
      applyFiltersAndSort();
    });

    // ── Toast ─────────────────────────────────────────────────────────────────
    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = '✓ ' + msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2500);
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    loadReports();