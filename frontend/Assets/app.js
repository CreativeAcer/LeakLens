  const API = '/api';

  let findings         = [];
  let filteredFindings = [];   // filtered + sorted subset rendered by virtual scroll
  let activeFilter     = 'ALL';
  let scanning         = false;
  let activeReader     = null;   // ReadableStreamDefaultReader
  let riskCounts       = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  let _vsRafPending    = false;  // requestAnimationFrame throttle flag
  const ROW_H          = 44;    // px — must match tbody tr rendered height
  const VS_OVERSCAN    = 5;     // extra rows rendered above/below viewport

  // ── Path input — show/hide SMB panel ──────────────────────────────────────
  function onPathInput() {
    const v = document.getElementById('scanPath').value;
    const isUnc = v.startsWith('\\\\') || v.startsWith('//');
    document.getElementById('smbPanel').style.display = isUnc ? 'block' : 'none';
  }

  // ── Tab switching ──────────────────────────────────────────────────────────
  function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === name);
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById('tab-' + name);
    if (panel) panel.classList.add('active');
    if (name === 'reports') loadReports();
  }

  // ── Filter ─────────────────────────────────────────────────────────────────
  function setFilter(f) {
    activeFilter = f;
    ['ALL','HIGH','MEDIUM','LOW'].forEach(x => {
      const id = 'f' + (x === 'ALL' ? 'All' : x === 'MEDIUM' ? 'Med' : x.charAt(0) + x.slice(1).toLowerCase());
      const btn = document.getElementById(id);
      if (btn) btn.className = 'filter-btn' + (x === f ? ' active-' + f : '');
    });
    renderTable();
  }

  // ── Start scan ─────────────────────────────────────────────────────────────
  async function startScan() {
    const scanPath      = document.getElementById('scanPath').value.trim();
    const maxFileSizeMB = parseInt(document.getElementById('maxFileSizeMB').value) || 10;
    const workers       = Math.max(1, Math.min(16, parseInt(document.getElementById('workerCount').value) || 8));
    const resume        = document.getElementById('resumeScan')?.checked || false;
    const username      = document.getElementById('smbUsername')?.value.trim() || '';
    const password      = document.getElementById('smbPassword')?.value || '';
    const domain        = document.getElementById('smbDomain')?.value.trim() || '';

    if (!scanPath) { alert('Please enter a file share path.'); return; }

    // Reset
    findings         = [];
    filteredFindings = [];
    riskCounts       = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    document.getElementById('tableBody').innerHTML    = '';
    document.getElementById('vsTopSpacer').style.height = '0';
    document.getElementById('vsBotSpacer').style.height = '0';
    document.getElementById('logWrap').innerHTML      = '';
    document.getElementById('statScanned').textContent  = '0';
    document.getElementById('statFindings').textContent = '0';
    document.getElementById('findingsBadge').style.display = 'none';
    document.getElementById('emptyState').style.display = 'block';
    document.getElementById('findingsTable').style.display = 'none';
    updateRiskBars();
    setStatus('scanning');

    let response;
    try {
      response = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanPath, maxFileSizeMB, workers, resume, username, password, domain }),
      });
    } catch (e) {
      alert('Cannot reach backend. Is it running?\n' + e.message);
      setStatus('idle');
      return;
    }

    if (!response.ok) {
      try {
        const err = await response.json();
        alert(err.error || 'Scan failed.');
      } catch (_) { alert('Scan failed.'); }
      setStatus('idle');
      return;
    }

    // Read the SSE stream from the POST response body
    activeReader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await activeReader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(trimmed.slice(6));
            handleStreamEvent(data);
          } catch (_) {}
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        appendLog('Stream error: ' + e.message, true);
      }
    }

    setStatus('done');
    activeReader = null;
    document.getElementById('progressFill').classList.remove('indeterminate');
    document.getElementById('progressFill').style.width = '100%';
    document.getElementById('progressText').textContent = 'Scan complete';
  }

  // ── Handle individual SSE events ───────────────────────────────────────────
  function handleStreamEvent(d) {
    switch (d.type) {
      case 'progress':
        document.getElementById('statScanned').textContent = d.scanned;
        if (d.current) {
          const rateStr = d.rate ? ` — ${d.rate} files/s` : '';
          document.getElementById('progressText').textContent = d.current + rateStr;
        }
        document.getElementById('progressFill').classList.add('indeterminate');
        break;

      case 'finding':
        findings.push(d);
        riskCounts[d.riskLevel] = (riskCounts[d.riskLevel] || 0) + 1;
        document.getElementById('statFindings').textContent = findings.length;
        document.getElementById('statFindings').classList.toggle('has-hits', findings.length > 0);
        const badge = document.getElementById('findingsBadge');
        badge.style.display = 'inline';
        badge.textContent = findings.length;
        updateRiskBars();
        onNewFinding(d);
        break;

      case 'log':
        appendLog(d.message, false);
        break;

      case 'error':
        appendLog(d.message, true);
        break;

      case 'summary':
        appendLog(`✔ Scan complete — ${d.scanned} files scanned, ${d.hits} findings. Scan ID: ${d.scanId}`, false);
        break;

      case 'done':
        setStatus('done');
        break;
    }
  }

  // ── Stop scan ──────────────────────────────────────────────────────────────
  async function stopScan() {
    if (activeReader) {
      try { activeReader.cancel(); } catch (_) {}
      activeReader = null;
    }
    await fetch(`${API}/scan/stop`, { method: 'POST' }).catch(() => {});
    setStatus('idle');
  }

  // ── SMB: Discover shares ───────────────────────────────────────────────────
  async function discoverShares() {
    const path = document.getElementById('scanPath').value.trim();
    const host = path.replace(/^\\\\|^\/\//, '').split(/[\\\/]/)[0];
    if (!host) { alert('Enter a server hostname or IP first.'); return; }

    const btn = document.getElementById('discoverBtn');
    btn.disabled = true;
    btn.textContent = '… Discovering';

    try {
      const res = await fetch(`${API}/shares`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host,
          username: document.getElementById('smbUsername').value.trim(),
          password: document.getElementById('smbPassword').value,
          domain:   document.getElementById('smbDomain').value.trim(),
        }),
      });
      const data = await res.json();

      if (!res.ok) { alert(data.error || 'Could not enumerate shares.'); return; }

      const container = document.getElementById('sharesList');
      if (!data.shares || data.shares.length === 0) {
        container.innerHTML = '<p style="font-size:11px;color:var(--text-dim);margin-top:8px;">No shares found.</p>';
        return;
      }
      container.innerHTML = '<div class="shares-list">' +
        data.shares.map(s =>
          `<div class="share-item" onclick="selectShare('${escHtml(host)}','${escHtml(s)}')">${escHtml(s)}</div>`
        ).join('') + '</div>';
    } catch (e) {
      alert('Share discovery failed: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = '⬡ Discover Shares';
    }
  }

  function selectShare(host, share) {
    document.getElementById('scanPath').value = `\\\\${host}\\${share}`;
  }

  // ── Status ─────────────────────────────────────────────────────────────────
  function setStatus(state) {
    scanning = state === 'scanning';
    const dot      = document.getElementById('statusDot');
    const text     = document.getElementById('statusText');
    const startBtn = document.getElementById('startBtn');
    const stopBtn  = document.getElementById('stopBtn');
    dot.className  = 'status-dot' + (state === 'scanning' ? ' scanning' : state === 'done' ? ' done' : '');
    text.textContent = state === 'scanning' ? 'Scanning…' : state === 'done' ? 'Complete' : 'Idle';
    startBtn.disabled = scanning;
    stopBtn.disabled  = !scanning;
  }

  // ── Risk bars ──────────────────────────────────────────────────────────────
  function updateRiskBars() {
    const total = findings.length || 1;
    ['HIGH','MEDIUM','LOW'].forEach(r => {
      const c   = riskCounts[r] || 0;
      const key = r === 'MEDIUM' ? 'Med' : r.charAt(0) + r.slice(1).toLowerCase();
      document.getElementById('riskFill' + key).style.width = (c / total * 100) + '%';
      document.getElementById('riskCount' + key).textContent = c;
    });
  }

  // ── Table rendering (virtual scroll) ──────────────────────────────────────
  function updateFilteredFindings() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    filteredFindings = findings.filter(f => {
      const matchFilter = activeFilter === 'ALL' || f.riskLevel === activeFilter;
      const matchSearch = !search ||
        f.fileName.toLowerCase().includes(search) ||
        f.fullPath.toLowerCase().includes(search);
      return matchFilter && matchSearch;
    });
  }

  function renderTable() {
    updateFilteredFindings();
    const empty = document.getElementById('emptyState');
    const table = document.getElementById('findingsTable');

    if (filteredFindings.length === 0) {
      empty.style.display = 'block';
      table.style.display = 'none';
      document.getElementById('tableBody').innerHTML = '';
      document.getElementById('vsTopSpacer').style.height = '0';
      document.getElementById('vsBotSpacer').style.height = '0';
      empty.innerHTML = findings.length === 0
        ? '<div class="icon">🔍</div><p>Configure a path and start a scan to see findings here.</p>'
        : '<div class="icon">✓</div><p>No findings match current filters.</p>';
      return;
    }

    empty.style.display = 'none';
    table.style.display = 'table';
    renderVisibleRows();
  }

  function renderVisibleRows() {
    const wrap    = document.querySelector('.findings-wrap');
    const scrollTop = wrap ? wrap.scrollTop : 0;
    const viewH   = wrap ? wrap.clientHeight : 600;
    const total   = filteredFindings.length;

    const start = Math.max(0, Math.floor(scrollTop / ROW_H) - VS_OVERSCAN);
    const end   = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + VS_OVERSCAN);

    document.getElementById('vsTopSpacer').style.height = (start * ROW_H) + 'px';
    document.getElementById('vsBotSpacer').style.height = ((total - end) * ROW_H) + 'px';

    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';
    for (let i = start; i < end; i++) {
      appendRow(filteredFindings[i], tbody);
    }
  }

  function scheduleVsRender() {
    if (!_vsRafPending) {
      _vsRafPending = true;
      requestAnimationFrame(() => {
        _vsRafPending = false;
        renderVisibleRows();
      });
    }
  }

  // Called for each new finding arriving from the SSE stream
  function onNewFinding(f) {
    const search = document.getElementById('searchInput').value.toLowerCase();
    const matchFilter = activeFilter === 'ALL' || f.riskLevel === activeFilter;
    const matchSearch = !search ||
      f.fileName.toLowerCase().includes(search) ||
      f.fullPath.toLowerCase().includes(search);

    if (matchFilter && matchSearch) {
      filteredFindings.push(f);
      document.getElementById('emptyState').style.display = 'none';
      document.getElementById('findingsTable').style.display = 'table';
      scheduleVsRender();
    }
  }

  function appendRow(f, tbody) {
    const list = f.findingsList || [];
    const tags = list.map(x => `<span class="finding-tag">${escHtml(x)}</span>`).join('');
    const conf = f.confidence || 0;
    const confDots = Array.from({length: 10}, (_, i) =>
      `<span class="confidence-dot${i < conf ? ' filled' : ''}" style="color:${riskColor(f.riskLevel)}"></span>`
    ).join('');
    const isSmb = !!f.smbShare;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <span class="risk-badge ${f.riskLevel}">${f.riskLevel}</span>
        <span class="confidence-dots">${confDots}</span>
        ${isSmb ? '<span class="smb-badge">SMB</span>' : ''}
      </td>
      <td class="filename" title="${escHtml(f.fileName)}">${escHtml(f.fileName)}</td>
      <td class="path" title="${escHtml(f.fullPath)}">${escHtml(f.fullPath)}</td>
      <td>${f.sizeKB} KB</td>
      <td class="findings-cell">
        ${tags}
        ${f.hashOnly ? `<div class="hash-note">${escHtml(f.note || '')}</div>` : ''}
      </td>
      <td>${escHtml(f.lastModified)}</td>
    `;
    tr.onclick = () => openDrawer(f);
    tbody.appendChild(tr);
  }

  function riskColor(risk) {
    return risk === 'HIGH' ? 'var(--high)' : risk === 'MEDIUM' ? 'var(--med)' : 'var(--low)';
  }

  // ── Log ────────────────────────────────────────────────────────────────────
  function appendLog(msg, isErr) {
    const wrap = document.getElementById('logWrap');
    const now  = new Date().toTimeString().slice(0, 8);
    const div  = document.createElement('div');
    div.className = 'log-entry';
    div.innerHTML = `<span class="log-time">${now}</span><span class="log-msg ${isErr ? 'err' : ''}">${escHtml(msg)}</span>`;
    wrap.appendChild(div);
    wrap.scrollTop = wrap.scrollHeight;
  }

  // ── Detail drawer ──────────────────────────────────────────────────────────
  function openDrawer(f) {
    const conf  = f.confidence || 0;
    const isSmb = !!f.smbShare;

    // Build match evidence section from findingsDetail (with line/snippet)
    const detail = f.findingsDetail || [];
    const evidenceHtml = detail.map(d => {
      const hasCtx = d.matchSnippet;
      return `<div class="evidence-item">
        <div class="evidence-header">
          <span class="finding-tag">${escHtml(d.name)}</span>
          ${hasCtx ? `<span class="evidence-line">Line ${d.matchLine}</span>` : ''}
        </div>
        ${hasCtx ? `<code class="evidence-snippet">${escHtml(d.matchSnippet)}</code>` : ''}
      </div>`;
    }).join('');

    const smbSection = isSmb ? `
      <div class="drawer-section">
        <h3>SMB Details</h3>
        <div class="detail-row"><span class="detail-key">Server</span><span class="detail-val">${escHtml(f.smbServer || '')}</span></div>
        <div class="detail-row"><span class="detail-key">Share</span><span class="detail-val">${escHtml(f.smbShare || '')}</span></div>
        <div class="detail-row"><span class="detail-key">Relative Path</span><span class="detail-val">${escHtml(f.smbRelativePath || '')}</span></div>
        <div class="detail-row"><span class="detail-key">Last Accessed</span><span class="detail-val">${escHtml(f.lastAccessed || '—')}</span></div>
      </div>` : '';

    document.getElementById('drawerContent').innerHTML = `
      <h2>${escHtml(f.fileName)}</h2>
      <span class="risk-badge ${f.riskLevel}" style="margin-top:6px;display:inline-block">${f.riskLevel} RISK</span>
      ${isSmb ? '<span class="smb-badge" style="margin-left:6px">SMB</span>' : ''}

      <div class="drawer-section">
        <h3>Confidence</h3>
        <div class="conf-bar">
          <div class="conf-track">
            <div class="conf-fill ${f.riskLevel}" style="width:${conf * 10}%"></div>
          </div>
          <span class="conf-label">${conf}/10</span>
        </div>
        ${f.hashOnly ? `<p class="hash-note" style="margin-top:6px">${escHtml(f.note || '')}</p>` : ''}
      </div>

      <div class="drawer-section">
        <h3>File Details</h3>
        <div class="detail-row"><span class="detail-key">Full Path</span><span class="detail-val">${escHtml(f.fullPath)}</span></div>
        <div class="detail-row"><span class="detail-key">Extension</span><span class="detail-val">${escHtml(f.extension)}</span></div>
        <div class="detail-row"><span class="detail-key">Size</span><span class="detail-val">${f.sizeKB} KB</span></div>
        <div class="detail-row"><span class="detail-key">Last Modified</span><span class="detail-val">${escHtml(f.lastModified || '—')}</span></div>
        <div class="detail-row"><span class="detail-key">Owner</span><span class="detail-val">${escHtml(f.owner || '—')}</span></div>
        <div class="detail-row"><span class="detail-key">Risky Filename</span><span class="detail-val">${f.riskyFilename ? '⚠ Yes' : 'No'}</span></div>
      </div>

      ${smbSection}

      <div class="drawer-section">
        <h3>Match Evidence</h3>
        ${evidenceHtml || '<p style="color:var(--text-dim);font-size:12px;">No content patterns — flagged by file type or name.</p>'}
      </div>

      <div class="drawer-section">
        <h3>Recommended Action</h3>
        <p style="color:var(--text);font-size:12px;line-height:1.7">${getRecommendation(f)}</p>
      </div>
    `;

    document.getElementById('drawerOverlay').classList.add('open');
    document.getElementById('drawer').classList.add('open');
  }

  function closeDrawer() {
    document.getElementById('drawerOverlay').classList.remove('open');
    document.getElementById('drawer').classList.remove('open');
  }

  function getRecommendation(f) {
    const p = (f.findingsList || []).join(' | ');
    const isSmb = !!f.smbShare;
    const share = isSmb ? ` on share <strong>${escHtml(f.smbShare)}</strong>` : '';
    const smbSuffix = isSmb
      ? ` Review NTFS permissions on the file and consider restricting access via AD/GPO.`
      : '';

    if (p.includes('Private Key'))
      return `Private key material detected${share}. Rotate immediately, revoke the exposed key, and move to a secure vault (e.g., Azure Key Vault).${smbSuffix}`;
    if (p.includes('NTLM'))
      return `NTLM/LM hash found${share}. Treat as compromised credentials — rotate the account password immediately and audit how the hash was exposed.${smbSuffix}`;
    if (p.includes('Plaintext Password'))
      return `Plaintext password found${share}. Remove credentials from the file, rotate the password, and use a secrets manager or encrypted config.${smbSuffix}`;
    if (p.includes('Sensitive file type'))
      return `Sensitive key/certificate file found${share}. Move to a secure, access-restricted secrets store and remove from the share.${smbSuffix}`;
    if (p.includes('Connection String'))
      return `Database connection string with embedded credentials found${share}. Migrate to managed identity or reference credentials from a secrets manager.${smbSuffix}`;
    if (p.includes('AWS Access Key'))
      return `AWS access key detected${share}. Revoke immediately via AWS IAM, check CloudTrail for unauthorized use, and use IAM roles instead.${smbSuffix}`;
    if (f.hashOnly)
      return `Hash strings detected — likely integrity checksums. Verify these are not credential hashes before dismissing.${smbSuffix}`;
    return `Review this file and remove any embedded credentials. Use environment variables, Azure Key Vault, or other secrets management solutions.${smbSuffix}`;
  }

  // ── Reports ────────────────────────────────────────────────────────────────
  async function loadReports() {
    const container = document.getElementById('reportsContent');
    container.innerHTML = '<p style="color:var(--text-dim);padding:20px 0;">Loading…</p>';
    try {
      const res = await fetch(`${API}/scans`);
      const scans = await res.json();
      if (!Array.isArray(scans) || scans.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No reports yet. Run a scan to generate a report.</p></div>';
        return;
      }
      container.innerHTML = scans.map(s => {
        const label = s.scan_path || s.id;
        const date  = s.scan_date  || '';
        const hits  = s.hits  != null ? `${s.hits} findings`  : '';
        const files = s.scanned != null ? `${s.scanned} files` : '';
        return `<div class="report-row" onclick="openReport('${escHtml(s.id)}')">
          <span class="report-name">${escHtml(label)}</span>
          <span class="report-meta">${escHtml(files)}</span>
          <span class="report-meta">${escHtml(hits)}</span>
          <span class="report-meta">${escHtml(date)}</span>
          <a class="report-dl"
             href="${API}/scans/${encodeURIComponent(s.id)}/export"
             download="LeakLens_${escHtml(s.id)}.json"
             onclick="event.stopPropagation()">↓ JSON</a>
        </div>`;
      }).join('');
    } catch (e) {
      container.innerHTML = `<p style="color:var(--high);padding:20px 0;">Error loading reports: ${escHtml(e.message)}</p>`;
    }
  }

  async function openReport(scanId) {
    try {
      const res = await fetch(`${API}/scans/${encodeURIComponent(scanId)}/export`);
      if (!res.ok) { alert('Could not load report.'); return; }
      const report = await res.json();

      findings         = report.findings || [];
      filteredFindings = [];
      riskCounts       = { HIGH: 0, MEDIUM: 0, LOW: 0 };
      findings.forEach(f => { riskCounts[f.riskLevel] = (riskCounts[f.riskLevel] || 0) + 1; });

      document.getElementById('statScanned').textContent  = report.scanned || 0;
      document.getElementById('statFindings').textContent = findings.length;
      document.getElementById('statFindings').classList.toggle('has-hits', findings.length > 0);
      const badge = document.getElementById('findingsBadge');
      badge.style.display = findings.length ? 'inline' : 'none';
      badge.textContent   = findings.length;
      updateRiskBars();
      switchTab('findings');
      renderTable();
      appendLog(`Loaded scan: ${report.scan_path || scanId} — ${findings.length} findings`, false);
    } catch (e) {
      alert('Could not load report: ' + e.message);
    }
  }

  function escHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  // ── Virtual scroll — attach scroll listener once DOM is ready ──────────────
  document.addEventListener('DOMContentLoaded', () => {
    const wrap = document.querySelector('.findings-wrap');
    if (wrap) wrap.addEventListener('scroll', scheduleVsRender, { passive: true });
  });
