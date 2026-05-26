const API = '';
const PAGE_SIZE = 20;

const state = {
  tab: 'overview',
  filter: 'all',
  offset: 0,
  total: 0,
  searchTerm: '',
  allEntries: [],
  logTypeFilter: '',
};

// ── Tab switching ─────────────────────────────────────────────────────────────

function switchTab(name) {
  state.tab = name;
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.style.display = p.id === `tab-${name}` ? '' : 'none';
  });
  if (name === 'overview') loadHealth();
  if (name === 'entries') { state.offset = 0; loadEntries(); }
  if (name === 'audit') loadAuditLogs();
}

document.querySelectorAll('.tab-btn').forEach(b => {
  b.addEventListener('click', () => switchTab(b.dataset.tab));
});

// ── Health / Overview ─────────────────────────────────────────────────────────

async function loadHealth() {
  try {
    const r = await fetch(`${API}/v1/health`);
    if (!r.ok) throw new Error();
    const d = await r.json();

    const dot = document.getElementById('health-dot');
    const txt = document.getElementById('health-text');
    dot.className = 'status-dot online';
    txt.textContent = 'ONLINE';

    const listR = await fetch(`${API}/v1/memory/list?limit=1&filter=all`);
    const listD = listR.ok ? await listR.json() : { total: 0 };
    const unsafeR = await fetch(`${API}/v1/memory/list?limit=1&filter=unsafe`);
    const unsafeD = unsafeR.ok ? await unsafeR.json() : { total: 0 };

    const total = listD.total ?? 0;
    const unsafe = unsafeD.total ?? 0;

    document.getElementById('s-total').textContent = total;
    document.getElementById('s-safe').textContent = total - unsafe;
    document.getElementById('s-unsafe').textContent = unsafe;

    const scanEl = document.getElementById('s-scanner');
    scanEl.textContent = d.scanner_running ? 'RUNNING' : 'STOPPED';
    scanEl.className = 'stat-val ' + (d.scanner_running ? 'accent' : 'danger');

    document.getElementById('s-attack').textContent = d.attack_bank_size ?? 0;
    document.getElementById('s-benign').textContent = d.benign_bank_size ?? 0;

    const immuneEl = document.getElementById('s-immune');
    if (immuneEl) {
      immuneEl.textContent = d.immune_enabled ? 'ENABLED' : 'DISABLED';
      immuneEl.className = 'stat-val ' + (d.immune_enabled ? 'cyan' : '');
      immuneEl.style.fontSize = '2rem';
    }
  } catch {
    const dot = document.getElementById('health-dot');
    const txt = document.getElementById('health-text');
    dot.className = 'status-dot offline';
    txt.textContent = 'OFFLINE';
  }
}

// ── Memory Entries ────────────────────────────────────────────────────────────

async function loadEntries() {
  const tbody = document.getElementById('entries-body');
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2.5rem;color:var(--fg-muted);"><span class="cursor">LOADING</span></td></tr>`;

  try {
    const url = `${API}/v1/memory/list?offset=${state.offset}&limit=${PAGE_SIZE}&filter=${state.filter}`;
    const r = await fetch(url);
    if (!r.ok) throw new Error();
    const d = await r.json();
    state.total = d.total;
    state.allEntries = d.entries;
    renderEntries();
  } catch {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2.5rem;color:var(--danger);">[ ERROR ] 加载失败，请确认服务已启动</td></tr>`;
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-10 text-center text-red-400 text-sm">加载失败，请确认服务已启动</td></tr>';
  }
}

function renderEntries() {
  const term = state.searchTerm.toLowerCase();
  const rows = term
    ? state.allEntries.filter(e => e.content.toLowerCase().includes(term))
    : state.allEntries;

  const tbody = document.getElementById('entries-body');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2.5rem;color:var(--fg-muted);">[ EMPTY ] 暂无数据</td></tr>`;
  } else {
    tbody.innerHTML = rows.map(e => {
      const tc = e.trust_score >= 0.7 ? 'trust-high' : e.trust_score >= 0.4 ? 'trust-mid' : 'trust-low';
      const pct = (e.trust_score * 100).toFixed(0);
      return `<tr>
        <td style="color:var(--fg-muted);font-size:0.7rem;">${e.entry_id.slice(0,8)}…</td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(e.content)}">${escHtml(e.content)}</td>
        <td style="color:var(--fg-muted);font-size:0.7rem;">${e.source_type}</td>
        <td>
          <div style="display:flex;align-items:center;gap:0.5rem;">
            <div class="trust-bar-bg"><div class="trust-bar-fill ${tc}" style="width:${pct}%"></div></div>
            <span style="font-size:0.68rem;color:var(--fg-muted);">${e.trust_score.toFixed(2)}</span>
          </div>
        </td>
        <td><span class="badge ${e.is_unsafe ? 'badge-unsafe' : 'badge-safe'}">${e.is_unsafe ? 'QUARANTINED' : 'SAFE'}</span></td>
        <td style="color:var(--fg-muted);font-size:0.68rem;">${fmtTime(e.timestamp)}</td>
      </tr>`;
    }).join('');
  }

  const start = state.offset + 1;
  const end = Math.min(state.offset + PAGE_SIZE, state.total);
  document.getElementById('entries-info').textContent =
    state.total ? `[ ${start} – ${end} / ${state.total} ]` : '[ EMPTY ]';
  document.getElementById('prev-btn').disabled = state.offset === 0;
  document.getElementById('next-btn').disabled = state.offset + PAGE_SIZE >= state.total;
}

document.getElementById('prev-btn').addEventListener('click', () => {
  state.offset = Math.max(0, state.offset - PAGE_SIZE);
  loadEntries();
});
document.getElementById('next-btn').addEventListener('click', () => {
  state.offset += PAGE_SIZE;
  loadEntries();
});

document.querySelectorAll('#filter-btns .filter-btn').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('#filter-btns .filter-btn').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    state.filter = b.dataset.filter;
    state.offset = 0;
    loadEntries();
  });
});

document.getElementById('search-box').addEventListener('input', e => {
  state.searchTerm = e.target.value;
  renderEntries();
});

// ── Audit Log ─────────────────────────────────────────────────────────────────

async function loadAuditLogs() {
  const container = document.getElementById('audit-log');
  container.innerHTML = '<div class="text-gray-500">加载中…</div>';
  try {
    const r = await fetch(`${API}/v1/audit/logs?limit=200`);
    if (!r.ok) throw new Error();
    const d = await r.json();
    const typeFilter = state.logTypeFilter.toUpperCase();
    const logs = typeFilter
      ? d.logs.filter(l => {
          const ev = (l.event || l.action || '').toUpperCase();
          return ev.includes(typeFilter);
        })
      : d.logs;

    document.getElementById('log-count').textContent = `共 ${logs.length} 条`;

    if (!logs.length) {
      container.innerHTML = '<div style="color:var(--fg-muted);font-size:0.7rem;">[ EMPTY ] 暂无日志</div>';
      return;
    }
    container.innerHTML = logs.map(l => {
      const ev = l.event || l.action || 'EVENT';
      const ts = l.timestamp ? fmtTime(l.timestamp) : '';
      const actor = l.actor || '';
      const detail = l.detail || l.reason || l.message || '';
      return `<div class="log-row">
        <span class="log-ts">${ts}</span>
        <span class="badge ${logBadgeClass(ev)}">${ev}</span>
        <span class="log-actor">${escHtml(actor)}</span>
        <span class="log-detail">${escHtml(detail)}</span>
      </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<div style="color:var(--danger);">[ ERROR ] 加载失败</div>';
  }
}

document.getElementById('log-type-filter').addEventListener('change', e => {
  state.logTypeFilter = e.target.value;
  loadAuditLogs();
});

// ── Write / Query ─────────────────────────────────────────────────────────────

document.getElementById('w-trust').addEventListener('input', e => {
  document.getElementById('w-trust-val').textContent = parseFloat(e.target.value).toFixed(2);
});
document.getElementById('q-nresults').addEventListener('input', e => {
  document.getElementById('q-n-val').textContent = e.target.value;
});

document.getElementById('write-btn').addEventListener('click', async () => {
  const btn = document.getElementById('write-btn');
  const resultBox = document.getElementById('write-result');
  btn.disabled = true;
  btn.textContent = '写入中…';
  try {
    const r = await fetch(`${API}/v1/memory/write`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: document.getElementById('w-content').value,
        source_id: document.getElementById('w-source-id').value,
        source_type: document.getElementById('w-source-type').value,
        session_hash: document.getElementById('w-session').value,
        trust_score: parseFloat(document.getElementById('w-trust').value),
      }),
    });
    const d = await r.json();
    resultBox.className = 'result-box ' + (r.ok ? 'ok' : 'err');
    resultBox.textContent = JSON.stringify(d, null, 2);
    resultBox.style.display = '';
  } catch (err) {
    resultBox.className = 'result-box err';
    resultBox.textContent = String(err);
    resultBox.style.display = '';
  } finally {
    btn.disabled = false;
    btn.textContent = '写入内存';
  }
});

document.getElementById('query-btn').addEventListener('click', async () => {
  const btn = document.getElementById('query-btn');
  const resultBox = document.getElementById('query-result');
  btn.disabled = true;
  btn.textContent = '查询中…';
  try {
    const r = await fetch(`${API}/v1/memory/read`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: document.getElementById('q-content').value,
        session_hash: document.getElementById('q-session').value,
        n_results: parseInt(document.getElementById('q-nresults').value),
      }),
    });
    const d = await r.json();
    resultBox.className = 'result-box ' + (r.ok ? 'ok' : 'err');
    resultBox.textContent = JSON.stringify(d, null, 2);
    resultBox.style.display = '';
  } catch (err) {
    resultBox.className = 'result-box err';
    resultBox.textContent = String(err);
    resultBox.style.display = '';
  } finally {
    btn.disabled = false;
    btn.textContent = '查询内存';
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function fmtTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-');
  } catch { return iso; }
}

function trustColor(v) {
  if (v >= 0.7) return 'trust-high';
  if (v >= 0.4) return 'trust-mid';
  return 'trust-low';
}

function logBadgeClass(ev) {
  if (ev.includes('WRITE')) return 'badge-write';
  if (ev.includes('READ')) return 'badge-read';
  if (ev.includes('IMMUNE')) return 'badge-immune';
  if (ev.includes('SHADOW')) return 'badge-shadow';
  if (ev.includes('QUARANTINE') || ev.includes('QUARANTINED')) return 'badge-quarantine';
  if (ev.includes('SCAN')) return 'badge-scan';
  if (ev.includes('INTERCEPT') || ev.includes('BLOCK')) return 'badge-intercept';
  return 'badge-default';
}

// ── Auto-refresh + boot ───────────────────────────────────────────────────────

setInterval(() => { if (state.tab === 'overview') loadHealth(); }, 5000);
setInterval(() => { if (state.tab === 'entries') loadEntries(); }, 10000);
setInterval(() => { if (state.tab === 'audit') loadAuditLogs(); }, 5000);

// ── Guide toggle ──────────────────────────────────────────────────────────────

document.getElementById('guide-toggle').addEventListener('click', () => {
  const body  = document.getElementById('guide-body');
  const arrow = document.getElementById('guide-arrow');
  const open  = body.style.display !== 'none';
  body.style.display  = open ? 'none' : '';
  arrow.textContent   = open ? '展开 ▾' : '收起 ▴';
});

// ── Tooltip bubble ────────────────────────────────────────────────────────────

const tipBubble = document.createElement('div');
tipBubble.id = 'tip-bubble';
document.body.appendChild(tipBubble);

function positionTip(e) {
  const x = e.clientX + 14;
  const y = e.clientY - 10;
  const bw = tipBubble.offsetWidth;
  const bh = tipBubble.offsetHeight;
  tipBubble.style.left = (x + bw > window.innerWidth  ? x - bw - 28 : x) + 'px';
  tipBubble.style.top  = (y + bh > window.innerHeight ? y - bh      : y) + 'px';
}

document.querySelectorAll('.tip').forEach(el => {
  el.addEventListener('mouseenter', e => {
    tipBubble.textContent = el.dataset.tip;
    tipBubble.style.display = 'block';
    positionTip(e);
  });
  el.addEventListener('mousemove', positionTip);
  el.addEventListener('mouseleave', () => { tipBubble.style.display = 'none'; });
});

switchTab('overview');
