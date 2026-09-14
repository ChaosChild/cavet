// cavet serve dashboard – the approved mock's behaviour with dummy data
// replaced by fetch() wiring. Load on open, manual Refresh, no polling.
'use strict';

const state = {
  period: 'weeks',
  filters: { scanner: '', severity: '', status: '' },
  page: 1,
  perPage: 6,
  metrics: null,
};

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status} ${await res.text()}`);
  return res.json();
}

// ---------- formatting ----------
function fmtStamp(iso) { // 2026-09-09 14:32
  if (!iso) return '–';
  const d = new Date(iso);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fmtDay(iso) { // 09-02
  if (!iso) return '–';
  const d = new Date(iso);
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function humanAge(iso) { // "3 months" / "5 weeks" / "12 days"
  if (!iso) return '–';
  const days = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000));
  if (days >= 60) return `${Math.round(days / 30)} months`;
  if (days >= 14) return `${Math.floor(days / 7)} weeks`;
  return `${days} days`;
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- overview ----------
function trendChip(el, delta, known) {
  if (!known || delta === 0) { el.innerHTML = '<span class="trend flat">● stable</span>'; return; }
  const sign = delta > 0 ? '+' : '−';
  el.innerHTML = delta > 0
    ? `<span class="trend up-bad">▲ ${sign}${Math.abs(delta)}</span>`
    : `<span class="trend down-good">▼ ${sign}${Math.abs(delta)}</span>`;
}

async function loadOverview() {
  const o = await fetchJSON('/api/overview');
  document.getElementById('repo-name').textContent = o.repo;
  document.getElementById('engine-line').textContent = o.engine ? `engine ${o.engine}` : '';
  document.getElementById('as-of').textContent = o.last_scan
    ? `${fmtStamp(o.as_of)} · ${o.last_scan.scope}` : fmtStamp(o.as_of);
  document.getElementById('open-total').textContent = o.open.total;
  document.getElementById('open-critical').textContent = o.open.critical;
  document.getElementById('open-high').textContent = o.open.high;
  document.getElementById('open-medlow').textContent = o.open.medium + o.open.low;
  document.getElementById('medlow-sub').textContent = `${o.open.medium} medium · ${o.open.low} low`;
  document.getElementById('open-sub').textContent = o.trend_known && o.trend.total !== 0
    ? 'trajectory ' + (o.trend.total > 0 ? 'rising' : 'falling') : 'trajectory steady';
  trendChip(document.getElementById('open-trend'), o.trend_known ? o.trend.total : 0, o.trend_known);
  trendChip(document.getElementById('critical-trend'), o.trend_known ? o.trend.critical : 0, o.trend_known);
  trendChip(document.getElementById('high-trend'), o.trend_known ? o.trend.high : 0, o.trend_known);
  trendChip(document.getElementById('medlow-trend'),
    o.trend_known ? o.trend.medium + o.trend.low : 0, o.trend_known);
  document.getElementById('oldest-critical').textContent = humanAge(o.oldest && o.oldest.critical);
  document.getElementById('oldest-high').textContent = humanAge(o.oldest && o.oldest.high);
  document.getElementById('baseline-count').textContent = o.baseline;
  document.getElementById('scan-scope').textContent = o.last_scan ? o.last_scan.scope : 'none';
  document.getElementById('scan-at').textContent = o.last_scan ? fmtStamp(o.last_scan.at) : '';
  document.getElementById('scanner-count').textContent = (o.scanners || []).length;
  document.getElementById('scanner-list').innerHTML = (o.scanners || []).map(s => `<li>${esc(s)}</li>`).join('');
  // scanner filter options follow the last scan's coverage
  const menu = document.querySelector('[data-menu="scanner"]');
  const dd = menu.closest('[data-dd]');
  menu.innerHTML = '<button class="dd-opt" data-val="" aria-selected="true">all scanners</button>' +
    (o.scanners || []).map(s => `<button class="dd-opt" data-val="${esc(s)}">${esc(s)}</button>`).join('');
  menu.querySelectorAll('.dd-opt').forEach(opt => opt.addEventListener('click', () => {
    menu.querySelectorAll('.dd-opt').forEach(x => x.setAttribute('aria-selected', 'false'));
    opt.setAttribute('aria-selected', 'true');
    dd.dataset.value = opt.dataset.val;
    dd.querySelector('.dd-btn').childNodes[0].textContent = opt.textContent + ' ';
    dd.classList.remove('open');
    state.filters.scanner = opt.dataset.val;
    state.page = 1;
    loadFindings();
  }));
}

// ---------- findings table ----------
async function loadFindings() {
  const q = new URLSearchParams();
  if (state.filters.scanner) q.set('scanner', state.filters.scanner);
  if (state.filters.severity) q.set('severity', state.filters.severity);
  if (state.filters.status) q.set('status', state.filters.status);
  q.set('page', state.page);
  q.set('per_page', state.perPage);
  const d = await fetchJSON('/api/findings?' + q.toString());
  state.page = d.page;
  const sevClass = { critical: 'crit', medium: 'med' };
  document.getElementById('findings-body').innerHTML = d.rows.map(f => {
    const loc = f.locations && f.locations.length ? `${f.locations[0].path}:${f.locations[0].line}` : '–';
    const extra = f.locations && f.locations.length > 1 ? ` (+${f.locations.length - 1})` : '';
    return `<tr data-id="${esc(f.id)}" style="cursor:pointer">
      <td><span class="sev ${sevClass[f.severity] || esc(f.sev || f.severity)}">${esc(f.severity)}</span></td>
      <td class="mono text-[11px]">${esc(f.rule)}</td>
      <td class="text-[11px] opacity-70">${esc(f.scanner)}</td>
      <td class="mono text-[11px] opacity-80" title="${esc(loc)}">${esc(loc + extra)}</td>
      <td class="text-[11px]">${esc(f.status)}</td>
      <td class="text-[11px] opacity-50" title="${esc(f.verdict || '')}">${esc(f.verdict || '–')}</td>
      <td class="mono text-[11px] opacity-50">${fmtDay(f.detected_at)}</td>
      <td class="mono text-[11px] opacity-50">${fmtDay(f.last_seen)}</td>
    </tr>`;
  }).join('');
  document.getElementById('findings-body').querySelectorAll('tr').forEach(tr =>
    tr.addEventListener('click', () => openDetail(tr.dataset.id)));
  const ov = document.querySelector('#page-label');
  ov.textContent = `${d.total} findings · server-side`;
  document.getElementById('page-indicator').textContent = `${d.page} / ${d.pages}`;
  document.getElementById('prev').disabled = d.page <= 1;
  document.getElementById('next').disabled = d.page >= d.pages;
}

// ---------- items ----------
async function loadItems() {
  const d = await fetchJSON('/api/items');
  document.getElementById('items-body').innerHTML = (d.items || []).map(it => `
    <tr>
      <td class="mono text-[11px] opacity-70">${esc(it.id)}</td>
      <td><span class="kind ${esc(it.kind)}">${esc(it.kind)}</span></td>
      <td><span class="kind open">open</span></td>
      <td class="text-[11.5px] opacity-80">${esc(it.question)}</td>
      <td class="text-[11px] mono opacity-50">${esc(it.raised_by)} · ${fmtDay(it.raised_at)}</td>
      <td class="text-[11px] mono opacity-50">–</td>
    </tr>`).join('') || '<tr><td colspan="6" class="text-[11px] opacity-50">no open items</td></tr>';
}

// ---------- metrics + charts ----------
const PERIODS = {
  days: { small: 6, unit: 'd', fullLabel: 'month to date', count: 30 },
  weeks: { small: 6, unit: 'w', fullLabel: 'year to date', count: 38 },
  months: { small: 6, unit: 'm', fullLabel: '24 months', count: 24 },
};
function labelsFor(period, n) {
  const unit = PERIODS[period].unit, out = [];
  for (let i = n; i >= 1; i--) out.push('-' + i + unit);
  return out;
}
function lastN(arr, n) { return arr.slice(Math.max(0, arr.length - n)); }

const steel = '#aebfd4', blue = '#7aa2f7', green = '#9ece9c', gray = '#6f7684';
Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
Chart.defaults.font.size = 10;
const grid = { color: 'rgba(255,255,255,0.05)' };
const ticks = { color: 'rgba(230,233,238,0.45)' };
const legend = { labels: { color: 'rgba(230,233,238,0.65)', font: { size: 10.5 }, boxWidth: 10, boxHeight: 10, usePointStyle: true, pointStyle: 'circle' } };

function flowConfig(m, n) {
  return {
    type: 'bar',
    data: {
      labels: labelsFor(state.period, n),
      datasets: [
        { label: 'new', data: lastN(m.flow.new, n), backgroundColor: steel, stack: 'v', borderRadius: 3, borderSkipped: false },
        { label: 'fixed', data: lastN(m.flow.fixed, n), backgroundColor: green, stack: 'v', borderRadius: 3, borderSkipped: false },
        { label: 'dismissed', data: lastN(m.flow.dismissed, n), backgroundColor: gray, stack: 'v', borderRadius: 3, borderSkipped: false },
        { label: 'deferred', data: lastN(m.flow.deferred, n), backgroundColor: blue, stack: 'v', borderRadius: 3, borderSkipped: false }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend },
      scales: { x: { stacked: true, grid: { display: false }, ticks }, y: { stacked: true, grid, ticks, beginAtZero: true, border: { display: false } } } }
  };
}
// ponytail: exposure lag cut from v1 – advisory publish dates are not in
// cavet's events, so the third line has no offline data source.
function ttvConfig(m, n) {
  return {
    type: 'line',
    data: {
      labels: labelsFor(state.period, n),
      datasets: [
        { label: 'to triage (h)', data: lastN(m.triage_median_hours, n), borderColor: steel, backgroundColor: steel, tension: 0.35, pointRadius: 2.5, borderWidth: 1.5, yAxisID: 'y' },
        { label: 'to remediate (h)', data: lastN(m.remediate_median_hours, n), borderColor: blue, backgroundColor: blue, tension: 0.35, pointRadius: 2.5, borderWidth: 1.5, yAxisID: 'y' }
      ]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend },
      scales: {
        x: { grid: { display: false }, ticks },
        y: { grid, ticks, beginAtZero: true, border: { display: false }, title: { display: true, text: 'hours to verdict', color: 'rgba(230,233,238,0.4)', font: { size: 9 } } }
      } }
  };
}

let flowChart = null, ttvChart = null, actorsChart = null, resolveChart = null, modalChart = null;

function renderSmall() {
  const p = PERIODS[state.period], m = state.metrics;
  if (!m) return;
  if (flowChart) flowChart.destroy();
  if (ttvChart) ttvChart.destroy();
  flowChart = new Chart(document.getElementById('chart-flow'), flowConfig(m, p.small));
  ttvChart = new Chart(document.getElementById('chart-ttv'), ttvConfig(m, p.small));
}

function renderDonuts() {
  const m = state.metrics;
  if (!m) return;
  const agent = m.actors.agent || 0, op = m.actors.operator || 0;
  const total = agent + op;
  const share = document.getElementById('agent-share');
  const faster = document.getElementById('agent-faster');
  if (actorsChart) actorsChart.destroy();
  if (resolveChart) resolveChart.destroy();
  if (total === 0) {
    share.textContent = '–'; faster.textContent = '–';
    actorsChart = new Chart(document.getElementById('chart-actors'), {
      type: 'doughnut',
      data: { labels: ['none'], datasets: [{ data: [1], backgroundColor: [gray], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } }
    });
    resolveChart = new Chart(document.getElementById('chart-resolve'), {
      type: 'doughnut',
      data: { labels: ['none'], datasets: [{ data: [1], backgroundColor: [gray], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } }
    });
    return;
  }
  share.textContent = Math.round(100 * agent / total) + '%';
  const aAvg = m.resolve_avg_hours.agent, oAvg = m.resolve_avg_hours.operator;
  if (aAvg && oAvg) faster.textContent = (oAvg / aAvg).toFixed(1) + '×';
  else faster.textContent = '–';
  actorsChart = new Chart(document.getElementById('chart-actors'), {
    type: 'doughnut',
    data: { labels: ['agent', 'human'], datasets: [{ data: [agent, op], backgroundColor: [blue, gray], borderWidth: 0, hoverOffset: 4 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } }
  });
  resolveChart = new Chart(document.getElementById('chart-resolve'), {
    type: 'doughnut',
    data: { labels: [`agent ${Math.round(aAvg || 0)}h`, `human ${Math.round(oAvg || 0)}h`], datasets: [{ data: [aAvg || 0, oAvg || 0], backgroundColor: [steel, gray], borderWidth: 0, hoverOffset: 4 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } }
  });
}

async function loadMetrics() {
  try {
    state.metrics = await fetchJSON('/api/metrics?period=' + state.period);
    renderSmall();
    renderDonuts();
  } catch (e) {
    state.metrics = null;
    console.error(e);
  }
}

// ---------- expand modal ----------
const MODAL_META = {
  flow: { title: 'Verdict flow', sub: 'stacked: what actually happened to each finding' },
  ttv: { title: 'Time to verdict', sub: 'hours to triage and remediate' },
};
let modalKind = 'flow';

function openModal(kind) {
  modalKind = kind;
  document.getElementById('modal-title').textContent = MODAL_META[kind].title;
  document.getElementById('modal-sub').textContent = MODAL_META[kind].sub;
  renderModal();
  document.getElementById('chart-modal').classList.add('open');
}
function closeModal(id) {
  const v = document.getElementById(id);
  if (!v.classList.contains('open')) return;
  v.classList.remove('open');
  if (id === 'chart-modal' && modalChart) { modalChart.destroy(); modalChart = null; }
}
function renderModal() {
  const p = PERIODS[state.period], m = state.metrics;
  if (!m) return;
  document.getElementById('modal-range').textContent =
    `expanded view: ${p.fullLabel} (${p.count} ${state.period}) · dashboard cards show the last ${p.small} ${state.period}`;
  if (modalChart) modalChart.destroy();
  const cfg = modalKind === 'flow' ? flowConfig(m, p.count) : ttvConfig(m, p.count);
  modalChart = new Chart(document.getElementById('modal-canvas'), cfg);
}
function setPeriod(p) {
  state.period = p;
  document.querySelectorAll('#period-seg button').forEach(b =>
    b.setAttribute('aria-pressed', String(b.dataset.period === p)));
  loadMetrics().then(() => {
    renderSmall();
    if (document.getElementById('chart-modal').classList.contains('open')) renderModal();
  });
}

// ---------- finding detail modal ----------
function detailText(kind, d) {
  if (!d) return '';
  if (d.reason) return d.reason;
  if (d.path) return `${d.path}:${d.line || '?'}${d.scanner ? ' · ' + d.scanner : ''}`;
  if (d.verdict) return `${d.verdict} (${d.confidence || '?'})`;
  if (d.answer) return d.answer;
  if (d.context) return d.context;
  try { return JSON.stringify(d); } catch { return ''; }
}
async function openDetail(id) {
  try {
    const d = await fetchJSON('/api/findings/' + encodeURIComponent(id));
    const f = d.finding;
    document.getElementById('detail-title').textContent = f.display_id || id;
    document.getElementById('detail-rule').textContent = `${f.rule_id} · ${f.originating_scanner}`;
    const sev = document.getElementById('detail-sev');
    sev.textContent = f.severity;
    sev.className = 'sev ' + ({ critical: 'crit', medium: 'med' }[f.severity] || f.severity);
    document.getElementById('detail-status').textContent = f.status;
    document.getElementById('detail-locations').textContent =
      (f.locations || []).map(l => `${l.path}:${l.line}`).join(' · ');
    document.getElementById('detail-verdict').textContent = f.verdict
      ? `${f.verdict.reason} · ${f.verdict.by}` : '–';
    document.getElementById('detail-history').innerHTML = (d.history || []).map(h => `
      <tr>
        <td class="mono text-[11px] opacity-50">${fmtStamp(h.ts)}</td>
        <td class="text-[11px]">${esc(h.kind)}</td>
        <td class="text-[11px] opacity-70">${esc(h.actor)}</td>
        <td class="text-[11px] opacity-60" title="${esc(detailText(h.kind, h.detail))}">${esc(detailText(h.kind, h.detail))}</td>
      </tr>`).join('');
    document.getElementById('detail-modal').classList.add('open');
  } catch (e) {
    console.error(e);
  }
}

// ---------- refresh ----------
async function refreshAll() {
  await Promise.all([loadOverview(), loadItems(), loadMetrics(), loadFindings()]);
}

// ---------- wiring ----------
document.getElementById('refresh').addEventListener('click', async ev => {
  ev.preventDefault();
  const ic = ev.currentTarget.querySelector('.ic');
  ic.textContent = '✓';
  await refreshAll();
  setTimeout(() => { ic.textContent = '↻'; }, 1400);
});
document.getElementById('prev').addEventListener('click', () => { state.page--; loadFindings(); });
document.getElementById('next').addEventListener('click', () => { state.page++; loadFindings(); });
document.querySelectorAll('[data-expand]').forEach(b => b.addEventListener('click', () => openModal(b.dataset.expand)));
document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => closeModal(b.dataset.close)));
document.querySelectorAll('#period-seg button').forEach(b => b.addEventListener('click', () => setPeriod(b.dataset.period)));
document.querySelectorAll('.modal-veil').forEach(v =>
  v.addEventListener('click', e => { if (e.target === v) closeModal(v.id); }));

// severity/status filter dropdowns (the scanner one is rebuilt per overview)
document.querySelectorAll('[data-dd][data-filter]').forEach(dd => {
  if (dd.dataset.filter === 'scanner') return;
  const btn = dd.querySelector('.dd-btn'), menu = dd.querySelector('.dd-menu');
  wireMenu(dd, btn, menu, val => {
    state.filters[dd.dataset.filter] = val;
    state.page = 1;
    loadFindings();
  });
});
function wireMenu(dd, btn, menu, onPick) {
  menu.querySelectorAll('.dd-opt').forEach(opt => opt.addEventListener('click', () => {
    menu.querySelectorAll('.dd-opt').forEach(o => o.setAttribute('aria-selected', 'false'));
    opt.setAttribute('aria-selected', 'true');
    btn.childNodes[0].textContent = opt.textContent + ' ';
    dd.classList.remove('open');
    onPick(opt.dataset.val);
  }));
}

// generic open/close for every dropdown (fixed-position menus)
document.querySelectorAll('[data-dd]').forEach(dd => {
  const btn = dd.querySelector('.dd-btn'), menu = dd.querySelector('.dd-menu');
  function place() {
    const r = btn.getBoundingClientRect();
    menu.style.visibility = 'hidden'; menu.style.display = 'flex';
    const mw = menu.offsetWidth;
    menu.style.display = ''; menu.style.visibility = '';
    menu.style.top = (r.bottom + 6) + 'px';
    menu.style.left = Math.max(8, Math.min(r.left, window.innerWidth - mw - 8)) + 'px';
  }
  btn.addEventListener('click', e => {
    e.stopPropagation();
    document.querySelectorAll('[data-dd].open').forEach(o => { if (o !== dd) o.classList.remove('open'); });
    dd.classList.toggle('open');
    if (dd.classList.contains('open')) place();
  });
});
// per-page dropdown (values 6/12/24)
{
  const dd = document.querySelector('[data-dd]:not([data-filter])');
  const btn = dd.querySelector('.dd-btn'), menu = dd.querySelector('.dd-menu');
  wireMenu(dd, btn, menu, val => {
    state.perPage = parseInt(val, 10);
    state.page = 1;
    loadFindings();
  });
}
document.addEventListener('click', () => document.querySelectorAll('[data-dd].open').forEach(o => o.classList.remove('open')));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('[data-dd].open').forEach(o => o.classList.remove('open'));
    closeModal('chart-modal');
    closeModal('detail-modal');
  }
});
window.addEventListener('scroll', () => document.querySelectorAll('[data-dd].open').forEach(o => o.classList.remove('open')), { passive: true });

refreshAll().catch(e => console.error(e));
