// cavet serve dashboard – behaviour converted from docs/serve-mock.html with
// its illustrative data replaced by fetch() wiring. Load on open, manual
// Refresh, no polling. Charts are inline SVG drawn from /api/metrics.
'use strict';

const state = {
  period: 'weeks',
  filters: { scanner: '', severity: '', status: 'actionable' },
  page: 1,
  perPage: 8,
  overview: null,
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
function fmtAge(iso) { // compact: 6d, 3w, 2mo
  if (!iso) return null;
  const days = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000));
  if (days >= 60) return `${Math.round(days / 30)}mo`;
  if (days >= 14) return `${Math.floor(days / 7)}w`;
  return `${days}d`;
}
function fmtHours(v) { // human hours for the chart read-out: 9m, 23.4h, 24h
  if (v == null) return 'no data';
  if (v < 1) return `${Math.round(v * 60)}m`;
  return (Number.isInteger(v) ? v : parseFloat(v.toFixed(1))) + 'h';
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const LRM = '\u200E'; // forces the left ellipsis on the rtl-trimmed cells
// escape first, then linkify the escaped text; trailing punctuation stays out
// of the href. Description text arrives from scanner output, never trusted.
function linkify(s) {
  const re = /https?:\/\/[^\s<>"']+/g;
  let out = '', last = 0, m;
  while ((m = re.exec(s))) {
    let url = m[0];
    const trimmed = url.replace(/[.,)]+$/, '');
    const tail = url.slice(trimmed.length);
    url = trimmed;
    out += esc(s.slice(last, m.index)) +
      `<a href="${esc(url)}" rel="noreferrer noopener">${esc(url)}</a>${esc(tail)}`;
    last = m.index + m[0].length;
  }
  return out + esc(s.slice(last));
}
const $ = id => document.getElementById(id);

// ---------- inline SVG charts ----------
const SVGNS = 'http://www.w3.org/2000/svg';
const el = (n, a = {}) => { const e = document.createElementNS(SVGNS, n); for (const k in a) e.setAttribute(k, a[k]); return e; };
const text = (s, a) => { const t = el('text', a); t.textContent = s; return t; };
const MONO = 'IBM Plex Mono, monospace';
const C = { steel:'#aebfd4', ink2:'#a8afba', ink3:'#8b93a0', ink4:'#6c7480',
            hair:'rgba(255,255,255,0.08)', surface:'#1b1f26',
            crit:'#ff5f66', high:'#f5a33f', med:'#d9c45f', low:'#85aed0', info:'#8b93a0', ok:'#5dc98d' };
const SEVCOLOR = { critical:C.crit, high:C.high, medium:C.med, low:C.low, info:C.info };

// round up to the next readable axis top (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10 × 10ⁿ)
function niceCap(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
  return ([1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find(x => n <= x + 1e-9)) * p;
}
// counts want whole-number gridlines, so land on a multiple of 4
const countCap = v => Math.ceil(niceCap(v) / 4) * 4;

// An outlier is a point that would swallow the rest of the series, not simply
// the largest one. Anything within 4× the median stays inside the domain; only
// what is past that pins to the cap and carries its real value as a label.
function domainCap(data) {
  const s = [...data].sort((a, b) => a - b);
  const med = s[Math.floor(s.length / 2)];
  const inliers = data.filter(v => v <= med * 4);
  return niceCap(Math.max(...(inliers.length ? inliers : data)));
}

// drop leading buckets where every series is empty, then keep the last 12
function trimBuckets(labels, cols) {
  const emptyAt = i => cols.every(c => !(c[i] > 0));
  let first = 0;
  while (first < labels.length - 1 && emptyAt(first)) first++;
  const start = Math.max(first, labels.length - 12);
  return { labels: labels.slice(start), cols: cols.map(c => c.slice(start)) };
}

// ---------- chart hover read-out ----------
// One fixed-position tooltip element shared by every chart (appended to body,
// so no card is ever its containing block) plus a per-chart guide drawn in
// the SVG. Handlers go on svg properties, not addEventListener: the draws
// re-render in place on bucket switches and property assignment cannot stack.
let tipEl = null;
function hideTip() {
  if (tipEl) tipEl.classList.remove('show');
}
function showTip(cx, cy, html) {
  if (!tipEl) {
    tipEl = document.createElement('div');
    tipEl.className = 'chart-tip';
    document.body.appendChild(tipEl);
  }
  tipEl.innerHTML = html;
  tipEl.classList.add('show');
  const r = tipEl.getBoundingClientRect();
  let left = cx + 14, top = cy + 14;
  if (left + r.width > window.innerWidth - 8) left = cx - r.width - 14;
  if (top + r.height > window.innerHeight - 8) top = cy - r.height - 14;
  tipEl.style.left = left + 'px';
  tipEl.style.top = top + 'px';
}

// cfg: { W, L, R, T, B, step, guide, ring, hideGuide, indexAt(vx), hover(i) }
// hover(i) returns { x, py, html } where x is the guide's viewBox x and py
// the anchor point for the ring (null hides the ring, e.g. empty buckets).
function mountHover(svg, cfg) {
  hideTip();
  cfg.hideGuide();
  svg.style.cursor = 'crosshair';
  svg.onmouseleave = () => { cfg.hideGuide(); hideTip(); };
  svg.onmousemove = ev => {
    const r = svg.getBoundingClientRect();
    if (!r.width) return;
    const vx = (ev.clientX - r.left) * (cfg.W / r.width);
    const i = cfg.indexAt(vx);
    if (i == null) { cfg.hideGuide(); hideTip(); return; }
    const res = cfg.hover(i);
    if (!res) { cfg.hideGuide(); hideTip(); return; }
    cfg.guide.setAttribute('x1', res.x);
    cfg.guide.setAttribute('x2', res.x);
    cfg.guide.setAttribute('visibility', 'visible');
    if (cfg.ring) {
      if (res.py == null) cfg.ring.setAttribute('visibility', 'hidden');
      else {
        cfg.ring.setAttribute('cx', res.x);
        cfg.ring.setAttribute('cy', res.py);
        cfg.ring.setAttribute('visibility', 'visible');
      }
    }
    showTip(ev.clientX, ev.clientY, res.html);
  };
}

function drawStacked(id, labels, series) {
  const svg = $(id);
  if (!svg) return;
  svg.innerHTML = '';
  const W = 720, H = 210, L = 34, R = 8, T = 8, B = 26, iw = W - L - R, ih = H - T - B;
  const totals = labels.map((_, i) => series.reduce((s, se) => s + (se.data[i] || 0), 0));
  const cap = countCap(Math.max(1, ...totals));
  const y = v => T + ih - (v / cap) * ih;
  const step = iw / labels.length, bw = Math.min(30, step * 0.62);

  for (let g = 0; g <= 4; g++) {
    const v = cap * g / 4;
    svg.appendChild(el('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: C.hair, 'stroke-width': 1 }));
    svg.appendChild(text(v, { x: L - 8, y: y(v) + 3.5, 'text-anchor': 'end', 'font-size': 9.5, fill: C.ink4, 'font-family': MONO }));
  }
  labels.forEach((lab, i) => {
    let acc = 0;
    const x = L + step * i + (step - bw) / 2;
    series.forEach(se => {
      const v = se.data[i] || 0;
      if (!v) return;
      const h = (v / cap) * ih;
      svg.appendChild(el('rect', { x, y: y(acc) - h, width: bw, height: h, fill: se.color, rx: 2 }));
      acc += v;
    });
    svg.appendChild(text(lab, { x: L + step * i + step / 2, y: H - 8, 'text-anchor': 'middle', 'font-size': 9.5,
      fill: i === labels.length - 1 ? C.ink2 : C.ink4, 'font-family': MONO }));
  });

  const guide = el('line', { y1: T, y2: T + ih, stroke: 'rgba(255,255,255,0.16)', 'stroke-width': 1, visibility: 'hidden' });
  svg.appendChild(guide);
  mountHover(svg, {
    W, guide,
    hideGuide: () => guide.setAttribute('visibility', 'hidden'),
    indexAt: vx => Math.max(0, Math.min(labels.length - 1, Math.floor((vx - L) / step))),
    hover: i => {
      const total = series.reduce((s, se) => s + (se.data[i] || 0), 0);
      const rows = series.map(se =>
        `<div class="r"><i style="background:${se.color}"></i>${esc(se.name)}<b>${se.data[i] || 0}</b></div>`).join('');
      return { x: L + step * i + step / 2,
        html: `<p class="h">${esc(labels[i])}</p>${rows}<div class="r total">total<b>${total}</b></div>` };
    },
  });
}

// nulls (buckets with no events) break the line into segments; only a genuine
// outlier pins to the cap, labelled with its real value
function drawSeries(id, labels, data, color) {
  const svg = $(id);
  if (!svg) return;
  svg.innerHTML = '';
  if (!data.some(v => v != null)) return;
  const W = 560, H = 170, L = 40, R = 14, T = 20, B = 26, iw = W - L - R, ih = H - T - B;
  const cap = domainCap(data.filter(v => v != null));
  const y = v => T + ih - (Math.min(v, cap) / cap) * ih;
  const span = labels.length > 1 ? iw / (labels.length - 1) : 0;
  const x = i => labels.length > 1 ? L + span * i : L + iw / 2;
  // two decimals keep small medians (fractions of an hour) distinct on the axis
  const fmt = v => Number.isInteger(v) ? String(v) : String(parseFloat(v.toFixed(2)));

  for (let g = 0; g <= 4; g++) {
    const v = cap * g / 4;
    svg.appendChild(el('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: C.hair, 'stroke-width': 1 }));
    svg.appendChild(text(fmt(v), { x: L - 8, y: y(v) + 3.5, 'text-anchor': 'end', 'font-size': 9.5, fill: C.ink4, 'font-family': MONO }));
  }
  let run = [];  // indices of the current non-null run
  const flush = () => {
    if (run.length === 0) return;
    const pts = run.map(i => x(i) + ',' + y(data[i]));
    svg.appendChild(el('path', { d: 'M' + pts.join(' L'), fill: 'none', stroke: color, 'stroke-width': 1.8,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    if (run.length > 1) {
      svg.appendChild(el('path', { d: 'M' + x(run[0]) + ',' + (T + ih) + ' L' + pts.join(' L') +
        ' L' + x(run[run.length - 1]) + ',' + (T + ih) + ' Z', fill: color, opacity: 0.1, stroke: 'none' }));
    }
    run = [];
  };
  data.forEach((v, i) => {
    if (v == null) { flush(); return; }
    run.push(i);
    const over = v > cap;
    svg.appendChild(el('circle', { cx: x(i), cy: y(v), r: over ? 4 : 3, fill: over ? 'none' : color,
      stroke: over ? C.high : C.surface, 'stroke-width': over ? 1.6 : 1.4 }));
    if (over) svg.appendChild(text(fmt(v) + 'h', { x: x(i), y: y(v) - 9, 'text-anchor': 'middle', class: 'outlier-tag' }));
  });
  flush();
  labels.forEach((lab, i) => {
    if (i % 2 === 0 || i === labels.length - 1)
      svg.appendChild(text(lab, { x: x(i), y: H - 8, 'text-anchor': 'middle', 'font-size': 9.5,
        fill: i === labels.length - 1 ? C.ink2 : C.ink4, 'font-family': MONO }));
  });

  const guide = el('line', { y1: T, y2: T + ih, stroke: 'rgba(255,255,255,0.16)', 'stroke-width': 1, visibility: 'hidden' });
  const ring = el('circle', { r: 5.5, fill: 'none', stroke: color, 'stroke-width': 1.5, visibility: 'hidden' });
  svg.appendChild(guide);
  svg.appendChild(ring);
  mountHover(svg, {
    W, guide, ring,
    hideGuide: () => {
      guide.setAttribute('visibility', 'hidden');
      ring.setAttribute('visibility', 'hidden');
    },
    indexAt: vx => labels.length > 1
      ? Math.max(0, Math.min(labels.length - 1, Math.round((vx - L) / span)))
      : 0,
    hover: i => {
      const v = data[i];
      return { x: x(i), py: v == null ? null : y(v),
        html: `<p class="h">${esc(labels[i])}</p><div class="r"><i style="background:${color}"></i>median<b>${fmtHours(v)}</b></div>` };
    },
  });
}

// ---------- overview ----------
function trendChip(elm, delta, known) {
  if (!known || delta === 0) { elm.innerHTML = '<span class="trend flat">stable</span>'; return; }
  elm.innerHTML = delta > 0
    ? `<span class="trend up">▲ ${delta}</span>`
    : `<span class="trend down">▼ ${-delta}</span>`;
}

async function loadOverview() {
  const o = await fetchJSON('/api/overview');
  state.overview = o;
  $('repo-name').textContent = o.repo;
  $('as-of').textContent = fmtStamp(o.as_of);
  $('meta-baseline').textContent = o.baseline;
  $('meta-items').textContent = o.open_items;
  $('chip-scanners').hidden = !(o.scanners || []).length;
  $('meta-scanners').textContent = (o.scanners || []).join(' · ');
  $('chip-engine').hidden = !o.engine;
  $('meta-engine').textContent = o.engine || '';
  $('chip-scope').hidden = !o.last_scan;
  $('meta-scope').textContent = o.last_scan ? o.last_scan.scope : '';
  $('chip-phase').hidden = !o.last_scan;
  $('meta-phase').textContent = o.last_scan ? o.last_scan.phase : '';

  // posture strip
  $('open-total').textContent = o.open.total;
  const traj = !o.trend_known || o.trend.total === 0 ? 'steady' : (o.trend.total > 0 ? 'rising' : 'falling');
  $('open-sub').textContent = `open + confirmed · trajectory ${traj}`;
  trendChip($('open-trend'), o.trend_known ? o.trend.total : 0, o.trend_known);
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    $(`n-${sev}`).textContent = o.open[sev] ?? 0;
    trendChip($(`t-${sev}`), o.trend_known ? (o.trend[sev] || 0) : 0, o.trend_known);
    const age = o.oldest ? fmtAge(o.oldest[sev]) : null;
    $(`s-${sev}`).textContent = (o.open[sev] ?? 0) === 0 ? 'none open'
      : age ? `oldest ${age}` : '';
  }

  // scanner filter options follow the last scan's coverage
  const sel = $('f-scanner');
  const cur = state.filters.scanner;
  sel.innerHTML = '<option value="">all scanners</option>' +
    (o.scanners || []).map(s =>
      `<option value="${esc(s)}"${s === cur ? ' selected' : ''}>${esc(s)}</option>`).join('');
}

// ---------- findings table ----------
// rule ids read opt.opengrep-rules.….<name>: the tail is the identity, so the
// name gets its own line and the namespace ellipsises from the left
function splitRule(rule) {
  const i = rule.lastIndexOf('.');
  return i > 0 ? { ns: rule.slice(0, i), name: rule.slice(i + 1) } : { ns: '', name: rule };
}

function findingsRow(f) {
  const { ns, name } = splitRule(f.rule || '');
  const locs = f.locations || [];
  const loc = locs.length ? `${locs[0].path}:${locs[0].line}` : '–';
  const extra = locs.length > 1 ? ` +${locs.length - 1}` : '';
  const sev = f.severity || 'info';
  return `<tr tabindex="0" data-id="${esc(f.id)}" style="--sev:${SEVCOLOR[sev] || C.info}">
    <td><span class="sev ${esc(sev)}">${esc(sev)}</span></td>
    <td><div class="rule">${ns ? `<span class="ns">${LRM}${esc(ns)}</span>` : ''}<span class="name">${esc(name)}</span></div></td>
    <td class="mono scanner" style="font-size:11.5px;color:${C.ink2}">${esc(f.scanner)}</td>
    <td><div class="loc" title="${esc(loc + extra)}">${LRM}${esc(loc)}${extra}</div></td>
    <td><span class="status ${esc(f.status)}">${esc(f.status)}</span></td>
    <td><div class="verdict-cell${f.verdict ? '' : ' none'}" title="${esc(f.verdict || '')}">${f.verdict ? esc(f.verdict) : 'awaiting triage'}</div></td>
    <td class="when">${fmtDay(f.detected_at)}</td><td class="when">${fmtDay(f.last_seen)}</td>
  </tr>`;
}

let findingsSeq = 0;
async function loadFindings() {
  const seq = ++findingsSeq; // only the most recent request may paint the table
  const q = new URLSearchParams();
  if (state.filters.scanner) q.set('scanner', state.filters.scanner);
  if (state.filters.severity) q.set('severity', state.filters.severity);
  if (state.filters.status) q.set('status', state.filters.status);
  q.set('page', state.page);
  q.set('per_page', state.perPage);
  const d = await fetchJSON('/api/findings?' + q.toString());
  if (seq !== findingsSeq) return;
  state.page = d.page;
  $('rows').innerHTML = d.rows.map(findingsRow).join('');
  $('rows').querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', () => openDetail(tr.dataset.id));
    tr.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(tr.dataset.id); }
    });
  });

  const none = d.total === 0;
  $('emptyState').hidden = !none;
  $('tblWrap').hidden = none;
  if (none) {
    const t = state.overview && state.overview.triaged;
    const triaged = t ? t.fixed + t.dismissed + t.deferred : 0;
    if (state.filters.status === 'actionable') {
      $('emptyTitle').textContent = 'Nothing open';
      $('emptyNote').textContent = triaged > 0
        ? `All ${triaged} findings carry a verdict: ${t.fixed} fixed, ${t.dismissed} dismissed with a rationale, ${t.deferred} deferred.`
        : 'No findings recorded yet; a scan populates the dashboard.';
      $('showAll').hidden = triaged === 0;
    } else {
      $('emptyTitle').textContent = 'No findings match';
      $('emptyNote').textContent = 'Nothing matches the current filters.';
      $('showAll').hidden = true;
    }
  }
  $('count').textContent = `${d.total} findings · server-side`;
  $('page-indicator').textContent = `${d.page} / ${d.pages}`;
  $('prev').disabled = d.page <= 1;
  $('next').disabled = d.page >= d.pages;
}

// ---------- items ----------
function itemExpanded(it) {
  const resolved = it.resolved_at
    ? `resolved ${esc(it.resolved_by || '?')} · ${fmtStamp(it.resolved_at)}${it.answer ? ' · ' + esc(it.answer) : ''}`
    : 'resolved –';
  return `<tr class="item-x hidden" data-x="${esc(it.id)}">
    <td colspan="6" style="white-space:normal">
      <p style="font-size:12px;color:var(--ink-2);line-height:1.6">${esc(it.question)}</p>
      <p class="mono" style="font-size:10.5px;color:var(--ink-3);margin-top:4px">raised ${esc(it.raised_by || '?')} · ${fmtStamp(it.raised_at)} · ${resolved}</p>
    </td>
  </tr>`;
}
async function loadItems() {
  const d = await fetchJSON('/api/items');
  const SEVCSS = { open: C.high, resolved: C.ok };
  $('items-body').innerHTML = (d.items || []).map(it => {
    const status = it.resolved_at ? 'resolved' : 'open';
    return `<tr class="item-row" data-item="${esc(it.id)}" style="--sev:${SEVCSS[status]}">
      <td class="mono" style="font-size:11.5px">${esc(it.id)}</td>
      <td style="color:var(--ink-2)">${esc(it.kind)}</td>
      <td><span class="status ${status}">${status}</span></td>
      <td style="color:var(--ink-2)">${esc(it.question)}</td>
      <td class="when">${fmtStamp(it.raised_at)}</td>
      <td class="when"${it.resolved_at ? '' : ` style="color:${C.ink4}"`}>${it.resolved_at ? fmtStamp(it.resolved_at) : '–'}</td>
    </tr>${itemExpanded(it)}`;
  }).join('') ||
    '<tr><td colspan="6" class="axis-note" style="margin:0">no open items</td></tr>';
  document.querySelectorAll('.item-row').forEach(tr =>
    tr.addEventListener('click', () => {
      const x = document.querySelector(`.item-x[data-x="${CSS.escape(tr.dataset.item)}"]`);
      if (x) x.classList.toggle('hidden');
    }));
}

// ---------- metrics + remediation ----------
async function loadMetrics() {
  try {
    state.metrics = await fetchJSON('/api/metrics?period=' + state.period);
    renderCharts();
  } catch (e) {
    state.metrics = null;
    console.error(e);
  }
}

function renderCharts() {
  const m = state.metrics;
  if (!m) return;
  const FLOWCOLORS = { new: C.low, fixed: C.ok, dismissed: C.ink4, deferred: C.high };
  const keys = ['new', 'fixed', 'dismissed', 'deferred'];
  const flow = trimBuckets(m.labels, keys.map(k => m.flow[k] || []));
  drawStacked('flow', flow.labels, keys.map((k, i) => ({ name: k, data: flow.cols[i], color: FLOWCOLORS[k] })));

  const ttt = trimBuckets(m.labels, [m.triage_median_hours || []]);
  drawSeries('ttt', ttt.labels, ttt.cols[0], C.steel);
  const ttr = trimBuckets(m.labels, [m.remediate_median_hours || []]);
  drawSeries('ttr', ttr.labels, ttr.cols[0], C.ok);

  renderRemediation();
}

function renderRemediation() {
  const m = state.metrics, o = state.overview;
  const counts = { agent: (m.actors && m.actors.agent) || 0, operator: (m.actors && m.actors.operator) || 0 };
  const med = m.resolve_median_hours || {};
  const total = counts.agent + counts.operator;
  const entries = [
    { key: 'agent', label: 'Agent', color: C.steel },
    { key: 'operator', label: 'Operator', color: C.ink4 },
  ].filter(e => counts[e.key] > 0).sort((a, b) => counts[b.key] - counts[a.key]);

  $('actor-bars').innerHTML = total === 0
    ? '<p class="axis-note" style="margin:0">No remediations recorded yet; resolved findings appear here with who closed them and how long they took.</p>'
    : entries.map(e => {
      const hrs = med[e.key];
      return `<div class="bar-row">
        <div class="top"><span><b>${e.label}</b> · ${counts[e.key]} resolved</span>
          <span class="hrs">${hrs != null ? hrs.toFixed(1) + 'h median' : ''}</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round(100 * counts[e.key] / total)}%;background:${e.color}"></div></div>
      </div>`;
    }).join('');

  $('kv-share').textContent = total ? Math.round(100 * counts.agent / total) + '%' : '–';
  const a = med.agent, op = med.operator;
  if (a != null && op != null && a > 0 && op !== a) {
    const agentFaster = op > a;
    $('kv-faster-k').textContent = agentFaster ? 'Agent faster by' : 'Operator faster by';
    $('kv-faster').textContent = (agentFaster ? op / a : a / op).toFixed(1) + '×';
    $('kv-faster').style.color = C.ok;
  } else {
    $('kv-faster-k').textContent = 'Faster actor by';
    $('kv-faster').textContent = '–';
    $('kv-faster').style.color = '';
  }
  $('kv-fixdis').textContent = o && o.triaged ? `${o.triaged.fixed} / ${o.triaged.dismissed}` : '–';
}

// ---------- finding detail slide-out panel ----------
const panel = $('panel'), veil = $('veil');
let lastFocus = null;

async function openDetail(id) {
  try {
    const d = await fetchJSON('/api/findings/' + encodeURIComponent(id));
    const f = d.finding;
    const { ns, name } = splitRule(f.rule_id || '');
    $('pTitle').textContent = name || f.rule_id || id;
    $('pNs').textContent = ns;
    const sev = f.severity || 'info';
    $('pSev').className = 'sev ' + sev;
    $('pSev').textContent = sev;
    $('pStatus').className = 'status ' + f.status;
    $('pStatus').textContent = f.status;
    $('pId').textContent = f.display_id || id;
    $('pScanner').textContent = f.originating_scanner || '';
    $('pDesc').innerHTML = linkify(f.description || '');
    $('pLocs').innerHTML = (f.locations || [])
      .map(l => `<li><span>${esc(l.path)}:${esc(String(l.line ?? '?'))}</span></li>`).join('') ||
      '<li style="color:var(--ink-4)">–</li>';
    // Triage verdicts carry confidence; remediation verdicts (resolved
    // findings) do not, so only present segments become tags. The history
    // replay below carries each event's actor and phase.
    const v = f.verdict;
    $('pVerdict').innerHTML = v && v.reason
      ? esc(v.reason)
      : '<span style="color:var(--ink-3);font-style:italic">No verdict yet: this finding has not been triaged.</span>';
    $('pVerdictMeta').innerHTML = v && v.reason
      ? [
          v.confidence ? `<span class="tag${v.confidence === 'high' ? ' conf-high' : ''}">${esc(v.confidence)} confidence</span>` : '',
          v.by ? `<span class="tag">by ${esc(v.by)}</span>` : '',
          v.at ? `<span class="tag">${fmtStamp(v.at)}</span>` : '',
        ].filter(Boolean).join('')
      : '';
    $('pHist').innerHTML = (d.history || []).map(h =>
      `<li><span class="t">${fmtStamp(h.ts)}</span> <span class="ev">${esc(h.kind)}</span>
        <span class="t">· ${esc(h.actor)}${h.phase ? ' · ' + esc(h.phase) : ''}</span></li>`).join('');

    lastFocus = document.activeElement;
    hideTip();
    veil.classList.add('open');
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
    document.body.classList.add('locked');
    $('pClose').focus();
  } catch (e) {
    console.error(e);
  }
}

function closePanel() {
  if (!panel.classList.contains('open')) return;
  veil.classList.remove('open');
  panel.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('locked');
  if (lastFocus) lastFocus.focus();
}

// ---------- refresh + wiring ----------
async function refreshAll() {
  await loadOverview(); // the tally and scanner options the other loads read
  await Promise.all([loadItems(), loadMetrics(), loadFindings()]);
}

$('refresh').addEventListener('click', async ev => {
  ev.preventDefault();
  const ic = ev.currentTarget.querySelector('.ic');
  ic.textContent = '✓';
  await refreshAll();
  setTimeout(() => { ic.textContent = '↻'; }, 1400);
});
$('prev').addEventListener('click', () => { state.page--; loadFindings(); });
$('next').addEventListener('click', () => { state.page++; loadFindings(); });
$('f-scanner').addEventListener('change', e => { state.filters.scanner = e.target.value; state.page = 1; loadFindings(); });
$('f-severity').addEventListener('change', e => { state.filters.severity = e.target.value; state.page = 1; loadFindings(); });
$('f-status').addEventListener('change', e => { state.filters.status = e.target.value; state.page = 1; loadFindings(); });
$('showAll').addEventListener('click', () => {
  state.filters.status = 'all';
  $('f-status').value = 'all';
  state.page = 1;
  loadFindings();
});
$('perPage').addEventListener('change', e => { state.perPage = parseInt(e.target.value, 10); state.page = 1; loadFindings(); });
$('bucketSel').addEventListener('change', e => { state.period = e.target.value; loadMetrics(); });
$('pClose').addEventListener('click', closePanel);
veil.addEventListener('click', closePanel);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closePanel();
});

refreshAll().catch(e => console.error(e));
