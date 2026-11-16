import { ago, checkText, clear, el, getJson, short, units, verdictPill } from './common.js';

const PAGE = 50;
let oldest = null;

function attempted(a) {
  const x = a.attempted ?? {};
  const parts = [];
  if (x.tool) parts.push(el('code', { text: x.tool }));
  if (x.mode === 'prove-only') parts.push(' prove-only');
  if (x.precheck === false) parts.push(' precheck off');
  if (x.arguments) parts.push(el('div', { class: 'mono', text: x.arguments }));
  if (x.envelope === null) parts.push(el('div', { class: 'hint', text: 'no proof' }));
  else if (x.envelope?.malformed) parts.push(el('div', { class: 'hint', text: 'envelope: not an object' }));
  else if (x.envelope) parts.push(el('div', { class: 'hint', text: `proof ${x.envelope.proofBytes ?? '?'} bytes, sha256 ${x.envelope.proofSha256 ?? '?'}…, ts ${x.envelope.current_timestamp ?? '?'}, commitment ${short(x.envelope.policy_commitment)}` }));
  if (x.metaKeys?.length) parts.push(el('div', { class: 'hint', text: `other _meta: ${x.metaKeys.join(', ')}` }));
  if (x.passkey) parts.push(el('div', { class: 'mono', text: Object.entries(x.passkey).map(([k, v]) => `${k}: ${k === 'policyCommitment' ? short(v) : v}`).join(' · ') }));
  if (a.note) parts.push(el('div', { class: 'hint', text: `“${a.note}”` }));
  return parts;
}

function resultCell(a) {
  const out = [verdictPill(a.verdict), ' ', a.result];
  if (a.payment) out.push(el('div', { class: 'hint', text: `${units(a.payment.amount)} fake USDC → ${short(a.payment.recipient, 18, 6)}` }));
  if (a.breakReasons?.length) out.push(el('div', { class: 'hint', text: a.breakReasons.join(', ') }));
  return out;
}

function row(a) {
  return el(
    'tr',
    { id: a.id },
    el('td', {}, el('a', { href: `#${a.id}`, title: a.at, text: ago(a.at) }), el('div', { class: 'hint', text: `${a.ms} ms` })),
    el('td', { text: a.who }),
    el('td', { text: a.route }),
    el('td', {}, attempted(a)),
    el('td', {}, resultCell(a)),
    el('td', { text: checkText(a.caughtBy) }),
  );
}

function filters() {
  const q = new URLSearchParams({ limit: String(PAGE) });
  for (const k of ['verdict', 'route', 'who']) {
    const v = document.getElementById(`f-${k}`).value.trim();
    if (v) q.set(k, v);
  }
  const check = document.getElementById('f-check').value;
  if (check) {
    const [layer, c] = check.split(':');
    q.set('layer', layer);
    q.set('check', c);
  }
  return q;
}

async function loadAttempts(append) {
  const q = filters();
  if (append && oldest) q.set('before', oldest);
  const { body } = await getJson(`/api/log?${q}`);
  const tbody = document.querySelector('#attempts-table tbody');
  if (!append) clear(tbody);
  for (const a of body.attempts) tbody.append(row(a));
  oldest = body.attempts.at(-1)?.id ?? oldest;
  document.getElementById('more').hidden = body.attempts.length < PAGE;
  if (!append && tbody.children.length === 0) tbody.append(el('tr', {}, el('td', { colspan: '6', class: 'hint', text: 'Nothing matches yet.' })));
}

async function loadStats() {
  const { body } = await getJson('/api/leaderboard');
  const s = body.stats;
  document.getElementById('s-total').textContent = String(s.total);
  document.getElementById('s-span').textContent = s.firstAt ? `since ${new Date(s.firstAt).toLocaleString()}${s.persisted ? '' : ' (not persisted)'}` : 'none yet';
  document.getElementById('s-caught').textContent = String(s.byVerdict.caught);
  document.getElementById('s-legit').textContent = String(s.byVerdict.legitimate);
  document.getElementById('s-break').textContent = String(s.byVerdict.break);
  document.getElementById('s-break-tile').className = `tile ${s.byVerdict.break > 0 ? 'alarm' : 'good'}`;

  const breaks = clear(document.getElementById('breaks-body'));
  if (s.breaks.length === 0) breaks.append(el('p', { class: 'flush-p', text: 'None so far. Every attempt was either caught by a named check or was inside the published policy.' }));
  else {
    breaks.className = 'card report';
    breaks.append(el('p', { text: 'The break detector flagged these. If one is yours, please report it privately on GitHub, with its link.' }));
    const t = el('table', {}, el('tbody', {}, s.breaks.map(row)));
    breaks.append(el('div', { class: 'table-scroll' }, t));
  }

  const checks = clear(document.querySelector('#checks tbody'));
  const max = Math.max(1, ...s.byCheck.map((c) => c.count));
  for (const c of s.byCheck) {
    checks.append(el('tr', {}, el('td', { text: c.layer }), el('td', {}, el('code', { text: c.check })), el('td', { class: 'num', text: String(c.count) }), el('td', {}, el('div', { class: 'bar', style: `width:${Math.round((c.count / max) * 100)}%` }))));
  }
  if (s.byCheck.length === 0) checks.append(el('tr', {}, el('td', { colspan: '4', class: 'hint', text: 'No checks have fired yet.' })));

  const sel = document.getElementById('f-check');
  const keep = sel.value;
  clear(sel).append(el('option', { value: '', text: 'any' }));
  for (const c of s.byCheck) sel.append(el('option', { value: `${c.layer}:${c.check}`, text: `${c.layer} › ${c.check}` }));
  sel.value = keep;

  const board = clear(document.querySelector('#board tbody'));
  body.leaderboard.forEach((r, i) => board.append(el('tr', {}, el('td', { class: 'num', text: String(i + 1) }), el('td', {}, el('a', { href: '#attempts', onclick: () => setWho(r.who), text: r.who })), el('td', { class: 'num', text: String(r.breaks) }), el('td', { class: 'num', text: String(r.distinctChecks) }), el('td', { class: 'num', text: String(r.attempts) }))));
  if (body.leaderboard.length === 0) board.append(el('tr', {}, el('td', { colspan: '5', class: 'hint', text: 'Nobody yet. Be first.' })));
}

function setWho(who) {
  document.getElementById('f-who').value = who;
  oldest = null;
  void loadAttempts(false);
}

async function showHash() {
  const id = decodeURIComponent(location.hash.slice(1));
  const box = clear(document.getElementById('highlight'));
  if (!/^[0-9a-f-]{36}$/.test(id)) return;
  const { status, body } = await getJson(`/api/log?id=${encodeURIComponent(id)}`);
  if (status !== 200) {
    box.append(el('p', { class: 'hint', text: `Attempt ${id} is not in the recent window.` }));
    return;
  }
  const a = body.attempt;
  box.append(
    el('div', { class: 'card highlight' }, el('h3', { class: 'flush', text: `Attempt ${a.id}` }), el('p', {}, verdictPill(a.verdict), ` ${a.result} · caught by ${checkText(a.caughtBy)} · ${a.at}`), el('pre', { text: JSON.stringify(a, null, 2) })),
  );
  box.scrollIntoView({ block: 'start' });
}

for (const id of ['f-verdict', 'f-route', 'f-check']) document.getElementById(id).addEventListener('change', () => ((oldest = null), void loadAttempts(false)));
document.getElementById('f-who').addEventListener('change', () => ((oldest = null), void loadAttempts(false)));
document.getElementById('more').addEventListener('click', () => void loadAttempts(true));
window.addEventListener('hashchange', () => void showHash());

await Promise.all([loadStats(), loadAttempts(false)]);
void showHash();
setInterval(() => {
  void loadStats().catch(() => undefined);
}, 20_000);
