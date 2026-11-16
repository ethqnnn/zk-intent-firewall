// Shared helpers for the break-it pages. Everything shown comes from strangers, so nothing is ever
// written as HTML: every node is built with textContent.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    // Through CSSOM: the CSP refuses style attributes.
    else if (k === 'style') node.style.cssText = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export async function getJson(path) {
  const r = await fetch(path, { headers: { accept: 'application/json' } });
  return { status: r.status, body: await r.json() };
}

export async function postJson(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}

/** Base units to "1,250.50". */
export function units(value, decimals = 6) {
  let v = BigInt(value);
  const neg = v < 0n;
  if (neg) v = -v;
  const base = 10n ** BigInt(decimals);
  const whole = (v / base).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  let frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  if (frac.length < 2) frac = frac.padEnd(2, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

export function short(hex, head = 10, tail = 6) {
  return typeof hex === 'string' && hex.length > head + tail + 1 ? `${hex.slice(0, head)}…${hex.slice(-tail)}` : String(hex ?? '');
}

export function ago(iso) {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function verdictPill(v) {
  const label = v === 'break' ? 'BREAK' : v;
  return el('span', { class: `pill ${v}`, text: label });
}

export function checkText(c) {
  if (!c) return '—';
  return `${c.layer} › ${c.check}${c.assertion ? ` (“${c.assertion}”)` : ''}`;
}
