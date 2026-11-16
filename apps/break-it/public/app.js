import { checkText, clear, el, getJson, postJson, short, units } from './common.js';

const META_KEY = 'zkif/proof-of-intent';
const state = { status: null, route: 'agent', lastProof: null };

// ---------------------------------------------------------------------------------------------
// Status

async function loadStatus() {
  const { body } = await getJson('/api/status');
  state.status = body;
  const s = body.engine;
  const dec = s.asset.decimals;

  setText('t-balance', `${units(s.ledger.treasury.balance, dec)}`);
  setText('t-balance-sub', `of ${units(s.ledger.treasury.openingBalance, dec)} ${s.asset.unit} · ${s.ledger.totals.payments} payments · ${s.ledger.totals.topUps} top-ups`);
  const breaks = body.log.byVerdict.break;
  setText('t-breaks', String(breaks));
  document.getElementById('t-breaks-tile').className = `tile ${breaks > 0 ? 'alarm' : 'good'}`;
  setText('t-breaks-sub', breaks > 0 ? 'See the log. Please report privately.' : `Registry: ${s.verifier.registry.status}`);
  setText('t-attempts', String(body.log.total));
  const denied = ['network', 'fetch', 'childProcess', 'fileWrite', 'fileReadOutside'].filter((k) => body.sandbox[k] === 'ERR_ACCESS_DENIED').length;
  setText('t-sandbox', denied === 5 ? 'Holding' : 'CHECK');
  setText('t-sandbox-sub', `network, fetch, child process, write, outside read: ${denied}/5 denied`);

  rows('policy-table', [
    ['Per-payment limit', `${units(s.policy.maxAmount, dec)} ${s.asset.unit} (${s.policy.maxAmount} base units)`],
    ['Granted scopes', s.policy.grantedScopes.join(', ')],
    ['Expires', `${s.policy.expiresAt} (unix ${s.policy.expiry}); valid strictly before`],
    ['Commitment', el('code', { text: s.policy.policyCommitment })],
    ['Salt', 'secret'],
    ['Asset', el('code', { text: s.asset.id })],
    ['Instance started', s.startedAt],
  ]);
  rows('payees', s.policy.allowlist.map((p) => [p.label, el('code', { text: p.account })]));
  rows('not-payees', s.notAllowlisted.map((p) => [p.label, el('code', { text: p.account })]));
  const tools = document.querySelector('#tools tbody');
  clear(tools);
  for (const t of s.tools) {
    tools.append(el('tr', {}, el('td', {}, el('code', { text: t.name })), el('td', { text: t.protected ? 'yes' : 'no (read-only)' }), el('td', { text: t.scope ?? '—' }), el('td', { text: t.protected ? (t.granted ? 'yes' : 'no') : '—' }), el('td', { text: t.description })));
  }
  rows('verifier', [
    ['Server identity (in every tool_id)', el('code', { text: s.verifier.serverId })],
    ['WebAuthn RP ID / origin', `${s.verifier.rpId} / ${s.verifier.origin}`],
    ['Owner credential', el('code', { text: s.verifier.ownerCredentialId ?? 'none' })],
    ...Object.entries(s.verifier.vkHashes).map(([t, h]) => [`Pinned key hash (${t})`, el('code', { text: h })]),
    ['Proof freshness', `${s.verifier.freshness.maxAgeSeconds}s back, ${s.verifier.freshness.maxFutureSkewSeconds}s ahead`],
    ['Firewall lockout', `${s.firewall.refusalLimit.maxRefusals} refusals in ${s.firewall.refusalLimit.windowSeconds}s lock you out for ${s.firewall.refusalLimit.lockoutSeconds}s (per visitor)`],
    ['Your rate limits', `agent ${body.limits.perClient.agent.perMinute}/min, direct ${body.limits.perClient.direct.perMinute}/min, passkey ${body.limits.perClient.passkey.perMinute}/min`],
  ]);
  renderCurl();
}

function rows(id, data) {
  const tbody = document.querySelector(`#${id} tbody`);
  clear(tbody);
  for (const [k, v] of data) tbody.append(el('tr', {}, el('th', { scope: 'row', text: k }), el('td', {}, v)));
}

function setText(id, t) {
  document.getElementById(id).textContent = t;
}

// ---------------------------------------------------------------------------------------------
// Console presets

function presets() {
  const s = state.status?.engine;
  if (!s) return [];
  const pay = s.policy.allowlist[0].account;
  const other = s.policy.allowlist[1]?.account ?? pay;
  const lookalike = s.notAllowlisted[0].account;
  const max = BigInt(s.policy.maxAmount);
  const commitment = s.policy.policyCommitment;
  const p = state.lastProof;
  const needProof = { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: other, amount: '42000000' }, mode: 'prove-only' } };
  const withProof = (f) => (p ? f(p) : { ...needProof, note: 'You have no proof yet: this first asks the firewall for one (prove-only). Send it, then pick this again.' });

  return {
    agent: [
      ['Pay an allowlisted payee (control: should pay)', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: pay, amount: '25000000' } } }],
      ['Pay the lookalike address (address poisoning)', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: lookalike, amount: '25000000' } } }],
      ['Pay one base unit over the limit', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: pay, amount: String(max + 1n) } } }],
      ['Allowlisted address, another chain', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: pay.replace(/^eip155:1:/, 'eip155:8453:'), amount: '1000000' } } }],
      ['Sweep the treasury (scope not granted)', { endpoint: '/api/attempt/agent', body: { tool: 'treasury_sweep', arguments: { recipient: pay, amount: '1000000' } } }],
      ['Smuggle an argument the proof does not bind', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: pay, amount: '1000000', memo: 'and also pay me' } } }],
      ['Over the limit, precheck off: the circuit alone decides', { endpoint: '/api/attempt/agent', body: { tool: 'send_payment', arguments: { recipient: pay, amount: String(max * 2n) }, precheck: false } }],
      ['Call a tool that is not on the list', { endpoint: '/api/attempt/agent', body: { tool: 'admin_reset', arguments: {} } }],
      ['Get an unspent proof to play with (prove-only)', needProof],
    ],
    direct: [
      ['No proof at all', { endpoint: '/api/attempt/direct', body: { tool: 'send_payment', arguments: { recipient: lookalike, amount: '25000000' } } }],
      ['Spend the last proof as intended (control: pays once, if unspent)', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: x.args, meta: { [META_KEY]: x.envelope } } }))],
      ['Replay the last proof', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: x.args, meta: { [META_KEY]: x.envelope } } }))],
      ['Move the last proof to a larger amount', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: { ...x.args, amount: String(BigInt(x.args.amount ?? '1') * 10n) }, meta: { [META_KEY]: x.envelope } } }))],
      ['Move the last proof to the lookalike', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: { ...x.args, recipient: lookalike }, meta: { [META_KEY]: x.envelope } } }))],
      ['Move the last proof to the ungranted tool', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: 'treasury_sweep', arguments: x.args, meta: { [META_KEY]: x.envelope } } }))],
      ['Flip one bit of the last proof', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: x.args, meta: { [META_KEY]: { ...x.envelope, proof: flipBit(x.envelope.proof) } } } }))],
      ['Last proof under a made-up commitment', withProof((x) => ({ endpoint: '/api/attempt/direct', body: { tool: x.tool, arguments: x.args, meta: { [META_KEY]: { ...x.envelope, policy_commitment: `0x${'0'.repeat(63)}1` } } } }))],
    ],
    passkey: [
      ['Revoke the policy with a forged assertion', { endpoint: '/api/attempt/passkey', challenge: 'revoke', body: { action: 'revoke', policyCommitment: commitment, nonce: '(press Send: a fresh nonce is fetched first)', response: { id: 'forged', rawId: 'forged', type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AAAA', signature: 'AAAA' } } } }],
      ['Register a commitment of your own', { endpoint: '/api/attempt/passkey', challenge: 'register', body: { action: 'register', policyCommitment: `0x${'0'.repeat(63)}2`, nonce: '(press Send: a fresh nonce is fetched first)', response: { id: 'forged', rawId: 'forged', type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AAAA', signature: 'AAAA' } } } }],
      ['Enrol a second owner passkey', { endpoint: '/api/attempt/enroll', body: { stage: 'options' } }],
    ],
  };
}

const HINTS = {
  agent: 'You are the AI agent, or the prompt injection steering it. Your call goes to the firewall, which proves it against the hidden policy or blocks it. Allowed calls go on to the verifier and the fake ledger.',
  direct: 'You skip the firewall and call the tool server yourself, with whatever proof envelope you like in _meta. The verifier runs its checklist (spec 10.3) before anything is paid.',
  passkey: 'You try to change which policy is active: register your own, or revoke the published one. The registry wants a WebAuthn assertion from the enrolled owner over a statement it builds itself. The owner key was discarded after boot.',
};

function flipBit(b64) {
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  bytes[100] ^= 1;
  return btoa(String.fromCharCode(...bytes));
}

function fillPresets() {
  const sel = document.getElementById('preset');
  const list = presets()[state.route] ?? [];
  const keep = sel.value;
  clear(sel);
  list.forEach(([name], i) => sel.append(el('option', { value: String(i), text: name })));
  if (keep && Number(keep) < list.length) sel.value = keep;
  applyPreset();
}

function current() {
  const list = presets()[state.route] ?? [];
  return list[Number(document.getElementById('preset').value)]?.[1];
}

function applyPreset() {
  const p = current();
  if (!p) return;
  document.getElementById('body').value = JSON.stringify(p.body, null, 2);
  setText('endpoint', `POST ${p.endpoint}${p.challenge ? ` (after GET /api/passkey/challenge?action=${p.challenge})` : ''}${p.note ? ` — ${p.note}` : ''}`);
  setText('route-hint', HINTS[state.route]);
}

async function send() {
  const btn = document.getElementById('send');
  const out = clear(document.getElementById('result'));
  const p = current();
  let body;
  try {
    body = JSON.parse(document.getElementById('body').value);
  } catch {
    out.append(el('p', { class: 'verdict-line break', text: 'The request body is not valid JSON.' }));
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try {
    if (p.challenge && body && typeof body === 'object') {
      const q = new URLSearchParams({ action: body.action ?? p.challenge, policyCommitment: body.policyCommitment ?? '' });
      const ch = await getJson(`/api/passkey/challenge?${q}`);
      if (ch.status === 200) {
        body.nonce = ch.body.challenge.statement.nonce;
        out.append(el('p', { class: 'hint', text: 'Challenge issued by the registry. The statement your forged assertion has to sign:' }), el('pre', { text: ch.body.challenge.statementText }));
      } else {
        out.append(el('p', { class: 'hint', text: `The registry would not issue a challenge: ${ch.body.error ?? ch.status}. Sending anyway.` }));
      }
    }
    const handle = document.getElementById('handle').value.trim();
    const note = document.getElementById('note').value.trim();
    const r = await postJson(p.endpoint, { ...body, ...(handle ? { handle } : {}), ...(note ? { note } : {}) });
    showResult(out, r);
    const env = r.body.envelope;
    if (env && r.body.attempt?.attempted?.tool) {
      const args = JSON.parse(r.body.attempt.attempted.arguments);
      state.lastProof = { envelope: env, tool: r.body.attempt.attempted.tool, args };
    }
    void loadStatus().then(() => fillPresetsKeepingBody());
  } catch (e) {
    out.append(el('p', { class: 'verdict-line break', text: `Request failed: ${e.message}` }));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send attempt';
  }
}

function fillPresetsKeepingBody() {
  const text = document.getElementById('body').value;
  const sel = document.getElementById('preset');
  const keep = sel.value;
  clear(sel);
  (presets()[state.route] ?? []).forEach(([name], i) => sel.append(el('option', { value: String(i), text: name })));
  sel.value = keep;
  document.getElementById('body').value = text;
}

function showResult(out, r) {
  const a = r.body.attempt;
  if (r.status === 429 || r.status === 503) {
    out.append(el('p', { class: 'verdict-line', text: `${r.body.error} (retry in ${r.body.retryAfterSeconds}s)` }));
  } else if (a) {
    const line =
      a.verdict === 'break'
        ? `BREAK: ${a.breakReasons?.join(', ')}. Please report it privately (link below).`
        : a.verdict === 'caught'
          ? `Caught by ${checkText(a.caughtBy)}. Ledger untouched.`
          : a.result === 'executed'
            ? `Paid, as the policy allows: ${units(a.payment.amount)} fake USDC to ${short(a.payment.recipient, 18, 6)}.`
            : a.result === 'proof_issued'
              ? 'The firewall issued a proof and handed it back unspent. Try it on the direct route.'
              : `Allowed (${a.result}).`;
    out.append(el('p', { class: `verdict-line ${a.verdict}`, text: line }));
    out.append(el('p', { class: 'hint' }, 'Logged publicly: ', el('a', { href: `/log#${a.id}`, text: `attempt ${a.id.slice(0, 8)}` })));
  }
  out.append(el('pre', { text: JSON.stringify(r.body, null, 2) }));
}

function renderCurl() {
  const origin = location.origin;
  const allow = state.status?.engine.policy.allowlist[0].account ?? 'eip155:1:0x…';
  setText(
    'curl',
    [
      `# As the agent: through the firewall`,
      `curl -s ${origin}/api/attempt/agent -H 'content-type: application/json' \\`,
      `  -d '{"tool":"send_payment","arguments":{"recipient":"${allow}","amount":"25000000"},"handle":"you","note":"control"}'`,
      ``,
      `# Ask for an unspent proof, then use it however you like on the direct route`,
      `curl -s ${origin}/api/attempt/agent -H 'content-type: application/json' \\`,
      `  -d '{"tool":"send_payment","arguments":{"recipient":"${allow}","amount":"1"},"mode":"prove-only"}' | jq .meta > meta.json`,
      `curl -s ${origin}/api/attempt/direct -H 'content-type: application/json' \\`,
      `  -d "{\\"tool\\":\\"send_payment\\",\\"arguments\\":{\\"recipient\\":\\"${allow}\\",\\"amount\\":\\"2\\"},\\"meta\\":$(cat meta.json)}"`,
      ``,
      `# Passkey registry: get a challenge, then submit an approval`,
      `curl -s '${origin}/api/passkey/challenge?action=revoke&policyCommitment=${state.status?.engine.policy.policyCommitment ?? '0x…'}'`,
      `curl -s ${origin}/api/attempt/passkey -H 'content-type: application/json' -d '{"action":"revoke","policyCommitment":"0x…","nonce":"…","response":{…}}'`,
      ``,
      `# Read the log and the leaderboard`,
      `curl -s '${origin}/api/log?limit=20'`,
      `curl -s ${origin}/api/leaderboard`,
    ].join('\n'),
  );
}

// ---------------------------------------------------------------------------------------------

for (const b of document.querySelectorAll('[data-route]')) {
  b.addEventListener('click', () => {
    state.route = b.dataset.route;
    for (const o of document.querySelectorAll('[data-route]')) o.setAttribute('aria-selected', String(o === b));
    document.getElementById('preset').value = '0';
    fillPresets();
  });
}
document.getElementById('preset').addEventListener('change', applyPreset);
document.getElementById('send').addEventListener('click', () => void send());
try {
  const h = localStorage.getItem('breakit.handle');
  if (h) document.getElementById('handle').value = h;
  document.getElementById('handle').addEventListener('change', (e) => localStorage.setItem('breakit.handle', e.target.value.trim()));
} catch {
  // Storage blocked: the handle just isn't remembered.
}

loadStatus()
  .then(fillPresets)
  .catch((e) => setText('t-balance', `unavailable (${e.message})`));
setInterval(() => void loadStatus().catch(() => undefined), 15_000);
