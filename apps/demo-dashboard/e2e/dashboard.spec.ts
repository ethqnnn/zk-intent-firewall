/**
 * The whole dashboard in a real browser, with Chromium's virtual WebAuthn authenticator standing
 * in for Face ID / Touch ID: the browser's own WebAuthn implementation produces every credential
 * and signature, and the verifier process checks them.
 *
 *   enrol passkey → author policy → approve (passkey) → arm → run agent:
 *     two invoices paid with verified proofs, the redirect and the inflated amount blocked
 *   → revoke (passkey) → run again with a firewall that ignores revocation:
 *     the verifier refuses every proof (commitment_revoked) before the policy's expiry
 */
import { expect, type Page, test } from '@playwright/test';
import { E2E_TOKEN } from '../playwright.config.ts';

const SHOTS = process.env['SHOTS'];
/** Full page, except while a dialog is open: it is fixed to the viewport. */
const shot = async (page: Page, name: string) => {
  if (!SHOTS) return;
  const dialog = await page.getByRole('dialog').count();
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: dialog === 0, animations: 'disabled' });
};

test('passkey approval, live demo, revocation', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  await page.goto(`/#token=${E2E_TOKEN}`);
  // The token leaves the address bar at once.
  await expect(page).not.toHaveURL(/token=/);
  await expect(page.getByTestId('status-bar')).toContainText('No passkey');
  await shot(page, '01-start');

  // Enrol.
  await page.getByTestId('enrol-passkey').click();
  await expect(page.getByTestId('status-bar')).toContainText('Passkey enrolled');
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(creds.credentials).toHaveLength(1);

  // Author the preset policy.
  await page.getByTestId('create-policy').click();
  const item = page.getByTestId('policy-item').first();
  await expect(item.getByTestId('policy-status')).toHaveText('not approved');

  // Approve: the dialog shows the statement the passkey signs.
  await item.getByTestId('approve-policy').click();
  const statement = page.getByTestId('approval-statement');
  await expect(statement).toContainText('zkif.policy-approval.v1');
  await expect(statement).toContainText('action: register');
  await expect(statement).toContainText('vk_hash.noir-recursive: 0x15bd93c9');
  await expect(statement).toContainText('vk_hash.evm: 0x0ada696c');
  await shot(page, '02-approval');
  await page.getByTestId('sign-approval').click();
  await expect(item.getByTestId('policy-status')).toHaveText('active');
  const signCount = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials[0]!.signCount;
  expect(signCount).toBeGreaterThan(0);

  // Arm and run.
  await item.getByTestId('arm-policy').click();
  await expect(page.getByTestId('status-bar')).toContainText('Firewall armed');
  await shot(page, '03-policy');
  await page.getByTestId('tab-demo').click();
  await page.getByText('Fast (no pauses between steps)').click();
  await page.getByTestId('run-demo').click();
  await expect(page.getByTestId('run-summary')).toBeVisible({ timeout: 180_000 });

  const cards = page.getByTestId('payment-card');
  await expect(cards).toHaveCount(4);
  await expect(cards.nth(0)).toHaveAttribute('data-outcome', 'paid');
  await expect(cards.nth(1)).toHaveAttribute('data-outcome', 'blocked');
  await expect(cards.nth(1)).toContainText('Recipient is not on the allowlist');
  await expect(cards.nth(1)).toContainText('Never received the call');
  await expect(cards.nth(2)).toHaveAttribute('data-outcome', 'blocked');
  await expect(cards.nth(2)).toContainText('48,750.00 USDC');
  await expect(cards.nth(2)).toContainText('Amount is above the per-payment limit');
  await expect(cards.nth(3)).toHaveAttribute('data-outcome', 'paid');
  await expect(cards.nth(0)).toContainText('14,656 bytes');
  await shot(page, '04-demo');

  // Audit log and verifier view.
  await page.getByTestId('tab-audit').click();
  await expect(page.getByTestId('ledger').locator('li')).toHaveCount(2);
  await shot(page, '05-audit');
  await page.getByTestId('tab-verifier').click();
  await expect(page.getByTestId('verifier-calls').locator('li')).toHaveCount(2);
  await shot(page, '06-verifier');

  // Revoke with the passkey.
  await page.getByTestId('tab-policy').click();
  await item.getByTestId('revoke-policy').click();
  await expect(page.getByTestId('approval-statement')).toContainText('action: revoke');
  await page.getByTestId('sign-approval').click();
  await expect(item.getByTestId('policy-status')).toHaveText('revoked');

  // A firewall that ignores revocation keeps proving; the verifier refuses on its own.
  await page.getByTestId('tab-demo').click();
  await page.getByTestId('ignore-revocation').check();
  await page.getByTestId('run-demo').click();
  // The previous run's summary is on screen until this run replaces it: wait on this run's last card.
  await expect(cards.nth(3)).toHaveAttribute('data-outcome', 'rejected', { timeout: 180_000 });
  // The legitimate payments are proven, then refused by the verifier; the injections are still blocked.
  for (const [i, outcome] of ['rejected', 'blocked', 'blocked', 'rejected'].entries()) await expect(cards.nth(i)).toHaveAttribute('data-outcome', outcome);
  await expect(cards.nth(0)).toContainText('Policy was revoked');
  await expect(page.getByTestId('run-summary')).toContainText('0 paid with a verified proof');
  await expect(page.getByTestId('run-summary')).toContainText('2 refused by the verifier');
  await shot(page, '07-revoked');
});

test('the API refuses requests without the session token', async ({ request }) => {
  expect((await request.get('/api/state')).status()).toBe(401);
  expect((await request.post('/api/firewall/arm', { data: {} })).status()).toBe(401);
});
