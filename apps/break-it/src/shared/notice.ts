/**
 * The fake-money notice. It is in every API response, in a response header, and in a fixed banner
 * on every page, so that nobody can mistake this environment for a payment system.
 */
export const FAKE_MONEY_NOTICE = 'FAKE MONEY — this is a test environment. No real funds, no real payment rail, no blockchain.';

/** Response header carrying the notice (ASCII only, as HTTP headers require). */
export const FAKE_MONEY_HEADER = 'x-fake-money';
export const FAKE_MONEY_HEADER_VALUE = 'true; this is a test environment, no real funds';

/** The unit every amount is shown in. */
export const FAKE_UNIT = 'fake USDC';

export const LINKS = {
  repo: 'https://github.com/ethqnnn/zk-intent-firewall',
  circuitSpec: 'https://github.com/ethqnnn/zk-intent-firewall/blob/main/docs/circuit-spec.md',
  circuitSource: 'https://github.com/ethqnnn/zk-intent-firewall/blob/main/packages/zk-circuit/crates/proof_of_intent/src/main.nr',
  breakItSource: 'https://github.com/ethqnnn/zk-intent-firewall/tree/main/apps/break-it',
  /** GitHub private vulnerability reporting, enabled on the repository. */
  reportVulnerability: 'https://github.com/ethqnnn/zk-intent-firewall/security/advisories/new',
  securityPolicy: 'https://github.com/ethqnnn/zk-intent-firewall/blob/main/SECURITY.md',
} as const;
