# Security policy

zk-intent-firewall is alpha software. It has not been externally audited and must not be used
with real funds.

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**
   (direct link: <https://github.com/ethqnnn/zk-intent-firewall/security/advisories/new>).
3. Describe the issue, the affected component and version or commit, and steps to reproduce it.
   A failing test is the most useful form of proof.

Please do not open a public issue, pull request or discussion for a vulnerability, and do not
disclose it publicly until a fix or an advisory has been published. Reports are handled on a
best-effort basis by the maintainer.

## Scope

In scope: anything that lets an action outside an approved policy execute, or leaks the policy.
That includes:

- **The circuit** (`packages/zk-circuit`): a proof accepted for a false statement, a constraint
  that can be bypassed, or a witness that reveals the policy.
- **The firewall and verifier SDK** (`packages/mcp-firewall`): a call forwarded or executed
  without a valid proof for that exact call, replay, cross-server replay, or a policy value
  reaching the agent or the tool server.
- **The passkey registry and dashboard** (`apps/demo-dashboard`): registering or revoking a
  policy without the owner's passkey, getting the passkey to sign a different statement, the API
  guards, or the agent sandbox.

Out of scope: the limits the project already documents, such as per-payment limits with no
cumulative budget, in-memory state, unencrypted policy storage in the browser, and the other
items in the README's threat model ("Partial" and "Planned" rows) and in
[`docs/circuit-spec.md`](docs/circuit-spec.md) section 9. A report that one of them is worse than
documented is welcome.

## Supported versions

Only the latest commit on `main` is supported. There are no releases yet.
