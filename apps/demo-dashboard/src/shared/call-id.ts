/**
 * `_meta` key under which the demo agent labels each tool call, so the dashboard can line up the
 * agent's step, the firewall's decision and the verifier's outcome. It is not part of the
 * protocol and carries no authority: the firewall forwards it like any other `_meta` entry.
 */
export const CALL_ID_META = 'zkif-demo/call-id';
