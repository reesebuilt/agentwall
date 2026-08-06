/**
 * Hostname shape gates shared by the two egress listeners.
 *
 * Both proxies recover destinations from bytes an untrusted process composed: SNI out of a
 * ClientHello, an authority out of a `Host:` header or a `CONNECT` line. Those names become
 * arguments to a connect call, keys an allowlist is matched against, and fields in the
 * ledger, so they are validated in one place rather than once per parser. Two copies of a
 * hostname rule that disagree is how a name gets allowed on one path and denied on the other.
 */

const HOSTNAME_LABEL = /^[A-Za-z0-9_-]+$/;

const MAX_HOSTNAME_CHARS = 253;
const MAX_LABEL_CHARS = 63;

/**
 * Is this something we are willing to hand to a connect call?
 *
 * The name arrives inside a packet an untrusted process composed, so it is validated before
 * it becomes an argument anywhere. Length and per-label limits come from DNS itself; the
 * character allowlist is what rejects an embedded NUL, a CR, a slash, or any other byte that
 * would mean one thing to this parser and something else to a downstream consumer of the
 * ledger. A trailing dot is rejected on purpose: it is legal in DNS but forbidden in SNI,
 * and permitting it would give one destination two spellings for an exact-match allowlist to
 * disagree about.
 */
export function isPlausibleHostname(name: string): boolean {
  if (name.length === 0 || name.length > MAX_HOSTNAME_CHARS) return false;
  for (const label of name.split(".")) {
    if (label.length === 0 || label.length > MAX_LABEL_CHARS) return false;
    if (!HOSTNAME_LABEL.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return true;
}

/**
 * A charset and shape gate for a bracketed IPv6 authority, not a full address validator.
 * Anything that passes it and is not actually an address fails at connect time with a normal
 * upstream error; what matters is that nothing outside hex, colons and dots reaches that call.
 */
export const IPV6_CHARS = /^[0-9A-Fa-f:.]{2,45}$/;
