import { EgressPolicy, NetworkInspection, NetworkRequest } from "../../types";

const IPV4_PRIVATE_PATTERNS: RegExp[] = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^100\.6[4-9]\./,
  /^100\.[7-9]\d\./,
  /^100\.1[01]\d\./,
  /^100\.12[0-7]\./,
  /^0\./,
  /^255\./,
];

// These are matched against the BRACKET-STRIPPED hostname (see normalizeHostname).
// `new URL("http://[::1]/").hostname` is "[::1]", so an unstripped hostname matches
// none of these anchored patterns and every IPv6 private range is silently ignored.
const IPV6_PRIVATE_PATTERNS: RegExp[] = [
  /^::1$/,
  /^::$/, // unspecified address; connects to loopback on most stacks
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe8[0-9a-f]:/i,
  /^fe9[0-9a-f]:/i,
  /^fea[0-9a-f]:/i,
  /^feb[0-9a-f]:/i,
];

const PRIVATE_HOSTNAMES = new Set(["localhost", "broadcasthost", "ip6-localhost", "ip6-loopback"]);

const METADATA_HOSTS = new Set([
  "169.254.169.254",
  "metadata.google.internal",
  "metadata.google.com",
]);

const SUSPICIOUS_INTERNAL_SUFFIXES = [".internal", ".local", ".localhost"];

export const DEFAULT_EGRESS_POLICY: EgressPolicy = {
  enabled: true,
  defaultDeny: true,
  allowPrivateRanges: false,
  allowedHosts: [],
  allowedSchemes: ["https"],
  allowedPorts: [443],
};

/**
 * Canonical hostname form used by every check in this file: lowercased, with the
 * brackets the URL parser keeps around IPv6 literals removed and the optional DNS
 * root dot trimmed.
 *
 * The brackets are load-bearing. `URL.hostname` returns an IPv6 literal WITH them, so
 * `http://[::1]/`, `http://[fd00::1]/` and every other private-range IPv6 target slips
 * past an inspector whose patterns are anchored on the bare address.
 */
export function normalizeHostname(hostname: string): string {
  const lowered = hostname.trim().toLowerCase();
  const unbracketed =
    lowered.startsWith("[") && lowered.endsWith("]") ? lowered.slice(1, -1) : lowered;

  // "localhost." resolves exactly like "localhost" but matched neither PRIVATE_HOSTNAMES
  // nor the .internal/.local suffixes, so http://localhost./ was classified as a public
  // target. The pattern requires a surviving label: normalising "." to "" would slip past
  // the defaultDeny guard, which deliberately skips empty hostnames.
  const rooted = /^(.+[^.])\.$/.exec(unbracketed);
  return rooted ? rooted[1] : unbracketed;
}

/**
 * Dotted-quad embedded in an IPv4-mapped (::ffff:127.0.0.1) or IPv4-compatible
 * (::127.0.0.1) IPv6 address, else null.
 *
 * The URL parser re-serialises those to hex — "::ffff:7f00:1" — which matches neither
 * the IPv6 nor the IPv4 patterns, so `http://[::ffff:127.0.0.1]/` reached loopback even
 * with bracket stripping in place. Decoding the low 32 bits closes that.
 */
function embeddedIpv4(hostname: string): string | null {
  const match = /^::(?:ffff:)?([0-9a-f.:]+)$/i.exec(hostname);
  if (!match) return null;
  const tail = match[1];
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(tail)) return tail;

  const groups = tail.split(":");
  if (groups.length > 2 || !groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return null;
  const words = groups.map((group) => parseInt(group, 16));
  const [high, low] = words.length === 2 ? words : [0, words[0]];
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
}

export function extractHostname(url: string): string | null {
  try {
    return normalizeHostname(new URL(url).hostname);
  } catch {
    return null;
  }
}

export function isPrivateHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  return (
    PRIVATE_HOSTNAMES.has(host) ||
    SUSPICIOUS_INTERNAL_SUFFIXES.some((suffix) => host.endsWith(suffix))
  );
}

// Normalises internally so exported callers (policy loader/rules pass raw config values
// and payload hostnames) cannot reintroduce the bracketed-hostname bypass.
export function isPrivateIp(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  const mapped = embeddedIpv4(host);
  return (
    IPV4_PRIVATE_PATTERNS.some((pattern) => pattern.test(host)) ||
    IPV6_PRIVATE_PATTERNS.some((pattern) => pattern.test(host)) ||
    (mapped !== null && IPV4_PRIVATE_PATTERNS.some((pattern) => pattern.test(mapped)))
  );
}

function getPort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : url.protocol === "http:" ? 80 : -1;
}

function makeDenied(reason: string, riskLevel: NetworkInspection["riskLevel"], blockedCategory: string, privateRange = false, ssrf = false, egressDenied = false): NetworkInspection {
  return {
    allowed: false,
    reason,
    riskLevel,
    ssrf,
    privateRange,
    blockedCategory,
    egressDenied,
  };
}

export function inspectNetworkRequest(
  req: NetworkRequest,
  policy: Partial<EgressPolicy> = {}
): NetworkInspection {
  const effectivePolicy = { ...DEFAULT_EGRESS_POLICY, ...policy };
  let parsed: URL;
  try {
    parsed = new URL(req.url);
  } catch {
    return makeDenied("Malformed URL", "high", "invalid-url");
  }

  const hostname = normalizeHostname(parsed.hostname);
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  const port = getPort(parsed);

  if (METADATA_HOSTS.has(hostname)) {
    return makeDenied(`Cloud metadata endpoint blocked: ${hostname}`, "critical", "cloud-metadata", true, true, true);
  }

  const privateRange = isPrivateHostname(hostname) || isPrivateIp(hostname);
  if (privateRange && !effectivePolicy.allowPrivateRanges) {
    return makeDenied(`Private or local target blocked: ${hostname}`, "critical", "private-target", true, true, true);
  }

  if (parsed.username || parsed.password) {
    return makeDenied("URLs with embedded credentials are blocked", "high", "embedded-credentials", false, false, true);
  }

  if (!effectivePolicy.allowedSchemes.includes(scheme)) {
    return makeDenied(`Scheme blocked by egress policy: ${scheme}`, "high", "blocked-scheme", false, false, true);
  }

  if (!effectivePolicy.allowedPorts.includes(port)) {
    return makeDenied(`Port blocked by egress policy: ${port}`, "high", "blocked-port", false, false, true);
  }

  // Both sides are normalised: hostnames are case-insensitive, and an IPv6 allowlist
  // entry may be written bracketed ("[::1]") or bare depending on where it was copied from.
  if (effectivePolicy.allowedHosts.some((entry) => normalizeHostname(entry) === hostname)) {
    return {
      allowed: true,
      reason: "Host is in the configured egress allowlist",
      riskLevel: privateRange ? "medium" : "low",
      ssrf: false,
      privateRange,
      egressDenied: false,
    };
  }

  if (effectivePolicy.defaultDeny && hostname !== "") {
    return makeDenied(`Host is not allowlisted by egress policy: ${hostname}`, privateRange ? "critical" : "high", "default-deny-egress", privateRange, privateRange, true);
  }

  return {
    allowed: true,
    reason: "Request passes network inspection",
    riskLevel: privateRange ? "medium" : "low",
    ssrf: false,
    privateRange,
    egressDenied: false,
  };
}
