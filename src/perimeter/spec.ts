import { isIP } from "net";

/**
 * The perimeter's ruleset generator and status reader: every part of kernel-level containment
 * that can be decided, tested, and reviewed without root.
 *
 * The perimeter closes the hole the forward proxy cannot: cooperative capture. A proxy reached
 * through environment variables only sees clients that choose to honour them, and an agent that
 * has been talked into ignoring `HTTPS_PROXY` is neither observed nor blocked. The fix is to stop
 * asking. The agent runs as its own unprivileged uid, nftables redirects that uid's outbound TCP
 * into the local proxy, and everything else that uid tries to send is dropped by the kernel. No
 * environment variable, no client cooperation, nothing for a prompt to talk its way around.
 *
 * This file is deliberately pure. It renders text and reads text; it never touches the host.
 * Applying a ruleset needs root, root is exactly where a mistake is unrecoverable, and a function
 * that can only be exercised on a privileged machine is a function that ships untested. So the
 * generator and the parser live here with full test coverage, and `index.ts` holds the thin
 * privileged wrapper that pipes this output into `nft` — a wrapper with no logic to get wrong.
 *
 * Limits, stated plainly. These rules govern one uid's packets. They do not contain a process
 * running as any other uid, they do not contain root (root can flush this table), they do not see
 * unix domain sockets or filesystem writes, and they cannot tell you what is inside a TLS session.
 * They are also Linux-only: nftables has no equivalent on macOS or Windows, and `renderNftables`
 * will happily produce a ruleset on those hosts that nothing there can apply.
 */

/** uid_t is 32-bit and (uid_t)-1 is reserved as the "no change / error" sentinel. */
const UID_MAX = 4294967294;

/** The dedicated table. Never merged into an operator's existing table — see `renderNftables`. */
const TABLE = "inet agentwall";

/**
 * The only destination ports the perimeter captures, and the reason the capture is scoped at all.
 *
 * REDIRECT rewrites the destination before the proxy ever sees the socket, and Node cannot call
 * `getsockopt(SO_ORIGINAL_DST)` to ask the kernel what it was. So the proxy recovers the
 * destination from the stream: SNI for TLS, the `Host:` header for plain HTTP. That recovers the
 * HOST. It does not recover the PORT for TLS — SNI carries none — so a TLS stream is necessarily
 * attributed to 443.
 *
 * Capture every port and that inference is a lie with consequences: the agent opens
 * example.com:8443, the proxy names it example.com:443, policy allows example.com:443, and the
 * connection that gets made is to a service the agent never asked for while the ledger records a
 * destination it never asked for either. A verdict evaluated against the wrong destination is
 * worse than no verdict, because it is signed.
 *
 * Scoping the redirect to 80 and 443 removes that class entirely: those are the two ports where
 * the port the proxy infers is the port the agent asked for. Everything else falls through to the
 * default-drop that is already last, so an agent that dials :8443 itself meets a kernel drop rather
 * than a silent misroute. This narrows the perimeter — it opens nothing.
 *
 * Two residual limits, stated rather than hidden.
 *
 * First, nftables matches ports and not protocols: a TLS stream deliberately sent to port 80 is
 * still attributed to 443, because at that point nothing in the stream or the socket disagrees.
 * That one really is a single port wide.
 *
 * Second, and this is the limit the first sentence of this comment could mislead somebody into
 * missing: the drop constrains what the AGENT may dial, never what the PROXY opens on its behalf.
 * The proxy uid is exempt by design and connects to whatever the stream names, and an HTTP request
 * names its own port — `Host: host:8443` is honoured, judged as :8443, and opened as :8443. So the
 * captured pair is not a port allowlist and this ruleset does not make any port unreachable. It is
 * not a misattribution either: the verdict is evaluated against exactly the destination that gets
 * opened. Port containment is egress policy's job, and policy has to key on port for it to bite.
 *
 * These must agree with the proxy's `config.transparent.tlsPort` (default 443). They fail closed
 * if they do not: a TLS port the ruleset does not capture is dropped by the kernel, not misrouted.
 */
const TLS_PORT = 443;
const CAPTURED_PORTS = [80, TLS_PORT];

export interface PerimeterSpec {
  /** uid the agent process runs as. Every packet it sends is redirected to the proxy or dropped. */
  agentUid: number;
  /** uid the proxy runs as. Exempt from the redirect, or the proxy captures its own upstream. */
  proxyUid: number;
  /** Local TCP port the transparent proxy listens on. */
  proxyPort: number;
  /**
   * The single resolver the agent may query on port 53. Left unset, the agent gets no DNS at all:
   * the default-drop eats port 53 with everything else, and every name lookup fails immediately.
   * That is the intended posture until an operator names a resolver, because an unrestricted DNS
   * path is an exfiltration channel that never touches the proxy.
   */
  dnsResolver?: string;
  /**
   * Whether the agent may reach loopback services other than the proxy. Off is the safe default:
   * a local service can itself be a route to the outside, so this is an explicit hole, opened
   * knowingly by an operator who needs the agent to talk to something on the same host.
   */
  allowLoopback: boolean;
}

/**
 * Reject a spec that would produce a firewall rule nobody meant to write.
 *
 * Every message names the offending field, because these values arrive from an operator's command
 * line and the operator is the only one who can fix them. A malformed ruleset that applies
 * silently is worse than a refusal: nftables will accept a syntactically valid rule that contains
 * nothing, and the operator walks away believing the agent is boxed in.
 */
function assertValidSpec(spec: PerimeterSpec): void {
  checkUid("agentUid", spec.agentUid);
  checkUid("proxyUid", spec.proxyUid);

  if (spec.agentUid === spec.proxyUid) {
    throw new Error(
      `agentUid: must differ from proxyUid (both are ${spec.agentUid}). The whole model is that one ` +
        "uid is captured and another is exempt; collapsing them into one uid makes the proxy's " +
        "exemption the agent's exemption, and the perimeter contains nothing."
    );
  }

  if (!Number.isInteger(spec.proxyPort) || spec.proxyPort < 1 || spec.proxyPort > 65535) {
    throw new Error(
      `proxyPort: expected an integer TCP port between 1 and 65535, got ${JSON.stringify(spec.proxyPort)}.`
    );
  }

  if (spec.dnsResolver !== undefined && isIP(spec.dnsResolver) === 0) {
    throw new Error(
      `dnsResolver: ${JSON.stringify(spec.dnsResolver)} is not an IPv4 or IPv6 literal. This has to be a ` +
        "bare address: a hostname would have to be resolved to be written into a rule, and resolving " +
        "it needs the DNS this rule is what permits. Prefixes and zone ids are rejected too — the " +
        "agent is allowed exactly one resolver, not a range."
    );
  }
}

function checkUid(field: "agentUid" | "proxyUid", value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > UID_MAX) {
    throw new Error(`${field}: expected an integer uid between 0 and ${UID_MAX}, got ${JSON.stringify(value)}.`);
  }
  if (value !== 0) return;

  throw new Error(
    field === "agentUid"
      ? "agentUid: refusing to build a perimeter around uid 0. Root can flush or rewrite this table at " +
        "will, so the containment would be advisory, and every rule here is written against `meta " +
        "skuid 0`, which is every root process on the host rather than the agent. Run the agent as a " +
        "dedicated unprivileged uid."
      : "proxyUid: refusing to exempt uid 0. The exemption renders as `meta skuid 0 accept`, which " +
        "would let every root process on the host egress unfiltered instead of just the proxy. Run " +
        "the proxy as its own unprivileged uid."
  );
}

/**
 * Render the complete nftables ruleset for a perimeter.
 *
 * Its own table, always. Rules merged into a shared table cannot be rolled back cleanly: removing
 * them means matching handles inside somebody else's chains and hoping nothing else was added in
 * between, and a control an operator cannot cleanly remove is a control they will refuse to
 * install. A dedicated `inet agentwall` table makes uninstall a single `delete table`, which is
 * also why `rollback` is one line and why re-applying this file is safe.
 *
 * Idempotent by construction: `add table` is a no-op when the table already exists, so the
 * add/delete pair at the top always has something to remove and always leaves exactly one
 * agentwall table however many times the file is applied. nft applies a `-f` file as one
 * transaction, so there is no window where the old table is gone and the new one is not yet there.
 *
 * Output is deterministic — no timestamps, no hostnames — so an operator can diff two plans and
 * see only what they changed.
 */
export function renderNftables(spec: PerimeterSpec): string {
  assertValidSpec(spec);

  const { agentUid, proxyUid, proxyPort, dnsResolver, allowLoopback } = spec;
  const dnsFamily = dnsResolver === undefined ? null : isIP(dnsResolver) === 6 ? "ip6" : "ip";

  const out: string[] = [
    "#!/usr/sbin/nft -f",
    "#",
    "# AgentWall perimeter. Generated by `agentwall perimeter plan` — do not hand-edit; edit the",
    "# command line and re-render, or the next `install` silently reverts your change.",
    "#",
    `#   agent uid      ${agentUid}   (captured on tcp ${CAPTURED_PORTS.join("/")}; everything else it sends is dropped)`,
    `#   proxy uid      ${proxyUid}   (exempt: this is the only uid that reaches the network directly)`,
    `#   proxy port     ${proxyPort}`,
    `#   dns resolver   ${dnsResolver ?? "none — the agent resolves nothing"}`,
    `#   loopback       ${allowLoopback ? "allowed for the agent uid" : "denied except the proxy port"}`,
    "#",
    "# Its own table so that uninstall is `delete table inet agentwall` and nothing else on this",
    "# host is disturbed by installing or removing it.",
    "",
    "# `add` is a no-op when the table is already there, so this pair is safe on a clean host and",
    "# on a host that already has a perimeter. Everything below is one nft transaction.",
    `add table ${TABLE}`,
    `delete table ${TABLE}`,
    "",
    `table ${TABLE} {`,
    "\t# Destination NAT for locally generated packets. This hook runs before the filter hook",
    "\t# below, so by the time a captured connection reaches `egress` it has already been",
    "\t# rewritten to the proxy's address and port.",
    // Not `redirect`: nft reserves that word as a statement keyword and rejects the file with
    // a syntax error at the chain declaration. A unit test on the rendered string cannot see
    // that — only the kernel's own parser can — so the name is deliberate, not cosmetic.
    "\tchain capture {",
    "\t\ttype nat hook output priority dstnat; policy accept;",
    "",
    "\t\t# The proxy must not be redirected into itself. Without this rule the proxy dials",
    "\t\t# example.com:443 on the agent's behalf, its own SYN is rewritten to the proxy port,",
    "\t\t# and it connects to itself — a loop that presents as a hang rather than an error, and",
    "\t\t# the single easiest way to get this model wrong.",
    `\t\tmeta skuid ${proxyUid} accept`,
  ];

  if (allowLoopback) {
    out.push(
      "",
      "\t\t# Loopback is exempt from capture as well as from the drop: redirecting a connection to",
      "\t\t# a local database into an HTTP proxy would break it rather than police it.",
      `\t\tmeta skuid ${agentUid} ip daddr 127.0.0.0/8 accept`,
      `\t\tmeta skuid ${agentUid} ip6 daddr ::1 accept`
    );
  }

  out.push(
    "",
    "\t\t# The capture itself: connections this uid opens to the ports the proxy can truthfully name",
    "\t\t# land on the local proxy, whatever destination the process asked for. The client is never",
    "\t\t# told, which is the point — there is no proxy setting for it to ignore.",
    "\t\t#",
    "\t\t# Scoped rather than blanket because the proxy reads the destination out of the stream and",
    "\t\t# TLS carries no port there. Capturing :8443 would mean policing it as :443 — right host,",
    "\t\t# wrong service, allowed. Every other port falls to the drop below instead, which is a",
    "\t\t# narrowing: unreachable rather than misrouted. Port 53 is not captured either, so an",
    "\t\t# approved resolver needs no exemption here.",
    `\t\tmeta skuid ${agentUid} tcp dport { ${CAPTURED_PORTS.join(", ")} } redirect to :${proxyPort}`,
    "\t}",
    "",
    "\t# Egress filter. `policy accept` is deliberate: this chain sees every locally generated",
    "\t# packet on the host, not just the agent's, so a drop policy here would take the machine",
    "\t# off the network. Containment comes from the explicit uid-scoped drop at the end.",
    "\tchain egress {",
    "\t\ttype filter hook output priority filter; policy accept;",
    "",
    `\t\tmeta skuid ${proxyUid} accept`,
    "",
    "\t\t# The captured connections, post-NAT: the destination is now loopback and the port is the",
    "\t\t# proxy's. Without this they would meet the drop below and the agent would have no path",
    "\t\t# at all — contained, but useless.",
    `\t\tmeta skuid ${agentUid} ip daddr 127.0.0.1 tcp dport ${proxyPort} accept`,
    `\t\tmeta skuid ${agentUid} ip6 daddr ::1 tcp dport ${proxyPort} accept`
  );

  if (allowLoopback) {
    out.push(
      "",
      "\t\t# Operator-opened hole: other services on this host. Off by default, because a local",
      "\t\t# service can be a route to the outside that never passes the proxy.",
      `\t\tmeta skuid ${agentUid} oif "lo" accept`
    );
  }

  if (dnsResolver !== undefined && dnsFamily !== null) {
    out.push(
      "",
      "\t\t# One resolver, both transports, and nothing else on port 53. Scoped to an address rather",
      "\t\t# than to the port because `udp dport 53 accept` would be a tunnel to any host willing to",
      "\t\t# answer on it.",
      `\t\tmeta skuid ${agentUid} ${dnsFamily} daddr ${dnsResolver} udp dport 53 accept`,
      `\t\tmeta skuid ${agentUid} ${dnsFamily} daddr ${dnsResolver} tcp dport 53 accept`
    );
  }

  out.push(
    "",
    "\t\t# Default-drop, and the reason the rest of this file is worth anything. A set of redirects",
    "\t\t# over a permissive default contains nothing: it moves the traffic it knows about and waves",
    "\t\t# through QUIC, raw sockets, ICMP tunnels, and every protocol nobody thought to name. This",
    "\t\t# rule must stay last — anything below it for this uid is dead.",
    `\t\tmeta skuid ${agentUid} drop`,
    "\t}",
    "}",
    ""
  );

  return out.join("\n");
}

/** One chain lifted out of an `nft list table` listing, with its rules normalised to single spaces. */
interface ParsedChain {
  name: string;
  rules: string[];
}

/**
 * Read `nft list table inet agentwall` output back into the facts that decide whether an agent is
 * actually contained.
 *
 * This checks invariants, not text. An operator may legitimately add rules to this table, and a
 * status command that demanded a byte-for-byte match with `plan` would cry wolf at every local
 * adjustment until it was ignored. What it does insist on is the set of properties that cannot be
 * missing without the perimeter being a decoration: the table exists, the agent's TCP is redirected
 * to the port the proxy is actually on, that redirect captures no port the proxy cannot name, the
 * proxy is exempted before the redirect, and the last word on the agent's traffic is a drop.
 *
 * `installed` is false when the drop is missing even though the redirect is there. That state looks
 * healthy from the outside — traffic flows, the ledger fills up, the proxy is clearly working — and
 * it contains nothing, because everything the redirect does not match still leaves the host. It is
 * precisely the state an operator must not be told is fine.
 */
export function parsePerimeterStatus(
  nftListOutput: string,
  spec: PerimeterSpec
): { installed: boolean; redirectPresent: boolean; dropPresent: boolean; problems: string[] } {
  // Same validation as rendering: comparing a listing against a spec that could never have been
  // installed would produce confident nonsense in either direction.
  assertValidSpec(spec);

  const { tablePresent, chains } = parseListing(nftListOutput);
  if (!tablePresent) {
    return {
      installed: false,
      redirectPresent: false,
      dropPresent: false,
      problems: [
        `nftables table \`${TABLE}\` is not present: the perimeter is not installed, and the agent uid ` +
          `${spec.agentUid} reaches the network directly. Apply it with \`agentwall perimeter install\` as root.`,
      ],
    };
  }

  const problems: string[] = [];
  const redirect = findRedirect(chains, spec, problems);
  const drop = findDrop(chains, spec, problems);

  if (redirect !== null) checkProxyExemption(redirect, spec, problems);
  if (drop !== null) checkDropIsLast(drop, spec, problems);

  const redirectPresent = redirect !== null;
  const dropPresent = drop !== null;
  return { installed: redirectPresent && dropPresent && problems.length === 0, redirectPresent, dropPresent, problems };
}

/** Where a rule was found, so ordering within its chain can be checked. */
interface RuleSite {
  chain: ParsedChain;
  index: number;
}

function findRedirect(chains: ParsedChain[], spec: PerimeterSpec, problems: string[]): RuleSite | null {
  const found: Array<RuleSite & { rule: string; uid: number | null; port: number | null }> = [];
  for (const chain of chains) {
    chain.rules.forEach((rule, index) => {
      if (!rule.includes("redirect to")) return;
      found.push({ chain, index, rule, uid: matchUid(rule), port: matchRedirectPort(rule) });
    });
  }

  const exact = found.find((r) => r.uid === spec.agentUid && r.port === spec.proxyPort);
  if (exact !== undefined) {
    checkCaptureScope(exact.rule, spec, problems);
    return { chain: exact.chain, index: exact.index };
  }

  const wrongPort = found.find((r) => r.uid === spec.agentUid);
  if (wrongPort !== undefined) {
    problems.push(
      `the redirect for uid ${spec.agentUid} sends traffic to port ${wrongPort.port ?? "an unreadable port"}, ` +
        `but the proxy is configured on port ${spec.proxyPort}. Captured connections land on a port nothing ` +
        "is listening on, so the agent's egress fails without ever being recorded."
    );
    return null;
  }

  const otherUids = [...new Set(found.map((r) => r.uid).filter((uid): uid is number => uid !== null))];
  problems.push(
    otherUids.length === 0
      ? `no redirect rule for uid ${spec.agentUid}: nothing captures the agent's TCP connections, so the ` +
        "proxy only sees clients that cooperate."
      : `the table redirects uid(s) ${otherUids.join(", ")} but not uid ${spec.agentUid}, which is the uid ` +
        "the agent is configured to run as."
  );
  return null;
}

/** What an installed redirect rule captures, as far as its text can be trusted to say. */
type CaptureScope =
  | { kind: "ports"; ports: number[] }
  | { kind: "unrestricted" }
  | { kind: "unverifiable"; expression: string };

/**
 * A redirect wider than the proxy can name is a live misattribution, not a stylistic difference.
 *
 * The proxy recovers the destination host from the stream and infers the port, so a captured
 * connection to :8443 is policed and recorded as :443 of that host — the wrong service, under an
 * allow verdict, in a signed ledger. Narrower than `CAPTURED_PORTS` is fine and reported as
 * healthy: an uncaptured port meets the default-drop, which is a refusal, not a lie.
 */
function checkCaptureScope(rule: string, spec: PerimeterSpec, problems: string[]): void {
  const scope = captureScopeOf(rule);

  if (scope.kind === "unrestricted") {
    problems.push(
      `the redirect for uid ${spec.agentUid} captures every TCP port (\`${rule}\`). The proxy reads the ` +
        "destination out of the stream and TLS carries no port there, so a connection to any other port is " +
        `policed and recorded as ${TLS_PORT} of the same host — the wrong service, under an allow verdict. ` +
        "Re-apply the current ruleset with `agentwall perimeter install`."
    );
    return;
  }

  if (scope.kind === "unverifiable") {
    problems.push(
      `the redirect for uid ${spec.agentUid} matches \`${scope.expression}\`, which this check cannot resolve ` +
        `to a port list. Confirm by hand that it captures only ${CAPTURED_PORTS.join(" and ")}: any other ` +
        `captured port is attributed to ${TLS_PORT} of the same host.`
    );
    return;
  }

  const unnameable = scope.ports.filter((port) => !CAPTURED_PORTS.includes(port));
  if (unnameable.length === 0) return;

  problems.push(
    `the redirect for uid ${spec.agentUid} captures port(s) ${unnameable.join(", ")}, which the proxy cannot ` +
      `recover from the stream. Connections there are attributed to ${TLS_PORT} of the same host. Capture ` +
      `only ${CAPTURED_PORTS.join(" and ")} and let the default-drop refuse the rest.`
  );
}

/** `tcp dport { 80, 443 }` / `tcp dport 443` / no dport match at all. */
function captureScopeOf(rule: string): CaptureScope {
  const match = /\btcp dport (\{[^}]*\}|[^ ]+)/.exec(rule);
  if (match === null) return { kind: "unrestricted" };

  const expression = match[1];
  const ports = expression
    .replace(/[{}]/g, "")
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part !== "");

  // Named sets, ranges, and service names are all legal nft and none of them are a port list.
  if (ports.length === 0 || ports.some((part) => !/^\d+$/.test(part))) return { kind: "unverifiable", expression };
  return { kind: "ports", ports: ports.map(Number) };
}

function findDrop(chains: ParsedChain[], spec: PerimeterSpec, problems: string[]): RuleSite | null {
  const unconditional = `meta skuid ${spec.agentUid} drop`;
  for (const chain of chains) {
    const index = chain.rules.indexOf(unconditional);
    if (index !== -1) return { chain, index };
  }

  const conditional = chains
    .flatMap((chain) => chain.rules)
    .find((rule) => rule.endsWith(" drop") && rule.includes(`skuid ${spec.agentUid} `));

  problems.push(
    conditional === undefined
      ? `no default-drop for uid ${spec.agentUid}: without a final \`${unconditional}\` everything the ` +
        "redirect does not match — UDP, QUIC, raw sockets, ICMP — still leaves this host. A redirect over " +
        "a permissive default looks installed and contains nothing."
      : `the only drop for uid ${spec.agentUid} is conditional (\`${conditional}\`). A perimeter needs the ` +
        `unconditional \`${unconditional}\` last, or every protocol nobody thought to name is permitted.`
  );
  return null;
}

/**
 * The proxy exemption has to sit above the redirect in the same chain.
 *
 * Below it, or absent, the proxy's own upstream connections are rewritten back to the proxy and it
 * talks to itself. nftables evaluates a chain in order, so "present somewhere in the table" is not
 * the property that matters — "reached before the redirect" is.
 */
function checkProxyExemption(redirect: RuleSite, spec: PerimeterSpec, problems: string[]): void {
  const exemption = `meta skuid ${spec.proxyUid} accept`;
  const index = redirect.chain.rules.indexOf(exemption);
  if (index !== -1 && index < redirect.index) return;

  problems.push(
    index === -1
      ? `chain \`${redirect.chain.name}\` redirects the agent but never exempts the proxy uid ` +
        `${spec.proxyUid} (\`${exemption}\`). The proxy's own upstream connections are redirected into the ` +
        "proxy, which hangs every request instead of forwarding it."
      : `the exemption for proxy uid ${spec.proxyUid} sits below the redirect in chain ` +
        `\`${redirect.chain.name}\`; nftables evaluates in order, so the proxy is redirected into itself ` +
        "before the exemption is ever reached."
  );
}

function checkDropIsLast(drop: RuleSite, spec: PerimeterSpec, problems: string[]): void {
  const dead = drop.chain.rules.slice(drop.index + 1).filter((rule) => rule.includes(`skuid ${spec.agentUid} `));
  if (dead.length === 0) return;

  problems.push(
    `${dead.length} rule(s) for uid ${spec.agentUid} sit below the default-drop in chain ` +
      `\`${drop.chain.name}\` and are unreachable (first: \`${dead[0]}\`). Whatever they were meant to ` +
      "permit is being dropped."
  );
}

/** `meta skuid 1001 ...` -> 1001. Null when the rule matches on something other than a numeric uid. */
function matchUid(rule: string): number | null {
  const match = /\bskuid (\d+)\b/.exec(rule);
  return match === null ? null : Number(match[1]);
}

/** `... redirect to :8080` -> 8080. */
function matchRedirectPort(rule: string): number | null {
  const match = /\bredirect to :(\d+)\b/.exec(rule);
  return match === null ? null : Number(match[1]);
}

/**
 * Split a listing into chains and rules.
 *
 * Whitespace-tolerant on purpose: nft indents with tabs, operators paste with spaces, and a status
 * check that depended on either would be a status check that fails for the wrong reason. Comments
 * and the `type ... hook ...` chain declaration are dropped — neither is a rule.
 */
function parseListing(text: string): { tablePresent: boolean; chains: ParsedChain[] } {
  let tablePresent = false;
  const chains: ParsedChain[] = [];
  let current: ParsedChain | null = null;

  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s+/g, " ").trim();
    if (line === "" || line.startsWith("#")) continue;

    if (/^table inet agentwall( \{)?$/.test(line)) {
      tablePresent = true;
      continue;
    }

    const chainOpen = /^chain ([A-Za-z0-9_.-]+) \{?$/.exec(line);
    if (chainOpen !== null) {
      current = { name: chainOpen[1], rules: [] };
      chains.push(current);
      continue;
    }

    if (line === "}") {
      current = null;
      continue;
    }

    if (current === null || line.startsWith("type ")) continue;
    current.rules.push(line.replace(/;$/, "").trim());
  }

  return { tablePresent, chains };
}
