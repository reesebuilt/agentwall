/**
 * What is genuinely different about each agent runtime, and how much of it we actually checked.
 *
 * The reason this file exists is narrow and worth stating plainly. Every integration reduces to
 * "point the runtime at the proxy", and that sentence hides a per-runtime minefield: Node 24
 * ignores HTTPS_PROXY outright, `requests` treats REQUESTS_CA_BUNDLE as a REPLACEMENT for the
 * public trust store rather than an addition, and curl silently drops CURL_CA_BUNDLE the moment
 * an explicit --capath is present. A profile that names the wrong variable produces an operator
 * who believes traffic is governed while it goes straight out. That is strictly worse than
 * shipping nothing, because it converts an open question into a false answer.
 *
 * So every claim here carries its own grade and the observation behind it:
 *
 *   "verified"   - exercised end to end against that runtime ON THIS HOST, and the observation
 *                  was made on the wire (a logging proxy saw the CONNECT) or at the TLS layer
 *                  (a request that must fail without the variable succeeded with it).
 *   "partial"    - the runtime's own shipped code was executed and answered, or the fact was
 *                  measured on the exact underlying engine but not through the agent itself.
 *                  Believable, not proven.
 *   "unverified" - not exercised at all. Says so in its own output, loudly.
 *
 * Grading is PER FIELD, never per profile, because the two axes come apart. Codex's proxy
 * capture is verified on the wire while its CA trust store is completely unknown, and rolling
 * those into one number would either overstate the second or understate the first. The overall
 * grade is derived from the fields by profileGrade() rather than stored, so it cannot drift out
 * of agreement with the evidence beneath it.
 *
 * `evidence` is the literal thing that was observed, not a summary of documentation. If you
 * change a value here, re-run the observation and change the evidence with it. A profile whose
 * evidence no longer matches its claim is the failure this file was written to prevent.
 *
 * Verification pass: 2026-08-06, Ubuntu 24.04 x86_64, Node v24.14.1, Bun 1.3.14,
 * python3 3.12.3 with requests 2.31.0, curl 8.5.0.
 */

/** How much confidence one claim has earned. */
export type ProfileGrade = "verified" | "partial" | "unverified";

/**
 * What a CA trust variable does to the EXISTING public trust store.
 *
 * The distinction is operational, not academic. "additive" means you point the variable at the
 * interception CA and everything keeps working. "replacement" means that same action breaks
 * every public TLS connection the agent makes, because the public roots are now gone, and the
 * operator must instead point it at a bundle containing the interception CA *and* the system
 * roots. Getting this backwards takes an agent off the network.
 */
export type CaSemantics = "additive" | "replacement" | "ignored" | "unknown";

export interface CaTrustFact {
  /** Variable an operator would reach for. */
  variable: string;
  semantics: CaSemantics;
  grade: ProfileGrade;
  /** What was observed, verbatim enough to re-run. */
  evidence: string;
}

export interface ProxyEnvFact {
  /** Variables this runtime demonstrably reads. */
  honoured: readonly string[];
  /**
   * Variables an operator would reasonably expect to work and which demonstrably DO NOT on
   * this runtime, each one measured. Empty means "no negative was measured", never "all the
   * others work": absence of evidence is not evidence, and this field never pretends otherwise.
   */
  ignored: readonly string[];
  grade: ProfileGrade;
  evidence: string;
}

export interface AgentProfile {
  id: string;
  label: string;
  /** The concrete thing that egresses, named precisely enough to re-check. */
  runtime: string;
  /** Exact version string the checks ran against, or null when nothing was checked. */
  verifiedAgainst: string | null;
  proxyEnv: ProxyEnvFact;
  caTrust: readonly CaTrustFact[];
  /** MCP surface, and whether those servers egress on their own. */
  mcp: string;
  /** Subprocesses that reach the network independently of the parent. */
  subprocessEgress: string;
  /** Hosts a starter allowlist grants. Deliberately small. */
  starterHosts: readonly string[];
  /**
   * The things this profile does NOT cover. Printed with the profile, not buried here, because
   * an integration guide that omits its own gaps is how an operator gets surprised during an
   * incident rather than during onboarding.
   */
  limits: readonly string[];
}

const GRADE_ORDER: Record<ProfileGrade, number> = { unverified: 0, partial: 1, verified: 2 };

/**
 * The weakest claim in the profile, which is the only honest summary of it.
 *
 * Derived rather than stored so that adding an unverified fact automatically downgrades the
 * profile. The alternative, a hand-maintained field, is how a profile ends up advertising
 * "verified" over a fact nobody ever checked.
 */
export function profileGrade(profile: AgentProfile): ProfileGrade {
  const grades = [profile.proxyEnv.grade, ...profile.caTrust.map((fact) => fact.grade)];
  return grades.reduce<ProfileGrade>(
    (weakest, grade) => (GRADE_ORDER[grade] < GRADE_ORDER[weakest] ? grade : weakest),
    "verified"
  );
}

/**
 * The grade that decides whether onboarding can be trusted at all.
 *
 * Capture is mandatory and interception is opt-in, so an operator who is not intercepting
 * should not be scared off by an unverified CA line, and an operator who IS intercepting must
 * not be reassured by a verified proxy line. They are reported separately for that reason.
 */
export function captureGrade(profile: AgentProfile): ProfileGrade {
  return profile.proxyEnv.grade;
}

/** The weakest CA claim, or "unverified" when the profile makes none. */
export function interceptionGrade(profile: AgentProfile): ProfileGrade {
  if (profile.caTrust.length === 0) return "unverified";
  return profile.caTrust.reduce<ProfileGrade>(
    (weakest, fact) => (GRADE_ORDER[fact.grade] < GRADE_ORDER[weakest] ? fact.grade : weakest),
    "verified"
  );
}

/**
 * The shipped profiles.
 *
 * Ordered by how likely someone is to onboard them, not alphabetically. `generic` is last and
 * is the honest answer for anything not on this list rather than a pretend default.
 */
export const AGENT_PROFILES: readonly AgentProfile[] = [
  {
    id: "claude-code",
    label: "Claude Code",
    runtime: "Compiled single-file binary (ELF) with a bundled JS runtime, plus the MCP servers it spawns",
    verifiedAgainst: "2.1.220 (Claude Code)",
    proxyEnv: {
      honoured: ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY"],
      ignored: ["no_proxy"],
      grade: "verified",
      evidence:
        "`claude -p` run behind a logging CONNECT proxy. Uppercase pair set: the proxy observed " +
        "CONNECT api.anthropic.com:443. Repeated with only the lowercase pair: CONNECT " +
        "api.anthropic.com:443 again. With ALL_PROXY/all_proxy the proxy received absolute-form " +
        "requests (GET https://api.anthropic.com/... , User-Agent axios/1.15.2 and " +
        "claude-cli/2.1.220). It does NOT need NODE_USE_ENV_PROXY: unlike bare Node it routes " +
        "through the proxy on its own. " +
        "NO_PROXY was tested by exempting one host while leaving the proxy set, which is a " +
        "controlled experiment rather than an absence: with NO_PROXY=api.anthropic.com the " +
        "proxy saw ZERO api.anthropic.com connections while STILL seeing CONNECT " +
        "platform.claude.com:443 and CONNECT agent.robinhood.com:443 in the same run, so the " +
        "exemption applied to exactly the named host. The lowercase spelling is IGNORED: " +
        "no_proxy=api.anthropic.com left 3 api.anthropic.com connections going through the " +
        "proxy, reproduced identically on three consecutive runs (3, 3, 3). Spell it uppercase.",
    },
    caTrust: [
      {
        variable: "NODE_EXTRA_CA_CERTS",
        semantics: "additive",
        grade: "partial",
        evidence:
          "The binary references NODE_EXTRA_CA_CERTS (54 occurrences) and additive, " +
          "startup-only semantics were verified end to end on Node 24 and on Bun, the runtime " +
          "family it bundles. NOT exercised against an interception CA through Claude Code " +
          "itself, so the semantics are inherited rather than observed here. Try this variable " +
          "first and confirm with verify-capture before relying on it.",
      },
    ],
    mcp:
      "Yes, and its MCP servers egress to their OWN destinations. Observed directly: during a " +
      "single `claude -p` run behind the logging proxy, alongside api.anthropic.com the proxy " +
      "also saw CONNECT platform.claude.com:443 and CONNECT agent.robinhood.com:443, the latter " +
      "belonging to a globally configured MCP server (`robinhood-trading` in ~/.claude.json). " +
      "An allowlist covering only the model API will refuse MCP traffic.",
    subprocessEgress:
      "Yes. MCP servers are separate processes with their own destinations, and they inherit the " +
      "parent environment, so they pick up the proxy variables. That inheritance is what makes " +
      "them governable; it also means one per-agent budget is shared across the agent and " +
      "everything it spawns. Bash tool invocations inherit and egress on their own too.",
    starterHosts: ["api.anthropic.com", "platform.claude.com"],

    limits: [
      "MCP server destinations are per-install. The starter allowlist came from this host and yours will differ; expect to widen it after the first verify-capture run.",
      "The CA variable is inherited from the Node/Bun measurement, not observed through Claude Code against a real interception CA.",
    ],
  },
  {
    id: "codex",
    label: "OpenAI Codex CLI",
    runtime: "Node launcher (bin/codex.js) that execs a native binary; the native binary owns the HTTP and TLS stack",
    verifiedAgainst: "codex-cli 0.146.0",
    proxyEnv: {
      honoured: ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY"],
      ignored: [],
      grade: "verified",
      evidence:
        "`codex exec --skip-git-repo-check` behind the logging proxy. Uppercase pair set: 11 " +
        "proxy hits including CONNECT auth.openai.com:443 and CONNECT chatgpt.com:443, " +
        "User-Agent codex_exec/0.146.0 (Ubuntu 24.4.0; x86_64). Lowercase pair set: 8 hits, same " +
        "destinations. Egress comes from the native binary rather than from Node, which is why " +
        "the Node NODE_USE_ENV_PROXY caveat does not apply to it. " +
        "NO_PROXY verified by the same exemption experiment: control run showed 4 " +
        "auth.openai.com connections at the proxy, and with NO_PROXY=auth.openai.com that fell " +
        "to 0 while 7 other proxied connections remained in the same run.",
    },
    caTrust: [
      {
        variable: "(unknown)",
        semantics: "unknown",
        grade: "unverified",
        evidence:
          "NOT VERIFIED, and deliberately not guessed. Egress is from a NATIVE binary, so " +
          "neither the Node result nor the Python result transfers, and the fact that Codex " +
          "installs through npm says nothing about the trust store its own TLS stack reads. The " +
          "verification pass covered Node, Bun, python3 requests and curl; no native-binary TLS " +
          "stack was tested. Do not set a CA variable for Codex on the strength of this profile. " +
          "If you need interception here, determine the variable against the real binary first " +
          "and prove it with verify-capture.",
      },
    ],
    mcp:
      "Codex supports MCP servers configured in its own config. Not exercised in this pass, so " +
      "no destination list is claimed.",
    subprocessEgress:
      "The Node launcher execs the native binary, so the process that egresses is not the one you " +
      "started. That matters for uid+comm binding, where the comm is the native binary's name " +
      "rather than `node`. Credential binding is unaffected, because the credential rides the " +
      "proxy connection rather than the process table.",
    starterHosts: ["api.openai.com", "chatgpt.com", "auth.openai.com"],
    limits: [
      "CA trust store is unverified for this runtime. TLS interception is NOT proven to work with Codex.",
      "MCP destinations were not enumerated.",
    ],
  },
  {
    id: "openclaw",
    label: "OpenClaw",
    runtime: "Node ESM launcher into a bundled dist; egress via undici with EnvHttpProxyAgent",
    verifiedAgainst: "OpenClaw 2026.6.33 (7af0cfc)",
    proxyEnv: {
      honoured: ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"],
      ignored: [],
      grade: "partial",
      evidence:
        "OpenClaw's OWN shipped module was imported and executed (dist/proxy-env-*.js from the " +
        "installed package, not a reimplementation). With HTTPS_PROXY set it returned " +
        "PROXY_ENV_KEYS = [HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, http_proxy, https_proxy, " +
        "all_proxy], hasEnvHttpProxyConfigured true, resolveEnvHttpProxyUrl " +
        "'http://127.0.0.1:39999' and shouldUseEnvHttpProxyForUrl true; with no proxy " +
        "environment every one of those went false. The dist wires undici's EnvHttpProxyAgent " +
        "(13 references), which is exactly the mechanism that closes the bare-Node gap. " +
        "NOT OBSERVED ON THE WIRE: every attempt to drive a live model turn stopped at a " +
        "provider credential check before a socket was opened, so there is no CONNECT " +
        "observation for OpenClaw. The grade is partial for that reason, not because the " +
        "evidence is thin.",
    },
    caTrust: [
      {
        variable: "NODE_EXTRA_CA_CERTS",
        semantics: "additive",
        grade: "partial",
        evidence:
          "Runs on Node 24, where additive startup-only semantics were verified end to end, and " +
          "the dist references NODE_EXTRA_CA_CERTS (14 occurrences). Not exercised against an " +
          "interception CA through OpenClaw itself.",
      },
    ],
    mcp: "OpenClaw hosts MCP servers. Not exercised in this pass; no destination list is claimed.",
    subprocessEgress:
      "OpenClaw runs a long-lived gateway process plus per-agent workers, and it can drive other " +
      "CLIs (a `claude-cli` provider appears in its model catalogue on this host). Traffic you " +
      "expect from OpenClaw may therefore leave from a Claude Code process instead, bound to " +
      "whichever credential that process presents.",
    starterHosts: ["api.anthropic.com", "api.openai.com"],
    limits: [
      "No on-the-wire CONNECT observation. The mechanism was proven, the end-to-end path was not.",
      "Provider set is per-install; the starter allowlist reflects the two most common and will need widening.",
    ],
  },
  {
    id: "hermes-agent",
    label: "Hermes Agent",
    runtime: "Python (profile assumes the `requests` HTTP client)",
    verifiedAgainst: null,
    proxyEnv: {
      honoured: ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY"],
      ignored: [],
      grade: "partial",
      evidence:
        "Hermes Agent itself is NOT INSTALLED on the verification host, so nothing was checked " +
        "against it. What WAS verified is the stack this profile assumes: python3 3.12.3 with " +
        "requests 2.31.0, behind the logging proxy, produced CONNECT example.com:443 with " +
        "HTTPS_PROXY/HTTP_PROXY set, and NO_PROXY=example.com in the same shape dropped that to " +
        "zero proxy connections. That is evidence about `requests`, not about Hermes Agent. " +
        "If Hermes Agent uses httpx, aiohttp, or a raw socket, this profile may be wrong.",
    },
    caTrust: [
      {
        variable: "REQUESTS_CA_BUNDLE",
        semantics: "replacement",
        grade: "verified",
        evidence:
          "Verified against requests 2.31.0, and this is the most dangerous CA result in the " +
          "pass. Pointed at a throwaway CA the intercepted endpoint returned 200 (control failed " +
          "CERTIFICATE_VERIFY_FAILED), but https://example.com then FAILED with " +
          "CERTIFICATE_VERIFY_FAILED. The public roots are REPLACED, not extended. Mechanism " +
          "confirmed: Session.merge_environment_settings reports verify = the file path. " +
          "CONSEQUENCE: point this at a bundle containing the interception CA CONCATENATED WITH " +
          "the system roots (/etc/ssl/certs/ca-certificates.crt on this host), never at the bare " +
          "CA file, or the agent loses all public TLS.",
      },
      {
        variable: "CURL_CA_BUNDLE",
        semantics: "replacement",
        grade: "verified",
        evidence:
          "requests treats CURL_CA_BUNDLE as an alias for REQUESTS_CA_BUNDLE: with only " +
          "CURL_CA_BUNDLE set, merge_environment_settings reported verify = that path, the local " +
          "endpoint returned 200, and https://example.com failed. Same replacement hazard, same " +
          "full-bundle requirement.",
      },
      {
        variable: "SSL_CERT_FILE",
        semantics: "ignored",
        grade: "verified",
        evidence:
          "IGNORED by requests: setting it left the local endpoint failing " +
          "CERTIFICATE_VERIFY_FAILED and merge_environment_settings reported verify = True (the " +
          "default bundle). It IS honoured by the Python STDLIB, where it is additive: the same " +
          "variable made urllib.request.urlopen return 200 against the local endpoint while " +
          "example.com kept working. If the agent mixes requests and urllib you need both " +
          "variables set, and they have different semantics.",
      },
    ],
    mcp: "Unknown. Not verified.",
    subprocessEgress: "Unknown. Not verified.",
    starterHosts: ["api.openai.com", "api.anthropic.com"],
    limits: [
      "The runtime was not present on the verification host. Everything above describes python3 + requests, which is an ASSUMPTION about Hermes Agent rather than a measurement of it.",
      "Confirm which HTTP client it uses before trusting the proxy line, and run verify-capture before trusting anything.",
      "REQUESTS_CA_BUNDLE replaces the trust store. The emitted line points at a concatenated bundle for that reason; building that bundle is a step you must actually perform.",
    ],
  },
  {
    id: "pi-agent",
    label: "Pi Agent",
    runtime: "Bun",
    verifiedAgainst: "bun 1.3.14",
    proxyEnv: {
      honoured: ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY"],
      ignored: [],
      grade: "partial",
      evidence:
        "Pi Agent itself is not installed here; Bun is, and Bun is what this profile is about. " +
        "bun -e \"await fetch('https://example.com')\" behind the logging proxy: 1 hit, CONNECT " +
        "example.com:443, with the uppercase pair, again with the lowercase pair, and again with " +
        "each variable alone. NO_PROXY=example.com with the proxy still set dropped it to zero " +
        "hits, so the exemption is honoured. Unlike Node it needs NO opt-in flag. Verified for " +
        "Bun, inherited for Pi Agent.",
    },
    caTrust: [
      {
        variable: "NODE_EXTRA_CA_CERTS",
        semantics: "additive",
        grade: "verified",
        evidence:
          "Verified against bun 1.3.14 for both fetch and node:https: the intercepted endpoint " +
          "failed without the variable and returned 200 with it, while https://example.com kept " +
          "working, so additive. Startup-only, same as Node: setting it via process.env inside a " +
          "running Bun process left the fetch failing.",
      },
      {
        variable: "SSL_CERT_FILE",
        semantics: "additive",
        grade: "verified",
        evidence:
          "HONOURED by Bun, and this is the sharpest divergence in the whole pass: the identical " +
          "variable is IGNORED by Node 24 and honoured by Bun 1.3.14. With it set the local " +
          "endpoint returned 200 (control failed) and example.com still returned 200. A script " +
          "that sets SSL_CERT_FILE and works under Bun will silently fail to intercept when the " +
          "same code runs under Node.",
      },
    ],
    mcp: "Unknown for Pi Agent. Not verified.",
    subprocessEgress: "Unknown for Pi Agent. Not verified.",
    starterHosts: ["api.anthropic.com", "api.openai.com"],
    limits: [
      "Pi Agent was not present on the verification host. The Bun facts are measured; applying them to Pi Agent is an assumption.",
      "Bun-specific: SSL_CERT_FILE works here but not on Node, so do not copy this profile's CA line to a Node runtime.",
    ],
  },
  {
    id: "generic",
    label: "Generic runtime",
    runtime: "Unknown. Ask the runtime, then prove it with verify-capture.",
    verifiedAgainst: null,
    proxyEnv: {
      honoured: ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"],
      ignored: [],
      grade: "unverified",
      evidence:
        "NOT VERIFIED against anything, by definition. This is the conventional set most HTTP " +
        "clients read, offered as a starting point. Two measured counterexamples from this very " +
        "host show why you must not assume it holds: Node 24 ignores all of them unless " +
        "NODE_USE_ENV_PROXY=1 is also set, and it fails SILENTLY, returning 200 and exiting 0 " +
        "while the proxy sees nothing. Set these, then run verify-capture and believe only that.",
    },
    caTrust: [
      {
        variable: "(unknown)",
        semantics: "unknown",
        grade: "unverified",
        evidence:
          "Unknown for an unknown runtime, and there is no safe default to offer. Measured " +
          "semantics differ per runtime for the SAME variable name: SSL_CERT_FILE is ignored by " +
          "Node, ignored by python requests, additive for Bun, additive for curl, and additive " +
          "for the python stdlib. Determine it for your runtime before enabling interception.",
      },
    ],
    mcp: "Unknown.",
    subprocessEgress:
      "Unknown, and this is the question most often answered wrong. Anything the agent spawns " +
      "that inherits the environment is governed; anything that re-execs with a cleaned " +
      "environment, or that ships a static binary with its own trust store, is not.",
    starterHosts: [],
    limits: [
      "Nothing in this profile is verified. It is a checklist, not a configuration.",
      "If the runtime is bare Node (v24.14.1 measured here), these variables do NOTHING on their own. Node ignores HTTPS_PROXY, HTTP_PROXY and both lowercase spellings for global fetch AND for require('https').get, and egresses directly while returning 200 and exiting 0. Set NODE_USE_ENV_PROXY=1 as well. Nothing about the agent's own output reveals the bypass; only the proxy's logs do.",
      "Case matters and is not consistent across runtimes. Claude Code honours NO_PROXY and ignores no_proxy, measured three times. Do not assume a lowercase spelling is equivalent.",
      "An empty starter allowlist means monitor mode records everything and blocks nothing. Read the records, then write a real allowlist.",
    ],
  },
];

/** Look a profile up by id. Returns undefined rather than a fallback: guessing is the bug. */
export function findProfile(id: string): AgentProfile | undefined {
  return AGENT_PROFILES.find((profile) => profile.id === id);
}

/** Profile ids, for usage text and for the error on an unknown profile. */
export function profileIds(): string[] {
  return AGENT_PROFILES.map((profile) => profile.id);
}
