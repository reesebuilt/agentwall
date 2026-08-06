import { createHash, timingSafeEqual } from "crypto";
import { z } from "zod";

/**
 * Per-agent identity for a fleet sharing one host.
 *
 * AgentWall already resolved a pid and a comm for every proxied connection. That answers
 * "which process" and stops short of "which agent", and on a box running an MCP wrapper, a
 * scraper, and four cron jobs those are different questions. This module is the binding
 * between an observed connection and a principal the operator actually declared, so a
 * record can say WHICH agent rather than only which process name the kernel reported.
 *
 * Scope, stated up front because the rest of the file only makes sense against it: this is
 * per-agent governance on ONE host. There is no clustered control plane, no cross-host
 * identity, and no shared budget across instances. See docs/fleet.md.
 *
 * The three signals, and exactly what each is worth:
 *
 *   credential  A secret the client presents on the proxy connection (Proxy-Authorization).
 *               Unforgeable by a process that cannot read the secret, forgeable by any
 *               process that can. On a single-uid host every agent can usually read every
 *               other agent's environment, so this separates COOPERATING agents; it does
 *               not contain a hostile one.
 *
 *   uid         The kernel's owner of the socket, read from column 7 of /proc/net/tcp. A
 *               process cannot change its own uid without privilege, which makes this the
 *               only signal here an agent cannot simply assert. It is also the coarsest:
 *               agents sharing a uid are indistinguishable by it alone.
 *
 *   comm        The process name. Measured, not assumed: Node rewrites its own comm to
 *               "MainThread" at startup, and `process.title = "aw-scraper"` sets it to
 *               anything the process likes. comm is therefore a LABEL the process chose,
 *               not a credential. It is genuinely useful for telling apart agents you
 *               yourself launched and worth nothing against one that lies.
 *
 * Precedence runs strongest-first (credential, then uid+comm, then uid, then comm) so a
 * specific declaration always beats a general one. Which signal actually matched is carried
 * into the audit record, because "this was agent X" means something different when it came
 * from a presented secret than when it came from a string the process picked.
 */

/** How an observed connection was bound to a declared agent, strongest first. */
export type AgentMatchSignal = "credential" | "uid+comm" | "uid" | "comm" | "none";

/**
 * Sentinel for a connection no declared agent claims.
 *
 * Shared with the proxy and the MCP wrap on purpose. Where attribution is unavailable the
 * record says so rather than inventing a plausible name.
 */
export const UNDECLARED_AGENT_ID = "unattributed";

const CREDENTIAL_HELP =
  'A credential must be "sha256:<64 hex>" (the digest of the presented secret) or "env:<VAR>" ' +
  "(the secret is read from that environment variable at load and hashed). A bare secret in the " +
  "config file is rejected: this file is routinely committed, and a proxy credential in git is a " +
  "credential you have to rotate.";

const AgentMatchSchema = z
  .object({
    /** Numeric uid the socket must be owned by. */
    uid: z.number().int().min(0).optional(),
    /** Process names to accept. Self-declared by the process; see the note above. */
    comm: z.array(z.string().min(1)).min(1).optional(),
    /** Secret the client presents via Proxy-Authorization. `sha256:` or `env:` form only. */
    credential: z.string().min(1).optional(),
  })
  .refine((m) => m.uid !== undefined || m.comm !== undefined || m.credential !== undefined, {
    message: "an agent match must name at least one of uid, comm, or credential",
  });

const AgentBudgetSchema = z
  .object({
    /** Sliding window the counters are measured over. */
    windowSeconds: z.number().int().positive(),
    /** Connections admitted per window. Omit for no request ceiling. */
    maxRequests: z.number().int().positive().optional(),
    /** Bytes in both directions per window. Omit for no byte ceiling. */
    maxBytes: z.number().int().positive().optional(),
  })
  .refine((b) => b.maxRequests !== undefined || b.maxBytes !== undefined, {
    message: "a budget must set maxRequests, maxBytes, or both",
  });

const AgentEgressSchema = z
  .object({
    allowedHosts: z.array(z.string().min(1)).optional(),
    allowedPorts: z.array(z.number().int().min(1).max(65535)).optional(),
  })
  .refine((e) => e.allowedHosts !== undefined || e.allowedPorts !== undefined, {
    message: "an agent egress block must set allowedHosts, allowedPorts, or both",
  });

export const FleetAgentSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1).optional(),
  match: AgentMatchSchema,
  egress: AgentEgressSchema.optional(),
  budget: AgentBudgetSchema.optional(),
});
export type FleetAgentConfig = z.infer<typeof FleetAgentSchema>;

export const FleetConfigSchema = z.object({
  /**
   * What happens to egress the registry cannot bind to a declared agent.
   *
   * "global" is the default and preserves today's behaviour exactly: the process-wide
   * allowlist judges it, and the record carries the comm as it always did. Upgrading into a
   * version that understands fleets must never start blocking traffic on its own.
   *
   * "deny" is the closed posture: guarded and strict refuse anything undeclared. Monitor
   * still only records, because monitor blocking things is how an adoption path dies.
   */
  unmatched: z.enum(["global", "deny"]).default("global"),
  agents: z.array(FleetAgentSchema).default([]),
});
export type FleetConfig = z.infer<typeof FleetConfigSchema>;

/** A declared agent with its credential resolved to a digest. */
export interface RegisteredAgent {
  id: string;
  label: string;
  uid?: number;
  comm: readonly string[];
  /** sha256 of the presented secret, or null when this agent is not credential-matched. */
  credentialDigest: Buffer | null;
  egress?: { allowedHosts?: readonly string[]; allowedPorts?: readonly number[] };
  budget?: { windowSeconds: number; maxRequests?: number; maxBytes?: number };
}

/** Everything an observed connection can offer the registry. */
export interface AgentSignals {
  uid?: number | null;
  comm?: string | null;
  /** Raw secret the client presented, already stripped of its auth scheme. */
  credential?: string | null;
}

/** The registry's answer for one connection. */
export interface ResolvedAgent {
  /** Declared id when one matched, otherwise the comm or the undeclared sentinel. */
  id: string;
  label: string;
  matchedOn: AgentMatchSignal;
  /** True only when a configured agent claimed this connection. */
  declared: boolean;
  agent: RegisteredAgent | null;
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function resolveCredentialDigest(raw: string, agentId: string): Buffer {
  if (raw.startsWith("sha256:")) {
    const hex = raw.slice("sha256:".length).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      throw new Error(`agentwall: fleet agent "${agentId}" has an invalid sha256 credential. ${CREDENTIAL_HELP}`);
    }
    return Buffer.from(hex, "hex");
  }
  if (raw.startsWith("env:")) {
    const name = raw.slice("env:".length).trim();
    if (!name) {
      throw new Error(`agentwall: fleet agent "${agentId}" has an empty env credential name. ${CREDENTIAL_HELP}`);
    }
    const secret = process.env[name];
    if (!secret) {
      // A boot failure rather than an agent that silently never matches. An operator whose
      // credential rule quietly stopped binding would see the fleet fall back to the global
      // allowlist and have no signal that it happened.
      throw new Error(
        `agentwall: fleet agent "${agentId}" reads its credential from $${name}, which is unset or empty.`
      );
    }
    return sha256(secret);
  }
  throw new Error(`agentwall: fleet agent "${agentId}" declares a literal credential. ${CREDENTIAL_HELP}`);
}

/**
 * Reject declarations that cannot be resolved deterministically.
 *
 * Two agents matching the same connection at the same strength is not a runtime edge case to
 * paper over with "first one wins": it means the operator believes two different policies are
 * in force for one agent, and whichever the iteration order picks will be the wrong one half
 * the time. A boot failure naming both ids is the only outcome that gets it fixed.
 */
function assertUnambiguous(agents: RegisteredAgent[]): void {
  const seenIds = new Set<string>();
  for (const agent of agents) {
    if (seenIds.has(agent.id)) {
      throw new Error(`agentwall: fleet declares agent id "${agent.id}" twice.`);
    }
    seenIds.add(agent.id);
  }

  const claim = (key: string, agentId: string, tier: string, owners: Map<string, string>): void => {
    const existing = owners.get(key);
    if (existing) {
      throw new Error(
        `agentwall: fleet agents "${existing}" and "${agentId}" both match on ${tier} ${key}. ` +
          `Give one of them a narrower match so a connection resolves to exactly one agent.`
      );
    }
    owners.set(key, agentId);
  };

  const credentials = new Map<string, string>();
  const uidComm = new Map<string, string>();
  const uidOnly = new Map<string, string>();
  const commOnly = new Map<string, string>();

  for (const agent of agents) {
    if (agent.credentialDigest) {
      claim(agent.credentialDigest.toString("hex"), agent.id, "credential", credentials);
    }
    if (agent.uid !== undefined && agent.comm.length > 0) {
      for (const comm of agent.comm) claim(`${agent.uid}/${comm}`, agent.id, "uid+comm", uidComm);
    } else if (agent.uid !== undefined) {
      claim(String(agent.uid), agent.id, "uid", uidOnly);
    } else if (agent.comm.length > 0) {
      for (const comm of agent.comm) claim(comm, agent.id, "comm", commOnly);
    }
  }
}

/**
 * The declared fleet, indexed for lookup on the egress hot path.
 *
 * Every index is built once at construction. resolve() runs inside a socket handler for every
 * proxied connection, so it does no allocation beyond its own answer and no scanning beyond
 * four map lookups.
 */
export class AgentRegistry {
  readonly unmatched: "global" | "deny";
  private readonly agents: readonly RegisteredAgent[];
  private readonly byCredential = new Map<string, RegisteredAgent>();
  private readonly byUidComm = new Map<string, RegisteredAgent>();
  private readonly byUid = new Map<number, RegisteredAgent>();
  private readonly byComm = new Map<string, RegisteredAgent>();

  constructor(config: FleetConfig) {
    this.unmatched = config.unmatched;
    this.agents = config.agents.map((declared) => ({
      id: declared.id,
      label: declared.label ?? declared.id,
      uid: declared.match.uid,
      comm: declared.match.comm ?? [],
      credentialDigest: declared.match.credential
        ? resolveCredentialDigest(declared.match.credential, declared.id)
        : null,
      egress: declared.egress,
      budget: declared.budget,
    }));

    assertUnambiguous([...this.agents]);

    for (const agent of this.agents) {
      if (agent.credentialDigest) this.byCredential.set(agent.credentialDigest.toString("hex"), agent);
      if (agent.uid !== undefined && agent.comm.length > 0) {
        for (const comm of agent.comm) this.byUidComm.set(`${agent.uid}/${comm}`, agent);
      } else if (agent.uid !== undefined) {
        this.byUid.set(agent.uid, agent);
      } else if (agent.comm.length > 0) {
        for (const comm of agent.comm) this.byComm.set(comm, agent);
      }
    }
  }

  get size(): number {
    return this.agents.length;
  }

  list(): readonly RegisteredAgent[] {
    return this.agents;
  }

  get(id: string): RegisteredAgent | null {
    return this.agents.find((agent) => agent.id === id) ?? null;
  }

  /**
   * Bind one observed connection to a declared agent, or report that none claims it.
   *
   * An empty registry is the common case for a single-agent deployment and must cost nothing:
   * it returns the same shape the old code produced, with the comm as the id.
   */
  resolve(signals: AgentSignals): ResolvedAgent {
    if (this.agents.length > 0) {
      if (signals.credential) {
        const presented = sha256(signals.credential);
        const found = this.byCredential.get(presented.toString("hex"));
        // Confirmed in constant time. The map probe above only finds the candidate; a hash
        // table lookup is not what decides a credential match. Lengths always agree here
        // because both sides are sha256 outputs, and the guard stays anyway: timingSafeEqual
        // throws on a length mismatch, and a registry that throws inside a socket handler
        // would let a client take the proxy down by presenting a malformed credential.
        if (
          found?.credentialDigest &&
          found.credentialDigest.length === presented.length &&
          timingSafeEqual(found.credentialDigest, presented)
        ) {
          return { id: found.id, label: found.label, matchedOn: "credential", declared: true, agent: found };
        }
      }
      if (signals.uid != null && signals.comm) {
        const found = this.byUidComm.get(`${signals.uid}/${signals.comm}`);
        if (found) return { id: found.id, label: found.label, matchedOn: "uid+comm", declared: true, agent: found };
      }
      if (signals.uid != null) {
        const found = this.byUid.get(signals.uid);
        if (found) return { id: found.id, label: found.label, matchedOn: "uid", declared: true, agent: found };
      }
      if (signals.comm) {
        const found = this.byComm.get(signals.comm);
        if (found) return { id: found.id, label: found.label, matchedOn: "comm", declared: true, agent: found };
      }
    }

    const fallbackId = signals.comm ?? UNDECLARED_AGENT_ID;
    return { id: fallbackId, label: fallbackId, matchedOn: "none", declared: false, agent: null };
  }
}

/**
 * Parse a Proxy-Authorization header into the secret the registry hashes.
 *
 * Bearer yields the token. Basic yields the decoded "user:pass", which is what an agent gets
 * for free by putting userinfo in its proxy URL and is therefore the form most HTTP clients
 * will actually send. Anything else yields null rather than a guess.
 *
 * The header is hop-by-hop and MUST NOT reach the destination; forward-proxy.ts strips it.
 */
export function parseProxyCredential(header: string | undefined): string | null {
  if (!header) return null;
  const space = header.indexOf(" ");
  if (space <= 0) return null;
  const scheme = header.slice(0, space).toLowerCase();
  const value = header.slice(space + 1).trim();
  if (!value) return null;
  if (scheme === "bearer") return value;
  if (scheme === "basic") {
    try {
      const decoded = Buffer.from(value, "base64").toString("utf8");
      return decoded.includes(":") ? decoded : null;
    } catch {
      return null;
    }
  }
  return null;
}
