import { createHash, timingSafeEqual } from "crypto";
import { z } from "zod";
import type { CredentialSource, StoredCredential } from "./credentials";

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
 *
 * Two things sit on top of that, and both exist because a fleet is not one host:
 *
 *   A minimum binding tier. `fleet.minimumMatchTier` lets an operator say "credential tier
 *   or refuse" for the whole instance. Without it, whether an agent could be impersonated by
 *   any process that sets its own `process.title` depended on how carefully each host's
 *   config was written, and an organisation cannot audit that by hoping.
 *
 *   A credential lifecycle. src/fleet/credentials.ts holds issued credentials with an
 *   issued-at, an optional rotation expiry, and a revocation tombstone. A credential this
 *   registry recognises but that is revoked or past its overlap is a HARD refusal: it does
 *   not fall through to uid or comm. Falling through would mean a revoked agent that also
 *   matches `comm: ["aw-scraper"]` keeps working, and a revocation that can be survived by
 *   renaming a process is not a revocation.
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

/**
 * `match.credential: issued` means "the lifecycle store supplies this agent's digest".
 *
 * A word rather than another prefixed form, because there is no argument: the store is found
 * from the config path and keyed by agent id. Its job is to let an agent whose ONLY identity
 * is an issued credential still declare something in `match`, and to say so in the file a
 * reviewer reads. An issued credential also binds an agent that declares no credential line
 * at all, deliberately: requiring a config edit on every host before a credential can be
 * issued would put back exactly the coupling this store exists to remove.
 */
const ISSUED_CREDENTIAL = "issued";

const CREDENTIAL_HELP =
  'A credential must be "sha256:<64 hex>" (the digest of the presented secret), "env:<VAR>" ' +
  '(the secret is read from that environment variable at load and hashed), or "issued" (the ' +
  "digest comes from the credential store, so it can be rotated with an overlap and revoked " +
  "without a restart). A bare secret in the config file is rejected: this file is routinely " +
  "committed, and a proxy credential in git is a credential you have to rotate.";

const AgentMatchSchema = z
  .object({
    /** Numeric uid the socket must be owned by. */
    uid: z.number().int().min(0).optional(),
    /** Process names to accept. Self-declared by the process; see the note above. */
    comm: z.array(z.string().min(1)).min(1).optional(),
    /** Secret the client presents via Proxy-Authorization. `sha256:`, `env:`, or `issued`. */
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

/**
 * The weakest binding an operator will accept from a connection that claims a declared agent.
 *
 * Three values, not five, and the two that are missing are missing on purpose. `uid+comm` is
 * not a trust level above `uid`: it is the same kernel fact plus a self-declared label, so
 * offering it as a floor would suggest a strength it does not have. `comm` as a floor is the
 * default already, since comm is the weakest thing that binds at all.
 *
 *   any         Today's behaviour. Whatever binds, binds.
 *   uid         Refuse a binding that rests on a process name alone. uid, uid+comm, and
 *               credential all pass, because all three rest on something the process cannot
 *               simply assert about itself.
 *   credential  Only a presented secret counts. This is the setting an organisation running
 *               agents on hosts it does not individually audit actually wants.
 *
 * Scope: this governs how a CLAIM is proven. A connection no agent claims at all made no
 * claim to judge, and `unmatched` is what decides its fate. Setting `minimumMatchTier:
 * credential` and leaving `unmatched: global` closes impersonation of declared agents and
 * leaves undeclared traffic on the global allowlist, which is a coherent posture and not
 * usually the intended one. Set both.
 */
export type MinimumMatchTier = "any" | "uid" | "credential";

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
  /**
   * The fleet-wide identity floor. Defaults to "any", which is exactly today's behaviour.
   */
  minimumMatchTier: z.enum(["any", "uid", "credential"]).default("any"),
  /**
   * Where issued credentials live, relative to the config file that declares the fleet.
   *
   * Optional because the default (fleet-credentials.json beside the config) is right for
   * every single-host deployment. An organisation that mounts one store read-only on several
   * hosts points this at the mount, which is the cheapest form of multi-host issuance that
   * works: one place to revoke, no listener on any agent host.
   */
  credentialStore: z.string().min(1).optional(),
  agents: z.array(FleetAgentSchema).default([]),
});
export type FleetConfig = z.infer<typeof FleetConfigSchema>;

/** A declared agent with its credential resolved to a digest. */
export interface RegisteredAgent {
  id: string;
  label: string;
  uid?: number;
  comm: readonly string[];
  /** sha256 pinned in config, or null when the digest is not pinned there. */
  credentialDigest: Buffer | null;
  /** True when the agent declared `match.credential: issued`, so the store supplies it. */
  credentialFromStore: boolean;
  egress?: { allowedHosts?: readonly string[]; allowedPorts?: readonly number[] };
  budget?: { windowSeconds: number; maxRequests?: number; maxBytes?: number };
}

/**
 * The uid/comm rule this declaration binds by, with the key material, or null when it names
 * neither. Credentials are deliberately absent: they are not exclusive with these, so they
 * are handled beside this rather than inside it.
 *
 * One definition, three readers: the ambiguity check, the index construction, and the
 * binding-tier helpers below. The three used to spell the same if/else-if chain out
 * separately, and a doctor that reports a tier the resolver does not actually use is
 * exactly the kind of confidently wrong reporting this project keeps having to remove.
 *
 * Returns a discriminated object rather than a bare tier so callers get the uid narrowed
 * without an assertion. It allocates once per declared agent at construction, and nothing
 * on the egress hot path calls it: `resolve()` reads the prebuilt indexes.
 */
type UidCommBinding =
  | { tier: "uid+comm"; uid: number; comm: readonly string[] }
  | { tier: "uid"; uid: number }
  | { tier: "comm"; comm: readonly string[] };

function uidCommBinding(agent: RegisteredAgent): UidCommBinding | null {
  if (agent.uid !== undefined && agent.comm.length > 0) {
    return { tier: "uid+comm", uid: agent.uid, comm: agent.comm };
  }
  if (agent.uid !== undefined) return { tier: "uid", uid: agent.uid };
  if (agent.comm.length > 0) return { tier: "comm", comm: agent.comm };
  return null;
}

/** The strongest tier this declaration can bind at. */
export function strongestBindingTier(agent: RegisteredAgent): AgentMatchSignal {
  if (agent.credentialDigest) return "credential";
  return uidCommBinding(agent)?.tier ?? "none";
}

/**
 * The WEAKEST tier this declaration can bind at, which is the one that decides what the
 * declaration is actually worth.
 *
 * A credential is not exclusive with the uid/comm rules: `resolve()` tries the credential
 * first and falls through to uid and comm when none is presented, and the registry indexes
 * the agent under both. So an agent declaring a credential AND a comm is a comm-bound agent
 * that sometimes gets a stronger proof, not a credential-bound agent: any process on the
 * host that names itself the same thing binds to it without presenting anything. An
 * operator reading "credential" for that agent would be reading a security property it does
 * not have, which is why this exists separately from `strongestBindingTier`.
 */
export function weakestBindingTier(agent: RegisteredAgent): AgentMatchSignal {
  return uidCommBinding(agent)?.tier ?? (agent.credentialDigest ? "credential" : "none");
}

/** Weakest first. The order a report sorts by, and the inverse of the resolve order. */
export const BINDING_TIER_ORDER: readonly AgentMatchSignal[] = [
  "none",
  "comm",
  "uid",
  "uid+comm",
  "credential",
];

/** Negative when `left` is the weaker binding. */
export function compareBindingTier(left: AgentMatchSignal, right: AgentMatchSignal): number {
  return BINDING_TIER_ORDER.indexOf(left) - BINDING_TIER_ORDER.indexOf(right);
}

/** Everything an observed connection can offer the registry. */
export interface AgentSignals {
  uid?: number | null;
  comm?: string | null;
  /** Raw secret the client presented, already stripped of its auth scheme. */
  credential?: string | null;
}

/**
 * Where a refusal came from, which decides whether it is an alarm or a chore.
 *
 * This distinction exists because the alternative is a control that cries wolf. Every kind of
 * refusal below denies a connection, but they do not mean remotely the same thing, and
 * stamping all of them "Valid Accounts, high" would bury the one that matters under the
 * migration traffic of an operator who flipped a config key an hour ago.
 *
 *   operator-configuration  The refusal is caused by something the OPERATOR did, and would
 *                           happen identically to any client. Raising the floor above what an
 *                           agent can satisfy, or deleting an agent that still holds a
 *                           credential. Nobody attacked anything. The record says which key
 *                           did it and what to run.
 *   unproven-claim          Something bound to a declared agent on a weaker signal while the
 *                           proof the floor asks for EXISTS for that agent. A process that
 *                           set its own `comm` to a name whose credential it does not hold is
 *                           what this catches, and it is the reason the floor exists.
 *   indeterminate           A credential the operator withdrew is still being presented. This
 *                           is a stale deployment that missed a rotation, or a credential
 *                           that left with someone, and NOTHING on the connection tells the
 *                           two apart. Recorded as both, because a confident answer here
 *                           would be a guess either way.
 */
export type RefusalOrigin = "operator-configuration" | "unproven-claim" | "indeterminate";

/**
 * Why a connection that presented something was refused rather than bound.
 *
 * Distinct from "nothing claimed this connection". A refusal means a claim was made and
 * judged insufficient, which is a different event with a different owner: the undeclared
 * case is usually a deployment nobody told you about, and a refusal is usually a credential
 * you revoked or a floor you raised.
 */
export interface AgentRefusal {
  kind: "credential-revoked" | "credential-expired" | "credential-orphaned" | "below-minimum-tier";
  origin: RefusalOrigin;
  /** One sentence an operator can act on. Lands at the front of the record's reasons. */
  reason: string;
  /** The credential this is about, when it is about one. Never the digest. */
  credentialId?: string;
}

/** The registry's answer for one connection. */
export interface ResolvedAgent {
  /** Declared id when one matched, otherwise the comm or the undeclared sentinel. */
  id: string;
  label: string;
  matchedOn: AgentMatchSignal;
  /** True only when a configured agent claimed this connection AND the claim was accepted. */
  declared: boolean;
  agent: RegisteredAgent | null;
  /**
   * Non-null means refuse. The connection is not merely unbound: it presented something the
   * operator has decided is not good enough, and enforcement denies it in guarded and strict
   * regardless of `unmatched`.
   */
  refusal: AgentRefusal | null;
  /** The issued credential that bound this connection, when one did. */
  credential: StoredCredential | null;
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * The digest a config declaration pins, or null when the store supplies it.
 *
 * Null is `match.credential: issued` and nothing else. Every other unrecognised form throws,
 * including a bare secret, because this file gets committed.
 */
function resolveCredentialDigest(raw: string, agentId: string): Buffer | null {
  if (raw === ISSUED_CREDENTIAL) return null;
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
    const binding = uidCommBinding(agent);
    switch (binding?.tier) {
      case "uid+comm":
        for (const comm of binding.comm) claim(`${binding.uid}/${comm}`, agent.id, "uid+comm", uidComm);
        break;
      case "uid":
        claim(String(binding.uid), agent.id, "uid", uidOnly);
        break;
      case "comm":
        for (const comm of binding.comm) claim(comm, agent.id, "comm", commOnly);
        break;
    }
  }
}

/**
 * True when a binding at `signal` satisfies the fleet's floor.
 *
 * `uid+comm` passes the `uid` floor because it IS a uid binding with a label attached, and
 * refusing it while accepting the broader `uid` agent beside it would be incoherent.
 */
function meetsMinimumTier(signal: AgentMatchSignal, minimum: MinimumMatchTier): boolean {
  if (minimum === "any") return true;
  if (minimum === "credential") return signal === "credential";
  return signal === "credential" || signal === "uid" || signal === "uid+comm";
}

/**
 * The declared fleet, indexed for lookup on the egress hot path.
 *
 * Every index is built once at construction. resolve() runs inside a socket handler for every
 * proxied connection, so it does no allocation beyond its own answer and no scanning beyond
 * four map lookups plus, when a credential was presented, one lookup in the issued-credential
 * store. That store re-reads its file at most once a second, which is what makes a revocation
 * take effect without a restart; see src/fleet/credentials.ts.
 */
export class AgentRegistry {
  readonly unmatched: "global" | "deny";
  readonly minimumMatchTier: MinimumMatchTier;
  private readonly agents: readonly RegisteredAgent[];
  private readonly credentials: CredentialSource | null;
  private readonly byId = new Map<string, RegisteredAgent>();
  private readonly byCredential = new Map<string, RegisteredAgent>();
  private readonly byUidComm = new Map<string, RegisteredAgent>();
  private readonly byUid = new Map<number, RegisteredAgent>();
  private readonly byComm = new Map<string, RegisteredAgent>();

  constructor(config: FleetConfig, credentials: CredentialSource | null = null) {
    this.unmatched = config.unmatched;
    this.minimumMatchTier = config.minimumMatchTier;
    this.credentials = credentials;
    this.agents = config.agents.map((declared) => ({
      id: declared.id,
      label: declared.label ?? declared.id,
      uid: declared.match.uid,
      comm: declared.match.comm ?? [],
      credentialDigest: declared.match.credential
        ? resolveCredentialDigest(declared.match.credential, declared.id)
        : null,
      credentialFromStore: declared.match.credential === ISSUED_CREDENTIAL,
      egress: declared.egress,
      budget: declared.budget,
    }));

    assertUnambiguous([...this.agents]);

    for (const agent of this.agents) {
      this.byId.set(agent.id, agent);
      // A hand-written digest and an issued one for the same agent is a boot failure rather
      // than a precedence rule. Precedence would be a rule nobody remembers under pressure:
      // an operator who revokes the issued credential and finds the agent still working
      // because a stale line in config still matches has been handed the worst possible
      // outcome by a design decision made to avoid an error message.
      if (agent.credentialDigest && (credentials?.listFor(agent.id).length ?? 0) > 0) {
        throw new Error(
          `agentwall: fleet agent "${agent.id}" declares match.credential in config AND has credentials issued ` +
            `by "agentwall fleet issue". Keep one source. Remove the config line to manage this agent's ` +
            `credential lifecycle, or "agentwall fleet revoke --agent ${agent.id}" to go back to the config digest.`
        );
      }
      if (agent.credentialDigest) this.byCredential.set(agent.credentialDigest.toString("hex"), agent);
      const binding = uidCommBinding(agent);
      switch (binding?.tier) {
        case "uid+comm":
          for (const comm of binding.comm) this.byUidComm.set(`${binding.uid}/${comm}`, agent);
          break;
        case "uid":
          this.byUid.set(binding.uid, agent);
          break;
        case "comm":
          for (const comm of binding.comm) this.byComm.set(comm, agent);
          break;
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
    return this.byId.get(id) ?? null;
  }

  /** Issued credentials for one agent, whatever state each is in. Empty without a store. */
  credentialsFor(id: string): readonly StoredCredential[] {
    return this.credentials?.listFor(id) ?? [];
  }

  /**
   * Declared agents that can never bind under the current floor, with the reason.
   *
   * Reported at boot and by `agentwall doctor` rather than refused at startup. Refusing to
   * start would be the codebase's usual answer to "this agent silently never binds", and it
   * is the wrong one here: raising the floor fleet-wide is exactly how an organisation
   * migrates, and a boot failure would mean the floor cannot be raised until every host has
   * already been issued a credential. So the agents keep their declaration, every one of
   * their connections is refused with a reason in the chain, and the fact that they are in
   * that state is on screen in two places instead of nowhere.
   */
  unbindable(): Array<{ id: string; reason: string }> {
    const out: Array<{ id: string; reason: string }> = [];
    for (const agent of this.agents) {
      const blocked = this.floorBlocks(agent);
      if (blocked) out.push({ id: agent.id, reason: blocked });
    }
    return out;
  }

  /**
   * Why this agent can never bind under the current declaration, or null if it can.
   *
   * One predicate, read by `unbindable()` for the boot log and doctor AND by `accept()` to
   * decide whether a below-floor refusal is the operator's own configuration or a claim that
   * could have been proven and was not. Two copies of this would eventually disagree about
   * which agents are refused, and the disagreement would surface as a control that alarms on
   * a migration while staying quiet on an impersonation.
   */
  private floorBlocks(agent: RegisteredAgent): string | null {
    const hasCredential = agent.credentialDigest !== null || this.credentialsFor(agent.id).length > 0;
    // Independent of the floor: an agent whose only declaration is `credential: issued` with
    // nothing issued yet binds on nothing at all. That is the normal state between adding an
    // agent and running `fleet issue`, and it is worth one line rather than a silent hole in
    // a config that looks finished.
    if (agent.credentialFromStore && !hasCredential && agent.uid === undefined && agent.comm.length === 0) {
      return `declares "credential: issued" and has none. Run "agentwall fleet issue --agent ${agent.id}".`;
    }
    if (this.minimumMatchTier === "any") return null;
    if (this.minimumMatchTier === "credential" && !hasCredential) {
      return (
        `declares no credential, and fleet.minimumMatchTier is "credential". Run ` +
        `"agentwall fleet issue --agent ${agent.id}".`
      );
    }
    if (this.minimumMatchTier === "uid" && !hasCredential && agent.uid === undefined) {
      return `matches on comm alone, and fleet.minimumMatchTier is "uid". Add match.uid or issue a credential.`;
    }
    return null;
  }

  /**
   * Bind one observed connection to a declared agent, refuse it, or report that none claims it.
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
          return this.accept(found, "credential", null);
        }
        // An ISSUED credential, which is the one with a lifecycle. A hit here returns
        // whatever the outcome is, accepted or refused, and never falls through to uid or
        // comm: a revoked secret that still works because the process kept its name is not a
        // revocation, and a rotation whose window closed has to actually close.
        const issued = this.credentials?.lookup(presented) ?? null;
        if (issued) {
          const agent = this.byId.get(issued.credential.agentId) ?? null;
          if (!agent) {
            return this.refuse(issued.credential.agentId, {
              kind: "credential-orphaned",
              // The operator deleted this agent from config while a credential for it was
              // still live. Nobody attacked anything.
              origin: "operator-configuration",
              credentialId: issued.credential.credentialId,
              reason:
                `credential ${issued.credential.credentialId} was issued to agent ` +
                `"${issued.credential.agentId}", which this instance no longer declares. Re-declare that ` +
                `agent, or revoke the credential so it stops being presented.`,
            });
          }
          if (issued.state === "revoked") {
            const at = issued.credential.revokedAt ?? "an unrecorded time";
            const why = issued.credential.revokedReason ? `: ${issued.credential.revokedReason}` : "";
            return this.refuse(agent.id, {
              kind: "credential-revoked",
              // Genuinely undecidable from here: a host that missed the offboarding and a
              // secret that left with someone present the same bytes.
              origin: "indeterminate",
              credentialId: issued.credential.credentialId,
              reason:
                `credential ${issued.credential.credentialId} for agent "${agent.id}" was revoked at ${at}${why}, ` +
                `and is still being presented. That is either a deployment that was not updated or a ` +
                `credential in someone else's hands; this connection cannot tell you which.`,
            });
          }
          if (issued.state === "expired") {
            return this.refuse(agent.id, {
              kind: "credential-expired",
              origin: "indeterminate",
              credentialId: issued.credential.credentialId,
              reason:
                `credential ${issued.credential.credentialId} for agent "${agent.id}" was rotated out and its ` +
                `overlap window closed at ${issued.credential.expiresAt}. Usually a host that missed the ` +
                `rotation; this connection cannot rule out a copy of the old secret.`,
            });
          }
          return this.accept(agent, "credential", issued.credential);
        }
      }
      if (signals.uid != null && signals.comm) {
        const found = this.byUidComm.get(`${signals.uid}/${signals.comm}`);
        if (found) return this.accept(found, "uid+comm", null);
      }
      if (signals.uid != null) {
        const found = this.byUid.get(signals.uid);
        if (found) return this.accept(found, "uid", null);
      }
      if (signals.comm) {
        const found = this.byComm.get(signals.comm);
        if (found) return this.accept(found, "comm", null);
      }
    }

    const fallbackId = signals.comm ?? UNDECLARED_AGENT_ID;
    return {
      id: fallbackId,
      label: fallbackId,
      matchedOn: "none",
      declared: false,
      agent: null,
      refusal: null,
      credential: null,
    };
  }

  /**
   * One binding, after the fleet's floor has had its say.
   *
   * The floor is applied HERE rather than at each of the four call sites above, so a future
   * signal added to resolve() cannot be the one that forgot to check it.
   */
  private accept(agent: RegisteredAgent, matchedOn: AgentMatchSignal, credential: StoredCredential | null): ResolvedAgent {
    if (!meetsMinimumTier(matchedOn, this.minimumMatchTier)) {
      // Two very different events wear this shape, and conflating them is how a control
      // becomes noise. If the agent cannot satisfy the floor AT ALL, the operator raised a
      // bar this declaration was never going to clear and every client would be refused
      // identically: that is configuration. If it CAN, then the proof exists and something
      // bound without presenting it, which is exactly the impersonation the floor is for.
      const blocked = this.floorBlocks(agent);
      return this.refuse(agent.id, {
        kind: "below-minimum-tier",
        origin: blocked === null ? "unproven-claim" : "operator-configuration",
        // Front-loaded, because this string becomes X-Agentwall-Block-Reason and the proxy
        // TRUNCATES that header. Measured: the config-detail-first version lost the sentence
        // explaining why a process name is not proof, which is the only part that tells a
        // developer with a broken agent what actually happened. What bound, what refused it,
        // and why come first; the remediation and the config detail come after.
        reason:
          `agent "${agent.id}" bound on ${matchedOn}, which fleet.minimumMatchTier ` +
          `"${this.minimumMatchTier}" refuses` +
          (matchedOn === "comm" ? "; a process name is chosen by the process, so anything here can claim it" : "") +
          (blocked === null
            ? `. A credential for this agent exists and was not presented.`
            : `. This agent ${blocked} The refusal is caused by that configuration, not by the client.`),
      });
    }
    return {
      id: agent.id,
      label: agent.label,
      matchedOn,
      declared: true,
      agent,
      refusal: null,
      credential,
    };
  }

  /**
   * A claim that was made and rejected.
   *
   * The id is the agent the claim was ABOUT, so the chain says which agent was refused rather
   * than filing the row under "unattributed" where nobody looking for that agent would find
   * it. `declared` stays false because nothing was bound: no per-agent allowlist applies and
   * no budget is charged.
   */
  private refuse(agentId: string, refusal: AgentRefusal): ResolvedAgent {
    const agent = this.byId.get(agentId) ?? null;
    return {
      id: agentId,
      label: agent?.label ?? agentId,
      matchedOn: "none",
      declared: false,
      agent: null,
      refusal,
      credential: null,
    };
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
