import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createHash } from "crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  CredentialStore,
  MAX_OVERLAP_SECONDS,
  StaticCredentialSource,
  credentialState,
  formatDuration,
  mintCredential,
  parseDurationSeconds,
} from "../src/fleet/credentials";
import type { StoredCredential } from "../src/fleet/credentials";
import { AgentRegistry, FleetConfigSchema } from "../src/fleet/registry";
import { AgentBudgetLedger } from "../src/fleet/budget";
import { PolicyEngine } from "../src/policy/engine";
import { decideEgress, setEgressPolicy, setFleet } from "../src/runtime/enforcement";
import { resetLockdown } from "../src/runtime/lockdown";

/**
 * The credential lifecycle's own contracts, at the level the integration suite cannot reach
 * cheaply: clock boundaries, malformed stores, and the boot refusals.
 *
 * The behaviour that matters most (a running proxy actually refusing a revoked credential) is
 * measured in tests/fleet-credential-lifecycle.integration.test.ts against a real server. What
 * is here is the set of edges that would need a contrived deployment to reach: a corrupted
 * store, a timestamp that will not parse, a credential issued to an agent that was later
 * deleted from config.
 */

const digestOf = (secret: string): string => createHash("sha256").update(secret, "utf8").digest("hex");

function fleet(section: Record<string, unknown>) {
  return FleetConfigSchema.parse(section);
}

function credential(overrides: Partial<StoredCredential> & { agentId: string; digest: string }): StoredCredential {
  return {
    credentialId: `cred-${overrides.agentId}`,
    issuedAt: new Date(0).toISOString(),
    expiresAt: null,
    revokedAt: null,
    revokedReason: null,
    ...overrides,
  };
}

describe("minting", () => {
  it("puts the agent id in the secret so the proxy-URL and Bearer forms hash alike", () => {
    const minted = mintCredential("scraper");
    // A client given `http://<secret>@proxy:3128` sends Basic base64("scraper:<token>"), and
    // parseProxyCredential hands the registry that decoded string whole. A bare token would
    // work over Bearer and bind nothing over the URL, which is the form most deployments use.
    expect(minted.secret.startsWith("scraper:")).toBe(true);
    expect(minted.digest).toBe(digestOf(minted.secret));
    // 256 bits of CSPRNG behind it, which is why an unsalted sha256 is the right primitive
    // here and would be the wrong one for a password.
    expect(minted.secret.slice("scraper:".length)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses an agent id that cannot survive a proxy URL", () => {
    // A colon would make the Basic decode ambiguous; a slash or an @ would break the URL.
    expect(() => mintCredential("team:scraper")).toThrow(/cannot appear in a credential/);
    expect(() => mintCredential("a/b")).toThrow(/cannot appear in a credential/);
  });

  it("never mints the same secret twice", () => {
    expect(mintCredential("x").secret).not.toBe(mintCredential("x").secret);
  });
});

describe("durations", () => {
  it("reads every unit and a bare count of seconds", () => {
    expect(parseDurationSeconds("90")).toBe(90);
    expect(parseDurationSeconds("90s")).toBe(90);
    expect(parseDurationSeconds("15m")).toBe(900);
    expect(parseDurationSeconds("2h")).toBe(7200);
    expect(parseDurationSeconds("1d")).toBe(86400);
  });

  it("refuses anything it would have to guess at", () => {
    expect(() => parseDurationSeconds("15 minutes")).toThrow(/cannot read/);
    expect(() => parseDurationSeconds("-5m")).toThrow(/cannot read/);
    expect(() => parseDurationSeconds("")).toThrow(/cannot read/);
  });

  it("carries the remainder rather than rounding a window into a lie", () => {
    // 90 seconds printed as "2m" would overstate a security window by a third, and the
    // operator reading it is the one deciding whether there is time to redeploy.
    expect(formatDuration(90)).toBe("1m 30s");
    expect(formatDuration(900)).toBe("15m");
    expect(formatDuration(MAX_OVERLAP_SECONDS)).toBe("1d");
  });
});

describe("credential state at the clock boundary", () => {
  const now = Date.parse("2026-08-06T12:00:00.000Z");

  it("is active while no expiry is set", () => {
    expect(credentialState(credential({ agentId: "a", digest: "0".repeat(64) }), now)).toBe("active");
  });

  it("is overlap up to the instant it closes, and expired from then on", () => {
    const closing = credential({ agentId: "a", digest: "0".repeat(64), expiresAt: new Date(now + 1).toISOString() });
    expect(credentialState(closing, now)).toBe("overlap");
    expect(credentialState(closing, now + 1)).toBe("expired");
  });

  it("treats an unparseable expiry as closed rather than open", () => {
    // Fails in the direction an operator can see. The invisible failure is a rotation window
    // that silently never ends.
    const broken = credential({ agentId: "a", digest: "0".repeat(64), expiresAt: "not-a-date" });
    expect(credentialState(broken, now)).toBe("expired");
  });

  it("reports revoked ahead of any expiry", () => {
    const both = credential({
      agentId: "a",
      digest: "0".repeat(64),
      expiresAt: new Date(now + 60_000).toISOString(),
      revokedAt: new Date(now).toISOString(),
    });
    expect(credentialState(both, now)).toBe("revoked");
  });
});

describe("the store on disk", () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentwall-credstore-"));
    path = join(dir, "fleet-credentials.json");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("starts empty when nothing has been issued, without inventing an error", () => {
    const store = new CredentialStore(path);
    expect(store.absent).toBe(true);
    expect(store.error).toBeNull();
    expect(store.list()).toHaveLength(0);
  });

  it("writes the digest, never the secret, at mode 0600", () => {
    const store = new CredentialStore(path);
    const { secret } = store.issue("scraper");
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain(secret);
    expect(raw).toContain(digestOf(secret));
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("refuses to issue beside an active credential and points at rotate", () => {
    const store = new CredentialStore(path);
    store.issue("scraper");
    // Minting a second active credential would silently orphan the one a live agent is
    // presenting right now. Replacing a working credential is rotation and has a window.
    expect(() => store.issue("scraper")).toThrow(/already has an active credential/);
    expect(() => store.issue("scraper")).toThrow(/fleet rotate --agent scraper/);
  });

  it("keeps both credentials matchable during an overlap and closes the old one on schedule", () => {
    const store = new CredentialStore(path);
    const first = store.issue("scraper");
    const rotated = store.rotate("scraper", 60);

    expect(store.lookup(Buffer.from(digestOf(first.secret), "hex"))?.state).toBe("overlap");
    expect(store.lookup(Buffer.from(digestOf(rotated.secret), "hex"))?.state).toBe("active");
    expect(Date.parse(rotated.previous.expiresAt ?? "")).toBeGreaterThan(Date.now());
  });

  it("treats a zero overlap as an immediate cutover rather than rejecting it", () => {
    // The legitimate case is a credential believed compromised. It is spelled out rather
    // than inferred, and it is not the default.
    const store = new CredentialStore(path);
    const first = store.issue("scraper");
    store.rotate("scraper", 0);
    expect(store.lookup(Buffer.from(digestOf(first.secret), "hex"))?.state).toBe("expired");
  });

  it("bounds the overlap, because two secrets that both work for a week are not a rotation", () => {
    const store = new CredentialStore(path);
    store.issue("scraper");
    expect(() => store.rotate("scraper", MAX_OVERLAP_SECONDS + 1)).toThrow(/exceeds the 1d maximum/);
    expect(() => store.rotate("scraper", -1)).toThrow(/cannot be negative/);
  });

  it("revokes one credential and leaves every other one alone", () => {
    const store = new CredentialStore(path);
    const scraper = store.issue("scraper");
    const wrapper = store.issue("wrapper");
    store.revoke(store.listFor("scraper")[0].credentialId, "laptop lost");

    expect(store.lookup(Buffer.from(digestOf(scraper.secret), "hex"))?.state).toBe("revoked");
    expect(store.lookup(Buffer.from(digestOf(wrapper.secret), "hex"))?.state).toBe("active");
  });

  it("keeps the revoked record rather than deleting it, so the refusal can name it", () => {
    const store = new CredentialStore(path);
    store.issue("scraper");
    const revoked = store.revoke(store.listFor("scraper")[0].credentialId, "laptop lost");
    expect(revoked.revokedReason).toBe("laptop lost");
    expect(store.listFor("scraper")).toHaveLength(1);
    expect(() => store.revoke(revoked.credentialId)).toThrow(/already revoked/);
  });

  it("keeps the last good records when the file becomes unparseable, and says so", () => {
    const store = new CredentialStore(path);
    const { secret } = store.issue("scraper");
    writeFileSync(path, "{ this is not json");
    store.reload();

    // Dropping every credential on a typo would turn a bad edit into a fleet-wide outage.
    // Enforcement continues on what was last parsed; the error is what doctor reports.
    expect(store.error).not.toBeNull();
    expect(store.lookup(Buffer.from(digestOf(secret), "hex"))?.state).toBe("active");
  });

  it("recovers without a restart once the file parses again", () => {
    const store = new CredentialStore(path);
    const { secret } = store.issue("scraper");
    const good = readFileSync(path, "utf8");
    writeFileSync(path, "{ broken");
    store.reload();
    expect(store.error).not.toBeNull();

    writeFileSync(path, good);
    store.reload();
    expect(store.error).toBeNull();
    expect(store.lookup(Buffer.from(digestOf(secret), "hex"))?.state).toBe("active");
  });

  it("keeps enforcing when the store file disappears, rather than dropping every identity", () => {
    const store = new CredentialStore(path);
    const { secret } = store.issue("scraper");
    rmSync(path);
    store.reload();

    // A deleted file or a shared mount that blips must not become a fleet-wide egress
    // outage. Under `minimumMatchTier: credential` with `unmatched: deny` that is exactly
    // what dropping the records would cause: every agent loses its identity at once.
    // Retention cannot grant anything either, because a revocation is a tombstone WRITTEN
    // into this file and never a deletion of it.
    expect(store.error?.message).toContain("has gone");
    expect(store.absent).toBe(false);
    expect(store.lookup(Buffer.from(digestOf(secret), "hex"))?.state).toBe("active");
  });

  it("reports an absent store as nothing-issued only when it was never there", () => {
    const fresh = new CredentialStore(join(dir, "never-written.json"));
    expect(fresh.absent).toBe(true);
    expect(fresh.error).toBeNull();
  });

  it("refuses to write over a store it could not read, instead of merging and clobbering it", () => {
    const store = new CredentialStore(path);
    store.issue("scraper");
    writeFileSync(path, "{ half a document");

    // Every write replaces the whole file. Merging into records that came from anywhere but
    // the current file would destroy whatever is in it, which for a credential store means
    // silently resurrecting or erasing access.
    expect(() => store.issue("wrapper")).toThrow(/Refusing to write/);
    expect(readFileSync(path, "utf8")).toBe("{ half a document");
  });

  it("refuses to write when the store vanished under it", () => {
    const store = new CredentialStore(path);
    store.issue("scraper");
    rmSync(path);
    // The reader keeps going; the writer stops. An operator who deleted the file did not ask
    // for the old digests to be written back out from another process's memory.
    expect(() => store.issue("wrapper")).toThrow(/Refusing to write/);
  });
});

describe("the registry, given issued credentials", () => {
  const active = mintCredential("scraper");
  const revoked = mintCredential("wrapper");

  const source = new StaticCredentialSource([
    credential({ agentId: "scraper", digest: active.digest, credentialId: "cred-live" }),
    credential({
      agentId: "wrapper",
      digest: revoked.digest,
      credentialId: "cred-dead",
      revokedAt: new Date(0).toISOString(),
      revokedReason: "laptop lost",
    }),
  ]);

  it("binds an issued credential at the credential tier", () => {
    const registry = new AgentRegistry(
      fleet({ agents: [{ id: "scraper", match: { credential: "issued" } }] }),
      source
    );
    const resolved = registry.resolve({ credential: active.secret });
    expect(resolved.declared).toBe(true);
    expect(resolved.matchedOn).toBe("credential");
    expect(resolved.credential?.credentialId).toBe("cred-live");
  });

  it("refuses a revoked credential instead of falling through to the process name", () => {
    // This is the whole point. `wrapper` also matches on comm, so a fall-through would mean a
    // revocation that anything can survive by keeping its process name.
    const registry = new AgentRegistry(
      fleet({ agents: [{ id: "wrapper", match: { comm: ["aw-wrapper"] } }] }),
      source
    );
    const resolved = registry.resolve({ credential: revoked.secret, comm: "aw-wrapper" });
    expect(resolved.declared).toBe(false);
    expect(resolved.refusal?.kind).toBe("credential-revoked");
    expect(resolved.refusal?.credentialId).toBe("cred-dead");
    expect(resolved.refusal?.reason).toContain("laptop lost");
  });

  it("refuses a credential issued to an agent this instance no longer declares", () => {
    const registry = new AgentRegistry(
      fleet({ agents: [{ id: "someone-else", match: { comm: ["aw-other"] } }] }),
      source
    );
    const resolved = registry.resolve({ credential: active.secret });
    expect(resolved.refusal?.kind).toBe("credential-orphaned");
  });

  it("ignores a credential nobody issued, exactly as before", () => {
    // An unknown secret is noise, not a claim. It falls through to the weaker signals, which
    // is what the registry did before a lifecycle existed.
    const registry = new AgentRegistry(
      fleet({ agents: [{ id: "scraper", match: { comm: ["aw-scraper"] } }] }),
      source
    );
    const resolved = registry.resolve({ credential: "never-issued", comm: "aw-scraper" });
    expect(resolved.declared).toBe(true);
    expect(resolved.matchedOn).toBe("comm");
    expect(resolved.refusal).toBeNull();
  });

  it("refuses two credential sources for one agent at construction", () => {
    // Precedence would be a rule nobody remembers under pressure: revoking the issued one and
    // finding the agent still working because a config line still matches is the worst
    // possible outcome of a quiet design decision.
    expect(
      () =>
        new AgentRegistry(
          fleet({ agents: [{ id: "scraper", match: { credential: `sha256:${"a".repeat(64)}` } }] }),
          source
        )
    ).toThrow(/declares match.credential in config AND has credentials issued/);
  });
});

describe("the fleet minimum binding tier", () => {
  const minted = mintCredential("scraper");
  const source = new StaticCredentialSource([
    credential({ agentId: "scraper", digest: minted.digest, credentialId: "cred-live" }),
  ]);

  const agents = [
    { id: "scraper", match: { credential: "issued" } },
    { id: "by-uid", match: { uid: 4242 } },
    { id: "by-comm", match: { comm: ["aw-comm"] } },
  ];

  it("accepts everything by default, which is exactly today's behaviour", () => {
    const registry = new AgentRegistry(fleet({ agents }), source);
    expect(registry.minimumMatchTier).toBe("any");
    expect(registry.resolve({ comm: "aw-comm" }).declared).toBe(true);
    expect(registry.resolve({ uid: 4242 }).declared).toBe(true);
  });

  it("refuses a comm-only binding at the uid floor and keeps uid and credential working", () => {
    const registry = new AgentRegistry(fleet({ minimumMatchTier: "uid", agents }), source);
    const byComm = registry.resolve({ comm: "aw-comm" });
    expect(byComm.declared).toBe(false);
    expect(byComm.refusal?.kind).toBe("below-minimum-tier");
    // Named, because the operator has to know a process name is self-declared to understand
    // why the floor exists at all.
    expect(byComm.refusal?.reason).toContain("chosen by the process");
    expect(byComm.refusal?.origin).toBe("operator-configuration");
    expect(registry.resolve({ uid: 4242 }).declared).toBe(true);
    expect(registry.resolve({ credential: minted.secret }).declared).toBe(true);
  });

  it("refuses everything but a presented secret at the credential floor", () => {
    const registry = new AgentRegistry(fleet({ minimumMatchTier: "credential", agents }), source);
    expect(registry.resolve({ uid: 4242 }).refusal?.kind).toBe("below-minimum-tier");
    expect(registry.resolve({ comm: "aw-comm" }).refusal?.kind).toBe("below-minimum-tier");
    expect(registry.resolve({ credential: minted.secret }).matchedOn).toBe("credential");
  });

  it("leaves a connection nobody claims to the unmatched posture rather than the floor", () => {
    // A floor judges how a CLAIM was proven. Nothing claimed this connection, so there is no
    // claim to judge and `unmatched` owns the outcome.
    const registry = new AgentRegistry(fleet({ minimumMatchTier: "credential", agents }), source);
    const stranger = registry.resolve({ comm: "aw-stranger", uid: 9999 });
    expect(stranger.declared).toBe(false);
    expect(stranger.refusal).toBeNull();
  });

  it("names the agents that can never bind rather than letting them fail silently", () => {
    const registry = new AgentRegistry(fleet({ minimumMatchTier: "credential", agents }), source);
    const blocked = registry.unbindable().map((entry) => entry.id);
    expect(blocked).toEqual(["by-uid", "by-comm"]);
    expect(registry.unbindable()[0].reason).toContain("fleet issue --agent by-uid");
  });

  it("names an agent that declares an issued credential it has never been given", () => {
    // The normal state between adding an agent and running `fleet issue`, and a silent one
    // without this: the config looks finished and the agent binds on nothing.
    const registry = new AgentRegistry(fleet({ agents: [{ id: "fresh", match: { credential: "issued" } }] }), null);
    expect(registry.unbindable()).toEqual([
      { id: "fresh", reason: `declares "credential: issued" and has none. Run "agentwall fleet issue --agent fresh".` },
    ]);
  });
});

describe("a refused identity, through the real egress decision", () => {
  const attempt = { host: "api.example.com", port: 443, scheme: "https", method: "CONNECT" };
  const engine = new PolicyEngine();
  const minted = mintCredential("scraper");
  const source = new StaticCredentialSource([
    credential({
      agentId: "scraper",
      digest: minted.digest,
      credentialId: "cred-dead",
      revokedAt: new Date(0).toISOString(),
      revokedReason: "laptop lost",
    }),
  ]);

  beforeEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: ["api.example.com"], ports: [443] });
  });

  afterEach(() => {
    resetLockdown();
    setFleet(null, null);
    setEgressPolicy({ hosts: [], ports: [] });
  });

  const withFleet = (section: Record<string, unknown>): void => {
    setFleet(new AgentRegistry(fleet(section), source), new AgentBudgetLedger());
  };

  it("denies a revoked credential even under the open posture", () => {
    // `unmatched: global` is the posture most deployments run. Revocation is an instruction,
    // not a posture, so it has to bite here too or an operator's revoke does nothing on the
    // majority of installs.
    withFleet({
      unmatched: "global",
      agents: [{ id: "scraper", match: { credential: "issued" }, egress: { allowedHosts: ["api.example.com"] } }],
    });

    const verdict = decideEgress({ ...attempt, credential: minted.secret }, "guarded", engine);
    expect(verdict.decision).toBe("deny");
    expect(verdict.matchedRules).toContain("fleet:deny-refused-agent-identity");
    expect(verdict.detectionIds).toContain("det.fleet.identity.refused");
    expect(verdict.reasons[0]).toContain("laptop lost");
    expect(verdict.agent.refusal?.kind).toBe("credential-revoked");
  });

  it("charges nothing to the budget for a refused connection", () => {
    withFleet({
      agents: [
        {
          id: "scraper",
          match: { credential: "issued" },
          egress: { allowedHosts: ["api.example.com"] },
          budget: { windowSeconds: 600, maxRequests: 1 },
        },
      ],
    });
    decideEgress({ ...attempt, credential: minted.secret }, "strict", engine);
    // A refusal is not an admission. Charging one would let a client's retry loop spend a
    // budget it was never allowed to use, and the counter an operator sizes against would
    // climb for traffic that never reached the network.
    expect(decideEgress({ ...attempt, credential: minted.secret }, "strict", engine).budget).toBeNull();
  });

  it("records but does not block in monitor, and says what the enforcing modes would do", () => {
    // Monitor gates nothing, including this. Stated as a limit rather than made an
    // exception: `fleet.unmatched: deny` follows the same rule, and an operator who has not
    // yet accepted enforcement risk should not get their first-ever block from a revoke.
    // The lockdown is the control that overrides monitor.
    withFleet({
      agents: [{ id: "scraper", match: { credential: "issued" }, egress: { allowedHosts: ["api.example.com"] } }],
    });

    const verdict = decideEgress({ ...attempt, credential: minted.secret }, "monitor", engine);
    expect(verdict.decision).toBe("allow");
    expect(verdict.reasons.join(" ")).toContain("guarded mode would deny");
    expect(verdict.reasons.join(" ")).toContain("laptop lost");
  });

  it("files a below-tier refusal the operator's own config caused as configuration, not as an intrusion", () => {
    withFleet({
      unmatched: "deny",
      minimumMatchTier: "credential",
      agents: [{ id: "by-comm", match: { comm: ["aw-comm"] }, egress: { allowedHosts: ["api.example.com"] } }],
    });

    const verdict = decideEgress({ ...attempt, comm: "aw-comm" }, "strict", engine);
    // Still refused, and the record still says why. What changed is that it is no longer
    // stamped "Valid Accounts, high": this agent cannot satisfy the floor at all, so every
    // client would be refused identically and there is nothing to investigate. Filing an
    // operator's own migration as an intrusion technique is how a control gets ignored.
    expect(verdict.decision).toBe("deny");
    expect(verdict.riskLevel).toBe("medium");
    expect(verdict.matchedRules).toContain("fleet:deny-unconfigured-agent-identity");
    expect(verdict.detectionIds).toContain("det.fleet.identity.unconfigured");
    expect(verdict.matchedRules).not.toContain("fleet:deny-refused-agent-identity");
    // Exactly one identity rule. `unmatched: deny` is also true of this connection.
    expect(verdict.matchedRules).not.toContain("fleet:deny-undeclared-agent");
    // And the reason still names the tier, the key, and why a process name is not proof.
    expect(verdict.reasons[0]).toContain("fleet.minimumMatchTier");
    expect(verdict.reasons[0]).toContain("chosen by the process");
  });

  it("files a below-tier refusal by an agent that HAS a credential as the alarm it is", () => {
    // The impersonation case: the proof exists for this agent and something bound on a
    // process name instead of presenting it. That is what the floor is for, and it is the
    // one below-tier refusal a person should look at.
    withFleet({
      minimumMatchTier: "credential",
      agents: [
        {
          id: "scraper",
          match: { credential: "issued", comm: ["aw-scraper"] },
          egress: { allowedHosts: ["api.example.com"] },
        },
      ],
    });

    const verdict = decideEgress({ ...attempt, comm: "aw-scraper" }, "strict", engine);
    expect(verdict.decision).toBe("deny");
    expect(verdict.riskLevel).toBe("high");
    expect(verdict.matchedRules).toContain("fleet:deny-refused-agent-identity");
    expect(verdict.reasons[0]).toContain("was not presented");
  });

  it("says out loud that a withdrawn credential cannot be told from a stolen one", () => {
    withFleet({
      agents: [{ id: "scraper", match: { credential: "issued" }, egress: { allowedHosts: ["api.example.com"] } }],
    });
    const verdict = decideEgress({ ...attempt, credential: minted.secret }, "strict", engine);
    // The INCONCLUSIVE outcome, stated rather than resolved by guessing. A deployment that
    // missed the offboarding and a secret in someone else's hands present identical bytes.
    expect(verdict.agent.refusal?.origin).toBe("indeterminate");
    expect(verdict.reasons.join(" ")).toContain("does not distinguish");
  });

  it("leaves an ordinary undeclared connection to the undeclared rule", () => {
    withFleet({
      unmatched: "deny",
      minimumMatchTier: "credential",
      agents: [{ id: "by-comm", match: { comm: ["aw-comm"] }, egress: { allowedHosts: ["api.example.com"] } }],
    });

    const verdict = decideEgress({ ...attempt, comm: "aw-stranger" }, "strict", engine);
    expect(verdict.matchedRules).toContain("fleet:deny-undeclared-agent");
    expect(verdict.matchedRules).not.toContain("fleet:deny-refused-agent-identity");
  });
});
