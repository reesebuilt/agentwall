import { describe, expect, it } from "@jest/globals";
import {
  AGENT_PROFILES,
  captureGrade,
  findProfile,
  interceptionGrade,
  profileGrade,
  profileIds,
} from "../src/onboard/profiles";

/**
 * The profile registry's contract is honesty, so that is what these tests defend.
 *
 * Every one of them fails on a plausible and specific bug. The dangerous edit to this data is
 * not a typo, it is someone adding a runtime they did not measure and leaving the grade at
 * "verified" because that is what the neighbouring entry says. A profile naming the wrong
 * environment variable produces an operator who believes traffic is governed while it goes
 * straight out, which is the exact failure the whole onboarding slice exists to prevent.
 */

describe("the shipped profile set", () => {
  it("ships exactly the six profiles the integration plan calls for", () => {
    expect(profileIds()).toEqual(["claude-code", "codex", "openclaw", "hermes-agent", "pi-agent", "generic"]);
  });

  it("returns undefined for an unknown profile rather than falling back to generic", () => {
    // A fallback here would silently hand someone the unverified generic environment while
    // they believed they had asked for their actual runtime.
    expect(findProfile("claude-code-v2")).toBeUndefined();
  });
});

describe("every claim carries the evidence behind it", () => {
  it.each(AGENT_PROFILES.map((profile) => [profile.id, profile] as const))(
    "%s states how its proxy behaviour was established",
    (_id, profile) => {
      expect(profile.proxyEnv.evidence.length).toBeGreaterThan(80);
      expect(profile.proxyEnv.honoured.length).toBeGreaterThan(0);
    }
  );

  it.each(AGENT_PROFILES.map((profile) => [profile.id, profile] as const))(
    "%s states how each CA claim was established, and names its limits",
    (_id, profile) => {
      expect(profile.caTrust.length).toBeGreaterThan(0);
      for (const fact of profile.caTrust) expect(fact.evidence.length).toBeGreaterThan(80);
      expect(profile.limits.length).toBeGreaterThan(0);
    }
  );

  it("never claims a version was checked for a profile graded unverified, or the reverse", () => {
    for (const profile of AGENT_PROFILES) {
      if (profile.proxyEnv.grade === "verified") {
        // A verified proxy claim without a version string means nobody can re-run it.
        expect(profile.verifiedAgainst).not.toBeNull();
      }
      if (profile.verifiedAgainst === null) {
        expect(profile.proxyEnv.grade).not.toBe("verified");
      }
    }
  });
});

describe("a variable is never both honoured and ignored", () => {
  // Claude Code honours NO_PROXY and ignores no_proxy, which is a real measured distinction.
  // Listing the same spelling in both lists would mean the renderer emits a variable the data
  // also says does nothing.
  it.each(AGENT_PROFILES.map((profile) => [profile.id, profile] as const))("%s", (_id, profile) => {
    for (const ignored of profile.proxyEnv.ignored) {
      expect(profile.proxyEnv.honoured).not.toContain(ignored);
    }
  });

  it("records the measured Claude Code case distinction rather than assuming case folding", () => {
    const claude = findProfile("claude-code");
    expect(claude?.proxyEnv.honoured).toContain("NO_PROXY");
    expect(claude?.proxyEnv.ignored).toContain("no_proxy");
  });
});

describe("grades are derived from the facts, never asserted over them", () => {
  it("reports the weakest field as the overall grade", () => {
    // Codex is the case that motivated per-field grading: its capture is measured on the wire
    // and its CA store is completely unknown. Rolling those together would either advertise an
    // untested trust store as verified or bury a genuinely strong capture result.
    const codex = findProfile("codex");
    expect(codex).toBeDefined();
    expect(captureGrade(codex!)).toBe("verified");
    expect(interceptionGrade(codex!)).toBe("unverified");
    expect(profileGrade(codex!)).toBe("unverified");
  });

  it("downgrades a profile the moment any single fact is unproven", () => {
    const verified = findProfile("claude-code")!;
    expect(captureGrade(verified)).toBe("verified");
    // Its CA claim is inherited from the Node/Bun measurement rather than observed through
    // Claude Code, so the profile as a whole must not read as fully verified.
    expect(profileGrade(verified)).toBe("partial");
  });

  it("grades the generic profile unverified, because it is a checklist and not a measurement", () => {
    const generic = findProfile("generic")!;
    expect(profileGrade(generic)).toBe("unverified");
    expect(generic.verifiedAgainst).toBeNull();
    expect(generic.starterHosts).toEqual([]);
  });

  it("never lets profileGrade exceed the weakest underlying grade", () => {
    const order = { unverified: 0, partial: 1, verified: 2 } as const;
    for (const profile of AGENT_PROFILES) {
      const weakest = Math.min(
        order[profile.proxyEnv.grade],
        ...profile.caTrust.map((fact) => order[fact.semantics === "unknown" ? "unverified" : fact.grade])
      );
      expect(order[profileGrade(profile)]).toBeLessThanOrEqual(weakest);
    }
  });
});

describe("the CA semantics that break an agent if reported backwards", () => {
  it("records REQUESTS_CA_BUNDLE as a replacement, not an addition", () => {
    // Measured: pointing it at a bare CA made https://example.com fail CERTIFICATE_VERIFY_FAILED.
    // If this ever flips to "additive" the renderer stops emitting the bundle-building step and
    // the emitted snippet takes the agent off the public internet.
    const hermes = findProfile("hermes-agent")!;
    const fact = hermes.caTrust.find((entry) => entry.variable === "REQUESTS_CA_BUNDLE");
    expect(fact?.semantics).toBe("replacement");
  });

  it("records SSL_CERT_FILE as ignored by python requests but honoured by Bun", () => {
    // The same variable name, opposite behaviour, both measured. This divergence is the reason
    // profiles exist instead of one shared environment template.
    const hermes = findProfile("hermes-agent")!;
    const pi = findProfile("pi-agent")!;
    expect(hermes.caTrust.find((f) => f.variable === "SSL_CERT_FILE")?.semantics).toBe("ignored");
    expect(pi.caTrust.find((f) => f.variable === "SSL_CERT_FILE")?.semantics).toBe("additive");
  });

  it("refuses to name a CA variable for Codex, whose TLS stack was never tested", () => {
    // Codex egress is a native binary. Inheriting NODE_EXTRA_CA_CERTS from the fact that it
    // installs via npm would be a guess dressed as a measurement.
    const codex = findProfile("codex")!;
    expect(codex.caTrust.every((fact) => fact.semantics === "unknown")).toBe(true);
  });
});
