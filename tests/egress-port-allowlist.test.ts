import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { PolicyEngine } from "../src/policy/engine";
import { decideEgress, setEgressPolicy } from "../src/runtime/enforcement";
import type { EgressAttempt } from "../src/runtime/enforcement";
import { resetLockdown } from "../src/runtime/lockdown";

/**
 * `egress.allowedPorts` has to bind on the proxy path.
 *
 * It did not. The key was configurable, shipped defaulted to `[443]`, and was enforced by the
 * `/evaluate` inspector — but `decideEgress` gated on the host alone, so strict mode reached
 * any port on an allowlisted host and wrote it into the chain as an ordinary allow. Confirmed
 * live before the fix: with `allowedHosts: [example.com]` and `allowedPorts: [443]`, a request
 * carrying `Host: example.com:80` was opened, returned 200 from the internet, and was recorded
 * `decision: allow` with no matched rules.
 *
 * That is the worst shape a security control can take. A missing feature is visible; a key
 * that reads as a control and enforces nothing means an operator writes it, believes the port
 * is closed, and stops looking. An agent on a host allowlisted for HTTPS reaches SSH, Postgres,
 * or an admin port on that same host, and every one of those connections is logged as normal.
 */

const HOST = "api.example.com";
const engine = new PolicyEngine();

function attempt(port: number, scheme: "http" | "https" = "https"): EgressAttempt {
  return { host: HOST, port, scheme, method: "CONNECT" };
}

describe("strict mode gates the port, not just the host", () => {
  beforeEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: [HOST], ports: [443] });
  });

  afterEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: [], ports: [] });
  });

  it("denies a non-allowlisted port on an allowlisted host", () => {
    // The exact bypass, as reproduced against the running proxy.
    const verdict = decideEgress(attempt(22), "strict", engine);

    expect(verdict.decision).toBe("deny");
    expect(verdict.matchedRules).toContain("net:deny-egress-port-not-allowlisted");
    expect(verdict.detectionIds).toContain("det.net.egress.port_blocked");
    expect(verdict.reasons.some((r) => r.includes("port 22"))).toBe(true);
  });

  it("still allows the allowlisted port on the allowlisted host", () => {
    // The fix must not turn strict mode into deny-everything.
    const verdict = decideEgress(attempt(443), "strict", engine);
    expect(verdict.decision).toBe("allow");
  });

  it("names the port and the permitted set, so the ledger is actionable", () => {
    const verdict = decideEgress(attempt(5432), "strict", engine);
    const reason = verdict.reasons.find((r) => r.includes("port 5432"));
    expect(reason).toBeDefined();
    // Naming only the rejected port leaves the operator guessing what to write instead.
    expect(reason).toContain("443");
  });

  it("reports host and port separately when both are wrong", () => {
    // Fixing one and rediscovering the other on the next attempt teaches the allowlist one
    // painful round-trip at a time.
    const verdict = decideEgress({ host: "other.example.com", port: 22, scheme: "https" }, "strict", engine);

    expect(verdict.decision).toBe("deny");
    expect(verdict.matchedRules).toEqual(
      expect.arrayContaining(["net:deny-egress-not-allowlisted", "net:deny-egress-port-not-allowlisted"])
    );
    expect(verdict.reasons.some((r) => r.includes("other.example.com is not in the egress allowlist"))).toBe(true);
    expect(verdict.reasons.some((r) => r.includes("port 22"))).toBe(true);
  });

  it("treats an empty port allowlist as permitting nothing", () => {
    // Empty-means-everything would turn the strictest mode into the most permissive one at
    // exactly the moment an operator misconfigures it.
    setEgressPolicy({ hosts: [HOST], ports: [] });
    expect(decideEgress(attempt(443), "strict", engine).decision).toBe("deny");
  });

  it("ignores structurally impossible ports in the configured list", () => {
    setEgressPolicy({ hosts: [HOST], ports: [0, -1, 70000, 443] });
    expect(decideEgress(attempt(443), "strict", engine).decision).toBe("allow");
    expect(decideEgress(attempt(0), "strict", engine).decision).toBe("deny");
    expect(decideEgress(attempt(70000), "strict", engine).decision).toBe("deny");
  });
});

describe("port gating is a strict-mode control", () => {
  beforeEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: [HOST], ports: [443] });
  });

  afterEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: [], ports: [] });
  });

  it("does not block the port in guarded mode", () => {
    // Guarded enforces matched deny rules and allows the unmatched; the allowlist pair is the
    // strict-mode control, exactly as the host half already behaves. Documented, not implied.
    expect(decideEgress(attempt(22), "guarded", engine).decision).toBe("allow");
  });

  it("allows in monitor mode but projects the strict denial with the port named", () => {
    // Monitor exists so an operator builds the allowlist by reading the ledger. A projection
    // that omitted the port would send them to add a host that is already allowlisted.
    const verdict = decideEgress(attempt(22), "monitor", engine);

    expect(verdict.decision).toBe("allow");
    expect(
      verdict.reasons.some((r) => r.startsWith("monitor: strict mode would deny") && r.includes("port 22"))
    ).toBe(true);
  });
});
