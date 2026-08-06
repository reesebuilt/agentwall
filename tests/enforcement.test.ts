import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { request as httpRequest } from "http";
import { connect as netConnect, createServer as createNetServer, Socket } from "net";
import type { AddressInfo, Server as NetServer } from "net";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { loadConfig } from "../src/config";
import type { AgentwallConfig } from "../src/config";
import { PolicyEngine } from "../src/policy/engine";
import { createForwardProxy } from "../src/proxy/forward-proxy";
import type { ProxyRecord } from "../src/proxy/forward-proxy";
import { decideEgress, setEgressAllowlist } from "../src/runtime/enforcement";
import type { EgressAttempt } from "../src/runtime/enforcement";
import { engageLockdown, resetLockdown } from "../src/runtime/lockdown";
import type { PolicyRule } from "../src/types";

/**
 * Egress enforcement, end to end.
 *
 * The mode tests run against a real PolicyEngine rather than a stub, because the property
 * that matters is not "decideEgress calls evaluate" — it is that guarded reads the engine's
 * answer correctly. The engine's default decision is `deny`, so a guarded implementation
 * that keyed on the returned decision instead of on whether any rule matched would turn
 * every unmatched destination into a block and silently become strict mode. Only the real
 * engine's real default catches that.
 *
 * The proxy tests drive actual sockets. A denied CONNECT that still opens the tunnel is a
 * complete bypass that reads perfectly at the unit level, so the only useful assertion is
 * against a listener that would have noticed.
 */

const PRIVATE_TARGET: EgressAttempt = { host: "10.1.2.3", port: 443, scheme: "https", method: "CONNECT" };
const UNMATCHED_TARGET: EgressAttempt = { host: "api.example.com", port: 443, scheme: "https", method: "CONNECT" };

describe("enforcement modes", () => {
  const engine = new PolicyEngine();

  beforeEach(() => {
    resetLockdown();
    setEgressAllowlist([]);
  });

  afterEach(() => {
    resetLockdown();
    setEgressAllowlist([]);
  });

  it("allows in monitor mode what guarded and strict would both deny, and says so", () => {
    const verdict = decideEgress(PRIVATE_TARGET, "monitor", engine);

    expect(verdict.decision).toBe("allow");
    expect(verdict.mode).toBe("monitor");
    // The projections are the whole point: an operator has to be able to read a monitor
    // ledger and know what switching would break, without switching to find out.
    expect(verdict.reasons).toContain("monitor: egress recorded, not gated");
    expect(
      verdict.reasons.some(
        (reason) =>
          reason.startsWith("monitor: guarded mode would deny") &&
          reason.includes("private or local network address")
      )
    ).toBe(true);
    expect(verdict.reasons.some((reason) => reason.startsWith("monitor: strict mode would deny"))).toBe(true);
    expect(verdict.matchedRules).toContain("net:block-ssrf-private");
    expect(verdict.riskLevel).toBe("critical");
  });

  it("projects the exact difference between guarded and strict for the same destination", () => {
    const verdict = decideEgress(UNMATCHED_TARGET, "monitor", engine);

    expect(verdict.decision).toBe("allow");
    expect(verdict.reasons).toContain("monitor: guarded mode would allow");
    expect(
      verdict.reasons.some(
        (reason) =>
          reason.startsWith("monitor: strict mode would deny") &&
          reason.includes("api.example.com is not in the egress allowlist")
      )
    ).toBe(true);
  });

  it("projects two allows once the destination is on the allowlist", () => {
    setEgressAllowlist(["api.example.com"]);
    const verdict = decideEgress(UNMATCHED_TARGET, "monitor", engine);

    expect(verdict.reasons).toContain("monitor: guarded mode would allow");
    expect(verdict.reasons).toContain("monitor: strict mode would allow");
    expect(verdict.matchedRules).toEqual([]);
  });

  it("denies a policy-denied destination in guarded mode", () => {
    const verdict = decideEgress(PRIVATE_TARGET, "guarded", engine);

    expect(verdict.decision).toBe("deny");
    expect(verdict.mode).toBe("guarded");
    expect(verdict.matchedRules).toContain("net:block-ssrf-private");
    expect(verdict.detectionIds).toContain("det.net.ssrf.private");
    expect(verdict.riskLevel).toBe("critical");
  });

  it("allows an unmatched destination in guarded mode despite the engine defaulting to deny", () => {
    expect(engine.evaluate({
      agentId: "probe",
      plane: "network",
      action: "egress:https",
      payload: { url: "https://api.example.com:443" },
      flow: { direction: "egress" },
    }).decision).toBe("deny");

    const verdict = decideEgress(UNMATCHED_TARGET, "guarded", engine);

    expect(verdict.decision).toBe("allow");
    expect(verdict.matchedRules).toEqual([]);
    // Not the engine's "high": every egress context is a high-risk flow by construction, so
    // reporting that verbatim would stamp a finding on every ordinary API call.
    expect(verdict.riskLevel).toBe("low");
    expect(verdict.reasons).toEqual(["no rule matched api.example.com:443"]);
  });

  it("denies a host outside the allowlist in strict mode", () => {
    const verdict = decideEgress(UNMATCHED_TARGET, "strict", engine);

    expect(verdict.decision).toBe("deny");
    expect(verdict.mode).toBe("strict");
    expect(verdict.matchedRules).toContain("net:deny-egress-not-allowlisted");
    expect(verdict.detectionIds).toContain("det.net.egress.blocked");
    expect(verdict.riskLevel).toBe("high");
  });

  it("allows an allowlisted host in strict mode, matching case-insensitively", () => {
    setEgressAllowlist(["API.Example.COM"]);
    const verdict = decideEgress(UNMATCHED_TARGET, "strict", engine);

    expect(verdict.decision).toBe("allow");
    expect(verdict.matchedRules).toEqual([]);
  });

  it("still denies an allowlisted host that a rule denies", () => {
    setEgressAllowlist(["10.1.2.3"]);
    const verdict = decideEgress(PRIVATE_TARGET, "strict", engine);

    expect(verdict.decision).toBe("deny");
    expect(verdict.matchedRules).toContain("net:block-ssrf-private");
    expect(verdict.matchedRules).not.toContain("net:deny-egress-not-allowlisted");
  });

  it("denies in strict mode even when the rule set no longer carries the allowlist rule", () => {
    // The gate must not depend on its own rule being present: an operator who replaced the
    // rule set would otherwise be running guarded mode under a strict label.
    const emptyRuleSet = new PolicyEngine([], "allow");
    const verdict = decideEgress(UNMATCHED_TARGET, "strict", emptyRuleSet);

    expect(verdict.decision).toBe("deny");
    expect(verdict.matchedRules).toContain("net:deny-egress-not-allowlisted");
    expect(verdict.detectionIds).toContain("det.net.egress.blocked");
  });

  it("allows and records a destination whose only matching rule asks for approval", () => {
    // A documented limit rather than an oversight: there is nothing to answer an approval
    // prompt on a TCP connect, so guarded enforces denials only.
    const approvalRule: PolicyRule = {
      id: "test:approve-egress",
      description: "Require approval for a specific test destination",
      plane: "network",
      match: (ctx) => ctx.metadata?.["host"] === "approve.example.com",
      decision: "approve",
      riskLevel: "high",
      reason: "test destination requires approval",
    };
    const verdict = decideEgress(
      { host: "approve.example.com", port: 443, scheme: "https" },
      "guarded",
      new PolicyEngine([approvalRule], "deny")
    );

    expect(verdict.decision).toBe("allow");
    expect(verdict.reasons).toContain("test destination requires approval");
    expect(
      verdict.reasons.some((reason) => reason.includes("not enforceable on a proxied connection"))
    ).toBe(true);
  });
});

describe("lockdown overrides the enforcement mode", () => {
  const engine = new PolicyEngine();

  beforeEach(() => {
    resetLockdown();
    // Allowlisted, so nothing but the stop itself can be responsible for the denial.
    setEgressAllowlist(["api.example.com"]);
  });

  afterEach(() => {
    resetLockdown();
    setEgressAllowlist([]);
  });

  for (const mode of ["monitor", "guarded", "strict"] as const) {
    it(`denies in ${mode} mode while the stop is engaged`, () => {
      engageLockdown("operator-cli", "incident 42");

      const verdict = decideEgress(UNMATCHED_TARGET, mode, engine);

      expect(verdict.decision).toBe("deny");
      expect(verdict.riskLevel).toBe("critical");
      // The mode is still reported truthfully. Monitor did not stop being monitor; it was
      // overridden, and the ledger has to show both facts.
      expect(verdict.mode).toBe(mode);
      expect(verdict.matchedRules).toContain("governance:lockdown");
      expect(verdict.detectionIds).toContain("det.governance.lockdown.active");
      expect(verdict.reasons[0]).toContain("operator-cli");
      expect(verdict.reasons[0]).toContain("incident 42");
    });
  }

  it("names every source holding the stop", () => {
    engageLockdown("operator-cli", "incident 42");
    engageLockdown("watchdog");

    const verdict = decideEgress(UNMATCHED_TARGET, "monitor", engine);

    expect(verdict.reasons[0]).toContain("operator-cli");
    expect(verdict.reasons[0]).toContain("watchdog");
  });

  it("allows again once every hold is released", () => {
    engageLockdown("operator-cli");
    resetLockdown();

    expect(decideEgress(UNMATCHED_TARGET, "monitor", engine).decision).toBe("allow");
  });
});

describe("forward proxy honours a denied verdict", () => {
  const servers: NetServer[] = [];
  const sockets: Socket[] = [];
  let records: ProxyRecord[] = [];
  let upstream: NetServer;
  let upstreamConnections: number;
  let upstreamPort: number;

  function track<T extends NetServer>(server: T): T {
    servers.push(server);
    return server;
  }

  // Executor form throughout: Promise.withResolvers reads better but is ES2024, and this
  // project compiles against lib ES2022. None of these helpers carry a timeout — a
  // response that never arrives fails through Jest's own deadline rather than a tuned
  // duration of ours that would eventually go stale.
  function listening(server: NetServer): Promise<number> {
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      if (server.listening) {
        resolve((server.address() as AddressInfo).port);
        return;
      }
      server.once("listening", () => resolve((server.address() as AddressInfo).port));
    });
  }

  /** Speak CONNECT to the proxy by hand and return everything it wrote back. */
  function connectThrough(proxyPort: number, authority: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let received = "";
      const socket = netConnect(proxyPort, "127.0.0.1", () => {
        socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
      });
      sockets.push(socket);
      socket.on("data", (chunk) => {
        received += chunk.toString();
        // The allow path leaves the tunnel open, so there is no close to wait for; the
        // status line is all this test needs and waiting for more would hang.
        if (received.includes("\r\n\r\n")) resolve(received);
      });
      socket.on("close", () => resolve(received));
      socket.on("error", reject);
    });
  }

  function get(proxyPort: number, url: string): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
    return new Promise((resolve, reject) => {
      // agent: false because Node's global agent keeps connections alive, which would
      // leave the proxy holding an open socket and stall server.close() in afterEach.
      const req = httpRequest({ host: "127.0.0.1", port: proxyPort, method: "GET", path: url, agent: false }, (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      });
      req.on("error", reject);
      req.end();
    });
  }

  beforeEach(async () => {
    records = [];
    upstreamConnections = 0;
    upstream = track(
      createNetServer((socket) => {
        upstreamConnections += 1;
        // Held open rather than destroyed on arrival. Tearing the upstream down under the
        // proxy would race the "200 Connection Established" it writes from its own connect
        // callback, and turn the allow-path control test into an intermittent failure.
        // afterEach destroys every socket before it closes any server.
        sockets.push(socket);
      })
    );
    upstream.listen(0, "127.0.0.1");
    upstreamPort = await listening(upstream);
  });

  afterEach(async () => {
    for (const socket of sockets.splice(0)) socket.destroy();
    await Promise.all(
      servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))
    );
  });

  it("returns 403 with the block reason on a denied plain HTTP request", async () => {
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: () => ({
          decision: "deny",
          reasons: ["blocked.example is not in the egress allowlist"],
          matchedRules: ["net:deny-egress-not-allowlisted"],
          riskLevel: "high",
        }),
        record: (record) => records.push(record),
        onError: () => {},
      })
    );
    const proxyPort = await listening(proxy);

    const response = await get(proxyPort, "http://blocked.example/data");

    expect(response.status).toBe(403);
    expect(response.headers["x-agentwall-block-reason"]).toBe("blocked.example is not in the egress allowlist");
    expect(response.body).toContain("destination not allowed");
    expect(records).toHaveLength(1);
    expect(records[0]?.decision).toBe("deny");
    expect(records[0]?.matchedRules).toEqual(["net:deny-egress-not-allowlisted"]);
    expect(records[0]?.reasons).toEqual(["blocked.example is not in the egress allowlist"]);
  });

  it("cannot be made to inject headers through the block reason", async () => {
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: () => ({ decision: "deny", reasons: ["blocked\r\nX-Injected: yes"] }),
        record: (record) => records.push(record),
        onError: () => {},
      })
    );
    const proxyPort = await listening(proxy);

    const response = await get(proxyPort, "http://blocked.example/data");

    expect(response.status).toBe(403);
    expect(response.headers["x-injected"]).toBeUndefined();
    expect(response.headers["x-agentwall-block-reason"]).toBe("blocked X-Injected: yes");
  });

  it("returns 403 to a denied CONNECT without opening the upstream socket", async () => {
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: () => ({
          decision: "deny",
          reasons: ["lockdown active (sources: operator-cli)"],
          matchedRules: ["governance:lockdown"],
          riskLevel: "critical",
        }),
        record: (record) => records.push(record),
        onError: () => {},
      })
    );
    const proxyPort = await listening(proxy);

    const response = await connectThrough(proxyPort, `127.0.0.1:${upstreamPort}`);

    expect(response).toContain("HTTP/1.1 403 Forbidden");
    expect(response).toContain("X-Agentwall-Block-Reason: lockdown active (sources: operator-cli)");
    expect(response).not.toContain("200 Connection Established");
    // The assertion this test exists for: the destination never saw a handshake.
    expect(upstreamConnections).toBe(0);
    expect(records).toHaveLength(1);
    expect(records[0]?.decision).toBe("deny");
  });

  it("opens the upstream socket when the same CONNECT is allowed", async () => {
    // The control for the test above: proves the recording listener would have noticed.
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: () => "allow",
        record: (record) => records.push(record),
        onError: () => {},
      })
    );
    const proxyPort = await listening(proxy);
    // Registered before the CONNECT, and awaited after it: the counter is incremented by a
    // handler registered ahead of this one, so once this resolves the count is settled.
    // Comparing the counter straight after the 200 would race the accept.
    const observed = new Promise<void>((resolve) => upstream.once("connection", () => resolve()));

    const response = await connectThrough(proxyPort, `127.0.0.1:${upstreamPort}`);
    await observed;

    expect(response).toContain("200 Connection Established");
    expect(upstreamConnections).toBe(1);
  });

  it("cannot be made to forge a success line through the CONNECT block reason", async () => {
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: () => ({
          decision: "deny",
          reasons: ["blocked\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n"],
        }),
        record: (record) => records.push(record),
        onError: () => {},
      })
    );
    const proxyPort = await listening(proxy);

    const response = await connectThrough(proxyPort, `127.0.0.1:${upstreamPort}`);

    // Structural, not substring: the sanitiser flattens the injected CRLFs to spaces, so the
    // words "200 Connection Established" legitimately survive INSIDE the header value. What
    // must not survive is a second message. Exactly one header terminator, at the very end,
    // means the client received one 403 and nothing after it.
    expect(response.startsWith("HTTP/1.1 403 Forbidden\r\n")).toBe(true);
    expect(response.indexOf("\r\n\r\n")).toBe(response.length - 4);
    expect(response).not.toContain("\r\nHTTP/1.1 200");
    expect(response).toContain(
      "X-Agentwall-Block-Reason: blocked HTTP/1.1 200 Connection Established\r\n"
    );
    expect(upstreamConnections).toBe(0);
  });
});

describe("enforcement configuration", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentwall-enforcement-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads a config file with no enforcement section and yields monitor", () => {
    const file = join(dir, "config.yaml");
    writeFileSync(file, "port: 3100\nhost: 127.0.0.1\nlogLevel: silent\n");

    const config = loadConfig(file);

    expect(config.enforcement?.mode).toBe("monitor");
    expect(config.port).toBe(3100);
    // Nothing else moved: adding the section must not have disturbed an existing default.
    expect(config.egress.defaultDeny).toBe(true);
    expect(config.policy.defaultDecision).toBe("deny");
  });

  it("accepts a config object written before enforcement existed", () => {
    // Compilation is the assertion. `enforcement` is optional precisely so that every
    // AgentwallConfig literal already in the codebase keeps type-checking untouched.
    const legacy: AgentwallConfig = {
      port: 3000,
      host: "127.0.0.1",
      logLevel: "silent",
      approval: { mode: "auto", timeoutMs: 1000 },
      policy: { defaultDecision: "deny" },
      dlp: { enabled: true, redactSecrets: true },
      egress: {
        enabled: true,
        defaultDeny: true,
        allowPrivateRanges: false,
        allowedHosts: [],
        allowedSchemes: ["https"],
        allowedPorts: [443],
      },
      manifestIntegrity: { enabled: true },
      watchdog: { enabled: true, staleAfterMs: 15000, timeoutMs: 30000, killSwitchMode: "deny_all" },
    };

    expect(legacy.enforcement).toBeUndefined();
  });

  it("keeps an explicitly configured mode", () => {
    const file = join(dir, "config.yaml");
    writeFileSync(file, "enforcement:\n  mode: strict\n");

    expect(loadConfig(file).enforcement?.mode).toBe("strict");
  });

  it("refuses to load an unrecognised mode, naming the value, the file, and the valid set", () => {
    // A typo must never resolve silently. Downgrading it to monitor leaves an operator
    // believing they are enforcing; upgrading it to strict is an outage they did not ask
    // for. Refusing to start is the only outcome that cannot mislead.
    const file = join(dir, "config.yaml");
    writeFileSync(file, "enforcement:\n  mode: strct\n");

    expect(() => loadConfig(file)).toThrow(/invalid enforcement\.mode "strct"/);
    expect(() => loadConfig(file)).toThrow(new RegExp(file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    expect(() => loadConfig(file)).toThrow(/"monitor", "guarded", and "strict"/);
  });
});
