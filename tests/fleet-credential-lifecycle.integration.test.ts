import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { spawn, type ChildProcess } from "child_process";
import { createServer as createHttpServer, request as httpRequest, type Server } from "http";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type { AddressInfo } from "net";

/**
 * Credential lifecycle, measured against a real running proxy rather than a registry object.
 *
 * The four claims this change makes are all claims about a SYSTEM, not about a function:
 *
 *   1. An issued credential binds at the credential tier.
 *   2. During a rotation both secrets work; after the window the old one is refused, and the
 *      refusal is in the audit chain.
 *   3. A revoked credential is refused while its siblings keep working.
 *   4. With the fleet minimum tier at "credential", an agent matching only comm is refused
 *      and the record says why.
 *
 * Every one of those depends on the CLI writing a file, a separate long-running process
 * noticing, /proc attribution, the registry, the enforcement gates, the proxy, and the chain
 * writer all agreeing. A unit test over AgentRegistry would exercise one of those seven and
 * would have passed just as happily if the running proxy never re-read the store, which is
 * the single most likely way for this feature to be green and useless.
 *
 * So: the credentials are minted by running `src/cli.ts` as its own process, the server is
 * started as its own process from a config file, requests come from child processes with
 * chosen comms, and the assertions read the audit JSONL the server wrote.
 *
 * Wall-clock waits are real and deliberate. Rotation expiry is a clock fact and the store's
 * staleness bound is a clock fact; fake timers in this process cannot move either, because
 * both live in a different process.
 *
 * Linux-only, because /proc attribution is. Skipped elsewhere rather than asserting less.
 */

const LINUX = process.platform === "linux";
const describeLinux = LINUX ? describe : describe.skip;

/**
 * A destination NAME, because `net:block-ssrf-private` denies loopback outright and it is
 * right to. The name resolves to loopback for the server process only, through the same
 * resolver shim the per-agent governance suite uses.
 */
const HOST = "alpha.fleet.test";
const ADDRESS = "127.0.0.1";

const RESOLVER_SHIM = `
const dns = require("dns");
const MAP = ${JSON.stringify({ [HOST]: ADDRESS })};
const real = dns.lookup;
dns.lookup = function (hostname, options, callback) {
  const address = MAP[hostname];
  if (!address) return real.call(dns, hostname, options, callback);
  const cb = typeof options === "function" ? options : callback;
  const all = typeof options === "object" && options !== null && options.all === true;
  process.nextTick(() => cb(null, all ? [{ address, family: 4 }] : address, 4));
};
`;

/**
 * How long the rotation overlap runs in the test that watches it close.
 *
 * Long enough that two child-process requests comfortably fit inside it on a loaded box,
 * short enough that the suite is not waiting on a coffee break. The test measures the real
 * boundary rather than trusting it: it asserts inside the window, then waits past the
 * recorded expiry, then asserts outside it.
 */
const OVERLAP_SECONDS = 8;

/**
 * The store's staleness bound, from src/fleet/credentials.ts, plus slack.
 *
 * This is what "revocation takes effect without a restart" costs. It is asserted rather than
 * assumed: every post-change assertion below waits exactly this long and no longer, so a
 * regression that made the proxy cache the store forever fails here instead of in production.
 */
const STORE_PICKUP_MS = 1_500;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (err: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/**
 * A real delay, deliberately, and the one place in this file that needs defending.
 *
 * Fake timers cannot help here and would not make the test deterministic, they would make it
 * vacuous: the clock that decides whether a rotation overlap has closed belongs to the SERVER
 * process, and the file-staleness bound belongs to that process too. Advancing this process's
 * timers moves neither. Both waits below are computed from a value the system under test
 * reported (the recorded expiry instant, and the documented one-second store bound) rather
 * than tuned until the test passed, so a regression that lengthened either shows up as a
 * failure rather than being absorbed by slack.
 */
function sleep(ms: number): Promise<void> {
  const { promise, resolve } = deferred<void>();
  setTimeout(resolve, ms);
  return promise;
}

interface AuditRecord {
  agentId: string;
  action: string;
  decision: string;
  reasons: string[];
  matchedRules: string[];
  detections?: Array<{ id: string }>;
  metadata?: Record<string, string>;
}

/** How the client presents its secret. Both forms must hash to the same digest. */
type Presentation = "bearer" | "proxy-url";

/**
 * One request through the proxy, from a CHILD process with a chosen comm.
 *
 * A child rather than an in-process socket because comm attribution is under test here too:
 * the minimum-tier case turns entirely on the proxy resolving a client port to a pid and
 * reading that pid's comm.
 */
function requestAs(
  comm: string,
  proxyPort: number,
  target: string,
  credential?: string,
  presentation: Presentation = "bearer"
): Promise<{ status: number; blockReason: string | null }> {
  const auth =
    credential === undefined
      ? ""
      : presentation === "bearer"
        ? `headers["proxy-authorization"] = "Bearer " + ${JSON.stringify(credential)};`
        : // Exactly what an HTTP client does with proxy-URL userinfo: base64 of the whole
          // "user:pass" string, under the Basic scheme. The minted secret is "<agentId>:<token>"
          // precisely so this and the Bearer line above hash identically.
          `headers["proxy-authorization"] = "Basic " + Buffer.from(${JSON.stringify(credential)}).toString("base64");`;
  const script = `
    process.title = ${JSON.stringify(comm)};
    const http = require("http");
    const target = new URL(${JSON.stringify(target)});
    const headers = { host: target.host };
    ${auth}
    const req = http.request(
      { host: "127.0.0.1", port: ${proxyPort}, method: "GET", path: target.href, headers },
      (res) => {
        res.resume();
        res.on("end", () => {
          process.stdout.write(JSON.stringify({
            status: res.statusCode,
            blockReason: res.headers["x-agentwall-block-reason"] ?? null,
          }));
        });
      }
    );
    req.on("error", (err) => {
      process.stdout.write(JSON.stringify({ status: 0, blockReason: String(err.message) }));
    });
    req.end();
  `;
  const { promise, resolve, reject } = deferred<{ status: number; blockReason: string | null }>();
  const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (chunk) => (out += String(chunk)));
  child.on("error", reject);
  child.on("close", () => {
    try {
      resolve(JSON.parse(out) as { status: number; blockReason: string | null });
    } catch {
      reject(new Error(`child produced no verdict: ${JSON.stringify(out)}`));
    }
  });
  return promise;
}

describeLinux("fleet credential lifecycle, measured end to end", () => {
  let workdir: string;
  let configPath: string;
  let storePath: string;
  let auditPath: string;
  let server: ChildProcess;
  let proxyPort: number;
  let upstream: Server;
  let upstreamPort: number;

  /** agent id -> the secret its current credential presents. Only this process ever holds it. */
  const secrets: Record<string, string> = {};
  /** agent id -> its current credential id, for asserting what the chain names. */
  const credentialIds: Record<string, string> = {};

  const chain = (): AuditRecord[] =>
    readFileSync(auditPath, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AuditRecord);

  const egressFor = (agentId: string): AuditRecord[] =>
    chain().filter((record) => record.agentId === agentId && record.action.startsWith("egress:"));

  /**
   * Run the real CLI, in its own process, against the real config and store.
   *
   * Through ts-node rather than dist/, so the suite measures the source it was run against
   * and does not silently pass on a stale build.
   */
  const cli = (...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    const { promise, resolve, reject } = deferred<{ code: number; stdout: string; stderr: string }>();
    const child = spawn(process.execPath, ["-r", "ts-node/register", join(__dirname, "..", "src", "cli.ts"), ...args], {
      cwd: join(__dirname, ".."),
      env: { ...process.env, AGENTWALL_CONFIG: configPath, TS_NODE_TRANSPILE_ONLY: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += String(chunk)));
    child.stderr.on("data", (chunk) => (stderr += String(chunk)));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
    return promise;
  };

  const issue = async (agentId: string): Promise<void> => {
    const result = await cli("fleet", "issue", "--agent", agentId, "--json");
    if (result.code !== 0) throw new Error(`fleet issue ${agentId} failed: ${result.stderr}${result.stdout}`);
    const parsed = JSON.parse(result.stdout) as { secret: string; credentialId: string };
    secrets[agentId] = parsed.secret;
    credentialIds[agentId] = parsed.credentialId;
  };

  beforeAll(async () => {
    workdir = mkdtempSync(join(tmpdir(), "agentwall-credlife-"));
    auditPath = join(workdir, "audit.jsonl");
    configPath = join(workdir, "agentwall.config.yaml");
    storePath = join(workdir, "fleet-credentials.json");

    const listen = (): Promise<{ srv: Server; port: number }> => {
      const { promise, resolve } = deferred<{ srv: Server; port: number }>();
      const srv = createHttpServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
      });
      srv.listen(0, ADDRESS, () => resolve({ srv, port: (srv.address() as AddressInfo).port }));
      return promise;
    };
    const up = await listen();
    upstream = up.srv;
    upstreamPort = up.port;

    const grab = (): Promise<number> => {
      const { promise, resolve } = deferred<number>();
      const probe = createHttpServer();
      probe.listen(0, "127.0.0.1", () => {
        const port = (probe.address() as AddressInfo).port;
        probe.close(() => resolve(port));
      });
      return promise;
    };
    const apiPort = await grab();
    proxyPort = await grab();

    const agent = (id: string, match: string): string[] => [
      `    - id: ${id}`,
      `      match:`,
      `        ${match}`,
      `      egress:`,
      `        allowedHosts: ["${HOST}"]`,
      `        allowedPorts: [${upstreamPort}]`,
    ];

    writeFileSync(
      configPath,
      [
        `port: ${apiPort}`,
        `host: 127.0.0.1`,
        `logLevel: silent`,
        `enforcement:`,
        `  mode: strict`,
        `egress:`,
        `  enabled: true`,
        `  defaultDeny: true`,
        `  allowPrivateRanges: false`,
        `  allowedHosts: []`,
        `  allowedSchemes: ["http", "https"]`,
        `  allowedPorts: []`,
        `fleet:`,
        // The closed posture AND the identity floor together, which is the pair an
        // organisation running agents on hosts it does not individually audit actually sets.
        `  unmatched: deny`,
        `  minimumMatchTier: credential`,
        `  agents:`,
        // Binds by an issued credential and is never touched again, so the revocation test
        // has a sibling to prove it did not hit.
        ...agent("steady", `credential: issued`),
        // Rotated mid-run, with a window that closes while the suite watches.
        ...agent("rotating", `credential: issued`),
        // Revoked mid-run.
        ...agent("revocable", `credential: issued`),
        // Declared before it has a credential, then issued while the server runs, to measure
        // that issuance needs no restart either.
        ...agent("latecomer", `credential: issued`),
        // Bindable only by a process name, which the floor refuses. This is the agent an
        // organisation wants forbidden fleet-wide rather than host by host.
        ...agent("commonly", `comm: ["aw-commonly"]`),
        ``,
      ].join("\n")
    );

    // Issued BEFORE the server starts, through the real CLI, so the server reads a store an
    // operator produced rather than one this test hand-wrote.
    await issue("steady");
    await issue("rotating");
    await issue("revocable");

    const shimPath = join(workdir, "resolver-shim.js");
    writeFileSync(shimPath, RESOLVER_SHIM);

    server = spawn(
      process.execPath,
      ["-r", shimPath, "-r", "ts-node/register", join(__dirname, "..", "src", "index.ts")],
      {
        cwd: join(__dirname, ".."),
        env: {
          ...process.env,
          AGENTWALL_CONFIG: configPath,
          AGENTWALL_AUDIT_FILE: auditPath,
          AGENTWALL_PROXY_PORT: String(proxyPort),
          AGENTWALL_PROXY_HOST: "127.0.0.1",
          AGENTWALL_OPERATOR_TOKEN: "credlife-test-token",
          TS_NODE_TRANSPILE_ONLY: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let serverLog = "";
    server.stdout?.on("data", (chunk) => (serverLog += String(chunk)));
    server.stderr?.on("data", (chunk) => (serverLog += String(chunk)));

    const deadline = Date.now() + 60_000;
    for (;;) {
      if (Date.now() > deadline) throw new Error(`server never came up. Output:\n${serverLog}`);
      const probe = deferred<boolean>();
      const req = httpRequest(
        { host: "127.0.0.1", port: proxyPort, method: "GET", path: "http://127.0.0.1:1/", timeout: 500 },
        (res) => {
          res.resume();
          probe.resolve(true);
        }
      );
      req.on("error", () => probe.resolve(false));
      req.on("timeout", () => {
        req.destroy();
        probe.resolve(false);
      });
      req.end();
      if (await probe.promise) break;
      await sleep(250);
    }
  }, 120_000);

  afterAll(async () => {
    if (server) {
      const exited = deferred<void>();
      server.once("exit", () => exited.resolve());
      server.kill("SIGTERM");
      const giveUp = setTimeout(() => server.kill("SIGKILL"), 5_000);
      await exited.promise;
      clearTimeout(giveUp);
    }
    upstream?.close();
    rmSync(workdir, { recursive: true, force: true });
  });

  it("binds an issued credential at the credential tier, over both presentation forms", async () => {
    const bearer = await requestAs("aw-anything", proxyPort, `http://${HOST}:${upstreamPort}/steady-bearer`, secrets["steady"]);
    // The same secret through proxy-URL userinfo, which is how most deployments will carry
    // it. It arrives as Basic base64("<agentId>:<token>") and must hash to the same digest.
    const basic = await requestAs(
      "aw-anything",
      proxyPort,
      `http://${HOST}:${upstreamPort}/steady-basic`,
      secrets["steady"],
      "proxy-url"
    );

    expect(bearer.status).toBe(200);
    expect(basic.status).toBe(200);

    const records = egressFor("steady");
    expect(records.length).toBeGreaterThanOrEqual(2);
    for (const record of records) {
      // The tier is the whole claim. The comm was "aw-anything", which no agent declares, so
      // nothing but the presented secret could have produced this binding.
      expect(record.metadata?.agentMatchedOn).toBe("credential");
      expect(record.metadata?.agentDeclared).toBe("true");
      expect(record.metadata?.egressAllowlistSource).toBe("agent:steady");
      // The credential is named by its id so an operator can revoke exactly this one. The
      // digest is never in the record.
      expect(record.metadata?.agentCredentialId).toBe(credentialIds["steady"]);
    }
    expect(readFileSync(auditPath, "utf8")).not.toContain(secrets["steady"]);
  }, 60_000);

  it("never writes the secret to the credential store", () => {
    const raw = readFileSync(storePath, "utf8");
    for (const agentId of Object.keys(secrets)) {
      expect(raw).not.toContain(secrets[agentId]);
    }
    // The digest is what is there, and it is what the registry compares against.
    expect(JSON.parse(raw).credentials.length).toBeGreaterThanOrEqual(3);
  });

  it("accepts a credential issued while the proxy is running, with no restart", async () => {
    // Before issuance the agent is declared and has nothing to present, so it is refused.
    const before = await requestAs("aw-late", proxyPort, `http://${HOST}:${upstreamPort}/latecomer-before`);
    expect(before.status).toBe(403);

    await issue("latecomer");
    await sleep(STORE_PICKUP_MS);

    const after = await requestAs(
      "aw-late",
      proxyPort,
      `http://${HOST}:${upstreamPort}/latecomer-after`,
      secrets["latecomer"]
    );
    expect(after.status).toBe(200);
    expect(egressFor("latecomer").some((record) => record.metadata?.agentMatchedOn === "credential")).toBe(true);
  }, 60_000);

  it("accepts both secrets during a rotation and refuses the old one once the window closes", async () => {
    const before = secrets["rotating"];
    const beforeId = credentialIds["rotating"];

    const rotated = await cli("fleet", "rotate", "--agent", "rotating", "--overlap", `${OVERLAP_SECONDS}s`, "--json");
    expect(rotated.code).toBe(0);
    const parsed = JSON.parse(rotated.stdout) as {
      secret: string;
      credentialId: string;
      previousCredentialId: string;
      previousAcceptedUntil: string;
    };
    expect(parsed.previousCredentialId).toBe(beforeId);
    // The window is explicit and bounded: the CLI states the instant it closes rather than a
    // duration the operator has to add to a clock themselves.
    const closesAt = Date.parse(parsed.previousAcceptedUntil);
    expect(Number.isFinite(closesAt)).toBe(true);

    await sleep(STORE_PICKUP_MS);

    // INSIDE the window. This is the property that makes rotation something other than an
    // outage: the fleet has not been redeployed yet and the old secret still works.
    const oldInside = await requestAs("aw-rot", proxyPort, `http://${HOST}:${upstreamPort}/rot-old-inside`, before);
    const newInside = await requestAs("aw-rot", proxyPort, `http://${HOST}:${upstreamPort}/rot-new-inside`, parsed.secret);
    expect(Date.now()).toBeLessThan(closesAt);
    expect(oldInside.status).toBe(200);
    expect(newInside.status).toBe(200);

    // OUTSIDE it. Waited on the real clock, because the expiry is a real timestamp in a file
    // read by another process.
    await sleep(Math.max(0, closesAt - Date.now()) + 750);
    const oldOutside = await requestAs("aw-rot", proxyPort, `http://${HOST}:${upstreamPort}/rot-old-outside`, before);
    const newOutside = await requestAs("aw-rot", proxyPort, `http://${HOST}:${upstreamPort}/rot-new-outside`, parsed.secret);

    expect(oldOutside.status).toBe(403);
    expect(oldOutside.blockReason).toContain("overlap window closed");
    // An expired overlap must not quietly become an outage for the new credential too.
    expect(newOutside.status).toBe(200);

    // And the refusal is evidence, not just a status code.
    const refusal = chain().find((record) => record.metadata?.["path"] === "/rot-old-outside");
    expect(refusal).toBeDefined();
    expect(refusal?.decision).toBe("deny");
    expect(refusal?.agentId).toBe("rotating");
    expect(refusal?.matchedRules).toContain("fleet:deny-refused-agent-identity");
    expect(refusal?.detections?.map((detection) => detection.id)).toContain("det.fleet.identity.refused");
    expect(refusal?.metadata?.agentIdentityRefusal).toBe("credential-expired");
    expect(refusal?.metadata?.agentCredentialId).toBe(beforeId);
    expect(refusal?.metadata?.agentIdentityRefusalReason).toContain("overlap window closed");
  }, 90_000);

  it("refuses a revoked credential while its siblings keep working", async () => {
    // Working before, so the refusal afterwards is attributable to the revocation and not to
    // something that was already broken.
    const before = await requestAs(
      "aw-revocable",
      proxyPort,
      `http://${HOST}:${upstreamPort}/revocable-before`,
      secrets["revocable"]
    );
    expect(before.status).toBe(200);

    const revoked = await cli("fleet", "revoke", "--credential", credentialIds["revocable"], "--reason", "laptop lost");
    expect(revoked.code).toBe(0);
    await sleep(STORE_PICKUP_MS);

    const after = await requestAs(
      "aw-revocable",
      proxyPort,
      `http://${HOST}:${upstreamPort}/revocable-after`,
      secrets["revocable"]
    );
    const sibling = await requestAs(
      "aw-steady",
      proxyPort,
      `http://${HOST}:${upstreamPort}/steady-during-revocation`,
      secrets["steady"]
    );

    // One credential ended. Nothing else did, which is the difference between revocation and
    // rotating the whole fleet.
    expect(after.status).toBe(403);
    expect(after.blockReason).toContain("revoked");
    expect(after.blockReason).toContain("laptop lost");
    expect(sibling.status).toBe(200);

    const refusal = chain().find((record) => record.metadata?.["path"] === "/revocable-after");
    expect(refusal?.decision).toBe("deny");
    expect(refusal?.agentId).toBe("revocable");
    expect(refusal?.matchedRules).toContain("fleet:deny-refused-agent-identity");
    expect(refusal?.metadata?.agentIdentityRefusal).toBe("credential-revoked");
    expect(refusal?.metadata?.agentCredentialId).toBe(credentialIds["revocable"]);
    expect(refusal?.metadata?.agentIdentityRefusalReason).toContain("laptop lost");
  }, 60_000);

  it("refuses a comm-only binding under a credential floor, and the record says why", async () => {
    const attempt = await requestAs("aw-commonly", proxyPort, `http://${HOST}:${upstreamPort}/commonly`);
    expect(attempt.status).toBe(403);
    // The one line the client sees names the tier it bound at and the floor it failed, not a
    // generic allowlist complaint about a host that was in fact allowed for this agent.
    expect(attempt.blockReason).toContain("bound on comm");
    expect(attempt.blockReason).toContain("minimumMatchTier");
    // And it says why a process name is not proof, which is the whole reason for the floor.
    expect(attempt.blockReason).toContain("chosen by the process");

    const refusal = chain().find((record) => record.metadata?.["path"] === "/commonly");
    expect(refusal?.decision).toBe("deny");
    // Filed under the agent it claimed to be, so a search for that agent finds the attempt.
    expect(refusal?.agentId).toBe("commonly");
    expect(refusal?.metadata?.agentIdentityRefusal).toBe("below-minimum-tier");
    expect(refusal?.metadata?.fleetMinimumMatchTier).toBe("credential");
    expect(refusal?.metadata?.agentDeclared).toBe("false");

    // This agent holds no credential, so it cannot satisfy the floor at all and EVERY client
    // claiming it is refused identically. That is the operator's configuration doing exactly
    // what they asked for, so it is filed as configuration and not as an intrusion: no
    // ATT&CK claim, medium rather than high. Stamping "Valid Accounts" on a fleet-wide floor
    // migration would bury the refusals that do mean something under the ones that do not.
    expect(refusal?.metadata?.agentIdentityOrigin).toBe("operator-configuration");
    expect(refusal?.matchedRules).toContain("fleet:deny-unconfigured-agent-identity");
    expect(refusal?.detections?.map((detection) => detection.id)).toContain("det.fleet.identity.unconfigured");
    expect(refusal?.matchedRules).not.toContain("fleet:deny-refused-agent-identity");
    // Exactly one identity rule fires. `unmatched: deny` is also true of this connection, and
    // a record carrying both would send an operator looking for two problems.
    expect(refusal?.matchedRules).not.toContain("fleet:deny-undeclared-agent");
  }, 60_000);

  it("reports the lifecycle through the CLI and the operator API without ever exposing a digest", async () => {
    const listed = await cli("fleet", "list", "--json");
    expect(listed.code).toBe(0);
    const payload = JSON.parse(listed.stdout) as {
      minimumMatchTier: string;
      credentials: Array<{ agentId: string; credentialId: string; state: string }>;
    };
    expect(payload.minimumMatchTier).toBe("credential");

    const states: Record<string, string> = {};
    for (const credential of payload.credentials) states[credential.credentialId] = credential.state;
    expect(states[credentialIds["steady"]]).toBe("active");
    expect(states[credentialIds["revocable"]]).toBe("revoked");

    // No digest and no secret anywhere in the operator-facing output, which is the property
    // that makes it safe to paste into a ticket.
    const store = JSON.parse(readFileSync(storePath, "utf8")) as { credentials: Array<{ digest: string }> };
    for (const credential of store.credentials) {
      expect(listed.stdout).not.toContain(credential.digest);
    }
    for (const secret of Object.values(secrets)) {
      expect(listed.stdout).not.toContain(secret);
    }
  }, 60_000);
});
