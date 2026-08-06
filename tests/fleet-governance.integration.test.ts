import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { spawn, type ChildProcess } from "child_process";
import { createServer as createHttpServer, request as httpRequest, type IncomingHttpHeaders, type Server } from "http";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";
import type { AddressInfo } from "net";

/**
 * Two agents, one host, different policies, measured against the real thing.
 *
 * This suite deliberately does NOT import AgentWall. It writes a config file, starts
 * `src/index.ts` as its own process exactly the way an operator does, drives real HTTP
 * through the real forward proxy from real child processes, and then reads the audit chain
 * file the server wrote. Every layer that a per-agent claim depends on is exercised:
 *
 *   - the config loader parses the fleet section and the registry rejects an ambiguous one
 *   - /proc/net/tcp maps a client socket to a pid, a comm, and a uid
 *   - the registry binds that to a declared agent
 *   - that agent's own allowlist decides the connection
 *   - the budget refuses the connection after the ceiling
 *   - the chain records which agent it was and what the counter said
 *
 * A test that asserted against a rendered verdict string would prove none of that. The
 * standard here is the same one the perimeter learned the hard way when nft rejected a chain
 * name that every unit test had happily accepted: only the real component's answer counts.
 *
 * Linux-only, because /proc attribution is. It is skipped elsewhere rather than silently
 * asserting less.
 */

const LINUX = process.platform === "linux";
const describeLinux = LINUX ? describe : describe.skip;

/**
 * Two distinct destination NAMES, so the agents have genuinely different hosts to reach.
 *
 * Names rather than loopback literals because the builtin `net:block-ssrf-private` rule
 * denies every private and loopback destination outright, and it is right to: a test that
 * neutered it to get a green tick would be measuring a weakened product. Each name resolves
 * to a loopback address for the SERVER PROCESS ONLY, through the resolver shim below, which
 * is the programmatic equivalent of the /etc/hosts entry an operator would add.
 */
const HOST_ALPHA = "alpha.fleet.test";
const HOST_BETA = "beta.fleet.test";
const ADDRESS_ALPHA = "127.0.0.1";
const ADDRESS_BETA = "127.0.0.2";

/**
 * A preload that teaches the server's resolver about the two test names, and nothing else.
 *
 * Name resolution is the operating system's job and is explicitly outside what AgentWall
 * governs, so overriding it does not weaken anything under test: the config loader, the
 * registry, /proc attribution, the allowlist gate, the budget, and the audit chain all run
 * exactly as shipped. It is here because there is no non-private address on a CI box that a
 * test can bind, and because the alternative -- pointing the suite at a real name on the
 * internet -- makes the result depend on DNS being up.
 */
const RESOLVER_SHIM = `
const dns = require("dns");
const MAP = ${JSON.stringify({ [HOST_ALPHA]: ADDRESS_ALPHA, [HOST_BETA]: ADDRESS_BETA })};
const real = dns.lookup;
dns.lookup = function (hostname, options, callback) {
  const address = MAP[hostname];
  if (!address) return real.call(dns, hostname, options, callback);
  const cb = typeof options === "function" ? options : callback;
  const all = typeof options === "object" && options !== null && options.all === true;
  process.nextTick(() => cb(null, all ? [{ address, family: 4 }] : address, 4));
};
`;

const CREDENTIAL = "fleet-credential-for-the-mcp-wrapper";
const CREDENTIAL_DIGEST = createHash("sha256").update(CREDENTIAL, "utf8").digest("hex");

/** One byte over what agent `capped` may spend in its window, so the second call is refused. */
const BODY_BYTES = 4096;

/**
 * Local stand-in for `Promise.withResolvers`.
 *
 * The project compiles against `lib: ["ES2022"]` (tsconfig.json), which predates the real
 * thing, and widening the project's lib target to suit one test file is not this change's
 * business. Same shape, same linear control flow, no executor callbacks in the tests below.
 */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (err: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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

interface UpstreamHit {
  path: string;
  headers: IncomingHttpHeaders;
}

/**
 * One request through the proxy, made from a CHILD process with a chosen comm.
 *
 * A child rather than an in-process socket because comm attribution is the thing under test:
 * the proxy resolves the client port to a pid through /proc and reads that pid's comm, so the
 * client has to genuinely be a different process with a different name. `process.title` is
 * what sets comm on Linux; it was confirmed on this host before this test was written, and
 * that it works at all is exactly why src/fleet/registry.ts ranks comm as the weakest signal.
 */
function requestAs(
  comm: string,
  proxyPort: number,
  target: string,
  credential?: string
): Promise<{ status: number; blockReason: string | null }> {
  const script = `
    process.title = ${JSON.stringify(comm)};
    const http = require("http");
    const target = new URL(${JSON.stringify(target)});
    const headers = { host: target.host };
    ${credential ? `headers["proxy-authorization"] = "Bearer " + ${JSON.stringify(credential)};` : ""}
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

describeLinux("per-agent governance, measured end to end", () => {
  let workdir: string;
  let auditPath: string;
  let server: ChildProcess;
  let proxyPort: number;
  let apiPort: number;
  let alphaUpstream: Server;
  let betaUpstream: Server;
  let alphaPort: number;
  let betaPort: number;
  const hits: UpstreamHit[] = [];

  const chain = (): AuditRecord[] =>
    readFileSync(auditPath, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AuditRecord);

  const egressFor = (agentId: string): AuditRecord[] =>
    chain().filter((record) => record.agentId === agentId && record.action.startsWith("egress:"));

  beforeAll(async () => {
    workdir = mkdtempSync(join(tmpdir(), "agentwall-fleet-"));
    auditPath = join(workdir, "audit.jsonl");

    // Two upstreams on two loopback addresses. The bodies are sized so the byte budget has
    // something real to count: an empty response would let a maxBytes ceiling pass by never
    // being approached.
    const listen = (host: string): Promise<{ srv: Server; port: number }> => {
      const { promise, resolve } = deferred<{ srv: Server; port: number }>();
      const srv = createHttpServer((req, res) => {
        hits.push({ path: req.url ?? "", headers: req.headers });
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(BODY_BYTES));
      });
      srv.listen(0, host, () => resolve({ srv, port: (srv.address() as AddressInfo).port }));
      return promise;
    };

    const alpha = await listen(ADDRESS_ALPHA);
    const beta = await listen(ADDRESS_BETA);
    alphaUpstream = alpha.srv;
    alphaPort = alpha.port;
    betaUpstream = beta.srv;
    betaPort = beta.port;

    // Free ports for the API and the proxy, released before the server claims them. A short
    // race window, and the alternative is hard-coding ports into a suite that runs beside
    // eleven other worktrees on this box.
    const grab = (): Promise<number> => {
      const { promise, resolve } = deferred<number>();
      const probe = createHttpServer();
      probe.listen(0, "127.0.0.1", () => {
        const port = (probe.address() as AddressInfo).port;
        probe.close(() => resolve(port));
      });
      return promise;
    };
    apiPort = await grab();
    proxyPort = await grab();

    const configPath = join(workdir, "agentwall.config.yaml");
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
        // Everything on this host is expected to be declared. This is the closed posture and
        // it is what makes "which agent" a gate rather than a label.
        `  unmatched: deny`,
        `  agents:`,
        `    - id: alpha`,
        `      label: Scraper`,
        `      match:`,
        `        comm: ["aw-alpha"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_ALPHA}"]`,
        `        allowedPorts: [${alphaPort}]`,
        `    - id: beta`,
        `      label: MCP wrapper`,
        `      match:`,
        `        comm: ["aw-beta"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_BETA}"]`,
        `        allowedPorts: [${betaPort}]`,
        `    - id: capped`,
        `      label: Budgeted agent`,
        `      match:`,
        `        comm: ["aw-capped"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_ALPHA}"]`,
        `        allowedPorts: [${alphaPort}]`,
        `      budget:`,
        `        windowSeconds: 600`,
        `        maxRequests: 2`,
        `    - id: metered`,
        `      label: Byte-budgeted agent`,
        `      match:`,
        `        comm: ["aw-metered"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_ALPHA}"]`,
        `        allowedPorts: [${alphaPort}]`,
        `      budget:`,
        `        windowSeconds: 600`,
        `        maxBytes: ${BODY_BYTES - 1}`,
        `    - id: credentialed`,
        `      label: Credential-matched agent`,
        `      match:`,
        `        credential: "sha256:${CREDENTIAL_DIGEST}"`,
        `      egress:`,
        `        allowedHosts: ["${HOST_BETA}"]`,
        `        allowedPorts: [${betaPort}]`,
        ``,
      ].join("\n")
    );

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
          AGENTWALL_OPERATOR_TOKEN: "fleet-test-token",
          TS_NODE_TRANSPILE_ONLY: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let serverLog = "";
    server.stdout?.on("data", (chunk) => (serverLog += String(chunk)));
    server.stderr?.on("data", (chunk) => (serverLog += String(chunk)));

    // Readiness is OBSERVED, not assumed: poll the proxy port until it accepts a connection.
    // A real delay is unavoidable here and fake timers cannot help, because what is being
    // waited on is another OS process finishing ts-node startup and calling listen(). The
    // 250ms backoff bounds how often we ask, not how long we wait; the loop exits on the
    // first accept and fails with the server's own output rather than a bare timeout.
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
      const backoff = deferred<void>();
      setTimeout(backoff.resolve, 250);
      await backoff.promise;
    }
  }, 90_000);

  afterAll(async () => {
    if (server) {
      // Awaiting the real exit rather than sleeping before SIGKILL: a fixed grace period is
      // either too short on a loaded box or wasted on every clean run.
      const exited = deferred<void>();
      server.once("exit", () => exited.resolve());
      server.kill("SIGTERM");
      const giveUp = setTimeout(() => server.kill("SIGKILL"), 5_000);
      await exited.promise;
      clearTimeout(giveUp);
    }
    alphaUpstream?.close();
    betaUpstream?.close();
    rmSync(workdir, { recursive: true, force: true });
  });

  it("routes two agents through two different allowlists on one host", async () => {
    const alphaToAlpha = await requestAs("aw-alpha", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/alpha-own`);
    const alphaToBeta = await requestAs("aw-alpha", proxyPort, `http://${HOST_BETA}:${betaPort}/alpha-crossing`);
    const betaToBeta = await requestAs("aw-beta", proxyPort, `http://${HOST_BETA}:${betaPort}/beta-own`);
    const betaToAlpha = await requestAs("aw-beta", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/beta-crossing`);

    // Each reaches its own destination and neither reaches the other's. One global allowlist
    // could not express this: whatever it contained would be true for both agents.
    expect(alphaToAlpha.status).toBe(200);
    expect(betaToBeta.status).toBe(200);
    expect(alphaToBeta.status).toBe(403);
    expect(betaToAlpha.status).toBe(403);

    // The denial is enforced before any upstream socket opens, so the destination never sees
    // the crossing attempt at all.
    expect(hits.map((hit) => hit.path)).toContain("/alpha-own");
    expect(hits.map((hit) => hit.path)).toContain("/beta-own");
    expect(hits.map((hit) => hit.path)).not.toContain("/alpha-crossing");
    expect(hits.map((hit) => hit.path)).not.toContain("/beta-crossing");

    // And the block reason names the agent's own list, not a generic one, so an operator
    // knows which of five allowlists to edit.
    expect(alphaToBeta.blockReason).toContain("alpha egress allowlist");
    expect(betaToAlpha.blockReason).toContain("beta egress allowlist");
  }, 60_000);

  it("distinguishes the two agents in the audit chain", () => {
    const alphaRecords = egressFor("alpha");
    const betaRecords = egressFor("beta");

    expect(alphaRecords.length).toBeGreaterThanOrEqual(2);
    expect(betaRecords.length).toBeGreaterThanOrEqual(2);

    // The chain says WHICH agent, on what evidence, and against whose allowlist. Before this
    // change the agentId on an egress record was the raw comm, which named a process and
    // asserted nothing about identity.
    for (const record of alphaRecords) {
      expect(record.metadata?.agentLabel).toBe("Scraper");
      expect(record.metadata?.agentMatchedOn).toBe("comm");
      expect(record.metadata?.agentDeclared).toBe("true");
      expect(record.metadata?.egressAllowlistSource).toBe("agent:alpha");
      expect(record.metadata?.comm).toBe("aw-alpha");
      // The uid comes off the same /proc/net/tcp line as the socket inode, so it is present
      // even though nothing in this config matches on it.
      expect(record.metadata?.uid).toBe(String(process.getuid?.()));
    }
    for (const record of betaRecords) {
      expect(record.metadata?.egressAllowlistSource).toBe("agent:beta");
      expect(record.metadata?.comm).toBe("aw-beta");
    }

    // The two agents are not merely labelled differently: the record of the crossing attempt
    // is a denial filed under the agent that attempted it.
    const crossing = alphaRecords.find((record) => record.decision === "deny");
    expect(crossing).toBeDefined();
    expect(crossing?.matchedRules).toContain("net:deny-egress-not-allowlisted");
  }, 30_000);

  it("refuses egress the fleet cannot attribute to a declared agent", async () => {
    const stranger = await requestAs("aw-stranger", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/stranger`);

    expect(stranger.status).toBe(403);
    expect(hits.map((hit) => hit.path)).not.toContain("/stranger");

    const record = chain()
      .filter((entry) => entry.action.startsWith("egress:"))
      .find((entry) => entry.matchedRules.includes("fleet:deny-undeclared-agent"));
    expect(record).toBeDefined();
    expect(record?.metadata?.agentDeclared).toBe("false");
    expect(record?.detections?.map((detection) => detection.id)).toContain("det.fleet.agent.undeclared");
  }, 30_000);

  it("blocks a request budget once it is spent, and records the counter", async () => {
    const first = await requestAs("aw-capped", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/capped-1`);
    const second = await requestAs("aw-capped", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/capped-2`);
    const third = await requestAs("aw-capped", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/capped-3`);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    // The ceiling is two per window, so the third is refused and never reaches the upstream.
    expect(third.status).toBe(403);
    expect(hits.map((hit) => hit.path)).not.toContain("/capped-3");
    expect(third.blockReason).toContain("2 of 2 connections");

    const records = egressFor("capped");
    const refused = records.find((record) => record.decision === "deny");
    expect(refused).toBeDefined();
    expect(refused?.matchedRules).toContain("fleet:deny-agent-budget-exhausted");
    expect(refused?.detections?.map((detection) => detection.id)).toContain("det.fleet.budget.exhausted");
    // The counter is IN the record, not only in the prose. An operator reading the chain a
    // week later can see the ceiling and how much of it was used without rerunning anything.
    expect(refused?.metadata?.budgetRequests).toBe("2");
    expect(refused?.metadata?.budgetMaxRequests).toBe("2");
    expect(refused?.metadata?.budgetWindowSeconds).toBe("600");

    // The two allowed connections carry the counter as it stood when each was admitted, which
    // is what makes the window readable from the chain alone.
    const admitted = records.filter((record) => record.decision === "allow");
    expect(admitted.map((record) => record.metadata?.budgetRequests).sort()).toEqual(["1", "2"]);
  }, 60_000);

  it("blocks a byte budget after the bytes are actually spent", async () => {
    // The first call is admitted with an empty window and is allowed to overrun: bytes are
    // attributable only once the connection closes, so a byte ceiling refuses the NEXT
    // admission rather than truncating a live response. src/fleet/budget.ts says so and this
    // is the measurement of it.
    const first = await requestAs("aw-metered", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/metered-1`);
    expect(first.status).toBe(200);

    const second = await requestAs("aw-metered", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/metered-2`);
    expect(second.status).toBe(403);
    expect(second.blockReason).toContain("bytes");

    const refused = egressFor("metered").find((record) => record.decision === "deny");
    expect(refused).toBeDefined();
    expect(refused?.matchedRules).toContain("fleet:deny-agent-budget-exhausted");
    // The bytes counted are the ones the connection really moved, settled after it closed.
    expect(Number(refused?.metadata?.budgetBytes)).toBeGreaterThanOrEqual(BODY_BYTES);
    expect(refused?.metadata?.budgetMaxBytes).toBe(String(BODY_BYTES - 1));
  }, 60_000);

  it("binds an agent by presented credential and never leaks it upstream", async () => {
    // comm says "aw-stranger", which no agent claims. The credential is what identifies this
    // connection, and it outranks comm because a secret is evidence and a process name is a
    // string the process chose.
    const allowed = await requestAs("aw-stranger", proxyPort, `http://${HOST_BETA}:${betaPort}/cred-ok`, CREDENTIAL);
    expect(allowed.status).toBe(200);

    const record = egressFor("credentialed").find((entry) => entry.decision === "allow");
    expect(record).toBeDefined();
    expect(record?.metadata?.agentMatchedOn).toBe("credential");
    expect(record?.metadata?.comm).toBe("aw-stranger");
    expect(record?.metadata?.egressAllowlistSource).toBe("agent:credentialed");

    // Proxy-Authorization is hop-by-hop. Relaying it would hand every destination the secret
    // that identifies this agent to AgentWall, which is a credential-disclosure bug wearing
    // an attribution feature's clothes.
    const hit = hits.find((entry) => entry.path === "/cred-ok");
    expect(hit).toBeDefined();
    expect(hit?.headers["proxy-authorization"]).toBeUndefined();

    // The same credential does not widen anything: it is bound to one agent's allowlist.
    const crossing = await requestAs("aw-stranger", proxyPort, `http://${HOST_ALPHA}:${alphaPort}/cred-crossing`, CREDENTIAL);
    expect(crossing.status).toBe(403);
    expect(crossing.blockReason).toContain("credentialed egress allowlist");
  }, 60_000);

  it("reports the declared fleet, with its scope, on the operator route", async () => {
    const fetched = deferred<string>();
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: apiPort,
        path: "/api/fleet",
        headers: { authorization: "Bearer fleet-test-token" },
      },
      (res) => {
        let out = "";
        res.on("data", (chunk) => (out += String(chunk)));
        res.on("end", () => fetched.resolve(out));
      }
    );
    req.on("error", fetched.reject);
    req.end();
    const body = await fetched.promise;

    const payload = JSON.parse(body) as {
      declared: boolean;
      scope: string;
      unmatched: string;
      agents: Array<{
        id: string;
        label: string;
        match: { uid: number | null; comm: string[]; credential: boolean };
        budget: { requests: number; maxRequests: number | null } | null;
      }>;
    };

    expect(payload.declared).toBe(true);
    // The route states its own scope. A fleet view that does not say "this host" is one
    // screenshot away from being read as a cluster view.
    expect(payload.scope).toBe("single-host");
    expect(payload.unmatched).toBe("deny");
    expect(payload.agents.map((agent) => agent.id).sort()).toEqual([
      "alpha",
      "beta",
      "capped",
      "credentialed",
      "metered",
    ]);

    // The credential is reported as present and never as a value. A digest of a shared secret
    // in a JSON response is an offline cracking target handed out by the tool.
    const credentialed = payload.agents.find((agent) => agent.id === "credentialed");
    expect(credentialed?.match.credential).toBe(true);
    expect(JSON.stringify(payload)).not.toContain(CREDENTIAL_DIGEST);
    expect(JSON.stringify(payload)).not.toContain(CREDENTIAL);

    // Live counters, not just the declaration: the budgeted agent's window reflects the
    // connections the earlier tests actually made.
    const capped = payload.agents.find((agent) => agent.id === "capped");
    expect(capped?.budget?.maxRequests).toBe(2);
    expect(capped?.budget?.requests).toBe(2);
  }, 30_000);
});
