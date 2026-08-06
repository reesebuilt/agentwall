import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { createHash } from "crypto";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { createServer as createHttpServer, request as httpRequest } from "http";
import { tmpdir } from "os";
import { join } from "path";
import type { AddressInfo } from "net";
import { runVerifyCapture } from "../src/capture/verify";
import type { CaptureReport } from "../src/capture/verify";

/**
 * verify-capture, measured against a real proxy carrying real traffic.
 *
 * This file is the point of the feature. The assertion logic is unit tested next door, and a
 * unit test cannot see the failure this command exists to catch: three controls in this
 * repository shipped green and non-functional because their checks never touched the thing they
 * claimed to check. So every case below runs a genuine child process against a genuine
 * AgentWall on loopback and reads the chain that process actually wrote.
 *
 * The four acceptance cases, each constructed deliberately rather than simulated:
 *
 *   - a correctly configured agent passes, and the reported tier matches its match rule;
 *   - an agent that bypasses the proxy FAILS, built by running the fetch with the proxy
 *     variables unset;
 *   - an agent bound only by comm passes and is reported as weakly bound;
 *   - an undeclared process is reported as unattributed and does not satisfy a named agent.
 *
 * Linux only, because attribution reads /proc/net/tcp and the whole identity story rests on it.
 */

const LINUX = process.platform === "linux";
const describeLinux = LINUX ? describe : describe.skip;

const CREDENTIAL = "verify-capture-credential-for-the-cred-agent";
const CREDENTIAL_DIGEST = createHash("sha256").update(CREDENTIAL, "utf8").digest("hex");

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

/**
 * The fetch a real agent would make, as a child process with a chosen comm.
 *
 * A child rather than an in-process request because comm attribution is half of what is under
 * test: the proxy resolves the client port to a pid through /proc and reads that pid's comm, so
 * the client has to genuinely be another process with another name. `process.title` is what
 * sets comm on Linux, and that it works at all is exactly why the registry ranks comm weakest.
 *
 * Whether it goes through the proxy is decided by AW_PROXY_PORT alone. Unset, it connects to the
 * canary directly, which is how the bypass case below is built: not simulated, just unconfigured.
 */
const FETCH_SCRIPT = `
if (process.env.AW_COMM) process.title = process.env.AW_COMM;
const http = require("http");
const target = new URL(process.argv[2]);
const proxy = process.env.AW_PROXY_PORT;
const finish = (code) => process.exit(code);
if (proxy) {
  const headers = { host: target.host };
  if (process.env.AW_CRED) headers["proxy-authorization"] = "Bearer " + process.env.AW_CRED;
  http
    .request({ host: "127.0.0.1", port: Number(proxy), method: "GET", path: target.href, headers }, (res) => {
      res.resume();
      res.on("end", () => finish(res.statusCode === 200 ? 0 : 3));
    })
    .on("error", () => finish(1))
    .end();
} else {
  http
    .get(target.href, (res) => {
      res.resume();
      res.on("end", () => finish(res.statusCode === 200 ? 0 : 3));
    })
    .on("error", () => finish(1));
}
`;

describeLinux("verify-capture, measured against a real proxy", () => {
  let workdir: string;
  let auditPath: string;
  let configPath: string;
  let fetchScript: string;
  let server: ChildProcess;
  let proxyPort: number;
  let apiPort: number;
  let serverLog = "";

  /** One `agentwall verify-capture` run, driving the fetch with the given environment. */
  const verify = (agentId: string, env: Record<string, string>, settleMs = 4_000): Promise<CaptureReport> => {
    const prefix = Object.entries(env)
      .map(([name, value]) => `${name}=${value}`)
      .join(" ");
    return runVerifyCapture({
      agentId,
      auditPath,
      configPath,
      command: `${prefix} ${process.execPath} ${fetchScript} {url}`,
      host: "127.0.0.1",
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
      timeoutMs: 30_000,
      settleMs,
    });
  };

  const statusOf = (report: CaptureReport, id: string): string =>
    report.assertions.find((assertion) => assertion.id === id)?.status ?? "missing";
  const detailOf = (report: CaptureReport, id: string): string =>
    report.assertions.find((assertion) => assertion.id === id)?.detail ?? "";

  beforeAll(async () => {
    workdir = mkdtempSync(join(tmpdir(), "agentwall-verify-capture-"));
    auditPath = join(workdir, "audit.jsonl");
    configPath = join(workdir, "agentwall.config.yaml");
    fetchScript = join(workdir, "fetch.js");
    writeFileSync(fetchScript, FETCH_SCRIPT);

    // Free ports, released before the server claims them. A short race window, and the
    // alternative is hard-coding ports into a suite that runs beside other worktrees.
    const grab = (): Promise<number> => {
      const found = deferred<number>();
      const probe = createHttpServer();
      probe.listen(0, "127.0.0.1", () => {
        const port = (probe.address() as AddressInfo).port;
        probe.close(() => found.resolve(port));
      });
      return found.promise;
    };
    apiPort = await grab();
    proxyPort = await grab();

    writeFileSync(
      configPath,
      [
        `port: ${apiPort}`,
        `host: 127.0.0.1`,
        `logLevel: silent`,
        `enforcement:`,
        // Monitor, so the canary on loopback is actually reached and the "did it arrive here,
        // and by which route" question has two possible answers. Strict would deny the canary
        // destination and every case would look the same from the listener's side.
        `  mode: monitor`,
        `egress:`,
        `  enabled: true`,
        `  defaultDeny: false`,
        `  allowPrivateRanges: true`,
        `  allowedHosts: []`,
        `  allowedSchemes: ["http", "https"]`,
        `  allowedPorts: []`,
        `fleet:`,
        `  unmatched: global`,
        `  agents:`,
        `    - id: alpha`,
        `      label: Comm matched agent`,
        `      match:`,
        `        comm: ["aw-alpha"]`,
        `    - id: cred`,
        `      label: Credential matched agent`,
        `      match:`,
        `        credential: "sha256:${CREDENTIAL_DIGEST}"`,
        `    - id: mixed`,
        `      label: Credential preferred with a comm fallback`,
        `      match:`,
        `        comm: ["aw-mixed"]`,
        // A digest of a secret nothing in this suite presents, so `mixed` can only ever bind by
        // its weaker signal. That is the shortfall case: configured strong, bound weak.
        `        credential: "sha256:${"1".repeat(64)}"`,
        ``,
      ].join("\n")
    );

    server = spawn(
      process.execPath,
      ["-r", "ts-node/register", join(__dirname, "..", "src", "index.ts")],
      {
        cwd: join(__dirname, ".."),
        env: {
          ...process.env,
          AGENTWALL_CONFIG: configPath,
          AGENTWALL_AUDIT_FILE: auditPath,
          AGENTWALL_PROXY_PORT: String(proxyPort),
          AGENTWALL_PROXY_HOST: "127.0.0.1",
          AGENTWALL_OPERATOR_TOKEN: "verify-capture-test-token",
          TS_NODE_TRANSPILE_ONLY: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    server.stdout?.on("data", (chunk) => (serverLog += String(chunk)));
    server.stderr?.on("data", (chunk) => (serverLog += String(chunk)));

    // Readiness is OBSERVED, not assumed: poll the proxy port until it accepts a connection.
    // A real delay is unavoidable here and fake timers cannot help, because what is being
    // waited on is another OS process finishing ts-node startup and calling listen().
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
      const exited = deferred<void>();
      server.once("exit", () => exited.resolve());
      server.kill("SIGTERM");
      const giveUp = setTimeout(() => server.kill("SIGKILL"), 5_000);
      await exited.promise;
      clearTimeout(giveUp);
    }
    rmSync(workdir, { recursive: true, force: true });
  });

  it("passes a correctly configured agent and reports the tier its match rule declares", async () => {
    const report = await verify("alpha", { AW_COMM: "aw-alpha", AW_PROXY_PORT: String(proxyPort) });

    expect(report.outcome).toBe("captured");
    expect(statusOf(report, "chain-record")).toBe("pass");
    expect(statusOf(report, "agent-binding")).toBe("pass");
    expect(statusOf(report, "no-bypass")).toBe("pass");

    // The tier is the one the config declared, and it is reported rather than implied.
    expect(report.declaredTier).toBe("comm");
    expect(report.observedTier).toBe("comm");
    expect(report.records[0].declared).toBe(true);
    expect(report.records[0].agentId).toBe("alpha");

    // And the record really is the canary's own request, not some other traffic on the box.
    expect(report.records).toHaveLength(1);
    expect(report.records[0].path).toContain(report.token);
    expect(report.hits).toHaveLength(1);
    expect(report.hits[0].token).toBe(true);
  }, 60_000);

  it("reports a comm-only agent as WEAKLY bound rather than simply captured", async () => {
    const report = await verify("alpha", { AW_COMM: "aw-alpha", AW_PROXY_PORT: String(proxyPort) });

    expect(report.captured).toBe(true);
    expect(report.tierStrength).toBe("weak");
    // The reason travels with the verdict. "Captured" alone would be true and misleading.
    expect(detailOf(report, "agent-binding")).toContain("self");
    expect(report.tierNote).toContain("comm is a 16-byte label the process writes itself");
  }, 60_000);

  it("reports a credential-matched agent as strongly bound", async () => {
    const report = await verify("cred", {
      AW_COMM: "aw-unrelated",
      AW_CRED: CREDENTIAL,
      AW_PROXY_PORT: String(proxyPort),
    });

    expect(report.outcome).toBe("captured");
    expect(report.observedTier).toBe("credential");
    expect(report.tierStrength).toBe("strong");
    expect(report.tierShortfall).toBeNull();
  }, 60_000);

  it("flags an agent configured for a credential that actually bound by comm", async () => {
    const report = await verify("mixed", { AW_COMM: "aw-mixed", AW_PROXY_PORT: String(proxyPort) });

    expect(report.outcome).toBe("captured");
    expect(report.declaredTier).toBe("credential");
    expect(report.observedTier).toBe("comm");
    expect(report.tierShortfall).toContain("credential is not being presented");
  }, 60_000);

  it("FAILS an agent that goes around the proxy, and names what escaped", async () => {
    // Constructed deliberately: identical to the passing case except AW_PROXY_PORT is unset, so
    // the child connects straight to the canary. This is what an agent whose harness ignores the
    // proxy environment does, and it is the failure a chain-record-only check would miss.
    const report = await verify("alpha", { AW_COMM: "aw-alpha" });

    expect(report.outcome).toBe("bypass");
    expect(report.captured).toBe(false);
    expect(statusOf(report, "no-bypass")).toBe("fail");

    // The canary really was reached, and the chain really has nothing.
    expect(report.hits).toHaveLength(1);
    expect(report.records).toHaveLength(0);

    // Named, not merely counted. An operator needs the process, not "something".
    expect(detailOf(report, "no-bypass")).toContain("BYPASS");
    expect(detailOf(report, "no-bypass")).toContain("aw-alpha");
    expect(detailOf(report, "no-bypass")).toContain(`pid ${report.hits[0].peer.pid}`);
    expect(report.hits[0].peer.pid).not.toBeNull();
    expect(report.hits[0].peer.uid).toBe(process.getuid?.() ?? null);
  }, 60_000);

  it("refuses to call a NO_PROXY-exempted canary a bypass, and names the entry instead", async () => {
    // The collision that nearly shipped: an onboarding profile exporting
    // NO_PROXY=localhost,127.0.0.1,::1 so the agent can reach the dashboard unproxied. A loopback
    // canary is then fetched directly BY CONSTRUCTION, and every onboarded agent would have
    // failed this check with a self-inflicted bypass. The environment read here is this process's
    // because the child inherits it unmodified, which is the same reason the check can see it.
    const previous = process.env["NO_PROXY"];
    process.env["NO_PROXY"] = "localhost,127.0.0.1,::1";
    try {
      const report = await verify("alpha", { AW_COMM: "aw-alpha" });

      // The direct hit is real and is reported. What changes is the claim made about it.
      expect(report.hits).toHaveLength(1);
      expect(report.records).toHaveLength(0);
      expect(report.outcome).toBe("inconclusive");
      expect(statusOf(report, "no-bypass")).toBe("unproven");
      expect(detailOf(report, "no-bypass")).not.toContain("BYPASS");

      // And the hole is named rather than forgiven.
      expect(report.exemption?.entry).toBe("127.0.0.1");
      expect(report.exemption?.certainty).toBe("exempted");
      expect(report.exemption?.source).toBe("NO_PROXY");
      expect(detailOf(report, "no-bypass")).toContain("told to reach without AgentWall");
    } finally {
      if (previous === undefined) delete process.env["NO_PROXY"];
      else process.env["NO_PROXY"] = previous;
    }
  }, 60_000);

  it("catches the half-captured agent: one request proxied, one around", async () => {
    // The case that motivates the whole command. A check that stopped at "is there a chain
    // record" would report this agent as captured, because there IS one, correctly bound.
    const proxied = `AW_COMM=aw-alpha AW_PROXY_PORT=${proxyPort} ${process.execPath} ${fetchScript} {url}`;
    const direct = `AW_COMM=aw-alpha ${process.execPath} ${fetchScript} {url}`;
    const report = await runVerifyCapture({
      agentId: "alpha",
      auditPath,
      configPath,
      command: `${proxied}; ${direct}`,
      host: "127.0.0.1",
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
      timeoutMs: 30_000,
      settleMs: 4_000,
    });

    expect(statusOf(report, "chain-record")).toBe("pass");
    expect(statusOf(report, "agent-binding")).toBe("pass");
    expect(statusOf(report, "no-bypass")).toBe("fail");
    expect(report.outcome).toBe("bypass");

    expect(report.hits).toHaveLength(2);
    expect(report.records).toHaveLength(1);
    // The second presentation is refused: the token is spent, which is what makes the two
    // connections distinguishable at all.
    expect(report.hits[1].replay).toBe(true);
    // Only the escapee is accused. The proxied hop came from AgentWall's own pid.
    expect(detailOf(report, "no-bypass")).toContain("aw-alpha");
    expect(detailOf(report, "no-bypass")).not.toContain(`pid ${report.hits[0].peer.pid} `);
  }, 60_000);

  it("reports traffic from an undeclared process as unattributed and refuses it for a named agent", async () => {
    const report = await verify("alpha", { AW_COMM: "aw-nobody", AW_PROXY_PORT: String(proxyPort) });

    // The proxy saw it, so capture itself is not in doubt.
    expect(statusOf(report, "chain-record")).toBe("pass");
    expect(statusOf(report, "no-bypass")).toBe("pass");
    // But nothing declared claims it, so it cannot answer a question about "alpha".
    expect(statusOf(report, "agent-binding")).toBe("fail");
    expect(report.outcome).toBe("not-captured");
    expect(detailOf(report, "agent-binding")).toContain("unattributed");
    expect(report.records[0].declared).toBe(false);
    expect(report.records[0].matchedOn).toBe("none");
  }, 60_000);

  it("refuses a process that merely names itself after a declared agent", async () => {
    // The registry falls back to the process comm for a connection no declared agent claims, so
    // this record carries agentId "alpha" while nothing declared bound it. Comparing the id
    // alone would let any process on the box impersonate any agent in this report.
    const report = await verify("alpha", { AW_COMM: "alpha", AW_PROXY_PORT: String(proxyPort) });

    expect(report.records[0].agentId).toBe("alpha");
    expect(report.records[0].declared).toBe(false);
    expect(statusOf(report, "agent-binding")).toBe("fail");
    expect(report.outcome).toBe("not-captured");
  }, 60_000);

  it("independently confirms the hop came from AgentWall's own process", async () => {
    const report = await verify("alpha", { AW_COMM: "aw-alpha", AW_PROXY_PORT: String(proxyPort) });

    // Not a correlation: the pid that opened the connection to the canary is resolved through
    // /proc and compared against the pid listening on the proxy port.
    expect(report.corroboration.status).toBe("confirmed");
    expect(report.corroboration.proxyPids).toContain(server.pid);
    expect(report.hits[0].peer.pid).toBe(server.pid);
  }, 60_000);

  it("reports silence as inconclusive rather than as captured or bypassed", async () => {
    const report = await runVerifyCapture({
      agentId: "alpha",
      auditPath,
      configPath,
      command: "true",
      host: "127.0.0.1",
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
      timeoutMs: 30_000,
      settleMs: 500,
    });

    expect(report.outcome).toBe("inconclusive");
    expect(report.assertions.every((assertion) => assertion.status === "unproven")).toBe(true);
  }, 60_000);

  it("mints a fresh token for every run, so no two checks can be confused", async () => {
    const first = await verify("alpha", { AW_COMM: "aw-alpha", AW_PROXY_PORT: String(proxyPort) });
    const second = await verify("alpha", { AW_COMM: "aw-alpha", AW_PROXY_PORT: String(proxyPort) });

    expect(first.token).not.toBe(second.token);
    // Each run sees only its own record, even though both are in the same chain file.
    expect(first.records).toHaveLength(1);
    expect(second.records).toHaveLength(1);
    expect(second.records[0].path).toContain(second.token);
    expect(second.records[0].path).not.toContain(first.token);
  }, 90_000);
});
