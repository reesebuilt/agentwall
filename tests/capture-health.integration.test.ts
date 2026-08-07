import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { spawn, spawnSync, type ChildProcess } from "child_process";
import { createServer as createHttpServer, request as httpRequest, type Server } from "http";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type { AddressInfo } from "net";

/**
 * `agentwall doctor` reporting capture, measured against a real server and real egress.
 *
 * The point of this file is that nothing in it is a fixture. A real `src/index.ts` process
 * writes the chain, real child processes with real comms make real proxied requests, and the
 * real `dist/cli.js doctor` reads what the server wrote. That matters more here than usual:
 * doctor's whole job is to notice traffic nobody declared, and a doctor tested only against
 * chains its own test file wrote would keep agreeing with itself right up until src/index.ts
 * renamed a metadata key, at which point the section would go quietly green over an escaping
 * agent. Three controls in this repo have already shipped green and non-functional. This is
 * the measurement that keeps this one from being the fourth.
 *
 * Test order is load-bearing. Doctor advances a bookmark on every run, and "undeclared egress
 * since the last run" only means anything across successive runs, so these cases are written
 * as a sequence: baseline, escape, quiet, and each states which run it is.
 *
 * Linux-only, because /proc attribution is.
 */

const LINUX = process.platform === "linux";
const describeLinux = LINUX ? describe : describe.skip;

/**
 * Destination NAMES rather than loopback literals, for the same reason the fleet governance
 * suite uses them: the builtin `net:block-ssrf-private` rule denies loopback outright and
 * weakening it to get a green tick would measure a weakened product. The shim below is the
 * programmatic equivalent of an /etc/hosts entry, and only the server process sees it.
 */
const HOST_FLEET = "fleet.capture.test";
const HOST_OPEN = "open.capture.test";
const HOST_CLOSED = "closed.capture.test";
const ADDRESS_FLEET = "127.0.0.1";
const ADDRESS_OPEN = "127.0.0.2";
const ADDRESS_CLOSED = "127.0.0.3";

const RESOLVER_SHIM = `
const dns = require("dns");
const MAP = ${JSON.stringify({
  [HOST_FLEET]: ADDRESS_FLEET,
  [HOST_OPEN]: ADDRESS_OPEN,
  [HOST_CLOSED]: ADDRESS_CLOSED,
})};
const real = dns.lookup;
dns.lookup = function (hostname, options, callback) {
  const address = MAP[hostname];
  if (!address) return real.call(dns, hostname, options, callback);
  const cb = typeof options === "function" ? options : callback;
  const all = typeof options === "object" && options !== null && options.all === true;
  process.nextTick(() => cb(null, all ? [{ address, family: 4 }] : address, 4));
};
`;

const BODY_BYTES = 2048;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (err: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** One proxied request from a CHILD process with a chosen comm, exactly as the fleet suite does. */
function requestAs(comm: string, proxyPort: number, target: string): Promise<number> {
  const script = `
    process.title = ${JSON.stringify(comm)};
    const http = require("http");
    const target = new URL(${JSON.stringify(target)});
    const req = http.request(
      { host: "127.0.0.1", port: ${proxyPort}, method: "GET", path: target.href, headers: { host: target.host } },
      (res) => {
        res.resume();
        res.on("end", () => process.stdout.write(String(res.statusCode)));
      }
    );
    req.on("error", () => process.stdout.write("0"));
    req.end();
  `;
  const { promise, resolve, reject } = deferred<number>();
  const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (chunk) => (out += String(chunk)));
  child.on("error", reject);
  child.on("close", () => resolve(Number(out) || 0));
  return promise;
}

/** The exact JSON shape `doctor --json` prints. Narrow: only what these tests assert on. */
interface DoctorJson {
  checks: Array<{ name: string; ok: boolean }>;
  capture: {
    unavailable: string | null;
    fleetError: { message: string; environmental: boolean } | null;
    watermarkError: string | null;
    verdict: "clear" | "inconclusive" | "escape";
    verdictReason: string;
    health: {
      chainPresent: boolean;
      egressRecords: number;
      fleetDeclared: boolean;
      since: { chainIndex: number } | null;
      agents: Array<{
        agentId: string;
        strongestTier: string;
        weakestTier: string;
        lastSeen: { at: string; tier: string } | null;
        windowSeconds: number;
        windowIsBudget: boolean;
        requests: number;
        bytes: number;
        maxRequests: number | null;
      }>;
      undeclared: {
        total: number;
        sinceLastRun: number;
        allowedSinceLastRun: number;
        deniedSinceLastRun: number;
        escapedSinceLastRun: number;
        permittedByConfigSinceLastRun: Array<{ reason: string; count: number }>;
        bytesSinceLastRun: number;
        byIdentity: Array<{ id: string; count: number }>;
        topHosts: Array<{ host: string; count: number }>;
      };
      weakestBinding: { tier: string; agentIds: string[] } | null;
    } | null;
  };
  failures: number;
  exitCode: number;
}

describeLinux("doctor reports capture from a chain a real server wrote", () => {
  let workdir: string;
  let auditPath: string;
  let configPath: string;
  let server: ChildProcess;
  let proxyPort: number;
  const upstreams: Server[] = [];
  const ports: Record<string, number> = {};
  /**
   * Undeclared records the chain already held when run 1 finished. Captured rather than
   * hardcoded because the harness itself contributes one: see run 1.
   */
  let baselineTotal = 0;

  /** Run the real CLI, from a directory whose install checks pass, and hand back both faces. */
  const doctor = (json: boolean): { status: number; stdout: string } => {
    const result = spawnSync(
      process.execPath,
      [join(__dirname, "..", "dist", "cli.js"), "doctor", "--audit", auditPath, "--config", configPath, ...(json ? ["--json"] : [])],
      { cwd: workdir, encoding: "utf8", env: { ...process.env, AGENTWALL_AUDIT_FILE: auditPath } },
    );
    return { status: result.status ?? -1, stdout: `${result.stdout ?? ""}${result.stderr ?? ""}` };
  };

  const doctorJson = (): { status: number; payload: DoctorJson } => {
    const { status, stdout } = doctor(true);
    return { status, payload: JSON.parse(stdout) as DoctorJson };
  };

  beforeAll(async () => {
    workdir = mkdtempSync(join(tmpdir(), "agentwall-capture-live-"));
    auditPath = join(workdir, "audit.jsonl");
    configPath = join(workdir, "agentwall.config.yaml");

    const listen = (host: string): Promise<{ srv: Server; port: number }> => {
      const { promise, resolve } = deferred<{ srv: Server; port: number }>();
      const srv = createHttpServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(BODY_BYTES));
      });
      srv.listen(0, host, () => resolve({ srv, port: (srv.address() as AddressInfo).port }));
      return promise;
    };

    for (const [name, address] of [
      [HOST_FLEET, ADDRESS_FLEET],
      [HOST_OPEN, ADDRESS_OPEN],
      [HOST_CLOSED, ADDRESS_CLOSED],
    ]) {
      const started = await listen(address);
      upstreams.push(started.srv);
      ports[name] = started.port;
    }

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
        // The global list, which judges anything the fleet cannot attribute. HOST_OPEN is on
        // it and HOST_CLOSED is not, so undeclared traffic produces BOTH an escape that got
        // out and an attempt the wall refused. Doctor has to tell those apart: one is a
        // failure and the other is the product working.
        `  allowedHosts: ["${HOST_OPEN}"]`,
        `  allowedSchemes: ["http", "https"]`,
        `  allowedPorts: [${ports[HOST_OPEN]}]`,
        `fleet:`,
        // Deliberately "global" rather than "deny": undeclared egress has to be ABLE to
        // escape for the alarm to have anything to alarm about. This is also the default
        // posture, so it is the one most deployments will be running when doctor first
        // tells them something is loose.
        `  unmatched: global`,
        `  agents:`,
        `    - id: worker`,
        `      label: Long window worker`,
        `      match:`,
        `        comm: ["aw-worker"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_FLEET}"]`,
        `        allowedPorts: [${ports[HOST_FLEET]}]`,
        `      budget:`,
        `        windowSeconds: 600`,
        `        maxRequests: 5`,
        // A one-second window, so that by the time doctor runs this agent has been SEEN but
        // has zero traffic in its window. That is the state a zero row has to be
        // distinguishable from "declared, never seen", and the only way to produce it
        // honestly is to let a real window roll.
        `    - id: blip`,
        `      label: Short window worker`,
        `      match:`,
        `        comm: ["aw-blip"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_FLEET}"]`,
        `        allowedPorts: [${ports[HOST_FLEET]}]`,
        `      budget:`,
        `        windowSeconds: 1`,
        `        maxRequests: 5`,
        // Declared and never started. The whole reason doctor cannot render capture as a
        // table of counters: this agent's row and an idle agent's row would both be zeros.
        `    - id: ghost`,
        `      label: Never launched`,
        `      match:`,
        `        comm: ["aw-ghost"]`,
        `      egress:`,
        `        allowedHosts: ["${HOST_FLEET}"]`,
        `        allowedPorts: [${ports[HOST_FLEET]}]`,
        ``,
      ].join("\n"),
    );

    // Doctor runs from a temporary project whose cwd intentionally has no dist directory.
    // Its package-root check must resolve the installed Agentwall package, not this project.
    writeFileSync(join(workdir, "policy.yaml"), "rules: []\n");

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
          AGENTWALL_OPERATOR_TOKEN: "capture-test-token",
          TS_NODE_TRANSPILE_ONLY: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let serverLog = "";
    server.stdout?.on("data", (chunk) => (serverLog += String(chunk)));
    server.stderr?.on("data", (chunk) => (serverLog += String(chunk)));

    // Readiness OBSERVED, not assumed: poll the proxy until it accepts.
    const deadline = Date.now() + 60_000;
    for (;;) {
      if (Date.now() > deadline) throw new Error(`server never came up. Output:\n${serverLog}`);
      const probe = deferred<boolean>();
      const req = httpRequest(
        { host: "127.0.0.1", port: proxyPort, method: "GET", path: "http://127.0.0.1:1/", timeout: 500 },
        (res) => {
          res.resume();
          probe.resolve(true);
        },
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

    // Drained and awaited, not fire-and-forget. `close()` alone resolves only once every
    // socket has ended, and a keep-alive connection the dead server process left behind
    // would keep the handle open past the end of the run, which surfaces as jest's
    // "worker failed to exit gracefully" on whichever suite happens to be last.
    for (const srv of upstreams) {
      const closed = deferred<void>();
      srv.closeAllConnections();
      srv.close(() => closed.resolve());
      await closed.promise;
    }
    rmSync(workdir, { recursive: true, force: true });
  });

  it("run 1: reports attributed traffic, undeclared traffic, and a never-seen agent", async () => {
    // Attributed: two declared agents, bound by comm through /proc.
    expect(await requestAs("aw-worker", proxyPort, `http://${HOST_FLEET}:${ports[HOST_FLEET]}/worker-1`)).toBe(200);
    expect(await requestAs("aw-worker", proxyPort, `http://${HOST_FLEET}:${ports[HOST_FLEET]}/worker-2`)).toBe(200);
    expect(await requestAs("aw-blip", proxyPort, `http://${HOST_FLEET}:${ports[HOST_FLEET]}/blip-1`)).toBe(200);

    // Undeclared and it got out. This is the escape the section exists to surface.
    expect(await requestAs("aw-stranger", proxyPort, `http://${HOST_OPEN}:${ports[HOST_OPEN]}/loose-1`)).toBe(200);
    expect(await requestAs("aw-stranger", proxyPort, `http://${HOST_OPEN}:${ports[HOST_OPEN]}/loose-2`)).toBe(200);
    // Undeclared and refused. Same lack of identity, opposite outcome.
    expect(await requestAs("aw-stranger", proxyPort, `http://${HOST_CLOSED}:${ports[HOST_CLOSED]}/blocked`)).toBe(403);

    // A REAL wait, and unavoidable. The window this rolls is measured from timestamps a
    // separate server process wrote and a separate CLI process reads, so a fake clock in
    // this process moves neither. 1.4s against a 1s window is the smallest honest margin.
    const wait = deferred<void>();
    setTimeout(wait.resolve, 1_400);
    await wait.promise;

    const { status, payload } = doctorJson();
    const health = payload.capture.health;

    expect(payload.capture.unavailable).toBeNull();
    expect(payload.capture.fleetError).toBeNull();
    expect(payload.capture.watermarkError).toBeNull();
    expect(payload.checks.find((check) => check.name === "dist/index.js exists")?.ok).toBe(true);
    expect(health?.chainPresent).toBe(true);
    expect(health?.fleetDeclared).toBe(true);

    // Attributed: the counters come off records the server wrote, keyed by the identity the
    // registry actually bound, at the tier it bound at.
    const worker = health?.agents.find((row) => row.agentId === "worker");
    expect(worker?.requests).toBe(2);
    expect(worker?.maxRequests).toBe(5);
    expect(worker?.windowSeconds).toBe(600);
    expect(worker?.windowIsBudget).toBe(true);
    expect(worker?.lastSeen?.tier).toBe("comm");
    // Real bytes off the wire, both directions, for two 2 KB responses.
    expect(worker?.bytes).toBeGreaterThanOrEqual(2 * BODY_BYTES);

    // Seen, and zero in its window. The contrast this whole section turns on.
    const blip = health?.agents.find((row) => row.agentId === "blip");
    expect(blip?.lastSeen).not.toBeNull();
    expect(blip?.requests).toBe(0);

    // Declared, never seen. Not a zero row: a null lastSeen, which is what lets the renderer
    // say something different about it.
    const ghost = health?.agents.find((row) => row.agentId === "ghost");
    expect(ghost?.lastSeen).toBeNull();
    expect(ghost?.requests).toBe(0);

    // Undeclared, split by outcome. The three aw-stranger connections are exact: two got
    // out and one was refused.
    const stranger = health?.undeclared.byIdentity.find((row) => row.id === "aw-stranger");
    expect(stranger?.count).toBe(3);
    expect(health?.undeclared.allowedSinceLastRun).toBe(2);
    expect(health?.undeclared.bytesSinceLastRun).toBeGreaterThanOrEqual(2 * BODY_BYTES);
    expect(health?.undeclared.topHosts.map((row) => row.host)).toEqual(
      expect.arrayContaining([HOST_OPEN, HOST_CLOSED]),
    );

    // The TOTAL is at least four, not three, and the extra one is the point. This suite's
    // own readiness probe is an undeclared process making a proxied request, and doctor
    // caught it without being told to look. That is what the section is for, so the totals
    // below are asserted as deltas from this baseline rather than pinned to a number that
    // would require the harness to be invisible.
    baselineTotal = health?.undeclared.total ?? 0;
    expect(baselineTotal).toBeGreaterThanOrEqual(3);
    expect(health?.undeclared.sinceLastRun).toBe(baselineTotal);
    expect(health?.undeclared.deniedSinceLastRun).toBe(baselineTotal - 2);

    // None of the undeclared traffic was charged to a declared agent.
    expect(worker?.requests).toBe(2);

    // Every agent here is comm-matched, so the fleet is only as strong as a process name.
    expect(health?.weakestBinding).toEqual({
      tier: "comm",
      agentIds: expect.arrayContaining(["worker", "blip", "ghost"]),
    });

    // Every allowed undeclared record carries the posture that was in force, and it says
    // `global`. That is the DEFAULT posture and it permits exactly this, so doctor must not
    // call it an escape. This assertion is also the drift check on src/index.ts: if
    // `fleetUnmatched` is ever renamed or dropped, escapedSinceLastRun goes non-zero here
    // and this test fails rather than the section quietly starting to accuse people.
    expect(health?.undeclared.escapedSinceLastRun).toBe(0);
    expect(health?.undeclared.permittedByConfigSinceLastRun[0]?.reason).toContain("fleet.unmatched: global");

    // The first run is the baseline: it seeds the bookmark and does not fail, because there
    // is no "last run" for "since the last run" to mean anything against yet.
    expect(health?.since).toBeNull();
    expect(payload.capture.verdict).toBe("clear");
    expect(status).toBe(0);
  }, 120_000);

  it("run 2: reports INCONCLUSIVE, not an escape, when the configuration permitted the egress", async () => {
    expect(await requestAs("aw-stranger", proxyPort, `http://${HOST_OPEN}:${ports[HOST_OPEN]}/loose-3`)).toBe(200);

    const { status, payload } = doctorJson();
    const health = payload.capture.health;

    // The bookmark from run 1 is in force, so only the new record counts. Everything run 1
    // saw is still in `total`, so history does not vanish when the verdict clears.
    expect(health?.since).not.toBeNull();
    expect(health?.undeclared.total).toBe(baselineTotal + 1);
    expect(health?.undeclared.sinceLastRun).toBe(1);
    expect(health?.undeclared.allowedSinceLastRun).toBe(1);

    // Undeclared traffic reached the network, and this deployment's own `unmatched: global`
    // is what let it. Calling that an escape would accuse the operator of a breach their
    // configuration prescribes, so the verdict is inconclusive and exit 2, not exit 1. There
    // is deliberately no end-to-end ESCAPE case in this file: under `unmatched: deny` and an
    // enforcing mode the proxy refuses undeclared connections before opening an upstream
    // socket, so the combination that means "escaped" is not producible against a real
    // server. That is the product working, and it is why the escape verdict is proved from a
    // crafted chain in tests/capture-health.test.ts instead of faked here.
    expect(health?.undeclared.escapedSinceLastRun).toBe(0);
    expect(payload.capture.verdict).toBe("inconclusive");
    expect(payload.failures).toBe(0);
    expect(payload.exitCode).toBe(2);
    expect(status).toBe(2);
  }, 60_000);

  it("run 3: renders never-seen and seen-idle differently, and names the weakest binding", async () => {
    expect(await requestAs("aw-stranger", proxyPort, `http://${HOST_OPEN}:${ports[HOST_OPEN]}/loose-4`)).toBe(200);

    const { status, stdout } = doctor(false);

    // The finding is a line of its own, above the per-agent table, and it says what happened
    // to the traffic rather than only that it existed. Exactly one record is new here, so
    // the singular is what the renderer has to produce.
    expect(stdout).toContain("1 undeclared egress record since the last run");
    expect(stdout).toContain("1 reached the network, 0 were refused");

    // Named as inconclusive, with the setting responsible and the remedy that makes the next
    // run able to answer. Not the word "escape" anywhere.
    expect(stdout).toContain("INCONCLUSIVE: 1 of those were allowed out by the configuration itself");
    expect(stdout).toContain("fleet.unmatched: global");
    expect(stdout).toContain("Set `fleet.unmatched: deny` to make the next run able to answer");
    expect(stdout).not.toContain("ESCAPE");

    // The two states that must never look alike.
    expect(stdout).toContain("DECLARED, NEVER SEEN");
    expect(stdout).toMatch(/ghost\s+comm\s+DECLARED, NEVER SEEN/);
    // The seen-idle agent renders as a real row with a last-seen time, not as the same
    // string, and its window is labelled as a budget rather than an observation.
    expect(stdout).toMatch(/blip\s+comm\s+\d+[smh] ago\s+1s budget\s+0 \/ 5/);

    expect(stdout).toContain("weakest binding in use: comm");
    expect(stdout).toContain("Anything on this host can claim it");
    expect(status).toBe(2);
  }, 60_000);

  it("run 4: goes quiet once the traffic is accounted for, without forgetting it happened", () => {
    const { status, payload } = doctorJson();
    const health = payload.capture.health;

    expect(health?.undeclared.sinceLastRun).toBe(0);
    expect(health?.undeclared.total).toBe(baselineTotal + 2);
    expect(payload.capture.verdict).toBe("clear");
    expect(status).toBe(0);
  }, 60_000);
});
