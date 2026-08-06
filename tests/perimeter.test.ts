import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import * as childProcess from "child_process";
import { parsePerimeterStatus, renderNftables } from "../src/perimeter/spec";
import { runPerimeterCommand } from "../src/perimeter";
import type { PerimeterSpec } from "../src/perimeter/spec";

/**
 * No test here may touch the host firewall, and `child_process.spawnSync` is not redefinable on
 * Node 22, so the module is replaced rather than spied. Any code path that reached for `nft` throws
 * instead of running it — a test failure on this machine rather than a firewall change.
 */
jest.mock("child_process", () => {
  const actual = jest.requireActual<typeof childProcess>("child_process");
  return {
    ...actual,
    spawnSync: jest.fn(() => {
      throw new Error("perimeter tests must never spawn a process");
    }),
  };
});

const spawnSyncMock = jest.mocked(childProcess.spawnSync);

/**
 * What this suite defends, and what it deliberately cannot.
 *
 * The perimeter's whole claim is that a contained uid reaches the network only through the proxy.
 * That claim rests on three properties of the generated ruleset — the agent's TCP is redirected,
 * the proxy is exempted before that redirect, and everything else the agent sends is dropped — and
 * on `parsePerimeterStatus` refusing to call a half-installed table healthy. All four are asserted
 * here against parsed rules rather than a golden string, because an assertion that breaks when a
 * comment is reworded gets deleted the first time it is inconvenient.
 *
 * Nothing here runs `nft` or needs root. `spawnSync` is replaced by a mock that throws, so any code
 * path that reached for the host firewall would fail loudly rather than mutating this machine, and
 * the privileged subcommands are exercised through their real refusal paths as the unprivileged uid
 * the suite actually runs as.
 */

const BASE: PerimeterSpec = { agentUid: 61001, proxyUid: 61002, proxyPort: 8080, allowLoopback: false };

const REDIRECT_RULE = "meta skuid 61001 tcp dport { 80, 443 } redirect to :8080";
const PROXY_EXEMPTION = "meta skuid 61002 accept";
const DROP_RULE = "meta skuid 61001 drop";

/**
 * Reduce a ruleset to its statements: comments gone, whitespace collapsed, chain declarations and
 * closing braces dropped. Independent of the module's own parser on purpose — a test that reads its
 * subject with the subject's code proves only that the code agrees with itself.
 */
function statementsOf(ruleset: string): string[] {
  return ruleset
    .split("\n")
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter((line) => line !== "" && !line.startsWith("#") && line !== "}" && !line.startsWith("type "));
}

/** A realistic `nft list table inet agentwall` listing of a correctly installed perimeter. */
const INSTALLED_LISTING = [
  "table inet agentwall {",
  "\tchain capture {",
  "\t\ttype nat hook output priority dstnat; policy accept;",
  "\t\tmeta skuid 61002 accept",
  "\t\tmeta skuid 61001 tcp dport { 80, 443 } redirect to :8080",
  "\t}",
  "",
  "\tchain egress {",
  "\t\ttype filter hook output priority filter; policy accept;",
  "\t\tmeta skuid 61002 accept",
  "\t\tmeta skuid 61001 ip daddr 127.0.0.1 tcp dport 8080 accept",
  "\t\tmeta skuid 61001 drop",
  "\t}",
  "}",
].join("\n");

function listingWithout(fragment: string): string {
  return INSTALLED_LISTING.split("\n")
    .filter((line) => !line.includes(fragment))
    .join("\n");
}

describe("renderNftables", () => {
  it("redirects the agent uid's tcp to the proxy port and drops everything else it sends", () => {
    const statements = statementsOf(renderNftables(BASE));

    expect(statements).toContain(REDIRECT_RULE);
    expect(statements).toContain(PROXY_EXEMPTION);
    // Last statement in the file, so nothing for this uid can slip past it.
    expect(statements[statements.length - 1]).toBe(DROP_RULE);
  });

  /**
   * Why the capture is scoped instead of blanket.
   *
   * REDIRECT has already replaced the destination by the time the proxy sees the socket, and Node
   * cannot ask the kernel what it was, so the proxy infers the port: 443 for TLS, because SNI
   * carries none. Capture :8443 under that inference and the agent's request for one service is
   * policed, allowed, and recorded as a different one on the same host. Leaving it uncaptured
   * sends it to the default-drop instead — refused rather than misrouted.
   */
  it("captures only the ports whose destination the proxy can recover from the stream", () => {
    const statements = statementsOf(renderNftables(BASE));
    const redirects = statements.filter((line) => line.includes("redirect to"));

    expect(redirects).toEqual([REDIRECT_RULE]);
    // Nothing widens the capture back out to every port.
    expect(statements.some((line) => line.includes("meta l4proto tcp redirect"))).toBe(false);
  });

  /**
   * The proxy's exemption, which is the single easiest thing to leave out.
   *
   * Without it the redirect applies to the proxy too: it dials the real destination, its own SYN is
   * rewritten back to the proxy port, and it connects to itself. Ordering is half the property —
   * nftables evaluates a chain top to bottom, so an exemption below the redirect never runs.
   */
  it("exempts the proxy uid above the redirect so the proxy is not looped into itself", () => {
    const statements = statementsOf(renderNftables(BASE));

    const exemption = statements.indexOf(PROXY_EXEMPTION);
    const redirect = statements.indexOf(REDIRECT_RULE);

    expect(exemption).toBeGreaterThanOrEqual(0);
    expect(redirect).toBeGreaterThan(exemption);
  });

  it("scopes the DNS allowance to the configured resolver", () => {
    const statements = statementsOf(renderNftables({ ...BASE, dnsResolver: "10.0.0.53" }));
    const dns = statements.filter((line) => line.includes("dport 53"));

    expect(dns).toContain("meta skuid 61001 ip daddr 10.0.0.53 udp dport 53 accept");
    expect(dns).toContain("meta skuid 61001 ip daddr 10.0.0.53 tcp dport 53 accept");
    // No blanket port-53 hole: every DNS rule names the one permitted address.
    expect(dns.every((line) => line.includes("10.0.0.53"))).toBe(true);
  });

  it("writes an ip6 match for an IPv6 resolver", () => {
    const statements = statementsOf(renderNftables({ ...BASE, dnsResolver: "2606:4700:4700::1111" }));

    expect(statements).toContain("meta skuid 61001 ip6 daddr 2606:4700:4700::1111 udp dport 53 accept");
    expect(statements.some((line) => line.includes("ip daddr 2606"))).toBe(false);
  });

  it("permits no DNS at all when no resolver is configured", () => {
    const statements = statementsOf(renderNftables(BASE));

    expect(statements.some((line) => line.includes("dport 53"))).toBe(false);
  });

  it("allows the agent no loopback beyond the proxy port when allowLoopback is false", () => {
    const statements = statementsOf(renderNftables(BASE));
    const loopback = statements.filter(
      (line) => line.endsWith(" accept") && /127\.0\.0|::1|oif "lo"/.test(line) && line.includes("skuid 61001")
    );

    // Exactly the post-NAT path to the proxy, nothing wider.
    expect(loopback).toEqual([
      "meta skuid 61001 ip daddr 127.0.0.1 tcp dport 8080 accept",
      "meta skuid 61001 ip6 daddr ::1 tcp dport 8080 accept",
    ]);
  });

  it("opens loopback in both chains when allowLoopback is true", () => {
    const statements = statementsOf(renderNftables({ ...BASE, allowLoopback: true }));

    // The nat chain must exempt it too, or a connection to a local database is redirected into an
    // HTTP proxy that cannot speak to it.
    expect(statements).toContain("meta skuid 61001 ip daddr 127.0.0.0/8 accept");
    expect(statements).toContain('meta skuid 61001 oif "lo" accept');
  });

  it("removes any prior table before creating this one, and renders identically every time", () => {
    const statements = statementsOf(renderNftables(BASE));

    expect(statements[0]).toBe("add table inet agentwall");
    expect(statements[1]).toBe("delete table inet agentwall");
    expect(statements[2]).toBe("table inet agentwall {");
    expect(renderNftables(BASE)).toBe(renderNftables(BASE));
  });

  it("refuses a spec that would produce a rule nobody meant, naming the field", () => {
    expect(() => renderNftables({ ...BASE, agentUid: 0 })).toThrow(/agentUid/);
    expect(() => renderNftables({ ...BASE, agentUid: 61002 })).toThrow(/agentUid/);
    expect(() => renderNftables({ ...BASE, proxyUid: 0 })).toThrow(/proxyUid/);
    expect(() => renderNftables({ ...BASE, proxyPort: 0 })).toThrow(/proxyPort/);
    expect(() => renderNftables({ ...BASE, proxyPort: 70000 })).toThrow(/proxyPort/);
    expect(() => renderNftables({ ...BASE, dnsResolver: "not-an-ip" })).toThrow(/dnsResolver/);
  });
});

describe("parsePerimeterStatus", () => {
  it("reports a well-formed table as installed", () => {
    const status = parsePerimeterStatus(INSTALLED_LISTING, BASE);

    expect(status).toEqual({ installed: true, redirectPresent: true, dropPresent: true, problems: [] });
  });

  /**
   * A redirect with no default-drop is the dangerous state: traffic flows, the ledger fills, and
   * everything the redirect does not match still leaves the host. It must never read as installed.
   */
  it("is not installed when the default-drop is missing, even though the redirect is there", () => {
    const status = parsePerimeterStatus(listingWithout("drop"), BASE);

    expect(status.redirectPresent).toBe(true);
    expect(status.dropPresent).toBe(false);
    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/drop/);
  });

  it("reports a redirect that targets a port the proxy is not on", () => {
    const status = parsePerimeterStatus(INSTALLED_LISTING.replace("redirect to :8080", "redirect to :9999"), BASE);

    expect(status.redirectPresent).toBe(false);
    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/9999/);
    expect(status.problems.join("\n")).toMatch(/8080/);
  });

  it("reports a missing proxy exemption in the chain that redirects", () => {
    const status = parsePerimeterStatus(listingWithout("skuid 61002"), BASE);

    expect(status.redirectPresent).toBe(true);
    expect(status.dropPresent).toBe(true);
    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/61002/);
  });

  it("reports rules stranded below the default-drop", () => {
    const stranded = INSTALLED_LISTING.replace(
      "\t\tmeta skuid 61001 drop",
      "\t\tmeta skuid 61001 drop\n\t\tmeta skuid 61001 udp dport 53 accept"
    );

    const status = parsePerimeterStatus(stranded, BASE);

    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/unreachable/);
  });

  /**
   * The pre-scoping ruleset: still redirecting, still dropping, and quietly misattributing every
   * TLS port that is not 443. Status must say so rather than reporting a healthy perimeter.
   */
  it("reports a redirect that captures every tcp port", () => {
    const unscoped = INSTALLED_LISTING.replace(
      "meta skuid 61001 tcp dport { 80, 443 } redirect to :8080",
      "meta skuid 61001 meta l4proto tcp redirect to :8080"
    );

    const status = parsePerimeterStatus(unscoped, BASE);

    expect(status.redirectPresent).toBe(true);
    expect(status.dropPresent).toBe(true);
    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/every TCP port/);
  });

  it("reports a capture that includes a port the proxy cannot name", () => {
    const widened = INSTALLED_LISTING.replace("{ 80, 443 }", "{ 80, 443, 8443 }");

    const status = parsePerimeterStatus(widened, BASE);

    expect(status.installed).toBe(false);
    expect(status.problems.join("\n")).toMatch(/8443/);
  });

  it("accepts a capture narrower than the renderer's, because an uncaptured port is refused", () => {
    const narrowed = INSTALLED_LISTING.replace("{ 80, 443 }", "443");

    const status = parsePerimeterStatus(narrowed, BASE);

    expect(status.installed).toBe(true);
    expect(status.problems).toEqual([]);
  });

  it("reports an absent table as not installed", () => {
    const status = parsePerimeterStatus("", BASE);

    expect(status).toEqual({
      installed: false,
      redirectPresent: false,
      dropPresent: false,
      problems: [expect.stringMatching(/not installed/)],
    });
  });
});

describe("runPerimeterCommand", () => {
  const ENV_KEYS = ["AGENTWALL_AGENT_UID", "AGENTWALL_PROXY_UID", "AGENTWALL_PROXY_PORT"];

  let stdout: string[];
  let stderr: string[];
  let savedEnv: Record<string, string | undefined>;

  beforeEach(() => {
    stdout = [];
    stderr = [];
    savedEnv = {};
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }

    jest.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      stdout.push(args.map(String).join(" "));
    });
    jest.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(" "));
    });

    spawnSyncMock.mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
  });

  it("plans a ruleset with no arguments and no privileged call", async () => {
    const code = await runPerimeterCommand(["plan"]);

    expect(code).toBe(0);
    expect(spawnSyncMock).not.toHaveBeenCalled();
    const printed = stdout.join("\n");
    expect(printed).toContain("add table inet agentwall");
    expect(printed).toContain("redirect to :8080");
    expect(printed).toContain("resolved spec");
  });

  it("plans with the operator's uids, port, resolver, and loopback choice", async () => {
    const code = await runPerimeterCommand([
      "plan",
      "--agent-uid",
      "4000",
      "--proxy-uid",
      "4001",
      "--proxy-port",
      "9090",
      "--dns-resolver",
      "1.1.1.1",
      "--allow-loopback",
    ]);

    expect(code).toBe(0);
    const statements = statementsOf(stdout.join("\n"));
    expect(statements).toContain("meta skuid 4000 tcp dport { 80, 443 } redirect to :9090");
    expect(statements).toContain("meta skuid 4001 accept");
    expect(statements).toContain("meta skuid 4000 ip daddr 1.1.1.1 udp dport 53 accept");
    expect(statements).toContain('meta skuid 4000 oif "lo" accept');
    expect(statements[statements.length - 1]).toBe("meta skuid 4000 drop");
  });

  it("refuses install without root, naming the privilege and the unprivileged alternative", async () => {
    // The refusal paths below are the real ones: this suite runs unprivileged.
    expect(process.getuid?.()).not.toBe(0);

    const code = await runPerimeterCommand(["install"]);

    expect(code).not.toBe(0);
    expect(spawnSyncMock).not.toHaveBeenCalled();
    expect(stderr.join("\n")).toMatch(/root/);
    expect(stderr.join("\n")).toMatch(/plan/);
  });

  it("refuses rollback without root", async () => {
    expect(process.getuid?.()).not.toBe(0);

    const code = await runPerimeterCommand(["rollback"]);

    expect(code).not.toBe(0);
    expect(spawnSyncMock).not.toHaveBeenCalled();
    expect(stderr.join("\n")).toMatch(/root/);
  });

  it("refuses to run a command without root rather than running it uncontained", async () => {
    expect(process.getuid?.()).not.toBe(0);

    const code = await runPerimeterCommand(["run", "--", "echo", "hello"]);

    expect(code).not.toBe(0);
    // Nothing was started: an uncontained agent is the outcome this refusal exists to prevent.
    expect(spawnSyncMock).not.toHaveBeenCalled();
    expect(stderr.join("\n")).toMatch(/root/);
  });

  it("rejects a spec the renderer would refuse, naming the field", async () => {
    const code = await runPerimeterCommand(["plan", "--proxy-port", "70000"]);

    expect(code).toBe(2);
    expect(stderr.join("\n")).toMatch(/proxyPort/);
  });

  it("rejects an unknown subcommand with usage", async () => {
    const code = await runPerimeterCommand(["enable"]);

    expect(code).toBe(2);
    expect(stderr.join("\n")).toMatch(/Usage: agentwall perimeter/);
  });
});
