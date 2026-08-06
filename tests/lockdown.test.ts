import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { registerAuditSink, resetAuditChain } from "../src/audit/logger";
import type { AuditEvent } from "../src/types";
import type { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import {
  engageLockdown,
  initLockdown,
  lockdownState,
  releaseLockdown,
  resetLockdown,
} from "../src/runtime/lockdown";

/**
 * The emergency stop's contract.
 *
 * The properties worth defending are the ones that make the stop trustworthy under failure:
 * four channels that each work alone, a release that only clears the channel it belongs to,
 * and no listener or timer left running after the module is torn down. The last one is not
 * cosmetic — an initLockdown that stacked a SIGUSR1 listener per server build would leak
 * silently in a long-lived process and hit Node's max-listeners warning in a test suite.
 *
 * The sentinel channel is driven with fake timers rather than a real short interval and a
 * sleep. The interval is still injected so the test states what period it is exercising,
 * but the clock is advanced explicitly: a wall-clock wait tuned to "long enough" is the
 * classic way to get a suite that passes locally and races on a loaded machine.
 */

const config: AgentwallConfig = {
  port: 0,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "always",
    timeoutMs: 30_000,
    backend: "memory",
  },
  policy: {
    defaultDecision: "deny",
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: ["api.openai.com"],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  enforcement: {
    mode: "monitor",
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: true,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

/** The poll period the sentinel tests exercise; the clock is advanced by hand, never waited on. */
const POLL_MS = 10;

const tempDirs: string[] = [];

function tempSentinelPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentwall-lockdown-"));
  tempDirs.push(dir);
  return join(dir, "STOP");
}

beforeEach(() => {
  resetLockdown();
  delete process.env.AGENTWALL_LOCKDOWN_FILE;
});

afterEach(() => {
  resetLockdown();
  delete process.env.AGENTWALL_LOCKDOWN_FILE;
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("lockdown activation sources", () => {
  it("activates from config alone", () => {
    initLockdown({ configActive: true });

    expect(lockdownState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("activates from the api source alone", () => {
    engageLockdown("api", "operator pulled the cord");

    const state = lockdownState();
    expect(state.active).toBe(true);
    expect(state.sources).toEqual(["api"]);
    expect(state.reason).toBe("operator pulled the cord");
  });

  it("activates from SIGUSR1 alone", () => {
    initLockdown();

    process.emit("SIGUSR1", "SIGUSR1");

    expect(lockdownState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("activates from a sentinel file alone", () => {
    const sentinel = tempSentinelPath();
    jest.useFakeTimers();
    try {
      initLockdown({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
      expect(lockdownState().active).toBe(false);

      writeFileSync(sentinel, "");
      jest.advanceTimersByTime(POLL_MS);

      expect(lockdownState()).toMatchObject({ active: true, sources: ["sentinel"] });
    } finally {
      jest.useRealTimers();
    }
  });

  it("reads the sentinel path from AGENTWALL_LOCKDOWN_FILE when none is passed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    process.env.AGENTWALL_LOCKDOWN_FILE = sentinel;

    initLockdown({ pollIntervalMs: POLL_MS });

    // Checked once before the timer is scheduled, so a process that starts with the
    // sentinel already in place comes up stopped rather than running for one interval.
    expect(lockdownState()).toMatchObject({ active: true, sources: ["sentinel"] });
  });

  it("lists every holding source, sorted", () => {
    initLockdown({ configActive: true });
    engageLockdown("api");
    process.emit("SIGUSR1", "SIGUSR1");

    expect(lockdownState().sources).toEqual(["api", "config", "signal"]);
  });

  it("treats re-engaging the same source as a no-op rather than a new period", () => {
    engageLockdown("api", "first reason");
    const first = lockdownState();

    engageLockdown("api", "second reason");
    const second = lockdownState();

    expect(second.sources).toEqual(["api"]);
    expect(second.since).toBe(first.since);
    expect(second.reason).toBe("first reason");
  });
});

describe("lockdown per-source release", () => {
  it("stays active when one of two sources releases, and names the one still holding", () => {
    initLockdown();
    engageLockdown("api", "operator");
    process.emit("SIGUSR1", "SIGUSR1");
    expect(lockdownState().sources).toEqual(["api", "signal"]);

    releaseLockdown("api");

    expect(lockdownState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("does NOT let an api release clear a config-held stop", () => {
    initLockdown({ configActive: true });
    engageLockdown("api", "operator");

    releaseLockdown("api");

    expect(lockdownState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("ignores a release for a source that holds nothing", () => {
    initLockdown({ configActive: true });

    releaseLockdown("api");
    releaseLockdown("sentinel");

    expect(lockdownState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("sets since on the first activation and clears it when the last source releases", () => {
    // The signal channel only exists once init has wired the handler.
    initLockdown();

    expect(lockdownState().since).toBeUndefined();

    engageLockdown("api", "operator");
    const since = lockdownState().since;
    expect(since).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);

    process.emit("SIGUSR1", "SIGUSR1");
    expect(lockdownState().since).toBe(since);

    releaseLockdown("api");
    expect(lockdownState().since).toBe(since);

    releaseLockdown("signal");
    expect(lockdownState()).toEqual({ active: false, sources: [] });
  });
});

describe("lockdown sentinel channel", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("releases when the sentinel file is removed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    initLockdown({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
    expect(lockdownState().active).toBe(true);

    rmSync(sentinel);
    jest.advanceTimersByTime(POLL_MS);

    expect(lockdownState()).toEqual({ active: false, sources: [] });
  });

  it("leaves other sources holding when the sentinel file is removed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    initLockdown({ sentinelPath: sentinel, pollIntervalMs: POLL_MS, configActive: true });
    expect(lockdownState().sources).toEqual(["config", "sentinel"]);

    rmSync(sentinel);
    jest.advanceTimersByTime(POLL_MS);

    expect(lockdownState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("keeps polling the configured path when a later init names none", () => {
    const sentinel = tempSentinelPath();
    initLockdown({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });

    // A rebuilt server calls init again with nothing to say about the sentinel. Dropping the
    // path there would retire the one channel that works when the API is wedged.
    initLockdown();
    writeFileSync(sentinel, "");
    jest.advanceTimersByTime(POLL_MS);

    expect(lockdownState()).toMatchObject({ active: true, sources: ["sentinel"] });
  });
});

describe("lockdown signal channel", () => {
  it("toggles on repeated SIGUSR1", () => {
    initLockdown();

    process.emit("SIGUSR1", "SIGUSR1");
    expect(lockdownState().active).toBe(true);

    process.emit("SIGUSR1", "SIGUSR1");
    expect(lockdownState()).toEqual({ active: false, sources: [] });

    process.emit("SIGUSR1", "SIGUSR1");
    expect(lockdownState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("does not stack listeners across repeated init", () => {
    expect(process.listenerCount("SIGUSR1")).toBe(0);

    for (let i = 0; i < 5; i += 1) {
      initLockdown({ pollIntervalMs: POLL_MS });
    }

    expect(process.listenerCount("SIGUSR1")).toBe(1);
  });
});

describe("lockdown teardown", () => {
  it("leaves no timer and no listener behind after reset", () => {
    const sentinel = tempSentinelPath();
    jest.useFakeTimers();
    try {
      initLockdown({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
      writeFileSync(sentinel, "");
      jest.advanceTimersByTime(POLL_MS);
      // The poll was genuinely running, so the absence proved below means something.
      expect(lockdownState().active).toBe(true);
      expect(process.listenerCount("SIGUSR1")).toBe(1);

      resetLockdown();

      expect(jest.getTimerCount()).toBe(0);
      expect(process.listenerCount("SIGUSR1")).toBe(0);

      // The sentinel is still on disk; nothing may re-engage from it once torn down.
      expect(existsSync(sentinel)).toBe(true);
      jest.advanceTimersByTime(POLL_MS * 100);
      expect(lockdownState()).toEqual({ active: false, sources: [] });
    } finally {
      jest.useRealTimers();
    }
  });
});

describe("lockdown audit evidence", () => {
  let events: AuditEvent[];

  beforeEach(() => {
    resetAuditChain();
    events = [];
    registerAuditSink((event) => {
      events.push(event);
    });
  });

  afterEach(() => {
    resetAuditChain();
  });

  it("records activation as a critical governance deny", () => {
    engageLockdown("api", "runaway agent");

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      plane: "governance",
      action: "lockdown:engage",
      decision: "deny",
      riskLevel: "critical",
    });
    expect(events[0].metadata).toMatchObject({
      lockdownSource: "api",
      lockdownActive: "true",
      lockdownReason: "runaway agent",
    });
  });

  it("records a full release as an allow, and a partial release as a still-denied stop", () => {
    initLockdown({ configActive: true });
    engageLockdown("api", "operator");
    events.length = 0;

    releaseLockdown("api");
    expect(events).toHaveLength(1);
    // Still held by config, so the posture recorded is still deny: an `allow` line here
    // would claim traffic resumed at a moment when it had not.
    expect(events[0]).toMatchObject({ action: "lockdown:release", decision: "deny", riskLevel: "critical" });
    expect(events[0].reasons).toContain("Lockdown remains engaged, held by: config");

    releaseLockdown("config");
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({ action: "lockdown:release", decision: "allow", riskLevel: "low" });
  });
});

describe("lockdown routes", () => {
  it("activates, reports, and releases through the operator API", async () => {
    const { app } = await buildServer(config);
    try {
      const idle = await app.inject({ method: "GET", url: "/lockdown" });
      expect(idle.statusCode).toBe(200);
      expect(idle.json()).toEqual({ active: false, sources: [] });

      const engaged = await app.inject({
        method: "POST",
        url: "/lockdown/engage",
        payload: { reason: "suspected exfiltration" },
      });
      expect(engaged.statusCode).toBe(200);
      expect(engaged.json()).toMatchObject({
        engaged: "api",
        active: true,
        sources: ["api"],
        reason: "suspected exfiltration",
      });

      const read = await app.inject({ method: "GET", url: "/lockdown" });
      expect(read.json()).toMatchObject({ active: true, sources: ["api"] });

      const released = await app.inject({ method: "POST", url: "/lockdown/release", payload: {} });
      expect(released.statusCode).toBe(200);
      expect(released.json()).toMatchObject({ released: "api", active: false, sources: [] });
    } finally {
      await app.close();
    }
  });

  it("says so explicitly when a release leaves the stop held by another source", async () => {
    const { app } = await buildServer(config);
    try {
      initLockdown({ configActive: true });
      await app.inject({ method: "POST", url: "/lockdown/engage", payload: {} });

      const released = await app.inject({ method: "POST", url: "/lockdown/release", payload: {} });

      const body = released.json();
      expect(body).toMatchObject({ released: "api", active: true, sources: ["config"] });
      expect(body.detail).toContain("remains ACTIVE");
      // No success flag that could be read as "traffic is flowing again".
      expect(body.ok).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it("rejects an activation body it cannot validate", async () => {
    const { app } = await buildServer(config);
    try {
      const res = await app.inject({
        method: "POST",
        url: "/lockdown/engage",
        payload: { reason: 42 },
      });

      expect(res.statusCode).toBe(400);
      expect(lockdownState().active).toBe(false);
    } finally {
      await app.close();
    }
  });

  it("rejects unauthenticated callers", async () => {
    const savedLoopback = process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
    const savedToken = process.env.AGENTWALL_OPERATOR_TOKEN;
    delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
    delete process.env.AGENTWALL_OPERATOR_TOKEN;

    const { app } = await buildServer(config);
    try {
      for (const route of [
        { method: "GET" as const, url: "/lockdown" },
        { method: "POST" as const, url: "/lockdown/engage" },
        { method: "POST" as const, url: "/lockdown/release" },
      ]) {
        const res = await app.inject({ method: route.method, url: route.url, payload: {} });
        expect({ url: route.url, status: res.statusCode }).toEqual({ url: route.url, status: 401 });
      }
      // The 401s above mean the allowlist model is working rather than the server being
      // globally broken: /health is the public path, and the lockdown routes are not on
      // that list.
      const health = await app.inject({ method: "GET", url: "/health" });
      expect(health.statusCode).toBe(200);
      // An unauthenticated caller must not have engaged the lockdown on the way to being refused.
      expect(lockdownState().active).toBe(false);
    } finally {
      await app.close();
      if (savedLoopback === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
      else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = savedLoopback;
      if (savedToken === undefined) delete process.env.AGENTWALL_OPERATOR_TOKEN;
      else process.env.AGENTWALL_OPERATOR_TOKEN = savedToken;
    }
  });
});
