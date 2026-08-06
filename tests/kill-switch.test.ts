import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { registerAuditSink, resetAuditChain } from "../src/audit/logger";
import type { AuditEvent } from "../src/types";
import type { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import {
  activateKillSwitch,
  deactivateKillSwitch,
  initKillSwitch,
  killSwitchState,
  resetKillSwitch,
} from "../src/runtime/kill-switch";

/**
 * The emergency stop's contract.
 *
 * The properties worth defending are the ones that make the stop trustworthy under failure:
 * four channels that each work alone, a release that only clears the channel it belongs to,
 * and no listener or timer left running after the module is torn down. The last one is not
 * cosmetic — an initKillSwitch that stacked a SIGUSR1 listener per server build would leak
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
  const dir = mkdtempSync(join(tmpdir(), "agentwall-killswitch-"));
  tempDirs.push(dir);
  return join(dir, "STOP");
}

beforeEach(() => {
  resetKillSwitch();
  delete process.env.AGENTWALL_KILLSWITCH_FILE;
});

afterEach(() => {
  resetKillSwitch();
  delete process.env.AGENTWALL_KILLSWITCH_FILE;
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("kill switch activation sources", () => {
  it("activates from config alone", () => {
    initKillSwitch({ configActive: true });

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("activates from the api source alone", () => {
    activateKillSwitch("api", "operator pulled the cord");

    const state = killSwitchState();
    expect(state.active).toBe(true);
    expect(state.sources).toEqual(["api"]);
    expect(state.reason).toBe("operator pulled the cord");
  });

  it("activates from SIGUSR1 alone", () => {
    initKillSwitch();

    process.emit("SIGUSR1", "SIGUSR1");

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("activates from a sentinel file alone", () => {
    const sentinel = tempSentinelPath();
    jest.useFakeTimers();
    try {
      initKillSwitch({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
      expect(killSwitchState().active).toBe(false);

      writeFileSync(sentinel, "");
      jest.advanceTimersByTime(POLL_MS);

      expect(killSwitchState()).toMatchObject({ active: true, sources: ["sentinel"] });
    } finally {
      jest.useRealTimers();
    }
  });

  it("reads the sentinel path from AGENTWALL_KILLSWITCH_FILE when none is passed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    process.env.AGENTWALL_KILLSWITCH_FILE = sentinel;

    initKillSwitch({ pollIntervalMs: POLL_MS });

    // Checked once before the timer is scheduled, so a process that starts with the
    // sentinel already in place comes up stopped rather than running for one interval.
    expect(killSwitchState()).toMatchObject({ active: true, sources: ["sentinel"] });
  });

  it("lists every holding source, sorted", () => {
    initKillSwitch({ configActive: true });
    activateKillSwitch("api");
    process.emit("SIGUSR1", "SIGUSR1");

    expect(killSwitchState().sources).toEqual(["api", "config", "signal"]);
  });

  it("treats re-engaging the same source as a no-op rather than a new period", () => {
    activateKillSwitch("api", "first reason");
    const first = killSwitchState();

    activateKillSwitch("api", "second reason");
    const second = killSwitchState();

    expect(second.sources).toEqual(["api"]);
    expect(second.since).toBe(first.since);
    expect(second.reason).toBe("first reason");
  });
});

describe("kill switch per-source release", () => {
  it("stays active when one of two sources releases, and names the one still holding", () => {
    initKillSwitch();
    activateKillSwitch("api", "operator");
    process.emit("SIGUSR1", "SIGUSR1");
    expect(killSwitchState().sources).toEqual(["api", "signal"]);

    deactivateKillSwitch("api");

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("does NOT let an api release clear a config-held stop", () => {
    initKillSwitch({ configActive: true });
    activateKillSwitch("api", "operator");

    deactivateKillSwitch("api");

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("ignores a release for a source that holds nothing", () => {
    initKillSwitch({ configActive: true });

    deactivateKillSwitch("api");
    deactivateKillSwitch("sentinel");

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("sets since on the first activation and clears it when the last source releases", () => {
    // The signal channel only exists once init has wired the handler.
    initKillSwitch();

    expect(killSwitchState().since).toBeUndefined();

    activateKillSwitch("api", "operator");
    const since = killSwitchState().since;
    expect(since).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);

    process.emit("SIGUSR1", "SIGUSR1");
    expect(killSwitchState().since).toBe(since);

    deactivateKillSwitch("api");
    expect(killSwitchState().since).toBe(since);

    deactivateKillSwitch("signal");
    expect(killSwitchState()).toEqual({ active: false, sources: [] });
  });
});

describe("kill switch sentinel channel", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("releases when the sentinel file is removed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    initKillSwitch({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
    expect(killSwitchState().active).toBe(true);

    rmSync(sentinel);
    jest.advanceTimersByTime(POLL_MS);

    expect(killSwitchState()).toEqual({ active: false, sources: [] });
  });

  it("leaves other sources holding when the sentinel file is removed", () => {
    const sentinel = tempSentinelPath();
    writeFileSync(sentinel, "");
    initKillSwitch({ sentinelPath: sentinel, pollIntervalMs: POLL_MS, configActive: true });
    expect(killSwitchState().sources).toEqual(["config", "sentinel"]);

    rmSync(sentinel);
    jest.advanceTimersByTime(POLL_MS);

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["config"] });
  });

  it("keeps polling the configured path when a later init names none", () => {
    const sentinel = tempSentinelPath();
    initKillSwitch({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });

    // A rebuilt server calls init again with nothing to say about the sentinel. Dropping the
    // path there would retire the one channel that works when the API is wedged.
    initKillSwitch();
    writeFileSync(sentinel, "");
    jest.advanceTimersByTime(POLL_MS);

    expect(killSwitchState()).toMatchObject({ active: true, sources: ["sentinel"] });
  });
});

describe("kill switch signal channel", () => {
  it("toggles on repeated SIGUSR1", () => {
    initKillSwitch();

    process.emit("SIGUSR1", "SIGUSR1");
    expect(killSwitchState().active).toBe(true);

    process.emit("SIGUSR1", "SIGUSR1");
    expect(killSwitchState()).toEqual({ active: false, sources: [] });

    process.emit("SIGUSR1", "SIGUSR1");
    expect(killSwitchState()).toMatchObject({ active: true, sources: ["signal"] });
  });

  it("does not stack listeners across repeated init", () => {
    expect(process.listenerCount("SIGUSR1")).toBe(0);

    for (let i = 0; i < 5; i += 1) {
      initKillSwitch({ pollIntervalMs: POLL_MS });
    }

    expect(process.listenerCount("SIGUSR1")).toBe(1);
  });
});

describe("kill switch teardown", () => {
  it("leaves no timer and no listener behind after reset", () => {
    const sentinel = tempSentinelPath();
    jest.useFakeTimers();
    try {
      initKillSwitch({ sentinelPath: sentinel, pollIntervalMs: POLL_MS });
      writeFileSync(sentinel, "");
      jest.advanceTimersByTime(POLL_MS);
      // The poll was genuinely running, so the absence proved below means something.
      expect(killSwitchState().active).toBe(true);
      expect(process.listenerCount("SIGUSR1")).toBe(1);

      resetKillSwitch();

      expect(jest.getTimerCount()).toBe(0);
      expect(process.listenerCount("SIGUSR1")).toBe(0);

      // The sentinel is still on disk; nothing may re-engage from it once torn down.
      expect(existsSync(sentinel)).toBe(true);
      jest.advanceTimersByTime(POLL_MS * 100);
      expect(killSwitchState()).toEqual({ active: false, sources: [] });
    } finally {
      jest.useRealTimers();
    }
  });
});

describe("kill switch audit evidence", () => {
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
    activateKillSwitch("api", "runaway agent");

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      plane: "governance",
      action: "killswitch:activate",
      decision: "deny",
      riskLevel: "critical",
    });
    expect(events[0].metadata).toMatchObject({
      killSwitchSource: "api",
      killSwitchActive: "true",
      killSwitchReason: "runaway agent",
    });
  });

  it("records a full release as an allow, and a partial release as a still-denied stop", () => {
    initKillSwitch({ configActive: true });
    activateKillSwitch("api", "operator");
    events.length = 0;

    deactivateKillSwitch("api");
    expect(events).toHaveLength(1);
    // Still held by config, so the posture recorded is still deny: an `allow` line here
    // would claim traffic resumed at a moment when it had not.
    expect(events[0]).toMatchObject({ action: "killswitch:deactivate", decision: "deny", riskLevel: "critical" });
    expect(events[0].reasons).toContain("Kill switch remains engaged, held by: config");

    deactivateKillSwitch("config");
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({ action: "killswitch:deactivate", decision: "allow", riskLevel: "low" });
  });
});

describe("kill switch routes", () => {
  it("activates, reports, and releases through the operator API", async () => {
    const { app } = await buildServer(config);
    try {
      const idle = await app.inject({ method: "GET", url: "/killswitch" });
      expect(idle.statusCode).toBe(200);
      expect(idle.json()).toEqual({ active: false, sources: [] });

      const engaged = await app.inject({
        method: "POST",
        url: "/killswitch/activate",
        payload: { reason: "suspected exfiltration" },
      });
      expect(engaged.statusCode).toBe(200);
      expect(engaged.json()).toMatchObject({
        engaged: "api",
        active: true,
        sources: ["api"],
        reason: "suspected exfiltration",
      });

      const read = await app.inject({ method: "GET", url: "/killswitch" });
      expect(read.json()).toMatchObject({ active: true, sources: ["api"] });

      const released = await app.inject({ method: "POST", url: "/killswitch/deactivate", payload: {} });
      expect(released.statusCode).toBe(200);
      expect(released.json()).toMatchObject({ released: "api", active: false, sources: [] });
    } finally {
      await app.close();
    }
  });

  it("says so explicitly when a release leaves the stop held by another source", async () => {
    const { app } = await buildServer(config);
    try {
      initKillSwitch({ configActive: true });
      await app.inject({ method: "POST", url: "/killswitch/activate", payload: {} });

      const released = await app.inject({ method: "POST", url: "/killswitch/deactivate", payload: {} });

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
        url: "/killswitch/activate",
        payload: { reason: 42 },
      });

      expect(res.statusCode).toBe(400);
      expect(killSwitchState().active).toBe(false);
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
        { method: "GET" as const, url: "/killswitch" },
        { method: "POST" as const, url: "/killswitch/activate" },
        { method: "POST" as const, url: "/killswitch/deactivate" },
      ]) {
        const res = await app.inject({ method: route.method, url: route.url, payload: {} });
        expect(res.statusCode).toBe(401);
      }
      // An unauthenticated caller must not have moved the switch on the way to being refused.
      expect(killSwitchState().active).toBe(false);
    } finally {
      await app.close();
      if (savedLoopback === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
      else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = savedLoopback;
      if (savedToken === undefined) delete process.env.AGENTWALL_OPERATOR_TOKEN;
      else process.env.AGENTWALL_OPERATOR_TOKEN = savedToken;
    }
  });
});
