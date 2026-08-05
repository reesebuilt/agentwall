import { describe, expect, it } from "@jest/globals";
import { HeartbeatWatchdog } from "../src/watchdog/heartbeat";

describe("Heartbeat watchdog", () => {
  const watchdog = new HeartbeatWatchdog({
    enabled: true,
    staleAfterMs: 1000,
    timeoutMs: 5000,
    killSwitchMode: "deny_all",
  });

  it("marks recent heartbeats healthy", () => {
    const now = new Date("2026-03-15T12:00:00.000Z");
    const state = watchdog.evaluate("agent-1", new Date("2026-03-15T11:59:59.500Z"), now);
    expect(state.status).toBe("healthy");
    expect(state.killSwitchEngaged).toBe(false);
  });

  it("engages the kill switch when heartbeat expires", () => {
    const now = new Date("2026-03-15T12:00:06.000Z");
    const state = watchdog.evaluate("agent-1", new Date("2026-03-15T12:00:00.000Z"), now);
    expect(state.status).toBe("expired");
    expect(state.killSwitchEngaged).toBe(true);
  });
});
