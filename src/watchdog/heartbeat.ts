import { HeartbeatConfig, WatchdogState } from "../types";

export class HeartbeatWatchdog {
  private readonly config: HeartbeatConfig;

  constructor(config: HeartbeatConfig) {
    this.config = config;
  }

  evaluate(agentId: string, lastHeartbeatAt?: Date, now = new Date()): WatchdogState {
    if (!this.config.enabled) {
      return {
        agentId,
        status: "disabled",
        killSwitchEngaged: false,
        reason: "Watchdog disabled by configuration",
      };
    }

    if (!lastHeartbeatAt) {
      return this.makeExpired(agentId, "No heartbeat received");
    }

    const ageMs = now.getTime() - lastHeartbeatAt.getTime();
    if (ageMs >= this.config.timeoutMs) {
      return this.makeExpired(agentId, `Heartbeat expired after ${ageMs}ms`);
    }

    if (ageMs >= this.config.staleAfterMs) {
      return {
        agentId,
        status: "stale",
        lastHeartbeatAt: lastHeartbeatAt.toISOString(),
        killSwitchEngaged: false,
        reason: `Heartbeat stale after ${ageMs}ms`,
      };
    }

    return {
      agentId,
      status: "healthy",
      lastHeartbeatAt: lastHeartbeatAt.toISOString(),
      killSwitchEngaged: false,
      reason: "Heartbeat within policy",
    };
  }

  private makeExpired(agentId: string, reason: string): WatchdogState {
    return {
      agentId,
      status: "expired",
      killSwitchEngaged: this.config.killSwitchMode !== "monitor",
      reason,
    };
  }
}
