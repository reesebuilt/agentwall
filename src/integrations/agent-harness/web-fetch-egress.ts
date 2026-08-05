import { AgentContext, NetworkRequest } from "../../types";
import { HarnessPreflightAdapter, HarnessPreflightConfig, HarnessPreflightEvent } from "./preflight";

export interface ObservedWebFetchConfig extends HarnessPreflightConfig {
  actor: {
    agentId: string;
    sessionId?: string;
  };
}

export interface ObservedWebFetchResult {
  status: number;
  finalUrl: string;
  text: string;
  blocked: boolean;
  preflight: {
    networkReason: string;
    policyReason: string;
    networkFailOpen: boolean;
    policyFailOpen: boolean;
  };
}

export class ObservedWebFetch {
  private readonly adapter: HarnessPreflightAdapter;
  private readonly actor: ObservedWebFetchConfig["actor"];

  constructor(config: ObservedWebFetchConfig) {
    this.adapter = new HarnessPreflightAdapter(config);
    this.actor = config.actor;
  }

  async fetch(url: string, init?: RequestInit): Promise<ObservedWebFetchResult> {
    const networkRequest: NetworkRequest = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: toHeaderRecord(init?.headers),
    };

    const context: AgentContext = {
      agentId: this.actor.agentId,
      sessionId: this.actor.sessionId,
      plane: "network",
      action: "web_fetch",
      payload: {
        url,
        method: networkRequest.method,
      },
      flow: {
        direction: "egress",
        target: url,
      },
    };

    const output = await this.adapter.runOutbound({
      networkRequest,
      context,
      execute: async () => {
        const response = await fetch(url, init);
        return {
          status: response.status,
          finalUrl: response.url,
          text: await response.text(),
        };
      },
    });

    if (output.blocked || !output.result) {
      throw new Error(`Outbound web fetch blocked by Agentwall preflight (${output.network.reason}; ${output.policy.reason})`);
    }

    return {
      ...output.result,
      blocked: false,
      preflight: {
        networkReason: output.network.reason,
        policyReason: output.policy.reason,
        networkFailOpen: output.network.failOpen,
        policyFailOpen: output.policy.failOpen,
      },
    };
  }
}

export function createObservedWebFetch(config: ObservedWebFetchConfig): ObservedWebFetch {
  return new ObservedWebFetch(config);
}

export type { HarnessPreflightEvent };

function toHeaderRecord(headers: RequestInit["headers"] | undefined): Record<string, string> | undefined {
  if (!headers) {
    return undefined;
  }

  if (headers instanceof Headers) {
    const output: Record<string, string> = {};
    headers.forEach((value, key) => {
      output[key] = value;
    });
    return output;
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }

  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    output[key] = Array.isArray(value) ? value.join(",") : String(value);
  }

  return output;
}
