import {
  AgentGateway,
  AgentwallFleetInstance,
  AgentwallInstanceStatus,
  OrganizationControlPlaneSnapshot,
  OrganizationFederationSummaryPayload,
  OrgAgentLane,
  OrgChannel,
} from "./control-plane";
import { RiskLevel } from "../types";

export interface OrganizationPeerPollingInstance extends AgentwallFleetInstance {
  summaryUrl?: string;
  authTokenEnv?: string;
  authHeaderName?: string;
  pollTimeoutMs?: number;
}

export interface OrganizationPeerStatusRecord {
  id: string;
  name: string;
  url: string;
  summaryUrl: string;
  ok: boolean;
  status: AgentwallInstanceStatus;
  error?: string;
  httpStatus?: number;
  generatedAt?: string;
}

export interface OrganizationPeerPollResult {
  payloads: OrganizationFederationSummaryPayload[];
  peers: OrganizationPeerStatusRecord[];
}

export interface OrganizationPeerPollOptions {
  instances: OrganizationPeerPollingInstance[];
  fetchImpl?: OrganizationSummaryFetch;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  requireCapability?: string;
}

export type OrganizationSummaryFetch = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    signal?: AbortSignal;
  }
) => Promise<OrganizationSummaryFetchResponse>;

export interface OrganizationSummaryFetchResponse {
  ok: boolean;
  status: number;
  statusText?: string;
  json: () => Promise<unknown>;
}

const SUMMARY_SCHEMA_VERSION = "agentwall.org.summary.v1";
const DEFAULT_POLL_TIMEOUT_MS = 1_500;
const DEFAULT_REQUIRED_CAPABILITY = "org-summary-read";
const RISK_SCORE: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function highestRisk(left: RiskLevel, right: RiskLevel): RiskLevel {
  return RISK_SCORE[right] > RISK_SCORE[left] ? right : left;
}

function latestIso(left?: string, right?: string): string | undefined {
  return [left, right].filter(Boolean).sort().slice(-1)[0];
}

function publicUrl(value: string): string {
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    const sanitized = parsed.toString();
    return value.endsWith("/") ? sanitized : sanitized.replace(/\/$/, "");
  } catch {
    return value.replace(/\/\/[^/@]+@/, "//").split(/[?#]/)[0];
  }
}

function peerSummaryUrl(instance: OrganizationPeerPollingInstance): string {
  if (instance.summaryUrl) {
    return instance.summaryUrl;
  }
  try {
    const parsed = new URL(instance.url);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    parsed.pathname = `${parsed.pathname.replace(/\/$/, "")}/api/org/summary`;
    return parsed.toString();
  } catch {
    return `${instance.url.split(/[?#]/)[0].replace(/\/$/, "")}/api/org/summary`;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeErrorMessage(error: unknown, token?: string): string {
  if (error instanceof Error && error.name === "AbortError") {
    return "Peer summary poll timed out";
  }
  if (error instanceof Error && error.message.trim().length > 0) {
    let message = error.message
      .replace(/Bearer\s+[^\s,;]+/gi, "Bearer [redacted]")
      .replace(/\/\/[^/@\s]+@/g, "//[redacted]@")
      .replace(/([?&][^=&#\s]*(?:token|key|secret|password|passwd|credential|auth|signature|session)[^=&#\s]*=)[^&#\s]+/gi, "$1[redacted]");
    if (token) {
      message = message.replace(new RegExp(escapeRegExp(token), "g"), "[redacted]");
    }
    return message.slice(0, 240);
  }
  return "Peer summary poll failed";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasString(value: Record<string, unknown>, key: string): boolean {
  return typeof value[key] === "string" && String(value[key]).length > 0;
}

function hasArray(value: Record<string, unknown>, key: string): boolean {
  return Array.isArray(value[key]);
}

function assertString(value: Record<string, unknown>, key: string, label: string) {
  if (!hasString(value, key)) {
    throw new Error(`Remote org summary ${label}.${key} is missing`);
  }
}

function assertArray(value: Record<string, unknown>, key: string, label: string) {
  if (!hasArray(value, key)) {
    throw new Error(`Remote org summary ${label}.${key} is missing`);
  }
}

function assertNumber(value: Record<string, unknown>, key: string, label: string) {
  if (typeof value[key] !== "number" || !Number.isFinite(value[key])) {
    throw new Error(`Remote org summary ${label}.${key} is missing`);
  }
}

function assertRiskLevel(value: Record<string, unknown>, key: string, label: string) {
  if (!["low", "medium", "high", "critical"].includes(String(value[key]))) {
    throw new Error(`Remote org summary ${label}.${key} is invalid`);
  }
}

function validateControlPlaneItems(controlPlane: Record<string, unknown>) {
  (controlPlane.instances as unknown[]).forEach((item, index) => {
    if (!isRecord(item)) throw new Error(`Remote org summary controlPlane.instances[${index}] is invalid`);
    assertString(item, "id", `controlPlane.instances[${index}]`);
    assertString(item, "name", `controlPlane.instances[${index}]`);
    assertString(item, "url", `controlPlane.instances[${index}]`);
    assertString(item, "role", `controlPlane.instances[${index}]`);
    assertString(item, "status", `controlPlane.instances[${index}]`);
  });
  (controlPlane.gateways as unknown[]).forEach((item, index) => {
    if (!isRecord(item)) throw new Error(`Remote org summary controlPlane.gateways[${index}] is invalid`);
    assertString(item, "id", `controlPlane.gateways[${index}]`);
    assertString(item, "instanceId", `controlPlane.gateways[${index}]`);
    assertString(item, "kind", `controlPlane.gateways[${index}]`);
    assertString(item, "name", `controlPlane.gateways[${index}]`);
    assertString(item, "status", `controlPlane.gateways[${index}]`);
    assertNumber(item, "channelCount", `controlPlane.gateways[${index}]`);
    assertNumber(item, "agentCount", `controlPlane.gateways[${index}]`);
  });
  (controlPlane.agents as unknown[]).forEach((item, index) => {
    if (!isRecord(item)) throw new Error(`Remote org summary controlPlane.agents[${index}] is invalid`);
    assertString(item, "agentId", `controlPlane.agents[${index}]`);
    assertArray(item, "instanceIds", `controlPlane.agents[${index}]`);
    assertArray(item, "gatewayIds", `controlPlane.agents[${index}]`);
    assertArray(item, "channelIds", `controlPlane.agents[${index}]`);
    assertRiskLevel(item, "highestRisk", `controlPlane.agents[${index}]`);
  });
  (controlPlane.channels as unknown[]).forEach((item, index) => {
    if (!isRecord(item)) throw new Error(`Remote org summary controlPlane.channels[${index}] is invalid`);
    assertString(item, "id", `controlPlane.channels[${index}]`);
    assertString(item, "instanceId", `controlPlane.channels[${index}]`);
    assertString(item, "gatewayId", `controlPlane.channels[${index}]`);
    assertString(item, "gatewayKind", `controlPlane.channels[${index}]`);
    assertString(item, "agentId", `controlPlane.channels[${index}]`);
    assertString(item, "channelId", `controlPlane.channels[${index}]`);
    assertString(item, "lastSeenAt", `controlPlane.channels[${index}]`);
    assertString(item, "lastPlane", `controlPlane.channels[${index}]`);
    assertString(item, "lastAction", `controlPlane.channels[${index}]`);
    assertRiskLevel(item, "riskLevel", `controlPlane.channels[${index}]`);
    assertArray(item, "sessionIds", `controlPlane.channels[${index}]`);
    assertArray(item, "userIds", `controlPlane.channels[${index}]`);
    assertArray(item, "roleIds", `controlPlane.channels[${index}]`);
  });
}

function assertPeerIdentity(instance: OrganizationPeerPollingInstance, payload: OrganizationFederationSummaryPayload) {
  const remoteId = payload.instance?.id;
  if (remoteId !== instance.id) {
    throw new Error("Remote org summary identity mismatch");
  }
}

export function validateOrganizationFederationSummaryPayload(
  value: unknown,
  options: { requireCapability?: string | false } = {}
): OrganizationFederationSummaryPayload {
  if (!isRecord(value)) {
    throw new Error("Remote org summary payload must be an object");
  }
  if (value.ok === false) {
    throw new Error("Remote org summary returned ok=false");
  }
  if (value.schemaVersion !== SUMMARY_SCHEMA_VERSION) {
    throw new Error("Remote org summary schemaVersion is unsupported");
  }
  if (!hasString(value, "generatedAt")) {
    throw new Error("Remote org summary generatedAt is missing");
  }
  if (!hasArray(value, "capabilities")) {
    throw new Error("Remote org summary capabilities are missing");
  }
  const requiredCapability = options.requireCapability === undefined ? DEFAULT_REQUIRED_CAPABILITY : options.requireCapability;
  if (requiredCapability && !(value.capabilities as unknown[]).includes(requiredCapability)) {
    throw new Error(`Remote org summary missing ${requiredCapability} capability`);
  }
  if (!isRecord(value.summary)) {
    throw new Error("Remote org summary summary is missing");
  }
  if (!isRecord(value.controlPlane)) {
    throw new Error("Remote org summary controlPlane is missing");
  }
  const controlPlane = value.controlPlane;
  for (const key of ["instances", "gateways", "agents", "channels"] as const) {
    if (!Array.isArray(controlPlane[key])) {
      throw new Error(`Remote org summary controlPlane.${key} is missing`);
    }
  }
  validateControlPlaneItems(controlPlane);
  return value as unknown as OrganizationFederationSummaryPayload;
}

function addUnique(target: string[], values: string[]) {
  for (const value of values) {
    if (!target.includes(value)) {
      target.push(value);
    }
  }
}

function normalizeRemoteInstance(instance: AgentwallFleetInstance, localInstanceIds: Set<string>): AgentwallFleetInstance {
  return {
    id: instance.id,
    name: instance.name,
    url: publicUrl(instance.url),
    role: localInstanceIds.has(instance.id) ? "local" : instance.role === "local" ? "remote" : instance.role,
    status: instance.status,
    environment: instance.environment,
    region: instance.region,
    lastSeenAt: instance.lastSeenAt,
  };
}

function mergeInstance(existing: AgentwallFleetInstance, incoming: AgentwallFleetInstance): AgentwallFleetInstance {
  if (existing.role === "local") {
    return existing;
  }
  return {
    ...existing,
    name: existing.name || incoming.name,
    url: existing.url || incoming.url,
    status: incoming.status === "online" || existing.status === "unknown" ? incoming.status : existing.status,
    environment: existing.environment ?? incoming.environment,
    region: existing.region ?? incoming.region,
    lastSeenAt: latestIso(existing.lastSeenAt, incoming.lastSeenAt),
  };
}

function mergeAgent(existing: OrgAgentLane, incoming: OrgAgentLane): OrgAgentLane {
  const next: OrgAgentLane = {
    ...existing,
    instanceIds: [...existing.instanceIds],
    gatewayIds: [...existing.gatewayIds],
    channelIds: [...existing.channelIds],
    highestRisk: highestRisk(existing.highestRisk, incoming.highestRisk),
    lastSeenAt: latestIso(existing.lastSeenAt, incoming.lastSeenAt),
  };
  addUnique(next.instanceIds, incoming.instanceIds);
  addUnique(next.gatewayIds, incoming.gatewayIds);
  addUnique(next.channelIds, incoming.channelIds);
  return next;
}

function recomputeGatewayCounts(gateways: AgentGateway[], channels: OrgChannel[]): AgentGateway[] {
  return gateways.map((gateway) => {
    const gatewayChannels = channels.filter((channel) => channel.gatewayId === gateway.id);
    if (gatewayChannels.length === 0) {
      return { ...gateway };
    }
    return {
      ...gateway,
      channelCount: gatewayChannels.length,
      agentCount: new Set(gatewayChannels.map((channel) => channel.agentId)).size,
      lastSeenAt: gatewayChannels.reduce<string | undefined>((latest, channel) => latestIso(latest, channel.lastSeenAt), gateway.lastSeenAt),
    };
  });
}

export function mergeOrganizationControlPlaneSnapshots(
  local: OrganizationControlPlaneSnapshot,
  remotePayloads: OrganizationFederationSummaryPayload[] = [],
  peerStatuses: OrganizationPeerStatusRecord[] = []
): OrganizationControlPlaneSnapshot {
  const localInstanceIds = new Set(local.instances.filter((instance) => instance.role === "local").map((instance) => instance.id));
  const instances = new Map<string, AgentwallFleetInstance>();
  const gateways = new Map<string, AgentGateway>();
  const agents = new Map<string, OrgAgentLane>();
  const channels = new Map<string, OrgChannel>();

  for (const instance of local.instances) {
    instances.set(instance.id, normalizeRemoteInstance(instance, localInstanceIds));
  }
  for (const gateway of local.gateways) {
    gateways.set(gateway.id, { ...gateway });
  }
  for (const agent of local.agents) {
    agents.set(agent.agentId, {
      ...agent,
      instanceIds: [...agent.instanceIds],
      gatewayIds: [...agent.gatewayIds],
      channelIds: [...agent.channelIds],
    });
  }
  for (const channel of local.channels) {
    channels.set(channel.id, {
      ...channel,
      sessionIds: [...channel.sessionIds],
      userIds: [...channel.userIds],
      roleIds: [...channel.roleIds],
    });
  }

  for (const payload of remotePayloads) {
    for (const instance of payload.controlPlane.instances) {
      const normalized = normalizeRemoteInstance(instance, localInstanceIds);
      const existing = instances.get(normalized.id);
      instances.set(normalized.id, existing ? mergeInstance(existing, normalized) : normalized);
    }
    for (const gateway of payload.controlPlane.gateways) {
      if (!gateways.has(gateway.id)) {
        gateways.set(gateway.id, { ...gateway });
      }
    }
    for (const agent of payload.controlPlane.agents) {
      const normalized: OrgAgentLane = {
        ...agent,
        instanceIds: [...agent.instanceIds],
        gatewayIds: [...agent.gatewayIds],
        channelIds: [...agent.channelIds],
      };
      const existing = agents.get(normalized.agentId);
      agents.set(normalized.agentId, existing ? mergeAgent(existing, normalized) : normalized);
    }
    for (const channel of payload.controlPlane.channels) {
      if (!channels.has(channel.id)) {
        channels.set(channel.id, {
          ...channel,
          sessionIds: [...channel.sessionIds],
          userIds: [...channel.userIds],
          roleIds: [...channel.roleIds],
        });
      }
    }
  }

  for (const peer of peerStatuses) {
    const existing = instances.get(peer.id);
    if (!existing) {
      continue;
    }
    instances.set(peer.id, {
      ...existing,
      status: peer.status,
      lastSeenAt: peer.ok ? peer.generatedAt ?? existing.lastSeenAt : existing.lastSeenAt,
    });
  }

  const instanceList = Array.from(instances.values()).sort((left, right) => {
    if (left.role !== right.role) return left.role === "local" ? -1 : right.role === "local" ? 1 : left.role.localeCompare(right.role);
    return left.name.localeCompare(right.name);
  });
  const channelList = Array.from(channels.values()).sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt) || left.id.localeCompare(right.id));
  const gatewayList = recomputeGatewayCounts(Array.from(gateways.values()), channelList).sort((left, right) => left.id.localeCompare(right.id));
  const agentList = Array.from(agents.values()).sort((left, right) => left.agentId.localeCompare(right.agentId));

  return {
    summary: {
      instances: instanceList.length,
      gateways: gatewayList.length,
      agents: agentList.length,
      channels: channelList.length,
      configuredInstances: local.summary.configuredInstances,
      observedChannels: channelList.length,
    },
    instances: instanceList,
    gateways: gatewayList,
    agents: agentList,
    channels: channelList,
  };
}

export async function pollOrganizationPeerSummaries(options: OrganizationPeerPollOptions): Promise<OrganizationPeerPollResult> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch as unknown as OrganizationSummaryFetch | undefined;
  if (!fetchImpl) {
    return {
      payloads: [],
      peers: options.instances.map((instance) => ({
        id: instance.id,
        name: instance.name,
        url: publicUrl(instance.url),
        summaryUrl: publicUrl(peerSummaryUrl(instance)),
        ok: false,
        status: "unknown",
        error: "No fetch implementation available",
      })),
    };
  }

  const env = options.env ?? process.env;
  const requiredCapability = options.requireCapability === undefined ? DEFAULT_REQUIRED_CAPABILITY : options.requireCapability;
  const results = await Promise.all(options.instances.map(async (instance) => {
    const summaryUrl = peerSummaryUrl(instance);
    const controller = new AbortController();
    const timeoutMs = instance.pollTimeoutMs ?? options.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const headers: Record<string, string> = { Accept: "application/json" };
    const token = instance.authTokenEnv ? env[instance.authTokenEnv] : undefined;
    if (token) {
      if (instance.authHeaderName && instance.authHeaderName !== "Authorization") {
        headers[instance.authHeaderName] = token;
      } else {
        headers.Authorization = `Bearer ${token}`;
      }
    }

    try {
      const response = await fetchImpl(summaryUrl, { method: "GET", headers, signal: controller.signal });
      if (!response.ok) {
        return {
          payload: null,
          peer: {
            id: instance.id,
            name: instance.name,
            url: publicUrl(instance.url),
            summaryUrl: publicUrl(summaryUrl),
            ok: false,
            status: "degraded" as const,
            httpStatus: response.status,
            error: `Peer summary returned HTTP ${response.status}`,
          },
        };
      }
      const payload = validateOrganizationFederationSummaryPayload(await response.json(), { requireCapability: requiredCapability });
      assertPeerIdentity(instance, payload);
      return {
        payload,
        peer: {
          id: instance.id,
          name: instance.name,
          url: publicUrl(instance.url),
          summaryUrl: publicUrl(summaryUrl),
          ok: true,
          status: "online" as const,
          generatedAt: payload.generatedAt,
        },
      };
    } catch (error) {
      return {
        payload: null,
        peer: {
          id: instance.id,
          name: instance.name,
          url: publicUrl(instance.url),
          summaryUrl: publicUrl(summaryUrl),
          ok: false,
          status: error instanceof Error && error.name === "AbortError" ? "unknown" as const : "degraded" as const,
          error: safeErrorMessage(error, token),
        },
      };
    } finally {
      clearTimeout(timeout);
    }
  }));

  return {
    payloads: results.map((result) => result.payload).filter((payload): payload is OrganizationFederationSummaryPayload => Boolean(payload)),
    peers: results.map((result) => result.peer),
  };
}
