import { RiskLevel } from "../types";

export type AgentwallInstanceRole = "local" | "managed" | "remote";
export type AgentwallInstanceStatus = "online" | "degraded" | "unknown";
export type AgentGatewayKind = "telegram" | "slack" | "discord" | "web" | "api" | "unknown";

export interface AgentwallFleetInstance {
  id: string;
  name: string;
  url: string;
  role: AgentwallInstanceRole;
  status: AgentwallInstanceStatus;
  environment?: string;
  region?: string;
  lastSeenAt?: string;
}

export interface AgentGateway {
  id: string;
  instanceId: string;
  kind: AgentGatewayKind;
  name: string;
  status: AgentwallInstanceStatus;
  channelCount: number;
  agentCount: number;
  lastSeenAt?: string;
}

export interface ObservedOrgChannel {
  id?: string;
  agentId: string;
  channelId: string;
  lastSeenAt: string;
  lastPlane: string;
  lastAction: string;
  riskLevel: RiskLevel;
  sessionIds: string[];
  userIds: string[];
  roleIds: string[];
}

export interface OrgChannel extends ObservedOrgChannel {
  id: string;
  instanceId: string;
  gatewayId: string;
  gatewayKind: AgentGatewayKind;
}

export interface OrgAgentLane {
  agentId: string;
  instanceIds: string[];
  gatewayIds: string[];
  channelIds: string[];
  highestRisk: RiskLevel;
  lastSeenAt?: string;
}

export interface OrganizationControlPlaneSummary {
  instances: number;
  gateways: number;
  agents: number;
  channels: number;
  configuredInstances: number;
  observedChannels: number;
}

export interface OrganizationControlPlaneSnapshot {
  summary: OrganizationControlPlaneSummary;
  instances: AgentwallFleetInstance[];
  gateways: AgentGateway[];
  agents: OrgAgentLane[];
  channels: OrgChannel[];
}

export interface OrganizationFederationSummaryPayload {
  schemaVersion: "agentwall.org.summary.v1";
  generatedAt: string;
  instance: AgentwallFleetInstance | null;
  capabilities: string[];
  summary: OrganizationControlPlaneSummary;
  controlPlane: OrganizationControlPlaneSnapshot;
}

export interface BuildOrganizationControlPlaneInput {
  localInstance: Omit<AgentwallFleetInstance, "role" | "status"> & Partial<Pick<AgentwallFleetInstance, "role" | "status">>;
  configuredInstances?: AgentwallFleetInstance[];
  observedChannels?: ObservedOrgChannel[];
  now?: string;
}

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

export function inferGatewayKind(channelId: string): AgentGatewayKind {
  const normalized = channelId.toLowerCase();
  if (normalized.startsWith("telegram:")) return "telegram";
  if (normalized.startsWith("slack:")) return "slack";
  if (normalized.startsWith("discord:")) return "discord";
  if (normalized.startsWith("web:")) return "web";
  if (normalized.startsWith("api:")) return "api";
  return "unknown";
}

function sanitizeFederationUrl(value: string): string {
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

function clonePublicInstance(instance: AgentwallFleetInstance): AgentwallFleetInstance {
  return {
    id: instance.id,
    name: instance.name,
    url: sanitizeFederationUrl(instance.url),
    role: instance.role,
    status: instance.status,
    environment: instance.environment,
    region: instance.region,
    lastSeenAt: instance.lastSeenAt,
  };
}

function cloneFederationInstance(instance: AgentwallFleetInstance): AgentwallFleetInstance {
  return clonePublicInstance(instance);
}

export function buildOrganizationFederationSummaryPayload(
  generatedAt: string,
  snapshot: OrganizationControlPlaneSnapshot
): OrganizationFederationSummaryPayload {
  const controlPlane: OrganizationControlPlaneSnapshot = {
    summary: { ...snapshot.summary },
    instances: snapshot.instances.map(cloneFederationInstance),
    gateways: snapshot.gateways.map((gateway) => ({ ...gateway })),
    agents: snapshot.agents.map((agent) => ({
      ...agent,
      instanceIds: [...agent.instanceIds],
      gatewayIds: [...agent.gatewayIds],
      channelIds: [...agent.channelIds],
    })),
    channels: snapshot.channels.map((channel) => ({
      ...channel,
      sessionIds: [],
      userIds: [],
      roleIds: [],
    })),
  };
  const instance = controlPlane.instances.find((item) => item.role === "local") ?? controlPlane.instances[0] ?? null;
  return {
    schemaVersion: "agentwall.org.summary.v1",
    generatedAt,
    instance,
    capabilities: [
      "org-summary-read",
      "redacted-federation-export",
      "instance-inventory",
      "gateway-inventory",
      "agent-inventory",
      "channel-inventory",
    ],
    summary: controlPlane.summary,
    controlPlane,
  };
}

export function buildGatewayId(instanceId: string, kind: AgentGatewayKind): string {
  return `${instanceId}:${kind}`;
}

export function buildOrganizationControlPlaneSnapshot(input: BuildOrganizationControlPlaneInput): OrganizationControlPlaneSnapshot {
  const now = input.now ?? new Date().toISOString();
  const localInstance: AgentwallFleetInstance = {
    ...input.localInstance,
    role: input.localInstance.role ?? "local",
    status: input.localInstance.status ?? "online",
    lastSeenAt: input.localInstance.lastSeenAt ?? now,
  };
  const configuredInstances = input.configuredInstances ?? [];
  const instancesById = new Map<string, AgentwallFleetInstance>();
  for (const instance of [localInstance, ...configuredInstances]) {
    instancesById.set(instance.id, clonePublicInstance(instance));
  }

  const channels: OrgChannel[] = (input.observedChannels ?? [])
    .map((channel) => {
      const gatewayKind = inferGatewayKind(channel.channelId);
      const gatewayId = buildGatewayId(localInstance.id, gatewayKind);
      return {
        ...channel,
        id: channel.id ?? `${localInstance.id}:${channel.agentId}:${channel.channelId}`,
        instanceId: localInstance.id,
        gatewayId,
        gatewayKind,
      };
    })
    .sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt) || left.channelId.localeCompare(right.channelId));

  const gatewayMap = new Map<string, AgentGateway>();
  for (const channel of channels) {
    const existing = gatewayMap.get(channel.gatewayId) ?? {
      id: channel.gatewayId,
      instanceId: channel.instanceId,
      kind: channel.gatewayKind,
      name: channel.gatewayKind === "unknown" ? "Unknown gateway" : `${channel.gatewayKind[0].toUpperCase()}${channel.gatewayKind.slice(1)} gateway`,
      status: "online" as const,
      channelCount: 0,
      agentCount: 0,
      lastSeenAt: channel.lastSeenAt,
    };
    existing.channelCount += 1;
    existing.lastSeenAt = latestIso(existing.lastSeenAt, channel.lastSeenAt);
    gatewayMap.set(channel.gatewayId, existing);
  }

  const agentsByGateway = new Map<string, Set<string>>();
  for (const channel of channels) {
    const set = agentsByGateway.get(channel.gatewayId) ?? new Set<string>();
    set.add(channel.agentId);
    agentsByGateway.set(channel.gatewayId, set);
  }
  for (const gateway of Array.from(gatewayMap.values())) {
    gateway.agentCount = agentsByGateway.get(gateway.id)?.size ?? 0;
  }

  const agentMap = new Map<string, OrgAgentLane>();
  for (const channel of channels) {
    const existing = agentMap.get(channel.agentId) ?? {
      agentId: channel.agentId,
      instanceIds: [],
      gatewayIds: [],
      channelIds: [],
      highestRisk: "low" as RiskLevel,
      lastSeenAt: channel.lastSeenAt,
    };
    if (!existing.instanceIds.includes(channel.instanceId)) existing.instanceIds.push(channel.instanceId);
    if (!existing.gatewayIds.includes(channel.gatewayId)) existing.gatewayIds.push(channel.gatewayId);
    if (!existing.channelIds.includes(channel.channelId)) existing.channelIds.push(channel.channelId);
    existing.highestRisk = highestRisk(existing.highestRisk, channel.riskLevel);
    existing.lastSeenAt = latestIso(existing.lastSeenAt, channel.lastSeenAt);
    agentMap.set(channel.agentId, existing);
  }

  const instances = Array.from(instancesById.values()).sort((left, right) => {
    if (left.role !== right.role) return left.role === "local" ? -1 : right.role === "local" ? 1 : left.role.localeCompare(right.role);
    return left.name.localeCompare(right.name);
  });
  const gateways = Array.from(gatewayMap.values()).sort((left, right) => left.kind.localeCompare(right.kind));
  const agents = Array.from(agentMap.values()).sort((left, right) => left.agentId.localeCompare(right.agentId));

  return {
    summary: {
      instances: instances.length,
      gateways: gateways.length,
      agents: agents.length,
      channels: channels.length,
      configuredInstances: configuredInstances.length,
      observedChannels: channels.length,
    },
    instances,
    gateways,
    agents,
    channels,
  };
}
