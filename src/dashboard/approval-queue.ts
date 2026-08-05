const riskScore = { critical: 4, high: 3, medium: 2, low: 1 } as const;

export interface PendingApprovalPriorityItem {
  sessionId?: string;
  riskLevel?: string;
  createdAt?: string | number;
}

function countApprovalSessionLane<T extends PendingApprovalPriorityItem>(pending: T[], sessionId?: string): number {
  if (!sessionId) return 0;
  return pending.filter((item) => item.sessionId === sessionId).length;
}

export function summarizeApprovalSessionLane<T extends PendingApprovalPriorityItem>(pending: T[]): string | null {
  const next = pending[0];
  const sessionId = next?.sessionId;
  const laneCount = countApprovalSessionLane(pending, sessionId);
  if (!sessionId || laneCount <= 0) return null;
  return `${sessionId} · ${laneCount} pending ${laneCount === 1 ? "approval" : "approvals"} in this session`;
}

export function summarizeApprovalSessionLaneLabel<T extends PendingApprovalPriorityItem>(pending: T[], item?: T): string | null {
  const laneCount = countApprovalSessionLane(pending, item?.sessionId);
  if (laneCount <= 0) return null;
  return `${laneCount} pending ${laneCount === 1 ? "approval" : "approvals"} in this session`;
}

export interface FloodTelemetryPrioritySnapshot {
  pressureBySession?: Array<{ sessionId?: string; pressure?: number }>;
}

export function prioritizePendingApprovals<T extends PendingApprovalPriorityItem>(
  pending: T[],
  flood: FloodTelemetryPrioritySnapshot
): T[] {
  const pressureIndex = new Map((flood.pressureBySession ?? []).map((item) => [item.sessionId, item.pressure]));
  return [...pending].sort((left, right) => {
    const riskDelta = (riskScore[String(right.riskLevel) as keyof typeof riskScore] ?? 0)
      - (riskScore[String(left.riskLevel) as keyof typeof riskScore] ?? 0);
    if (riskDelta !== 0) return riskDelta;
    const pressureDelta = (pressureIndex.get(String(right.sessionId)) ?? 0)
      - (pressureIndex.get(String(left.sessionId)) ?? 0);
    if (pressureDelta !== 0) return pressureDelta;
    return String(left.createdAt).localeCompare(String(right.createdAt));
  });
}
