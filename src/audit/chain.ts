import { createHash } from "crypto";
import { AuditEvent } from "../types";

export interface AuditChainState {
  chainIndex: number;
  previousHash: string | null;
}

const HASH_ALGORITHM = "sha256";
// Deliberately NOT "verified": this is a write-time attestation that the record was
// linked, not evidence that anything checked it. Verification is verifyChainFile();
// authorship is a signed checkpoint; binding is an off-box anchor.
const HASH_STATUS = "chained-local";

type AuditPayloadValue = string | number | boolean | null | AuditPayloadValue[] | { [key: string]: AuditPayloadValue };

function normalizeAuditPayload(value: unknown): AuditPayloadValue | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (value === null) {
    return null;
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value as string | number | boolean;
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeAuditPayload(item) ?? null);
  }

  if (typeof value === "object") {
    const normalizedEntries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([key, nestedValue]) => {
        const normalizedValue = normalizeAuditPayload(nestedValue);
        return normalizedValue === undefined ? [] : [[key, normalizedValue] as const];
      });

    return Object.fromEntries(normalizedEntries) as { [key: string]: AuditPayloadValue };
  }

  return String(value);
}

export function canonicalizeAuditPayload(event: Omit<AuditEvent, "integrity">): string {
  return JSON.stringify(normalizeAuditPayload(event));
}

export function chainAuditEvent(event: Omit<AuditEvent, "integrity">, state: AuditChainState): AuditEvent {
  const canonicalPayload = canonicalizeAuditPayload(event);
  const hashMaterial = JSON.stringify({
    chainIndex: state.chainIndex,
    previousHash: state.previousHash,
    algorithm: HASH_ALGORITHM,
    payload: canonicalPayload,
  });
  const hash = createHash(HASH_ALGORITHM).update(hashMaterial).digest("hex");

  return {
    ...event,
    integrity: {
      chainIndex: state.chainIndex,
      hash,
      previousHash: state.previousHash,
      algorithm: HASH_ALGORITHM,
      status: HASH_STATUS,
    },
  };
}
