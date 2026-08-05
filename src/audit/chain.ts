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
// Names the canonical form the hash was computed over. Without the marker a verifier has
// to guess which key ordering the writer used, and a wrong guess is indistinguishable from
// a tampered record.
const CANON = "cu1";

type AuditPayloadValue = string | number | boolean | null | AuditPayloadValue[] | { [key: string]: AuditPayloadValue };

function emitCanonical(value: AuditPayloadValue): string {
  if (value === null || typeof value !== "object") {
    // Scalars reuse the serializer that emits the record line, so the canonical form
    // carries the same number and string lexemes that land on disk. A verifier reuses the
    // lexemes it reads instead of reimplementing ECMAScript number formatting.
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    // Array order is data and is never sorted: reordering items changes the payload, so it
    // must change the hash.
    return `[${value.map(emitCanonical).join(",")}]`;
  }

  // Members sort by UTF-16 code unit order. Plain `<` on JS strings is exactly that: no
  // locale, no case folding, no punctuation weighting. That is the point. A verifier in
  // another language reproduces this ordering from the bytes alone, whereas ICU collation
  // would require it to reproduce this runtime, ICU tables included. Realistic metadata
  // keys do disagree between the two orderings ("aws-key" and "aws_key" swap places), so a
  // collated hash lets an independent verifier call an untouched record tampered, which
  // destroys the evidence value of every record it cannot recompute.
  const keys = Object.keys(value).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${keys.map((key) => `${JSON.stringify(key)}:${emitCanonical(value[key])}`).join(",")}}`;
}

/**
 * Canonical form cu1: JSON where every object's members are sorted by UTF-16 code unit
 * order. This is the form new records name in integrity.canon.
 */
export function canonicalizeAuditPayload(event: Omit<AuditEvent, "integrity">): string {
  // The round trip flattens toJSON results, undefined members, and non-finite numbers to
  // the values the written line actually carries, so the hash covers what a reader of the
  // file sees rather than what the in-memory object held.
  return emitCanonical(JSON.parse(JSON.stringify(event)) as AuditPayloadValue);
}

function normalizeAuditPayloadLocaleLegacy(value: unknown): AuditPayloadValue | undefined {
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
    return value.map((item) => normalizeAuditPayloadLocaleLegacy(item) ?? null);
  }

  if (typeof value === "object") {
    const normalizedEntries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([key, nestedValue]) => {
        const normalizedValue = normalizeAuditPayloadLocaleLegacy(nestedValue);
        return normalizedValue === undefined ? [] : [[key, normalizedValue] as const];
      });

    return Object.fromEntries(normalizedEntries) as { [key: string]: AuditPayloadValue };
  }

  return String(value);
}

/**
 * The canonical form that predates cu1. Records carrying no canon marker are hashed under
 * locale collation and verify only through this path, so it stays: removing it declares an
 * operator's untouched history invalid, which is the same outcome as tampering.
 */
export function canonicalizeAuditPayloadLocaleLegacy(event: Omit<AuditEvent, "integrity">): string {
  return JSON.stringify(normalizeAuditPayloadLocaleLegacy(event));
}

/**
 * Bind a canonical payload to its position in the chain. Writer and verifier share this one
 * function because the member order below is part of the format: two derivations of the same
 * bytes drift apart and then report honest records as broken.
 */
function hashChainMaterial(canonicalPayload: string, state: AuditChainState): string {
  const hashMaterial = JSON.stringify({
    chainIndex: state.chainIndex,
    previousHash: state.previousHash,
    algorithm: HASH_ALGORITHM,
    payload: canonicalPayload,
  });
  return createHash(HASH_ALGORITHM).update(hashMaterial).digest("hex");
}

export function chainAuditEvent(event: Omit<AuditEvent, "integrity">, state: AuditChainState): AuditEvent {
  const hash = hashChainMaterial(canonicalizeAuditPayload(event), state);

  return {
    ...event,
    integrity: {
      chainIndex: state.chainIndex,
      hash,
      previousHash: state.previousHash,
      algorithm: HASH_ALGORITHM,
      status: HASH_STATUS,
      canon: CANON,
    },
  };
}

/**
 * Recompute a written record's hash the way that record says it was computed.
 *
 * A cu1 record has exactly one derivation. A record with no marker predates the marker, so
 * both derivations are tried and the one matching the stored hash is accepted: keys that
 * sort identically under both comparators are unambiguous, and keys that disagree still
 * belong to the writer's untampered record. When neither matches, the cu1 value is returned
 * so a genuine mismatch is reported against the format new records use rather than against
 * a form nothing writes.
 */
export function rehashAuditEvent(event: AuditEvent): string {
  const { integrity, ...rest } = event;
  const payload = rest as Omit<AuditEvent, "integrity">;
  const state: AuditChainState = {
    chainIndex: integrity.chainIndex,
    previousHash: integrity.previousHash,
  };

  const current = hashChainMaterial(canonicalizeAuditPayload(payload), state);
  if (integrity.canon === CANON || current === integrity.hash) {
    return current;
  }

  const legacy = hashChainMaterial(canonicalizeAuditPayloadLocaleLegacy(payload), state);
  return legacy === integrity.hash ? legacy : current;
}
