import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import {
  ManifestAttestationAssessment,
  ManifestAttestationEnvelope,
  ManifestDrift,
  ManifestFingerprint,
  ManifestSubjectType,
} from "../types";

const manifestAttestationSecret = randomBytes(32);

function stableSerialize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`);
    return `{${entries.join(",")}}`;
  }

  return JSON.stringify(value);
}

function signManifestAttestation(attestation: Omit<ManifestAttestationEnvelope, "signature">): string {
  return createHmac("sha256", manifestAttestationSecret).update(stableSerialize(attestation)).digest("hex");
}

function assessManifestAttestation(params: {
  subjectId: string;
  subjectType: ManifestSubjectType;
  approvedFingerprint?: ManifestFingerprint;
}): ManifestAttestationAssessment {
  const attestation = params.approvedFingerprint?.attestation;
  if (!params.approvedFingerprint) {
    return { status: "not_applicable" };
  }

  if (!attestation) {
    return { status: "missing" };
  }

  return {
    status: verifyManifestAttestation({
      subjectId: params.subjectId,
      subjectType: params.subjectType,
      fingerprint: params.approvedFingerprint,
      attestation,
    })
      ? "valid"
      : "invalid",
    signer: attestation.signer,
    issuedAt: attestation.issuedAt,
  };
}

export function hashManifest(manifest: unknown, source?: string): ManifestFingerprint {
  const normalized = stableSerialize(manifest);
  const hash = createHash("sha256").update(normalized).digest("hex");
  return {
    algorithm: "sha256",
    hash,
    manifestSize: Buffer.byteLength(normalized, "utf8"),
    source,
  };
}

export function createManifestAttestation(params: {
  subjectId: string;
  subjectType: ManifestSubjectType;
  fingerprint: ManifestFingerprint;
  signer?: string;
  issuedAt?: string | Date;
}): ManifestAttestationEnvelope {
  const issuedAt = params.issuedAt instanceof Date ? params.issuedAt.toISOString() : params.issuedAt ?? new Date().toISOString();
  const unsignedAttestation: Omit<ManifestAttestationEnvelope, "signature"> = {
    version: 1,
    algorithm: "hmac-sha256",
    subjectId: params.subjectId,
    subjectType: params.subjectType,
    fingerprintHash: params.fingerprint.hash,
    fingerprintAlgorithm: params.fingerprint.algorithm,
    issuedAt,
    signer: params.signer ?? "agentwall-local",
  };

  return {
    ...unsignedAttestation,
    signature: signManifestAttestation(unsignedAttestation),
  };
}

export function verifyManifestAttestation(params: {
  subjectId: string;
  subjectType: ManifestSubjectType;
  fingerprint: ManifestFingerprint;
  attestation: ManifestAttestationEnvelope;
}): boolean {
  const { attestation } = params;
  if (
    attestation.subjectId !== params.subjectId ||
    attestation.subjectType !== params.subjectType ||
    attestation.fingerprintHash !== params.fingerprint.hash ||
    attestation.fingerprintAlgorithm !== params.fingerprint.algorithm
  ) {
    return false;
  }

  const { signature, ...unsignedAttestation } = attestation;
  const expectedSignature = signManifestAttestation(unsignedAttestation);
  const providedBuffer = Buffer.from(signature, "utf8");
  const expectedBuffer = Buffer.from(expectedSignature, "utf8");

  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(providedBuffer, expectedBuffer);
}

export function detectManifestDrift(params: {
  subjectId: string;
  subjectType: ManifestSubjectType;
  manifest: unknown;
  approvedFingerprint?: ManifestFingerprint;
  source?: string;
}): ManifestDrift {
  const currentFingerprint = hashManifest(params.manifest, params.source);
  const approvedFingerprint = params.approvedFingerprint;
  const attestation = assessManifestAttestation({
    subjectId: params.subjectId,
    subjectType: params.subjectType,
    approvedFingerprint,
  });

  if (!approvedFingerprint) {
    return {
      subjectId: params.subjectId,
      subjectType: params.subjectType,
      status: "untracked",
      trustState: "review_required",
      changed: false,
      requiresReapproval: true,
      reason: "No approved manifest fingerprint recorded",
      attestation,
      currentFingerprint,
    };
  }

  if (approvedFingerprint.hash !== currentFingerprint.hash) {
    return {
      subjectId: params.subjectId,
      subjectType: params.subjectType,
      status: "drifted",
      trustState: "untrusted",
      changed: true,
      requiresReapproval: true,
      reason: "Manifest hash drift detected; re-approval required",
      attestation,
      currentFingerprint,
      approvedFingerprint,
    };
  }

  if (attestation.status === "valid") {
    return {
      subjectId: params.subjectId,
      subjectType: params.subjectType,
      status: "approved",
      trustState: "trusted",
      changed: false,
      requiresReapproval: false,
      reason: "Manifest fingerprint matches approved state and attestation is valid",
      attestation,
      currentFingerprint,
      approvedFingerprint,
    };
  }

  if (attestation.status === "missing") {
    return {
      subjectId: params.subjectId,
      subjectType: params.subjectType,
      status: "approved",
      trustState: "review_required",
      changed: false,
      requiresReapproval: true,
      reason: "Manifest fingerprint matches approved state but attestation is missing",
      attestation,
      currentFingerprint,
      approvedFingerprint,
    };
  }

  return {
    subjectId: params.subjectId,
    subjectType: params.subjectType,
    status: "approved",
    trustState: "untrusted",
    changed: false,
    requiresReapproval: true,
    reason: "Manifest fingerprint matches approved state but attestation is invalid",
    attestation,
    currentFingerprint,
    approvedFingerprint,
  };
}
