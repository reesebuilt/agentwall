import { describe, expect, it } from "@jest/globals";
import {
  createManifestAttestation,
  detectManifestDrift,
  hashManifest,
} from "../src/integrity/manifest";

describe("Manifest integrity", () => {
  it("produces stable hashes for equivalent manifests", () => {
    const left = hashManifest({ b: 2, a: 1 });
    const right = hashManifest({ a: 1, b: 2 });
    expect(left.hash).toBe(right.hash);
  });

  it("marks a matching attested manifest as trusted", () => {
    const manifest = { command: "stdio", tools: ["search"] };
    const approvedFingerprint = hashManifest(manifest);
    approvedFingerprint.attestation = createManifestAttestation({
      subjectId: "mcp:search",
      subjectType: "mcp_server",
      fingerprint: approvedFingerprint,
      signer: "agentwall-test",
    });

    const result = detectManifestDrift({
      subjectId: "mcp:search",
      subjectType: "mcp_server",
      manifest,
      approvedFingerprint,
    });

    expect(result.status).toBe("approved");
    expect(result.changed).toBe(false);
    expect(result.requiresReapproval).toBe(false);
    expect(result.trustState).toBe("trusted");
    expect(result.attestation.status).toBe("valid");
    expect(result.attestation.signer).toBe("agentwall-test");
  });

  it("marks a matching unattested manifest for operator review", () => {
    const approvedFingerprint = hashManifest({ command: "stdio", tools: ["search"] });
    const result = detectManifestDrift({
      subjectId: "mcp:search",
      subjectType: "mcp_server",
      manifest: { command: "stdio", tools: ["search"] },
      approvedFingerprint,
    });

    expect(result.status).toBe("approved");
    expect(result.changed).toBe(false);
    expect(result.requiresReapproval).toBe(true);
    expect(result.trustState).toBe("review_required");
    expect(result.attestation.status).toBe("missing");
  });

  it("marks a drifted manifest as untrusted", () => {
    const approvedFingerprint = hashManifest({ command: "stdio", tools: ["search"] });
    approvedFingerprint.attestation = createManifestAttestation({
      subjectId: "mcp:search",
      subjectType: "mcp_server",
      fingerprint: approvedFingerprint,
      signer: "agentwall-test",
    });

    const result = detectManifestDrift({
      subjectId: "mcp:search",
      subjectType: "mcp_server",
      manifest: { command: "stdio", tools: ["search", "write"] },
      approvedFingerprint,
    });

    expect(result.status).toBe("drifted");
    expect(result.requiresReapproval).toBe(true);
    expect(result.changed).toBe(true);
    expect(result.trustState).toBe("untrusted");
  });
});
