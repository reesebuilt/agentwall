import { describe, expect, it } from "@jest/globals";
import { classifyContent, defaultTrustForSource, scanText } from "../src/planes/identity/dlp";

describe("DLP Scanner", () => {
  it("detects AWS access keys", () => {
    const result = scanText("My key is AKIAIOSFODNN7EXAMPLE and my secret is hidden.");
    expect(result.containsSecrets).toBe(true);
    expect(result.secretTypes).toContain("aws-access-key");
  });

  it("detects GitHub PATs", () => {
    const result = scanText("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
    expect(result.containsSecrets).toBe(true);
    expect(result.secretTypes).toContain("github-pat");
  });

  it("detects SSNs", () => {
    const result = scanText("SSN: 123-45-6789");
    expect(result.containsPII).toBe(true);
    expect(result.piiTypes).toContain("ssn");
  });

  it("redacts detected secrets", () => {
    const result = scanText("key: AKIAIOSFODNN7EXAMPLE rest of text", true);
    expect(result.redactedText).toContain("[REDACTED:AWS-KEY]");
    expect(result.redactedText).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("maps sources to trust defaults", () => {
    expect(defaultTrustForSource("system")).toBe("trusted");
    expect(defaultTrustForSource("web")).toBe("untrusted");
    expect(defaultTrustForSource("memory")).toBe("derived");
  });

  it("classifyContent assigns provenance labels", () => {
    const result = classifyContent("Contact alice@example.com", undefined, true, "email");
    expect(result.source).toBe("email");
    expect(result.trustLabel).toBe("untrusted");
    expect(result.labels).toContain("pii");
    expect(result.labels).toContain("cross_boundary");
  });

  it("classifyContent preserves explicit trusted labels", () => {
    const result = classifyContent("Hello world", "trusted", true, "system");
    expect(result.trustLabel).toBe("trusted");
    expect(result.riskLevel).toBe("low");
  });
});
