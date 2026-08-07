import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "@jest/globals";

const publicDir = join(__dirname, "..", "public");
const html = readFileSync(join(publicDir, "bootstrap.html"), "utf8");
const script = readFileSync(join(publicDir, "bootstrap.js"), "utf8");

describe("bootstrap console contract", () => {
  it("offers every fixed pre-start action with accessible feedback", () => {
    expect(html).toContain("Setup");
    expect(html).toContain("Initialize files");
    expect(html).toContain("Run onboarding");
    expect(html).toContain("Start Agentwall");
    expect(html).toContain("Development mode");
    expect(html).toContain("Stop Agentwall");
    expect(html).toContain('aria-live="polite"');
  });

  it("calls only typed bootstrap routes", () => {
    for (const route of ["status", "setup", "init", "onboard", "start", "dev", "stop"]) {
      expect(script).toContain(`/api/bootstrap/${route}`);
    }
    expect(script).not.toContain("/api/operator/actions");
    expect(script).not.toContain("command:");
    expect(script).not.toContain("localStorage");
  });

  it("handles connection and reduced-motion states", () => {
    expect(script).toContain("prefers-reduced-motion");
    expect(script).toContain("setConnectionState");
    expect(html).toContain('data-state="loading"');
    expect(script).toContain('credentials: "same-origin"');
    expect(script).toContain("Copy this environment now. AgentWall does not store the credential.");
  });
});
