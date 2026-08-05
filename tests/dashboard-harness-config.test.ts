import { afterAll, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * The dashboard reads the agent harness's own config.yaml to describe the runtime context.
 * That file belongs to the harness, not to Agentwall, so its bytes are foreign input: it can
 * hold nothing but comments, be caught half-written while an editor saves it, or be
 * deliberately malformed by anyone who can write into the agent home. A YAML parse failure
 * there costs one panel its detail and nothing more, because an attacker who can blind the
 * whole operator view can then act unobserved.
 */
const agentHome = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-harness-home-"));
process.env["AGENTWALL_AGENT_HOME"] = agentHome;

afterAll(() => {
  fs.rmSync(agentHome, { recursive: true, force: true });
});

// Loaded through await import, not a static import, because state.ts resolves
// AGENTWALL_AGENT_HOME once at module load and static imports are evaluated before the
// assignment above runs. This test exercises that module-loading boundary on purpose.
async function snapshotFacts(harnessConfig: string): Promise<Array<{ label: string; value: string }>> {
  fs.writeFileSync(path.join(agentHome, "config.yaml"), harnessConfig);
  const { RuntimeState } = await import("../src/dashboard/state");
  const { loadConfig } = await import("../src/config");
  const snapshot = new RuntimeState(loadConfig("examples/config.yaml")).getSnapshot(0);
  const entry = snapshot.knowledgeBase.entries.find((item) => item.id === "system_environment");
  expect(entry).toBeDefined();
  return entry?.facts ?? [];
}

describe("dashboard runtime context with an unreadable harness config", () => {
  it.each([
    ["a document with no content", "# nothing configured yet\n"],
    ["unparseable YAML", "model:\n\tdefault: gpt\n"],
    ["a truncated flow collection", "model: [\n"],
  ])("degrades one panel when the harness config is %s", async (_label, contents) => {
    const facts = await snapshotFacts(contents);

    // The file is present and was read; only the parse of it failed.
    expect(facts.find((fact) => fact.label === "Config file")?.value).toBe("configured");
    expect(facts.find((fact) => fact.label === "Config keys")?.value).toBe("none");
    expect(facts.find((fact) => fact.label === "Model")?.value).toBe("unknown");
  });

  it("still reports keys when the harness config parses", async () => {
    const facts = await snapshotFacts("model:\n  default: gpt-5\ndisplay:\n  skin: dark\n");

    expect(facts.find((fact) => fact.label === "Config keys")?.value).toBe("model, display");
    expect(facts.find((fact) => fact.label === "Model")?.value).toBe("gpt-5");
    expect(facts.find((fact) => fact.label === "Display skin")?.value).toBe("dark");
  });
});
