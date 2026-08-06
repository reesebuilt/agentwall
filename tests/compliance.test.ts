import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { ControlMapping, Framework, coverageSummary, mappingsFor, unmappedDetections } from "../src/compliance/mapping";
import { scoreConfig } from "../src/compliance/score";
import { detectionCatalog } from "../src/policy/detections";
import { builtinRules } from "../src/policy/rules";

/**
 * The integrity guard for the compliance mapping.
 *
 * A compliance table is the one artefact in a security project that nobody
 * verifies by using the product, so it is the one place where a false claim can
 * live indefinitely. These tests resolve EVERY evidence string in EVERY mapping
 * against the actual repository: a cited detection id must be in the catalog, a
 * cited rule id must be in the built-in rule set, a cited pattern id must be in
 * the pattern table, and a cited module must exist on disk. A mapping that cites
 * something imaginary fails here rather than misleading a reader.
 *
 * The classification test matters as much as the individual checks: an evidence
 * string of a shape nothing recognises would otherwise slip past every assertion
 * unexamined, which is exactly how this kind of guard rots.
 */

const REPO_ROOT = join(__dirname, "..");
const FRAMEWORKS: readonly Framework[] = ["owasp-llm", "owasp-agentic", "mitre-attack"];

const detectionIds = new Set(detectionCatalog.map((entry) => entry.id));
const ruleIds = new Set(builtinRules.map((rule) => rule.id));
const injectionSource = readFileSync(join(REPO_ROOT, "src/policy/injection.ts"), "utf8");

/** The catalog is a mutable export; the derivation test appends to it and must put it back. */
const catalogLength = detectionCatalog.length;

function allMappings(): ControlMapping[] {
  return FRAMEWORKS.flatMap((framework) => mappingsFor(framework));
}

function evidenceKind(item: string): "detection" | "rule" | "pattern" | "module" | "unrecognised" {
  if (item.startsWith("det.")) return "detection";
  if (item.startsWith("inj.")) return "pattern";
  if (item.includes("/") && item.endsWith(".ts")) return "module";
  if (item.includes(":")) return "rule";
  return "unrecognised";
}

afterEach(() => {
  detectionCatalog.length = catalogLength;
});

describe("control mapping integrity", () => {
  it("every claim of strong or partial coverage cites at least one piece of evidence", () => {
    const uncited = allMappings()
      .filter((row) => row.coverage !== "none" && row.evidence.length === 0)
      .map((row) => row.controlId);
    expect(uncited).toEqual([]);
  });

  it("claims of no coverage cite nothing, because there is nothing to cite", () => {
    const contradictory = allMappings()
      .filter((row) => row.coverage === "none" && row.evidence.length > 0)
      .map((row) => row.controlId);
    expect(contradictory).toEqual([]);
  });

  it("every cited detection id exists in the detection catalog", () => {
    const missing: string[] = [];
    for (const row of allMappings()) {
      for (const item of row.evidence) {
        if (evidenceKind(item) === "detection" && !detectionIds.has(item)) {
          missing.push(`${row.controlId} -> ${item}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("every cited rule id exists in the built-in rule set", () => {
    const missing: string[] = [];
    for (const row of allMappings()) {
      for (const item of row.evidence) {
        if (evidenceKind(item) === "rule" && !ruleIds.has(item)) {
          missing.push(`${row.controlId} -> ${item}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("every cited injection pattern id exists in the pattern table", () => {
    const missing: string[] = [];
    for (const row of allMappings()) {
      for (const item of row.evidence) {
        if (evidenceKind(item) === "pattern" && !injectionSource.includes(`patternId: "${item}"`)) {
          missing.push(`${row.controlId} -> ${item}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("every cited module path resolves to a file in this repository", () => {
    const missing: string[] = [];
    for (const row of allMappings()) {
      for (const item of row.evidence) {
        if (evidenceKind(item) === "module" && !existsSync(join(REPO_ROOT, item))) {
          missing.push(`${row.controlId} -> ${item}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("no evidence string is of a shape the checks above would skip", () => {
    const unrecognised: string[] = [];
    for (const row of allMappings()) {
      for (const item of row.evidence) {
        if (evidenceKind(item) === "unrecognised") unrecognised.push(`${row.controlId} -> ${item}`);
      }
    }
    expect(unrecognised).toEqual([]);
  });

  it("every mapping short of strong coverage states what is missing", () => {
    const silent = allMappings()
      .filter((row) => row.coverage !== "strong" && (row.gap ?? "").trim().length === 0)
      .map((row) => row.controlId);
    expect(silent).toEqual([]);
  });

  it("labels every row with the framework it was requested under", () => {
    for (const framework of FRAMEWORKS) {
      for (const row of mappingsFor(framework)) {
        expect(row.framework).toBe(framework);
      }
    }
  });

  it("hands back copies, so a caller cannot edit the tables through the result", () => {
    const first = mappingsFor("owasp-llm");
    first[0].coverage = "strong";
    first[0].evidence.push("det.does.not.exist");
    const second = mappingsFor("owasp-llm");
    expect(second[0].coverage).not.toBe("strong");
    expect(second[0].evidence).not.toContain("det.does.not.exist");
  });
});

describe("framework coverage", () => {
  it("covers all ten LLM controls exactly once", () => {
    const ids = mappingsFor("owasp-llm").map((row) => row.controlId);
    expect(ids.sort()).toEqual([
      "LLM01",
      "LLM02",
      "LLM03",
      "LLM04",
      "LLM05",
      "LLM06",
      "LLM07",
      "LLM08",
      "LLM09",
      "LLM10",
    ]);
  });

  it("covers all ten agentic controls exactly once", () => {
    const ids = mappingsFor("owasp-agentic").map((row) => row.controlId);
    expect(ids.sort()).toEqual([
      "ASI01",
      "ASI02",
      "ASI03",
      "ASI04",
      "ASI05",
      "ASI06",
      "ASI07",
      "ASI08",
      "ASI09",
      "ASI10",
    ]);
  });

  it("summarises coverage as a partition of the rows", () => {
    for (const framework of FRAMEWORKS) {
      const rows = mappingsFor(framework);
      const summary = coverageSummary(framework);
      expect(summary.total).toBe(rows.length);
      expect(summary.strong + summary.partial + summary.none).toBe(summary.total);
      expect(summary.strong).toBe(rows.filter((row) => row.coverage === "strong").length);
    }
  });
});

describe("derived ATT&CK view", () => {
  it("contains every technique the detection catalog names, and nothing else", () => {
    const catalogTechniques = new Set(
      detectionCatalog.filter((entry) => entry.mitreAttack).map((entry) => entry.mitreAttack!.techniqueId)
    );
    const derived = new Set(mappingsFor("mitre-attack").map((row) => row.controlId));
    expect([...catalogTechniques].sort()).toEqual([...derived].sort());
  });

  it("surfaces a technique added to the catalog without any edit to the mapping tables", () => {
    expect(mappingsFor("mitre-attack").map((row) => row.controlId)).not.toContain("T9999");

    detectionCatalog.push({
      id: "det.test.fixture.derived",
      ruleId: "net:block-ssrf-private",
      name: "Fixture detection",
      description: "Appended by tests to prove the ATT&CK view is computed from the catalog.",
      mitreAttack: { tactic: "Discovery", technique: "Fixture Technique", techniqueId: "T9999" },
      severity: "high",
    });

    const added = mappingsFor("mitre-attack").find((row) => row.controlId === "T9999");
    expect(added).toBeDefined();
    expect(added!.controlName).toBe("Fixture Technique");
    expect(added!.evidence).toContain("det.test.fixture.derived");
    expect(added!.evidence).toContain("net:block-ssrf-private");
  });

  it("rates a technique strong only when every backing rule denies", () => {
    const blocked = mappingsFor("mitre-attack").find((row) => row.controlId === "T1190");
    expect(blocked?.coverage).toBe("strong");
    expect(blocked?.gap).toBeUndefined();

    // T1552 is backed only by redaction rules: the call still happens.
    const redacted = mappingsFor("mitre-attack").find((row) => row.controlId === "T1552");
    expect(redacted?.coverage).toBe("partial");
    expect(redacted?.gap).toContain("mcp:redact-response-secret");
  });

  it("downgrades a technique whose weakest backing rule only gates the action", () => {
    // T1195 is denied for tool poisoning and merely approval-gated for inventory drift.
    const supplyChain = mappingsFor("mitre-attack").find((row) => row.controlId === "T1195");
    expect(supplyChain?.coverage).toBe("partial");
    expect(supplyChain?.gap).toContain("mcp:approve-tool-drift");
  });

  it("flags a detection whose backing rule is not in the built-in set", () => {
    detectionCatalog.push({
      id: "det.test.fixture.external",
      ruleId: "custom:operator-supplied",
      name: "Fixture detection with an external rule",
      description: "Appended by tests to prove an unbacked rule id is reported rather than assumed.",
      mitreAttack: { tactic: "Discovery", technique: "External Rule Technique", techniqueId: "T9998" },
      severity: "high",
    });

    const row = mappingsFor("mitre-attack").find((mapping) => mapping.controlId === "T9998");
    expect(row?.coverage).toBe("partial");
    expect(row?.gap).toContain("custom:operator-supplied");
    expect(row?.evidence).not.toContain("custom:operator-supplied");
  });
});

describe("unmappedDetections", () => {
  it("returns only ids that exist in the detection catalog", () => {
    for (const id of unmappedDetections()) {
      expect(detectionIds.has(id)).toBe(true);
    }
  });

  it("returns exactly the detections no hand-authored framework row cites", () => {
    const cited = new Set<string>();
    for (const row of [...mappingsFor("owasp-llm"), ...mappingsFor("owasp-agentic")]) {
      for (const item of row.evidence) {
        if (item.startsWith("det.")) cited.add(item);
      }
    }
    const expected = detectionCatalog.filter((entry) => !cited.has(entry.id)).map((entry) => entry.id);
    expect(unmappedDetections()).toEqual([...new Set(expected)]);
  });

  it("reports a newly appended detection that no framework row mentions", () => {
    detectionCatalog.push({
      id: "det.test.fixture.unmapped",
      ruleId: "net:block-ssrf-private",
      name: "Fixture detection nobody mapped",
      description: "Appended by tests to prove reverse drift is visible.",
      severity: "low",
    });
    expect(unmappedDetections()).toContain("det.test.fixture.unmapped");
  });
});

/** A deployment description with every scored signal set the way the docs recommend. */
function wellConfigured(): Record<string, unknown> {
  return {
    host: "127.0.0.1",
    port: 3000,
    env: {
      AGENTWALL_OPERATOR_TOKEN: "0123456789abcdef0123456789abcdef0123456789abcdef",
      AGENTWALL_AUDIT_FILE: "/var/lib/agentwall/audit.jsonl",
      AGENTWALL_PROXY_PORT: "3128",
      AGENTWALL_PROXY_LEDGER: "/var/lib/agentwall/egress.jsonl",
      AGENTWALL_LOCKDOWN_FILE: "/var/lib/agentwall/lockdown",
    },
    audit: { anchorIntervalMs: 21_600_000 },
    enforcement: { mode: "strict" },
    egress: {
      enabled: true,
      defaultDeny: true,
      allowPrivateRanges: false,
      allowedHosts: ["api.example.com"],
      allowedSchemes: ["https"],
      allowedPorts: [443],
    },
    policy: { defaultDecision: "deny", configPath: "./examples/policy.yaml" },
    approval: { mode: "always", timeoutMs: 30_000, backend: "file", persistencePath: "./agentwall-approvals.json" },
    dlp: { enabled: true, redactSecrets: true },
    telemetry: { enabled: true, endpoint: "http://collector.internal:4318/v1/traces" },
    watchdog: { enabled: true, staleAfterMs: 15_000, timeoutMs: 30_000, killSwitchMode: "deny_all" },
    runtimeGuards: {
      enabled: true,
      requestPerMinutePerSession: 180,
      toolActionPerMinutePerSession: 60,
      costBudgetPerHourPerSession: 1200,
    },
    manifestIntegrity: { enabled: true, approvedHashesPath: "./approved-manifests.json" },
  };
}

describe("scoreConfig", () => {
  it("grades a fully configured deployment at the top of the scale", () => {
    const score = scoreConfig(wellConfigured());
    expect(score.total).toBe(score.max);
    expect(score.grade).toBe("A");
    expect(score.capped).toBeUndefined();
    expect(score.categories.length).toBeGreaterThanOrEqual(12);
  });

  it("reports a category total that matches the categories it reports", () => {
    const score = scoreConfig(wellConfigured());
    expect(score.total).toBe(score.categories.reduce((sum, category) => sum + category.points, 0));
    expect(score.max).toBe(score.categories.reduce((sum, category) => sum + category.max, 0));
    expect(new Set(score.categories.map((category) => category.id)).size).toBe(score.categories.length);
  });

  it("forces F for a missing operator token however good everything else is", () => {
    const config = wellConfigured();
    const env = config["env"] as Record<string, string>;
    delete env["AGENTWALL_OPERATOR_TOKEN"];

    const score = scoreConfig(config);
    // The point of the cap: on the arithmetic alone this would have been a B.
    expect(score.total / score.max).toBeGreaterThan(0.8);
    expect(score.grade).toBe("F");
    expect(score.capped).toContain("no operator token");
    expect(score.capped).toContain(`${score.total}/${score.max}`);
  });

  it("forces F when the loopback development bypass is on and the bind host is not loopback", () => {
    const config = wellConfigured();
    config["host"] = "0.0.0.0";
    (config["env"] as Record<string, string>)["AGENTWALL_ALLOW_LOOPBACK_DEV"] = "1";

    const score = scoreConfig(config);
    expect(score.total / score.max).toBeGreaterThan(0.9);
    expect(score.grade).toBe("F");
    expect(score.capped).toContain("0.0.0.0");
  });

  it("does not cap the loopback development bypass when the listener is genuinely loopback", () => {
    const config = wellConfigured();
    (config["env"] as Record<string, string>)["AGENTWALL_ALLOW_LOOPBACK_DEV"] = "1";

    const score = scoreConfig(config);
    expect(score.capped).toBeUndefined();
    expect(score.grade).not.toBe("F");
    const exposure = score.categories.find((category) => category.id === "auth.exposure");
    expect(exposure?.points).toBeGreaterThan(0);
    expect(exposure?.points).toBeLessThan(exposure!.max);
    expect(exposure?.remediation).toBeTruthy();
  });

  it("gives every shortfall a concrete remediation", () => {
    const score = scoreConfig({});
    const shortWithoutAdvice = score.categories
      .filter((category) => category.points < category.max && !(category.remediation ?? "").trim())
      .map((category) => category.id);
    expect(shortWithoutAdvice).toEqual([]);
    expect(score.categories.every((category) => category.findings.length > 0)).toBe(true);
  });

  it("fails an empty description closed rather than giving it the benefit of the doubt", () => {
    const score = scoreConfig({});
    expect(score.grade).toBe("F");
    expect(score.capped).toContain("no operator token");
  });

  it("survives input that is not an object at all", () => {
    for (const input of [undefined, null, 42, "config", [1, 2, 3]]) {
      const score = scoreConfig(input);
      expect(score.grade).toBe("F");
      expect(score.max).toBeGreaterThan(0);
    }
  });

  it("flags strict enforcement with an empty egress allowlist as a misconfiguration", () => {
    const config = wellConfigured();
    (config["egress"] as Record<string, unknown>)["allowedHosts"] = [];

    const category = scoreConfig(config).categories.find((entry) => entry.id === "enforcement.mode");
    expect(category?.points).toBeLessThan(category!.max);
    expect(category?.findings.join(" ")).toContain("every outbound request is denied");
    expect(category?.remediation).toBeTruthy();
  });

  it("rejects an unrecognised enforcement mode outright", () => {
    const config = wellConfigured();
    config["enforcement"] = { mode: "paranoid" };

    const category = scoreConfig(config).categories.find((entry) => entry.id === "enforcement.mode");
    expect(category?.points).toBe(0);
    expect(category?.findings.join(" ")).toContain("not a recognised mode");
  });

  it("scores monitor mode low without capping, because monitor is a supported posture", () => {
    const config = wellConfigured();
    config["enforcement"] = { mode: "monitor" };

    const score = scoreConfig(config);
    expect(score.capped).toBeUndefined();
    const category = score.categories.find((entry) => entry.id === "enforcement.mode");
    expect(category?.points).toBeLessThan(category!.max);
    expect(category?.points).toBeGreaterThan(0);
  });

  it("scores a default-allow policy at zero for that category", () => {
    const config = wellConfigured();
    config["policy"] = { defaultDecision: "allow", configPath: "./examples/policy.yaml" };

    const score = scoreConfig(config);
    const category = score.categories.find((entry) => entry.id === "policy.default-decision");
    expect(category?.points).toBe(0);
    expect(category?.remediation).toContain('"deny"');
    // A weak default is a real deduction, not a critical exposure.
    expect(score.capped).toBeUndefined();
  });

  it("treats a blank operator token as no token", () => {
    const config = wellConfigured();
    (config["env"] as Record<string, string>)["AGENTWALL_OPERATOR_TOKEN"] = "   ";

    const score = scoreConfig(config);
    expect(score.grade).toBe("F");
    expect(score.capped).toContain("no operator token");
  });

  it("accepts a pre-resolved auth posture instead of an environment map", () => {
    const config = wellConfigured();
    delete config["env"];
    config["auth"] = { operatorTokenSet: true };

    const score = scoreConfig(config);
    expect(score.capped).toBeUndefined();
    expect(score.categories.find((entry) => entry.id === "auth.operator-token")?.points).toBe(15);
    // The env-only signals are still absent and still cost points.
    expect(score.categories.find((entry) => entry.id === "audit.evidence-file")?.points).toBe(0);
  });
});

/**
 * The docs restate the tables, so the docs can be wrong in a way the code is not.
 *
 * These read the shipped markdown and check it against the functions it claims to render.
 * The direction is deliberate: a row in the doc that the code does not produce is a
 * failure, because that is the case that misleads a reader, while a newly derived
 * technique the doc has not caught up with is merely incomplete and is reported by
 * unmappedDetections() rather than here. A failure names the exact row to fix.
 */
describe("shipped compliance docs", () => {
  it("states an ATT&CK coverage rating the derived view actually produces", () => {
    const doc = readFileSync(join(REPO_ROOT, "docs/owasp-mapping.md"), "utf8");
    const derived = new Map(mappingsFor("mitre-attack").map((row) => [row.controlId, row.coverage]));

    const rows = [...doc.matchAll(/^\|\s*`(T[\d.]+)`\s*\|[^|]*\|\s*`(strong|partial|none)`\s*\|/gm)];
    expect(rows.length).toBe(derived.size);

    const wrong: string[] = [];
    for (const [, techniqueId, coverage] of rows) {
      if (derived.get(techniqueId) !== coverage) {
        wrong.push(`${techniqueId}: doc says ${coverage}, code says ${derived.get(techniqueId) ?? "nothing"}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it("documents the scoring categories and point budget the scorer actually uses", () => {
    const doc = readFileSync(join(REPO_ROOT, "docs/compliance.md"), "utf8");
    const score = scoreConfig({});
    const maxById = new Map(score.categories.map((category) => [category.id, category.max]));

    const rows = [...doc.matchAll(/^\|\s*`([a-z][a-z.-]+)`\s*\|[^|]*\|\s*(\d+)\s*\|/gm)];
    expect(rows.map(([, id]) => id).sort()).toEqual([...maxById.keys()].sort());

    const wrong: string[] = [];
    for (const [, id, max] of rows) {
      if (maxById.get(id) !== Number(max)) wrong.push(`${id}: doc says ${max}, code says ${maxById.get(id)}`);
    }
    expect(wrong).toEqual([]);
    expect(doc).toContain(`${score.max} points`);
  });
});
