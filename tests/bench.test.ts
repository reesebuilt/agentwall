import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  BENCH_CATEGORIES,
  BENCH_EXPECTATIONS,
  BENCH_INPUT_KINDS,
  BENCH_SEVERITIES,
  BenchCase,
  buildReport,
  classifyOutcome,
  exitCodeFor,
  formatReport,
} from "../bench/report";
import { CORPUS_DIR, loadCorpus, parseCorpusFile, runCorpus, toolCallContext } from "../bench/run";

/**
 * Guards the benchmark, not the detectors.
 *
 * The numbers the benchmark produces are only worth reading if the corpus
 * behind them is intact, so the assertions here are about the corpus and the
 * scoring: every file parses, every case is complete and uniquely named, the
 * benign half is large enough to be load-bearing, and the arithmetic that
 * turns outcomes into precision and recall is correct on inputs whose answer
 * can be worked out by hand.
 *
 * Nothing here asserts a detection rate. Pinning one would mean this suite
 * fails whenever a detector improves, and would quietly make the corpus a
 * regression baseline instead of a measurement. Detection numbers belong in
 * `npm run bench`, where a human reads them.
 */

const KNOWN_CATEGORIES = new Set<string>(BENCH_CATEGORIES);
const KNOWN_KINDS = new Set<string>(BENCH_INPUT_KINDS);
const KNOWN_EXPECTATIONS = new Set<string>(BENCH_EXPECTATIONS);
const KNOWN_SEVERITIES = new Set<string>(BENCH_SEVERITIES);

const corpus = loadCorpus();

describe("benchmark corpus", () => {
  it("every corpus file parses and declares a known category", () => {
    const files = readdirSync(CORPUS_DIR).filter((name) => name.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const cases = parseCorpusFile(readFileSync(join(CORPUS_DIR, file), "utf8"), file);
      expect(cases.length).toBeGreaterThan(0);
      for (const testCase of cases) expect(KNOWN_CATEGORIES.has(testCase.category)).toBe(true);
    }
  });

  it("every case carries every required field with a known value", () => {
    for (const testCase of corpus) {
      expect(typeof testCase.id).toBe("string");
      expect(testCase.id.length).toBeGreaterThan(0);
      expect(KNOWN_CATEGORIES.has(testCase.category)).toBe(true);
      expect(KNOWN_SEVERITIES.has(testCase.severity)).toBe(true);
      expect(KNOWN_KINDS.has(testCase.input.kind)).toBe(true);
      expect(testCase.input.value.length).toBeGreaterThan(0);
      expect(KNOWN_EXPECTATIONS.has(testCase.expect)).toBe(true);
      expect(testCase.why.trim().length).toBeGreaterThan(0);
    }
  });

  it("case ids are unique", () => {
    const duplicates = corpus
      .map((testCase) => testCase.id)
      .filter((id, index, all) => all.indexOf(id) !== index);
    expect(duplicates).toEqual([]);
  });

  it("holds at least 120 cases", () => {
    expect(corpus.length).toBeGreaterThanOrEqual(120);
  });

  /**
   * The floor exists because the benign half is the half that decides whether
   * the tool is usable. A corpus that drifts down to a handful of negatives
   * stops being able to distinguish a detector from a klaxon.
   */
  it("holds at least 40 cases that must not be flagged", () => {
    expect(corpus.filter((testCase) => testCase.expect === "ignore").length).toBeGreaterThanOrEqual(
      40,
    );
  });

  it("covers every category", () => {
    for (const category of BENCH_CATEGORIES) {
      expect(corpus.some((testCase) => testCase.category === category)).toBe(true);
    }
  });

  it("covers every input kind", () => {
    for (const kind of BENCH_INPUT_KINDS) {
      expect(corpus.some((testCase) => testCase.input.kind === kind)).toBe(true);
    }
  });
});

describe("benchmark corpus loading", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentwall-bench-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function corpusFile(body: unknown): string {
    return JSON.stringify(body);
  }

  const validCase = {
    id: "benign.example.one",
    category: "benign",
    severity: "low",
    input: { kind: "text", value: "hello" },
    expect: "ignore",
    why: "a case",
  };

  it("rejects a file whose case is missing a field", () => {
    const { why, ...withoutWhy } = validCase;
    expect(why).toBeDefined();
    expect(() =>
      parseCorpusFile(
        corpusFile({ category: "benign", description: "d", cases: [withoutWhy] }),
        "t.json",
      ),
    ).toThrow(/why/);
  });

  it("rejects a case whose expectation is not detect or ignore", () => {
    expect(() =>
      parseCorpusFile(
        corpusFile({
          category: "benign",
          description: "d",
          cases: [{ ...validCase, expect: "maybe" }],
        }),
        "t.json",
      ),
    ).toThrow(/expect/);
  });

  it("rejects a case filed under a category the file does not declare", () => {
    expect(() =>
      parseCorpusFile(
        corpusFile({
          category: "benign",
          description: "d",
          cases: [{ ...validCase, category: "ssrf" }],
        }),
        "t.json",
      ),
    ).toThrow(/declares category "ssrf"/);
  });

  it("rejects invalid JSON with the file name attached", () => {
    expect(() => parseCorpusFile("{ nope", "broken.json")).toThrow(/^broken\.json: invalid JSON/);
  });

  it("rejects a duplicate id across two files", () => {
    const body = corpusFile({ category: "benign", description: "d", cases: [validCase] });
    writeFileSync(join(dir, "a.json"), body);
    writeFileSync(join(dir, "b.json"), body);
    expect(() => loadCorpus(dir)).toThrow(/duplicate case id "benign\.example\.one"/);
  });

  it("reads every json file in the directory", () => {
    writeFileSync(
      join(dir, "a.json"),
      corpusFile({ category: "benign", description: "d", cases: [validCase] }),
    );
    writeFileSync(
      join(dir, "b.json"),
      corpusFile({
        category: "ssrf",
        description: "d",
        cases: [
          {
            id: "ssrf.example.one",
            category: "ssrf",
            severity: "critical",
            input: { kind: "url", value: "http://127.0.0.1/" },
            expect: "detect",
            why: "loopback",
          },
        ],
      }),
    );
    expect(loadCorpus(dir).map((testCase) => testCase.id)).toEqual([
      "benign.example.one",
      "ssrf.example.one",
    ]);
  });
});

describe("tool_call encoding", () => {
  it("splits the action from a free-text argument", () => {
    const ctx = toolCallContext("db.execute_query SELECT 1 FROM orders");
    expect(ctx.plane).toBe("tool");
    expect(ctx.action).toBe("db.execute_query");
    expect(ctx.payload).toEqual({ argument: "SELECT 1 FROM orders" });
  });

  it("leaves the payload empty when the case is an action alone", () => {
    expect(toolCallContext("metrics.read").payload).toEqual({});
  });
});

describe("benchmark scoring", () => {
  it("maps expectation and detection onto the four outcomes", () => {
    expect(classifyOutcome("detect", true)).toBe("true_positive");
    expect(classifyOutcome("detect", false)).toBe("false_negative");
    expect(classifyOutcome("ignore", true)).toBe("false_positive");
    expect(classifyOutcome("ignore", false)).toBe("true_negative");
  });

  /**
   * Hand-checkable arithmetic: 3 attacks of which 2 are caught, 3 benign of
   * which 1 is flagged. Precision 2/3, recall 2/3, F1 2/3.
   */
  const worked: BenchCase[] = [
    caseOf("ssrf.a", "ssrf", "detect"),
    caseOf("ssrf.b", "ssrf", "detect"),
    caseOf("ssrf.c", "ssrf", "detect"),
    caseOf("benign.a", "benign", "ignore"),
    caseOf("benign.b", "benign", "ignore"),
    caseOf("benign.c", "benign", "ignore"),
  ];

  const workedResults = [
    resultOf(worked[0], true, "critical", ["net:private-target"]),
    resultOf(worked[1], true, "critical", ["net:cloud-metadata"]),
    resultOf(worked[2], false, "none", []),
    resultOf(worked[3], true, "medium", ["dlp:email"]),
    resultOf(worked[4], false, "none", []),
    resultOf(worked[5], false, "none", []),
  ];

  it("computes precision, recall and F1 over a hand-checked set", () => {
    const report = buildReport(workedResults, worked);
    expect(report.overall.truePositives).toBe(2);
    expect(report.overall.falsePositives).toBe(1);
    expect(report.overall.trueNegatives).toBe(2);
    expect(report.overall.falseNegatives).toBe(1);
    expect(report.overall.precision).toBeCloseTo(2 / 3, 10);
    expect(report.overall.recall).toBeCloseTo(2 / 3, 10);
    expect(report.overall.f1).toBeCloseTo(2 / 3, 10);
    expect(report.overall.falsePositiveRate).toBeCloseTo(1 / 3, 10);
  });

  it("reports recall as null for a slice that contains no attacks", () => {
    const benign = buildReport(workedResults, worked).categories.find(
      (entry) => entry.category === "benign",
    );
    expect(benign?.recall).toBeNull();
    expect(benign?.f1).toBeNull();
  });

  it("reports precision as null when nothing was flagged at all", () => {
    const quiet = worked.map((testCase) => resultOf(testCase, false, "none", []));
    expect(buildReport(quiet, worked).overall.precision).toBeNull();
  });

  it("names every miss and every false positive", () => {
    const report = buildReport(workedResults, worked);
    expect(report.falseNegatives.map((entry) => entry.id)).toEqual(["ssrf.c"]);
    expect(report.falsePositives.map((entry) => entry.id)).toEqual(["benign.a"]);
  });

  it("tallies true positives once per detector, not once per signal", () => {
    const noisy = [
      resultOf(worked[0], true, "high", ["inj:one", "inj:two", "inj:three", "dlp:email"]),
    ];
    expect(buildReport(noisy, worked).detectionSources).toEqual({ inj: 1, dlp: 1 });
  });

  it("fails the run only on a critical-severity false positive", () => {
    expect(exitCodeFor(buildReport(workedResults, worked))).toBe(0);
    const critical = [resultOf(worked[3], true, "critical", ["net:private-target"])];
    const report = buildReport(critical, worked);
    expect(report.criticalFalsePositives).toEqual(["benign.a"]);
    expect(exitCodeFor(report)).toBe(1);
  });
});

describe("benchmark run", () => {
  it("produces one result per case, in corpus order", () => {
    const subset = corpus.slice(0, 12);
    const results = runCorpus(subset);
    expect(results.map((result) => result.id)).toEqual(subset.map((testCase) => testCase.id));
    for (const result of results) {
      expect(typeof result.detected).toBe("boolean");
      expect(result.detected).toBe(result.signals.length > 0);
      if (!result.detected) expect(result.observedSeverity).toBe("none");
    }
  });

  it("builds a report with the shape the JSON output promises", () => {
    const subset = corpus.filter((testCase) =>
      ["ssrf.loopback.ipv4", "ssrf.metadata.aws-imds", "benign.url.status-page"].includes(
        testCase.id,
      ),
    );
    expect(subset).toHaveLength(3);

    const report = buildReport(runCorpus(subset), subset);
    expect(report.schema).toBe(1);
    expect(report.caseCount).toBe(3);
    expect(report.categories.map((entry) => entry.category)).toEqual(["ssrf", "benign"]);
    expect(report.overall.total).toBe(3);
    expect(
      report.overall.truePositives +
        report.overall.falsePositives +
        report.overall.trueNegatives +
        report.overall.falseNegatives,
    ).toBe(3);
    expect(JSON.parse(JSON.stringify(report))).toEqual(report);
  });

  /**
   * Two cases whose verdict is a property of the product's design rather than
   * of its tuning: loopback is always denied, and a bare public host on 443
   * with nothing in the URL has nothing for any detector to find. If either of
   * these flips, the benchmark is measuring something other than what it says.
   */
  it("anchors on a loopback target and an unremarkable public URL", () => {
    const byId = new Map(runCorpus(corpus).map((result) => [result.id, result]));
    expect(byId.get("ssrf.loopback.ipv4")?.detected).toBe(true);
    expect(byId.get("ssrf.loopback.ipv4")?.observedSeverity).toBe("critical");
    expect(byId.get("benign.url.status-page")?.detected).toBe(false);
  });

  it("renders a table with a row per category and an overall row", () => {
    const text = formatReport(buildReport(runCorpus(corpus), corpus));
    expect(text).toContain("category");
    expect(text).toContain("precision");
    expect(text).toContain("recall");
    for (const category of BENCH_CATEGORIES) expect(text).toContain(category);
    expect(text).toContain("overall");
  });
});

function caseOf(id: string, category: BenchCase["category"], expect_: BenchCase["expect"]): BenchCase {
  return {
    id,
    category,
    severity: "high",
    input: { kind: "text", value: "fixture" },
    expect: expect_,
    why: "fixture",
  };
}

function resultOf(
  testCase: BenchCase,
  detected: boolean,
  observedSeverity: "none" | "low" | "medium" | "high" | "critical",
  signals: string[],
) {
  return {
    id: testCase.id,
    category: testCase.category,
    kind: testCase.input.kind,
    expect: testCase.expect,
    detected,
    observedSeverity,
    signals,
  };
}
