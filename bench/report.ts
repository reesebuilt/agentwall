import { RiskLevel } from "../src/types";

/**
 * Scoring and formatting for the detection benchmark.
 *
 * This file is deliberately free of I/O and of any import from the detectors.
 * The runner routes cases to scanners and produces `CaseResult[]`; everything
 * downstream of that is arithmetic and text, which means the scoring can be
 * unit-tested against hand-written results without a corpus on disk.
 *
 * Two choices here are opinions, not mechanics, and both are stated in
 * bench/README.md so a reader can disagree with them explicitly:
 *
 *   1. Precision and recall are never combined into a headline number. F1 is
 *      computed and printed because people ask for it, but a tool that misses
 *      half the attacks and a tool that pages you on half your traffic can
 *      share an F1, and they are not the same product. The two columns are the
 *      result; F1 is a footnote.
 *
 *   2. Undefined ratios print as `n/a` rather than 0. Precision over a category
 *      that produced no positive verdicts is 0/0, and rendering that as 0%
 *      manufactures a failure that was never measured. The `benign` category
 *      exists precisely to have no true positives, so this is the common case,
 *      not an edge case.
 */

export const BENCH_CATEGORIES = ["exfiltration", "ssrf", "injection", "dlp", "benign"] as const;
export type BenchCategory = (typeof BENCH_CATEGORIES)[number];

export const BENCH_INPUT_KINDS = ["url", "text", "tool_call"] as const;
export type BenchInputKind = (typeof BENCH_INPUT_KINDS)[number];

export const BENCH_EXPECTATIONS = ["detect", "ignore"] as const;
export type BenchExpectation = (typeof BENCH_EXPECTATIONS)[number];

export const BENCH_SEVERITIES: readonly RiskLevel[] = ["low", "medium", "high", "critical"];

/** A single corpus case, exactly as it appears on disk. */
export interface BenchCase {
  /** Unique across the whole corpus; `<category>.<family>.<variant>` by convention. */
  id: string;
  category: BenchCategory;
  /**
   * How much it costs to get this case wrong. For `detect` cases that is the
   * blast radius of the miss; for `ignore` cases it is the disruption a false
   * positive would cause. It is the case author's judgement and never
   * participates in scoring — only `expect` does.
   */
  severity: RiskLevel;
  input: { kind: BenchInputKind; value: string };
  expect: BenchExpectation;
  /** One line. What this case is actually testing, not what the string says. */
  why: string;
}

/** Severity the detectors reported, or `none` when nothing fired. */
export type ObservedSeverity = RiskLevel | "none";

export type Outcome = "true_positive" | "false_positive" | "true_negative" | "false_negative";

export interface CaseResult {
  id: string;
  category: BenchCategory;
  kind: BenchInputKind;
  expect: BenchExpectation;
  detected: boolean;
  observedSeverity: ObservedSeverity;
  /**
   * Which detector fired, prefixed by source: `net:` for the network
   * inspection verdict, `dlp:` for a secret or PII pattern, `inj:` for an
   * injection pattern id, `policy:` for a matched rule id. The prefix is what
   * makes the per-scanner breakdown possible, and that breakdown is the part
   * of the report that tells you whether a deployment wiring only one plane
   * would still have caught the case.
   */
  signals: string[];
}

export interface Metrics {
  total: number;
  detected: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  /** tp / (tp + fp); null when nothing was flagged at all. */
  precision: number | null;
  /** tp / (tp + fn); null when the slice contains no attacks. */
  recall: number | null;
  /** Harmonic mean; null whenever either input is null. */
  f1: number | null;
  /** fp / (fp + tn); null when the slice contains no benign cases. */
  falsePositiveRate: number | null;
}

export interface CategoryMetrics extends Metrics {
  category: BenchCategory;
}

export interface FalsePositiveEntry {
  id: string;
  category: BenchCategory;
  observedSeverity: ObservedSeverity;
  signals: string[];
}

export interface FalseNegativeEntry {
  id: string;
  category: BenchCategory;
  severity: RiskLevel;
  why: string;
}

export interface BenchReport {
  /** Bumped when the JSON shape changes in a way a consumer would notice. */
  schema: 1;
  caseCount: number;
  overall: Metrics;
  categories: CategoryMetrics[];
  falsePositives: FalsePositiveEntry[];
  falseNegatives: FalseNegativeEntry[];
  /**
   * Ids of `ignore` cases the detectors flagged at `critical`. Separated out
   * because this list, not the aggregate numbers, is what decides the exit
   * code: a critical false positive wakes somebody up.
   */
  criticalFalsePositives: string[];
  /** Count of true positives per detector source prefix (`net`, `dlp`, `inj`, `policy`). */
  detectionSources: Record<string, number>;
}

const SEVERITY_RANK: Record<ObservedSeverity, number> = {
  none: -1,
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** Worst-of, used to fold several detector verdicts on one case into one severity. */
export function maxSeverity(a: ObservedSeverity, b: ObservedSeverity): ObservedSeverity {
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;
}

export function classifyOutcome(expect: BenchExpectation, detected: boolean): Outcome {
  if (expect === "detect") return detected ? "true_positive" : "false_negative";
  return detected ? "false_positive" : "true_negative";
}

function ratio(numerator: number, denominator: number): number | null {
  return denominator === 0 ? null : numerator / denominator;
}

function computeMetrics(results: CaseResult[]): Metrics {
  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;

  for (const result of results) {
    switch (classifyOutcome(result.expect, result.detected)) {
      case "true_positive":
        truePositives++;
        break;
      case "false_positive":
        falsePositives++;
        break;
      case "true_negative":
        trueNegatives++;
        break;
      case "false_negative":
        falseNegatives++;
        break;
    }
  }

  const precision = ratio(truePositives, truePositives + falsePositives);
  const recall = ratio(truePositives, truePositives + falseNegatives);
  const f1 =
    precision === null || recall === null || precision + recall === 0
      ? null
      : (2 * precision * recall) / (precision + recall);

  return {
    total: results.length,
    detected: truePositives + falsePositives,
    truePositives,
    falsePositives,
    trueNegatives,
    falseNegatives,
    precision,
    recall,
    f1,
    falsePositiveRate: ratio(falsePositives, falsePositives + trueNegatives),
  };
}

/** Signals are `<source>:<detail>`; the prefix is what the per-detector tally groups on. */
const SIGNAL_SOURCE = /^[^:]+/;

export function buildReport(results: CaseResult[], cases: readonly BenchCase[]): BenchReport {
  const byId = new Map(cases.map((c) => [c.id, c]));

  const categories: CategoryMetrics[] = [];
  for (const category of BENCH_CATEGORIES) {
    const slice = results.filter((r) => r.category === category);
    if (slice.length === 0) continue;
    categories.push({ category, ...computeMetrics(slice) });
  }

  const falsePositives: FalsePositiveEntry[] = [];
  const falseNegatives: FalseNegativeEntry[] = [];
  const detectionSources: Record<string, number> = {};

  for (const result of results) {
    const outcome = classifyOutcome(result.expect, result.detected);
    if (outcome === "false_positive") {
      falsePositives.push({
        id: result.id,
        category: result.category,
        observedSeverity: result.observedSeverity,
        signals: result.signals,
      });
    } else if (outcome === "false_negative") {
      const source = byId.get(result.id);
      falseNegatives.push({
        id: result.id,
        category: result.category,
        severity: source?.severity ?? "low",
        why: source?.why ?? "",
      });
    } else if (outcome === "true_positive") {
      // Counted once per distinct source, not once per signal: a case that
      // trips six injection patterns is still one case the injection scanner
      // caught, and weighting by pattern count would make a noisy pattern look
      // like broader coverage.
      for (const source of new Set(result.signals.map((s) => SIGNAL_SOURCE.exec(s)?.[0] ?? s))) {
        detectionSources[source] = (detectionSources[source] ?? 0) + 1;
      }
    }
  }

  falsePositives.sort(
    (a, b) =>
      SEVERITY_RANK[b.observedSeverity] - SEVERITY_RANK[a.observedSeverity] ||
      a.id.localeCompare(b.id),
  );
  falseNegatives.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
  );

  return {
    schema: 1,
    caseCount: results.length,
    overall: computeMetrics(results),
    categories,
    falsePositives,
    falseNegatives,
    criticalFalsePositives: falsePositives
      .filter((entry) => entry.observedSeverity === "critical")
      .map((entry) => entry.id),
    detectionSources,
  };
}

function pct(value: number | null): string {
  return value === null ? "n/a" : `${(value * 100).toFixed(1)}%`;
}

const LABEL_WIDTH = 13;

/** Fixed column widths, wide enough for the longest cell each column can hold. */
const COLUMNS: ReadonlyArray<readonly [header: string, width: number]> = [
  ["category", LABEL_WIDTH],
  ["n", 4],
  ["tp", 4],
  ["fp", 4],
  ["tn", 4],
  ["fn", 4],
  ["precision", 10],
  ["recall", 8],
  ["f1", 7],
];

const TABLE_WIDTH = COLUMNS.reduce((sum, [, width]) => sum + width, 0);

function row(label: string, m: Metrics): string {
  const cells = [
    String(m.total),
    String(m.truePositives),
    String(m.falsePositives),
    String(m.trueNegatives),
    String(m.falseNegatives),
    pct(m.precision),
    pct(m.recall),
    pct(m.f1),
  ];
  return (
    label.padEnd(LABEL_WIDTH) +
    cells.map((cell, i) => cell.padStart(COLUMNS[i + 1][1])).join("")
  );
}

/**
 * The operator-facing rendering. Deliberately plain text with fixed columns
 * rather than anything that needs a terminal: the output of this is pasted
 * into review notes and diffed between runs, and a table full of escape codes
 * diffs badly.
 */
export function formatReport(report: BenchReport): string {
  const lines: string[] = [];

  lines.push("AgentWall detection benchmark");
  lines.push(`${report.caseCount} cases`);
  lines.push("");
  lines.push(
    COLUMNS[0][0].padEnd(LABEL_WIDTH) +
      COLUMNS.slice(1).map(([header, width]) => header.padStart(width)).join(""),
  );
  lines.push("-".repeat(TABLE_WIDTH));
  for (const category of report.categories) {
    lines.push(row(category.category, category));
  }
  lines.push("-".repeat(TABLE_WIDTH));
  lines.push(row("overall", report.overall));
  lines.push("");
  lines.push(
    `false-positive rate on cases expected to be ignored: ${pct(report.overall.falsePositiveRate)}`,
  );

  const sources = Object.entries(report.detectionSources).sort((a, b) => b[1] - a[1]);
  if (sources.length > 0) {
    lines.push("");
    lines.push("true positives by detector:");
    for (const [source, count] of sources) {
      lines.push(`  ${source.padEnd(10)}${String(count).padStart(5)}`);
    }
  }

  if (report.falseNegatives.length > 0) {
    lines.push("");
    lines.push(`missed (${report.falseNegatives.length}):`);
    for (const entry of report.falseNegatives) {
      lines.push(`  [${entry.severity}] ${entry.id} — ${entry.why}`);
    }
  }

  if (report.falsePositives.length > 0) {
    lines.push("");
    lines.push(`flagged but expected to be ignored (${report.falsePositives.length}):`);
    for (const entry of report.falsePositives) {
      lines.push(`  [${entry.observedSeverity}] ${entry.id} — ${entry.signals.join(", ")}`);
    }
  }

  lines.push("");
  if (report.criticalFalsePositives.length > 0) {
    lines.push(
      `FAIL: ${report.criticalFalsePositives.length} critical-severity false positive(s): ${report.criticalFalsePositives.join(", ")}`,
    );
  } else {
    lines.push("PASS: no critical-severity false positives");
  }

  return lines.join("\n");
}

/** Non-zero exactly when a case expected to be ignored was flagged at `critical`. */
export function exitCodeFor(report: BenchReport): number {
  return report.criticalFalsePositives.length > 0 ? 1 : 0;
}
