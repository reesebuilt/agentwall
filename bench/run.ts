import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import { z } from "zod";
import { PolicyEngine } from "../src/policy/engine";
import { builtinRules } from "../src/policy/rules";
import { scanInjection } from "../src/policy/injection";
import { scanText } from "../src/planes/identity/dlp";
import { inspectNetworkRequest } from "../src/planes/network/ssrf";
import { AgentContext, EgressPolicy, RiskLevel, RiskLevelSchema } from "../src/types";
import {
  BENCH_CATEGORIES,
  BENCH_EXPECTATIONS,
  BENCH_INPUT_KINDS,
  BenchCase,
  BenchCategory,
  CaseResult,
  ObservedSeverity,
  buildReport,
  exitCodeFor,
  formatReport,
  maxSeverity,
} from "./report";

/**
 * The detection benchmark runner.
 *
 * What this measures: the in-process detection logic — `inspectNetworkRequest`,
 * `scanText`, `scanInjection`, and the policy rule pack — against a fixed
 * corpus of hand-written cases. What it does not measure: the deployed proxy,
 * the MCP transport, ordering between gates, or anything that depends on a
 * live socket. Those have their own tests; a number produced here is a
 * statement about the detectors, not about a running deployment.
 *
 * Three configuration choices below change the numbers materially, so they are
 * spelled out rather than buried:
 *
 *   1. Egress inspection runs with `defaultDeny: false`. The shipped default is
 *      deny-with-an-empty-allowlist, under which every URL in the corpus —
 *      attack and benign alike — is denied. That is a correct deployment
 *      posture and a useless measurement: it would report 100% recall and 0%
 *      precision and tell you nothing about the SSRF logic. Turning it off
 *      isolates the checks that hold regardless of allowlist configuration:
 *      metadata endpoints, private and link-local ranges, embedded
 *      credentials, and scheme and port restrictions.
 *
 *   2. The policy engine runs with a default decision of `allow` for the same
 *      reason. `deny` is the shipped default and would mark every tool call
 *      "detected" without a single rule matching.
 *
 *   3. `url` cases are scanned by BOTH the network inspector and the DLP
 *      patterns, because a URL is simultaneously a destination and a string of
 *      bytes leaving the host, and only the second view can see a credential
 *      in the query string. The per-detector breakdown in the report keeps the
 *      two apart, so a reader can see how much of the URL score belongs to
 *      each — which matters, because a deployment that wires only the network
 *      plane gets only the network half.
 */

/**
 * Egress policy used for `url` cases. Ports are the standard web pair on
 * purpose: a request to port 22 or 6379 is a real signal, and widening the
 * list to "whatever an app might use" would delete that signal from the
 * measurement.
 */
export const BENCH_EGRESS_POLICY: Partial<EgressPolicy> = {
  defaultDeny: false,
  allowPrivateRanges: false,
  allowedHosts: [],
  allowedSchemes: ["https", "http"],
  allowedPorts: [443, 80],
};

/**
 * Severity assigned to a DLP hit, by route.
 *
 * A URL is egress by construction, so credential material inside one is the
 * shape the product itself calls critical (`content:block-secret-exfil`). Bare
 * text carries no flow, and the product's flow-free rule for the same finding
 * is `mcp:redact-input-secret` at high. Mapping both to critical would inflate
 * the severity histogram and, because a critical false positive fails the run,
 * would turn every benign string containing a 40-character token into a build
 * break. Mapping both to high would defang the failure gate. The split follows
 * what the rule pack already decided.
 */
const DLP_SEVERITY: Record<"url" | "text", { secret: RiskLevel; pii: RiskLevel }> = {
  url: { secret: "critical", pii: "high" },
  text: { secret: "high", pii: "medium" },
};

export interface Probe {
  detected: boolean;
  observedSeverity: ObservedSeverity;
  signals: string[];
}

/**
 * The corpus is persisted data with a hand-edited surface, so it is parsed at
 * the boundary rather than trusted.
 *
 * Strictness is the point. A typo in `expect` silently inverts a case's own
 * scoring, a wrong `category` moves a case into a table row where it does not
 * belong, and both are invisible in a report that only prints aggregates. The
 * schema is annotated with `BenchCase` so the on-disk contract and the
 * scoring type cannot drift apart without a compile error.
 */
const BenchCaseSchema: z.ZodType<BenchCase> = z.object({
  id: z.string().min(1),
  category: z.enum(BENCH_CATEGORIES),
  severity: RiskLevelSchema,
  input: z.object({
    kind: z.enum(BENCH_INPUT_KINDS),
    value: z.string().min(1),
  }),
  expect: z.enum(BENCH_EXPECTATIONS),
  why: z.string().regex(/\S/, "must not be blank"),
});

/**
 * The file-level `category` is not decoration: every case in the file must
 * declare the same one, which is what stops a case from keeping its old
 * heading after being moved between files.
 */
const CorpusFileSchema = z.object({
  category: z.enum(BENCH_CATEGORIES),
  description: z.string(),
  cases: z.array(BenchCaseSchema).min(1),
});

export function parseCorpusFile(text: string, origin: string): BenchCase[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`${origin}: invalid JSON — ${(err as Error).message}`);
  }

  const parsed = CorpusFileSchema.safeParse(doc);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new Error(`${origin}: ${detail}`);
  }

  for (const testCase of parsed.data.cases) {
    if (testCase.category !== parsed.data.category) {
      throw new Error(
        `${origin}: case "${testCase.id}" declares category "${testCase.category}" in a "${parsed.data.category}" file`,
      );
    }
  }
  return parsed.data.cases;
}

export const CORPUS_DIR = join(__dirname, "corpus");

export function loadCorpus(dir: string = CORPUS_DIR): BenchCase[] {
  const files = readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  if (files.length === 0) throw new Error(`no corpus files in ${dir}`);

  const cases: BenchCase[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    for (const parsed of parseCorpusFile(readFileSync(join(dir, file), "utf8"), file)) {
      if (seen.has(parsed.id)) throw new Error(`${file}: duplicate case id "${parsed.id}"`);
      seen.add(parsed.id);
      cases.push(parsed);
    }
  }
  return cases;
}

/**
 * `tool_call` encoding: the first whitespace-delimited token is the action,
 * everything after it is a single free-text argument.
 *
 * Deliberately not JSON. Escaped JSON inside a JSON string file is unreadable,
 * and the rule pack reaches the payload through `JSON.stringify(payload)`
 * substring matching and a string-value walk, so one string field exercises
 * exactly the same code paths a richly structured payload would. The cost is
 * that rules keyed on `metadata` markers or `actor.channelId` are unreachable
 * from this corpus; those are covered by the MCP gate tests instead, and the
 * benchmark does not pretend otherwise.
 */
export function toolCallContext(value: string): AgentContext {
  const split = value.indexOf(" ");
  const action = split === -1 ? value : value.slice(0, split);
  const argument = split === -1 ? "" : value.slice(split + 1).trim();
  return {
    agentId: "bench",
    plane: "tool",
    action,
    payload: argument.length > 0 ? { argument } : {},
  };
}

export function probeCase(testCase: BenchCase, engine: PolicyEngine): Probe {
  const signals: string[] = [];
  let severity: ObservedSeverity = "none";
  const { kind, value } = testCase.input;

  if (kind === "url") {
    const inspection = inspectNetworkRequest({ url: value, method: "GET" }, BENCH_EGRESS_POLICY);
    if (!inspection.allowed) {
      signals.push(`net:${inspection.blockedCategory ?? "denied"}`);
      severity = maxSeverity(severity, inspection.riskLevel);
    }
  }

  if (kind === "url" || kind === "text") {
    const dlp = scanText(value);
    const levels = DLP_SEVERITY[kind];
    for (const type of dlp.secretTypes) {
      signals.push(`dlp:${type}`);
      severity = maxSeverity(severity, levels.secret);
    }
    for (const type of dlp.piiTypes) {
      signals.push(`dlp:${type}`);
      severity = maxSeverity(severity, levels.pii);
    }
  }

  if (kind === "text") {
    for (const finding of scanInjection(value).findings) {
      signals.push(`inj:${finding.patternId}`);
      severity = maxSeverity(severity, finding.severity);
    }
  }

  if (kind === "tool_call") {
    const result = engine.evaluate(toolCallContext(value));
    // `allow` is not a detection even when a rule matched. `tool:flag-write-operations`
    // fires on any write and returns allow-with-medium-risk: it is an audit
    // annotation, not an intervention, and counting it would let the benchmark
    // claim credit for noticing that a write is a write.
    if (result.decision !== "allow") {
      for (const ruleId of result.matchedRules) signals.push(`policy:${ruleId}`);
      severity = maxSeverity(severity, result.riskLevel);
    }
  }

  return { detected: signals.length > 0, observedSeverity: severity, signals };
}

export function runCorpus(cases: readonly BenchCase[], engine?: PolicyEngine): CaseResult[] {
  const policy = engine ?? new PolicyEngine(builtinRules, "allow");
  return cases.map((testCase) => {
    const probe = probeCase(testCase, policy);
    return {
      id: testCase.id,
      category: testCase.category,
      kind: testCase.input.kind,
      expect: testCase.expect,
      detected: probe.detected,
      observedSeverity: probe.observedSeverity,
      signals: probe.signals,
    };
  });
}

const USAGE = `usage: npm run bench -- [--json] [--category <name>]

  --json              emit the report as JSON instead of a table
  --category <name>   restrict the run to one category
                      (${BENCH_CATEGORIES.join(", ")})

exits 1 when a case expected to be ignored was flagged at critical severity`;

interface Options {
  json: boolean;
  category: BenchCategory | null;
}

function parseArgs(argv: readonly string[]): Options {
  const options: Options = { json: false, category: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--category") {
      const name = argv[++i];
      if (!BENCH_CATEGORIES.includes(name as BenchCategory)) {
        throw new Error(`--category expects one of ${BENCH_CATEGORIES.join(", ")}, got ${name ?? "nothing"}`);
      }
      options.category = name as BenchCategory;
    } else if (arg === "--help" || arg === "-h") {
      throw new Error(USAGE);
    } else {
      throw new Error(`unrecognised argument "${arg}"\n\n${USAGE}`);
    }
  }
  return options;
}

function main(argv: readonly string[]): number {
  let options: Options;
  try {
    options = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    return 2;
  }

  let cases: BenchCase[];
  try {
    cases = loadCorpus();
  } catch (err) {
    process.stderr.write(`corpus: ${(err as Error).message}\n`);
    return 2;
  }

  const selected = options.category
    ? cases.filter((testCase) => testCase.category === options.category)
    : cases;
  if (selected.length === 0) {
    process.stderr.write(`no cases in category "${options.category}"\n`);
    return 2;
  }

  const report = buildReport(runCorpus(selected), selected);
  process.stdout.write(
    options.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatReport(report)}\n`,
  );
  return exitCodeFor(report);
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
