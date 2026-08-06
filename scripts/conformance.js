#!/usr/bin/env node
"use strict";

/**
 * Conformance harness: run every corpus case through every verifier and compare.
 *
 * Verifiers agreeing about a forgery is evidence about the FORMAT. One verifier agreeing with
 * itself is evidence about nothing, which is why this drives four independent implementations
 * against each corpus case's expected.json: the bundled TypeScript one, and the Go, Rust and
 * Python verifiers, each written from docs/audit-format.md rather than ported from another.
 *
 * Every implementation is compared against expected.json, never against a majority. That is
 * the load-bearing choice. A pairwise or quorum design would let three implementations that
 * share a wrong assumption outvote the one that read the spec correctly, which inverts the
 * point of having four. The spec is the arbiter.
 *
 * Cases are copied to a temp directory before they run. A verifier may create a key file or
 * a lock as a side effect, and the corpus in git is immutable: a harness that mutated it
 * would make the next run's byte-identity check meaningless.
 *
 * expected.json carries the FORMAT's verdict, not any implementation's. Where an
 * implementation disagrees with the format, the disagreement is declared in DIVERGENCES below
 * with the reason, and it is printed on every run rather than absorbed. A declaration that
 * stops being true fails the run, so this table cannot rot into a list of excuses.
 *
 * Zero dependencies and plain node on purpose: the harness that checks zero-dependency
 * verifiers should not need an install step of its own.
 *
 * Environment:
 *   CONFORMANCE_VERIFIER     path to the Go binary (default verifier/agentwall-verify)
 *   CONFORMANCE_VERIFIER_RS  path to the Rust binary (default verifier-rs/target/release/agentwall-verify)
 *   CONFORMANCE_VERIFIER_PY  path to the Python entry point (default verifier-py/agentwall-verify-py)
 *   CONFORMANCE_PYTHON       interpreter to run the Python verifier with (default python3)
 *   CONFORMANCE_SKIP_GO      set to 1 to leave the Go verifier out of the run
 *   CONFORMANCE_SKIP_RS      set to 1 to leave the Rust verifier out of the run
 *   CONFORMANCE_SKIP_PY      set to 1 to leave the Python verifier out of the run
 */

const { spawnSync } = require("child_process");
const { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } = require("fs");
const { tmpdir } = require("os");
const { join, resolve } = require("path");

const REPO = resolve(__dirname, "..");
const CORPUS = join(REPO, "verifier", "testdata", "corpus");
const CLI = join(REPO, "dist", "cli.js");
const LAYERS = ["chained", "linked", "anchored"];
const COUNTERS = ["pending", "confirmed", "failed"];

/**
 * Cases where one implementation returns something other than the format's verdict, each
 * stating which implementation, what it returns instead, and why, in one line.
 *
 * Keyed by case and then by implementation, because a divergence belongs to the
 * implementation that has it. A table keyed by case alone would either make a Rust-only
 * divergence undeclarable or silently excuse the other three, which weakens the property
 * exactly when implementations are added to it.
 *
 * Empty is an assertion, not dead scaffolding: it says every implementation currently agrees
 * with the format on every case in this corpus. The harness enforces that in both directions.
 * A change that introduces a disagreement fails the run because the divergence is undeclared,
 * and papering over one by adding an entry here turns an empty object into a reviewable diff
 * carrying a human-written reason, rather than a gap that quietly becomes normal.
 *
 * Shape:
 *   "case-name": {
 *     python: { exit: 1, layers: { anchored: false }, counters: { failed: 1 }, why: "..." },
 *   }
 */
const DIVERGENCES = {};

function fail(message) {
	process.stderr.write(`${message}\n`);
	process.exit(2);
}

// Catalogue order rather than lexical, so a run reads as good cases, then forgeries, then
// the limits, and b10 does not land between b1 and b2.
const GROUPS = ["g", "b", "l"];

function order(name) {
	const parts = /^([a-z]+)(\d+)/.exec(name);
	if (!parts) return [GROUPS.length, 0];
	return [GROUPS.indexOf(parts[1]), Number(parts[2])];
}

function cases() {
	if (!existsSync(CORPUS)) fail(`no corpus at ${CORPUS}; run: npm run gen:corpus`);
	return readdirSync(CORPUS)
		.filter((name) => statSync(join(CORPUS, name)).isDirectory())
		.sort((left, right) => {
			const [leftGroup, leftIndex] = order(left);
			const [rightGroup, rightIndex] = order(right);
			return leftGroup - rightGroup || leftIndex - rightIndex || left.localeCompare(right);
		});
}

/** Normalize any verifier's JSON report to the fields the contract covers. */
function report(label, name, outcome) {
	if (outcome.error) return { label, error: `${label} verifier failed to start: ${outcome.error.message}` };
	let parsed;
	try {
		parsed = JSON.parse(outcome.stdout);
	} catch {
		const shown = (outcome.stdout || outcome.stderr || "").slice(0, 200).trim();
		return { label, error: `${label} produced no JSON for ${name}: ${shown}` };
	}
	const layers = {};
	for (const layer of parsed.layers || []) layers[layer.name] = layer.ok === true;
	const codes = [];
	for (const layer of parsed.layers || []) for (const problem of layer.problems || []) codes.push(String(problem));
	return {
		label,
		exit: outcome.status,
		layers,
		pending: parsed.pending,
		confirmed: parsed.confirmed,
		failed: parsed.failed,
		codes,
	};
}

/**
 * A case that ships a pinned key expects every implementation to pin it. Without the pin, a
 * checkpoint signed by a forger's own key verifies against the key it carries.
 */
function pinArgs(dir) {
	return existsSync(join(dir, "pubkey.txt")) ? ["--pubkey-file", "pubkey.txt"] : [];
}

// Run from inside the case so a relative manifest path resolves the way it does for a
// verifier that resolves against the manifest's own directory.
function spawnIn(dir, command, args, env) {
	return spawnSync(command, args, { cwd: dir, encoding: "utf8", env: env || process.env });
}

function tsEnv() {
	const env = { ...process.env };
	delete env.AGENTWALL_AUDIT_FILE;
	return env;
}

/**
 * The implementations, in the order a report should read them. Each declares how to find
 * itself, how to be skipped, and how to be run. Adding a fifth is one entry.
 *
 * `source` separates two situations a single existence check would confuse. An
 * implementation whose source tree is absent is not part of this checkout, so there is
 * nothing to run and nothing to skip; a branch that predates it must still be able to run the
 * harness. An implementation whose source is present but whose binary is not has simply not
 * been built, and that is a hard failure, because skipping it silently would turn this job
 * into a check that the corpus agrees with the verifier that generated it.
 */
const IMPLEMENTATIONS = [
	{
		label: "typescript",
		what: "bundled verifier",
		binary: CLI,
		missing: `no ${CLI}; run: npm run build`,
		run: (dir) => spawnIn(dir, process.execPath, [CLI, "verify", "--audit", "audit.jsonl", "--json"], tsEnv()),
	},
	{
		label: "go",
		what: "Go verifier",
		skipVar: "CONFORMANCE_SKIP_GO",
		pathVar: "CONFORMANCE_VERIFIER",
		source: join(REPO, "verifier", "main.go"),
		binary: process.env.CONFORMANCE_VERIFIER || join(REPO, "verifier", "agentwall-verify"),
		run(dir) {
			return spawnIn(dir, this.binary, ["--audit", "audit.jsonl", "--json", ...pinArgs(dir)]);
		},
	},
	{
		label: "rust",
		what: "Rust verifier",
		skipVar: "CONFORMANCE_SKIP_RS",
		pathVar: "CONFORMANCE_VERIFIER_RS",
		source: join(REPO, "verifier-rs", "Cargo.toml"),
		binary: process.env.CONFORMANCE_VERIFIER_RS || join(REPO, "verifier-rs", "target", "release", "agentwall-verify"),
		run(dir) {
			return spawnIn(dir, this.binary, ["--audit", "audit.jsonl", "--json", ...pinArgs(dir)]);
		},
	},
	{
		label: "python",
		what: "Python verifier",
		skipVar: "CONFORMANCE_SKIP_PY",
		// Nothing to build, so the script that ships in git is both source and binary.
		pathVar: "CONFORMANCE_VERIFIER_PY",
		source: join(REPO, "verifier-py", "pyproject.toml"),
		binary: process.env.CONFORMANCE_VERIFIER_PY || join(REPO, "verifier-py", "agentwall-verify-py"),
		run(dir) {
			// Spawn the interpreter rather than the script, so a checkout that lost the
			// executable bit still runs.
			const python = process.env.CONFORMANCE_PYTHON || "python3";
			return spawnIn(dir, python, [this.binary, "--audit", "audit.jsonl", "--json", ...pinArgs(dir)]);
		},
	},
];

function layerLine(result) {
	return LAYERS.map((layer) => `${layer}=${result.layers[layer]}`).join(" ");
}

function counterLine(result) {
	return COUNTERS.map((counter) => `${counter}=${result[counter]}`).join(" ");
}

/** expected.json for one implementation: the format's verdict, overridden by its declaration. */
function expectedFor(expected, declaration) {
	if (!declaration) return expected;
	return {
		exit: declaration.exit === undefined ? expected.exit : declaration.exit,
		layers: { ...expected.layers, ...(declaration.layers || {}) },
	};
}

function sameVerdict(result, expected) {
	if (result.exit !== expected.exit) return false;
	return LAYERS.every((layer) => result.layers[layer] === expected.layers[layer]);
}

function checkVerdicts(results, expected, declarations, problems) {
	for (const result of results) {
		const declaration = declarations[result.label];
		const want = expectedFor(expected, declaration);
		if (result.exit !== want.exit) {
			problems.push(`${result.label} exit ${result.exit}, expected ${want.exit}`);
		}
		for (const layer of LAYERS) {
			if (result.layers[layer] !== want.layers[layer]) {
				problems.push(`${result.label} ${layer}=${result.layers[layer]}, expected ${want.layers[layer]}`);
			}
		}
		if (declaration && (declaration.exit !== undefined || declaration.layers) && sameVerdict(result, expected)) {
			problems.push(`${result.label}: declared verdict divergence no longer happens; delete the entry in DIVERGENCES`);
		}
	}
}

/**
 * The three counters are contract, so they are compared across implementations rather than
 * against expected.json, which does not carry them. An implementation with a declared counter
 * divergence is held to its declaration and left out of the consensus.
 */
function checkCounters(results, declarations, problems) {
	const consensus = results.filter((result) => !(declarations[result.label] || {}).counters);
	for (const counter of COUNTERS) {
		const seen = new Map();
		for (const result of consensus) {
			if (!seen.has(result[counter])) seen.set(result[counter], []);
			seen.get(result[counter]).push(result.label);
		}
		if (seen.size > 1) {
			const rendered = [...seen].map(([value, labels]) => `${labels.join(" and ")} ${value}`).join(", ");
			problems.push(`${counter} counter disagrees: ${rendered}`);
		}
	}
	for (const result of results) {
		const declared = (declarations[result.label] || {}).counters;
		if (!declared) continue;
		let stale = true;
		for (const [counter, value] of Object.entries(declared)) {
			if (result[counter] !== value) {
				problems.push(`${result.label} ${counter}=${result[counter]}, declared ${value}`);
			}
			const agreed = consensus.length > 0 ? consensus[0][counter] : undefined;
			if (result[counter] !== agreed) stale = false;
		}
		if (stale && consensus.length > 0) {
			problems.push(`${result.label}: declared counter divergence no longer happens; delete the entry in DIVERGENCES`);
		}
	}
}

function main() {
	const active = [];
	const absent = [];
	for (const implementation of IMPLEMENTATIONS) {
		if (implementation.skipVar && process.env[implementation.skipVar] === "1") continue;
		// An explicit path override is a request to run that implementation, whatever this
		// checkout happens to contain.
		const requested = implementation.pathVar && process.env[implementation.pathVar];
		if (!requested && implementation.source && !existsSync(implementation.source)) {
			absent.push(implementation.label);
			continue;
		}
		if (!existsSync(implementation.binary)) {
			// Skipping silently would turn this job into a check that the corpus agrees with
			// the verifier that generated it, which proves nothing.
			fail(
				implementation.missing ||
					`no ${implementation.what} at ${implementation.binary}; build it or set ${implementation.skipVar}=1`,
			);
		}
		active.push(implementation);
	}
	if (active.length === 0) fail("every implementation was skipped; there is nothing to compare");
	for (const label of absent) {
		// Printed rather than passed over, so a run never quietly checks fewer things than
		// the reader of its summary believes.
		process.stdout.write(`note       ${label} is not in this checkout, so it is not part of this run\n`);
	}

	const names = cases();
	let failures = 0;
	let declaredCases = 0;

	for (const name of names) {
		const source = join(CORPUS, name);
		const dir = mkdtempSync(join(tmpdir(), "agentwall-conformance-"));
		try {
			cpSync(source, dir, { recursive: true });
			const expected = JSON.parse(readFileSync(join(source, "expected.json"), "utf8"));
			const declarations = DIVERGENCES[name] || {};

			const problems = [];
			const results = [];
			for (const implementation of active) {
				const result = report(implementation.label, name, implementation.run(dir));
				if (result.error) problems.push(result.error);
				else results.push(result);
			}

			checkVerdicts(results, expected, declarations, problems);
			checkCounters(results, declarations, problems);

			const go = results.find((result) => result.label === "go");
			if (go) {
				// Diagnostic names are each implementation's own interface and not part of the
				// format, so these are asserted for the implementation whose names they are.
				for (const code of expected.go_codes_include || []) {
					if (!go.codes.some((reported) => reported.includes(code))) {
						problems.push(`go output does not report ${code}`);
					}
				}
			}

			// A declaration for an implementation that did not run cannot be checked for
			// staleness, so it is neither reported as a divergence nor counted as one.
			const observed = Object.entries(declarations).filter(([label]) =>
				results.some((result) => result.label === label),
			);

			const shown = results.find((result) => result.label !== "typescript") || results[0];
			if (problems.length > 0) {
				failures++;
				process.stdout.write(`FAIL       ${name}\n`);
				for (const problem of problems) process.stdout.write(`             ${problem}\n`);
			} else if (Object.keys(declarations).length > 0) {
				declaredCases++;
				process.stdout.write(`DIVERGENCE ${name}\n`);
				process.stdout.write(`             format expects exit=${expected.exit} ${layerLine(expected)}\n`);
				for (const [label, declaration] of Object.entries(declarations)) {
					const result = results.find((candidate) => candidate.label === label);
					if (!result) continue;
					process.stdout.write(`             ${label} returns exit=${result.exit} ${layerLine(result)}\n`);
					process.stdout.write(`             ${label}: ${declaration.why}\n`);
				}
			} else {
				const agreed = `${results.length}/${results.length} agree`;
				process.stdout.write(
					`ok         ${name}  exit=${shown.exit} ${layerLine(shown)}  ${counterLine(shown)}  ${agreed}\n`,
				);
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}

	const side = active.map((implementation) => implementation.label).join(", ");
	process.stdout.write(
		`\n${names.length} cases across ${active.length} implementation(s) (${side}): ` +
			`${names.length - failures - declaredCases} agreed, ` +
			`${declaredCases} case(s) with a declared divergence, ${failures} failure(s)\n`,
	);
	process.exit(failures > 0 ? 1 : 0);
}

main();
