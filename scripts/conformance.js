#!/usr/bin/env node
"use strict";

/**
 * Conformance harness: run every corpus case through both verifiers and compare.
 *
 * Two verifiers agreeing about a forgery is evidence about the FORMAT. One verifier agreeing
 * with itself is evidence about nothing, which is why this compares the bundled TypeScript
 * verifier and the independent Go verifier against each corpus case's expected.json and
 * against each other.
 *
 * Cases are copied to a temp directory before they run. A verifier may create a key file or
 * a lock as a side effect, and the corpus in git is immutable: a harness that mutated it
 * would make the next run's byte-identity check meaningless.
 *
 * expected.json carries the FORMAT's verdict, not any implementation's. Where the bundled
 * verifier disagrees with the format, the disagreement is declared in DIVERGENCES below with
 * the reason, and it is printed on every run rather than absorbed. A declaration that stops
 * being true fails the run, so this table cannot rot into a list of excuses.
 *
 * Zero dependencies and plain node on purpose: the harness that checks a zero-dependency
 * verifier should not need an install step of its own.
 *
 * Environment:
 *   CONFORMANCE_VERIFIER  path to the Go binary (default verifier/agentwall-verify)
 *   CONFORMANCE_SKIP_GO   set to 1 to run the TypeScript side alone
 */

const { spawnSync } = require("child_process");
const { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } = require("fs");
const { tmpdir } = require("os");
const { join, resolve } = require("path");

const REPO = resolve(__dirname, "..");
const CORPUS = join(REPO, "verifier", "testdata", "corpus");
const CLI = join(REPO, "dist", "cli.js");
const GO = process.env.CONFORMANCE_VERIFIER || join(REPO, "verifier", "agentwall-verify");
const SKIP_GO = process.env.CONFORMANCE_SKIP_GO === "1";

/**
 * Cases where the bundled TypeScript verifier returns something other than the format's
 * verdict. Each entry states what it returns instead and why, in one line. These are gaps in
 * the bundled verifier, not opinions about the corpus.
 */
const DIVERGENCES = {
	"b9-anchor-digest-altered": {
		exit: 0,
		layers: { anchored: true },
		why: "it reports the digest the record claims was submitted and never recomputes one from the checkpoint the record embeds",
	},
	"b10-proof-truncated": {
		exit: 0,
		layers: { anchored: true },
		why: "it never opens a proof file, so a proof that cannot be parsed still counts as an anchor",
	},
	"b11-torn-tail": {
		exit: 1,
		layers: { chained: false },
		why: "it reports a partial final line as a broken chain rather than as the torn tail a hard kill leaves behind",
	},
	"b13-confirmed-without-proof": {
		exit: 0,
		layers: { anchored: true },
		why: "it counts the status field, so an anchor claiming confirmation passes with no proof bytes behind it",
	},
};

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

/** Normalize either verifier's JSON report to the fields the contract covers. */
function report(exitCode, stdout, label, name) {
	let parsed;
	try {
		parsed = JSON.parse(stdout);
	} catch {
		return { error: `${label} produced no JSON for ${name}: ${stdout.slice(0, 200).trim()}` };
	}
	const layers = {};
	for (const layer of parsed.layers || []) layers[layer.name] = layer.ok === true;
	const codes = [];
	for (const layer of parsed.layers || []) for (const problem of layer.problems || []) codes.push(String(problem));
	return {
		exit: exitCode,
		layers,
		pending: parsed.pending,
		confirmed: parsed.confirmed,
		failed: parsed.failed,
		codes,
	};
}

function runTs(dir, name) {
	// Run from inside the case so a relative manifest path resolves the way it does for a
	// verifier that resolves against the manifest's own directory.
	const env = { ...process.env };
	delete env.AGENTWALL_AUDIT_FILE;
	const out = spawnSync(process.execPath, [CLI, "verify", "--audit", "audit.jsonl", "--json"], {
		cwd: dir,
		env,
		encoding: "utf8",
	});
	if (out.error) return { error: `typescript verifier failed to start: ${out.error.message}` };
	return report(out.status, out.stdout, "typescript", name);
}

function runGo(dir, name) {
	const args = ["--audit", "audit.jsonl", "--json"];
	// A case that ships a pinned key expects both harnesses to pin it. Without the pin, a
	// checkpoint signed by a forger's own key verifies against the key it carries.
	if (existsSync(join(dir, "pubkey.txt"))) args.push("--pubkey-file", "pubkey.txt");
	const out = spawnSync(GO, args, { cwd: dir, encoding: "utf8" });
	if (out.error) return { error: `go verifier failed to start: ${out.error.message}` };
	return report(out.status, out.stdout, "go", name);
}

function layerLine(result) {
	return ["chained", "linked", "anchored"].map((l) => `${l}=${result.layers[l]}`).join(" ");
}

function compare(label, result, expected, problems) {
	if (result.exit !== expected.exit) problems.push(`${label} exit ${result.exit}, expected ${expected.exit}`);
	for (const layer of ["chained", "linked", "anchored"]) {
		if (result.layers[layer] !== expected.layers[layer]) {
			problems.push(`${label} ${layer}=${result.layers[layer]}, expected ${expected.layers[layer]}`);
		}
	}
}

function sameVerdict(a, b) {
	return (
		a.exit === b.exit &&
		["chained", "linked", "anchored"].every((layer) => a.layers[layer] === b.layers[layer])
	);
}

function main() {
	if (!existsSync(CLI)) fail(`no ${CLI}; run: npm run build`);
	if (!SKIP_GO && !existsSync(GO)) {
		// Skipping silently would turn this job into a check that the corpus agrees with the
		// verifier that generated it, which proves nothing.
		fail(`no verifier binary at ${GO}; build it or set CONFORMANCE_SKIP_GO=1`);
	}

	const names = cases();
	let failures = 0;
	let declared = 0;

	for (const name of names) {
		const source = join(CORPUS, name);
		const dir = mkdtempSync(join(tmpdir(), "agentwall-conformance-"));
		try {
			cpSync(source, dir, { recursive: true });
			const expected = JSON.parse(readFileSync(join(source, "expected.json"), "utf8"));
			const divergence = DIVERGENCES[name];
			const tsExpected = divergence
				? { exit: divergence.exit, layers: { ...expected.layers, ...divergence.layers } }
				: expected;

			const problems = [];
			const ts = runTs(dir, name);
			if (ts.error) problems.push(ts.error);
			else compare("typescript", ts, tsExpected, problems);

			if (!ts.error && divergence && sameVerdict(ts, expected)) {
				problems.push("declared divergence no longer happens; delete the entry in DIVERGENCES");
			}

			let go = null;
			if (!SKIP_GO) {
				go = runGo(dir, name);
				if (go.error) problems.push(go.error);
				else {
					compare("go", go, expected, problems);
					for (const code of expected.go_codes_include || []) {
						if (!go.codes.some((c) => c.includes(code))) problems.push(`go output does not report ${code}`);
					}
					if (!ts.error) {
						for (const counter of ["pending", "confirmed", "failed"]) {
							if (ts[counter] !== go[counter]) {
								problems.push(`${counter} counter disagrees: typescript ${ts[counter]}, go ${go[counter]}`);
							}
						}
						if (!divergence && !sameVerdict(ts, go)) problems.push("verifiers disagree and no divergence is declared");
					}
				}
			}

			const verdict = go && !go.error ? go : ts;
			if (problems.length > 0) {
				failures++;
				process.stdout.write(`FAIL       ${name}\n`);
				for (const problem of problems) process.stdout.write(`             ${problem}\n`);
			} else if (divergence) {
				declared++;
				process.stdout.write(`DIVERGENCE ${name}\n`);
				process.stdout.write(`             format expects exit=${expected.exit} ${layerLine(expected)}\n`);
				process.stdout.write(`             typescript returns exit=${ts.exit} ${layerLine(ts)}\n`);
				process.stdout.write(`             ${divergence.why}\n`);
			} else {
				process.stdout.write(`ok         ${name}  exit=${verdict.exit} ${layerLine(verdict)}\n`);
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}

	const side = SKIP_GO ? "typescript only" : "typescript and go";
	process.stdout.write(
		`\n${names.length} cases, ${side}: ${names.length - failures - declared} agreed, ` +
			`${declared} declared divergence(s), ${failures} failure(s)\n`,
	);
	process.exit(failures > 0 ? 1 : 0);
}

main();
