import { afterEach, describe, expect, it } from "@jest/globals";
import { appendFileSync, cpSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runAnchorPass, runVerify, resolvePaths } from "../src/audit/anchor-service";
import { readManifest } from "../src/audit/rotation";
import type { HttpPoster } from "../src/audit/anchor";
import { pendingProof } from "./ots-fixtures";

/**
 * The wired anchor path.
 *
 * Signing and anchoring are only a control if something invokes them, so these tests
 * pin the wired path rather than the library primitives. Two properties are easy to get
 * wrong and are covered explicitly:
 *
 *   - the live file must not be sealed each pass, or the record count inflates without
 *     bound as the file grows
 *   - closed segments must be discovered, or rotated history sits outside the anchor
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-anc-"));
	dirs.push(d);
	return d;
}
afterEach(() => {
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const rec = (i: number, seed = "h"): string =>
	JSON.stringify({
		id: `e${i}`,
		action: "test",
		integrity: {
			chainIndex: i,
			hash: `${seed}${i}`,
			previousHash: i === 0 ? null : `${seed}${i - 1}`,
			algorithm: "sha256",
			status: "chained-local",
		},
	}) + "\n";

function write(path: string, count: number, seed = "h"): void {
	writeFileSync(path, Array.from({ length: count }, (_, i) => rec(i, seed)).join(""));
}

/**
 * A calendar that answers with a genuine pending proof.
 *
 * The submitted digest is the request body, and every answer names a distinct calendar, so
 * repeated passes produce distinct proof bytes and an overwrite would be visible.
 */
let calendarCall = 0;
const okPoster: HttpPoster = {
	post: async () => ({ status: 200, body: pendingProof(`https://calendar-${++calendarCall}.example.com`) }),
};
const deadPoster: HttpPoster = {
	post: async () => {
		throw new Error("calendar unreachable");
	},
};

describe("anchor pass", () => {
	it("does not inflate the record count across repeated passes on a growing live file", async () => {
		// The original bug: the live file was sealed every pass, and because dedupe keyed
		// on finalHash, a growing file produced a new manifest entry each time. Two passes
		// over a 150-record file reported 250 records across 2 segments.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 100);
		const paths = { auditPath: audit };

		const first = await runAnchorPass(paths, () => new Date(), okPoster);
		for (let i = 100; i < 150; i++) appendFileSync(audit, rec(i));
		const second = await runAnchorPass(paths, () => new Date(), okPoster);

		expect(first.anchored).toBe(true);
		expect(second.anchored).toBe(true);
		expect(second.covered).toBe(150);
		// The live file is never a manifest entry, so nothing accumulates.
		expect(readManifest(resolvePaths(paths).manifestPath)).toHaveLength(0);
	});

	it("adopts closed segments so rotated history is inside the anchor", async () => {
		// The upgrade case: an archived segment alongside a live file that restarted
		// its chain at index 0.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(join(d, "audit.jsonl.1"), 72, "p");
		write(audit, 121, "c");

		const r = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		expect(r.anchored).toBe(true);
		expect(r.segments).toBe(1); // the archived file
		expect(r.liveRecords).toBe(121);
		expect(r.covered).toBe(193); // archived + live, counted once each
	});

	it("the checkpoint changes when the live tail grows, so an anchor tracks new records", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 10);
		const a = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		appendFileSync(audit, rec(10));
		const b = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		expect(a.checkpoint?.hash).not.toBe(b.checkpoint?.hash);
	});

	it("two passes with no rotation keep two distinct proofs instead of overwriting one", async () => {
		// The scheduled case, and the reason proof names cannot key on the chain index:
		// that counter is the SEALED SEGMENT COUNT, so a deployment which has never
		// rotated reports 0 on every pass. One name for every proof means each pass
		// deletes the merkle path the previous one collected, and an anchor without its
		// merkle path cannot be verified by anyone.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 10);
		const r = resolvePaths({ auditPath: audit });

		// Distinct bodies, so an overwrite is detected rather than merely suspected. Each is a
		// real proof, because the writer refuses a body it cannot parse.
		let call = 0;
		const distinctProofs: HttpPoster = {
			post: async () => ({ status: 200, body: pendingProof(`https://calendar-${++call}.example.com`) }),
		};
		// Two passes six hours apart, the interval a scheduler would use.
		let t = Date.parse("2026-01-01T00:00:00.000Z");
		const clock = (): Date => new Date((t += 6 * 60 * 60 * 1000));

		const first = await runAnchorPass({ auditPath: audit }, clock, distinctProofs);
		appendFileSync(audit, rec(10));
		const second = await runAnchorPass({ auditPath: audit }, clock, distinctProofs);

		// Zero rotations: the condition under which the old naming collided.
		expect(readManifest(r.manifestPath)).toHaveLength(0);
		expect(first.checkpoint?.chainIndex).toBe(0);
		expect(second.checkpoint?.chainIndex).toBe(0);

		const a = first.records?.[0].proofPath as string;
		const b = second.records?.[0].proofPath as string;
		expect(a).toBeDefined();
		expect(b).toBeDefined();
		expect(a).not.toBe(b);
		expect(readFileSync(a)).toEqual(pendingProof("https://calendar-1.example.com"));
		expect(readFileSync(b)).toEqual(pendingProof("https://calendar-2.example.com"));

		// Both log records still point at a file that is there, so either anchor can be
		// checked on its own.
		const logged = readFileSync(r.anchorLogPath, "utf8")
			.trim()
			.split("\n")
			.map((line) => (JSON.parse(line) as { proofPath?: string }).proofPath as string);
		expect(logged).toEqual([a, b]);
		expect(logged.every((p) => existsSync(p))).toBe(true);
	});

	it("records an anchor failure instead of throwing when the calendar is down", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 5);
		const r = await runAnchorPass({ auditPath: audit }, () => new Date(), deadPoster);
		expect(r.anchored).toBe(true);
		expect(r.records?.[0].error).toMatch(/all calendars failed/);

		// And it must NOT be reported as merely waiting on a block.
		const report = runVerify({ auditPath: audit });
		expect(report.failed).toBe(1);
		expect(report.pending).toBe(0);
		expect(report.layers.find((l) => l.name === "anchored")?.detail).toMatch(/FAILED/);
	});

	it("reports nothing to anchor rather than inventing a checkpoint", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		writeFileSync(audit, "");
		const r = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		expect(r.anchored).toBe(false);
		expect(r.checkpoint).toBeUndefined();
	});
});

describe("verify", () => {
	it("reports the three layers separately rather than as one verdict", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(join(d, "audit.jsonl.old"), 4, "o");
		write(audit, 6, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const report = runVerify({ auditPath: audit });
		expect(report.layers.map((l) => l.name)).toEqual(["chained", "linked", "anchored"]);
	});

	it("shows a pending anchor as pending, never as verified", async () => {
		// OpenTimestamps needs a Bitcoin block. Reporting that as proven would be the
		// precise overclaim this project exists to avoid.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(join(d, "audit.jsonl.old"), 3, "o");
		write(audit, 3, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const report = runVerify({ auditPath: audit });
		const anchored = report.layers.find((l) => l.name === "anchored");
		expect(report.pending).toBe(1);
		expect(anchored?.detail).toMatch(/pending a Bitcoin block/);
	});

	it("summarizes a badly damaged segment instead of printing one problem per record", async () => {
		// A file written by two processes at once produces a problem for nearly every
		// record. Emitting all of them buries the finding the report exists to surface.
		// The shape a concurrent-writer file has: many records, few distinct
		// chain indexes, because each writer kept its own chain state.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		const damaged = join(d, "audit.jsonl.damaged");
		// 40 records that reuse only 4 chain indexes.
		writeFileSync(
			damaged,
			Array.from({ length: 40 }, (_, i) => rec(i % 4, "x")).join(""),
		);
		write(audit, 3, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const chained = runVerify({ auditPath: audit }).layers.find((l) => l.name === "chained");
		expect(chained?.ok).toBe(false);
		const text = chained!.problems.join("\n");
		expect(text).toMatch(/CONCURRENT WRITERS/);
		expect(text).toMatch(/only 4 distinct chain indexes/);
		expect(text).toMatch(/\.\.\. and \d+ more/);
		// The whole point: output for a damaged segment is BOUNDED. One header, a few
		// examples, one tally; not one line per broken record.
		const fromDamaged = chained!.problems.filter((x) => x.includes("audit.jsonl.damaged"));
		expect(fromDamaged).toHaveLength(5);
	});

	it("passes linkage on a deployment that has never rotated", async () => {
		// A never-rotated deployment has no closed segments, so linkage has nothing to
		// verify and that is a pass, not a failure. Reporting FAIL here would tell a new
		// user the tool is broken on first run and point them at `agentwall anchor`,
		// which seals closed segments and therefore could never clear it. A check that
		// fails by default and recommends a remedy that cannot work is worse than none.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 3);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const linked = runVerify({ auditPath: audit }).layers.find((l) => l.name === "linked");
		expect(linked?.ok).toBe(true);
		expect(linked?.detail).toMatch(/no rotations yet/);
	});

	it("fails linkage when a rotated segment exists but is not sealed", () => {
		// The case where the remedy is genuinely correct, so it must still fire.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 3, "c");
		write(join(d, "audit.jsonl.1"), 3, "o");

		const linked = runVerify({ auditPath: audit }).layers.find((l) => l.name === "linked");
		expect(linked?.ok).toBe(false);
		expect(linked?.problems.join(" ")).toMatch(/not sealed into the manifest/);
		// The headline must not contradict the problem beneath it.
		expect(linked?.detail).toMatch(/none sealed yet/);
	});

	it("the remedy actually clears the failure it recommends", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 3, "c");
		write(join(d, "audit.jsonl.1"), 3, "o");
		expect(runVerify({ auditPath: audit }).layers.find((l) => l.name === "linked")?.ok).toBe(false);

		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const after = runVerify({ auditPath: audit }).layers.find((l) => l.name === "linked");
		expect(after?.ok).toBe(true);
		expect(after?.detail).toMatch(/1 segment\(s\) linked/);
	});

	it("flags a sealed segment that has gone missing from disk, on the manifest layer", async () => {
		// Segment accountability lives on one layer. If absence were reported only by the
		// per-record walk, `linked` would report PASS while a segment the manifest vouches
		// for is simply gone, which is the hole this whole change exists to close.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		const old = join(d, "audit.jsonl.old");
		write(old, 4, "o");
		write(audit, 4, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		rmSync(old);

		const report = runVerify({ auditPath: audit });
		const linked = report.layers.find((l) => l.name === "linked");
		const chained = report.layers.find((l) => l.name === "chained");
		expect(linked?.ok).toBe(false);
		expect(linked?.problems.join(" ")).toMatch(/segment-missing/);
		expect(linked?.problems.join(" ")).not.toMatch(/segment-content-mismatch/);
		// Not double-reported: the per-record layer says nothing about a file it never read.
		expect(chained?.problems.join(" ")).not.toMatch(/missing/);
		// And it does not claim to have covered it either. Counting a file it skipped would
		// overstate what the layer checked, which is the same overclaiming in miniature.
		expect(chained?.detail).toMatch(/4 records across 1 segment\(s\)/);
	});

	it("detects a checkpoint signed by a different key", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 3);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const r = resolvePaths({ auditPath: audit });
		const line = JSON.parse(readFileSync(r.anchorLogPath, "utf8").trim());
		line.checkpoint.publicKey = Buffer.from("a different key entirely").toString("base64");
		writeFileSync(r.anchorLogPath, JSON.stringify(line) + "\n");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/pinned key/);
	});

	it("a live file that has merely grown since the last anchor still passes", async () => {
		// The case a naive re-derivation gets wrong. A checkpoint commits a prefix, and a
		// running deployment appends to that prefix constantly. Comparing against the file's
		// current end would report tampering on every healthy box between anchor passes.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 20);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		for (let i = 20; i < 45; i++) appendFileSync(audit, rec(i));

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.problems).toEqual([]);
		expect(anchored?.ok).toBe(true);
	});

	it("a live tail that rotated into a sealed segment since the anchor still passes", async () => {
		// The other healthy case. After rotation the committed prefix is no longer in the
		// live file at all; it is the segment that was sealed in its place.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 12, "a");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		renameSync(audit, join(d, "audit.jsonl.1"));
		write(audit, 4, "b");
		// Verified before the next pass seals the rotated file, and again after.
		const between = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(between?.problems).toEqual([]);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		const after = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(after?.problems).toEqual([]);
		expect(after?.ok).toBe(true);
	});

	it("detects a live tail rewritten so the committed prefix no longer reproduces", async () => {
		// The attack. The checkpoint's signature still verifies, because the attacker did
		// not touch the anchor log; what changed is the evidence the signed value described.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 10, "a");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		write(audit, 10, "z"); // same shape, different records, internally consistent

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/live-tail-mismatch/);
	});

	it("detects a live tail truncated back behind what the checkpoint committed", async () => {
		// Dropping records off the end leaves a valid chain and a shorter file. The
		// committed count no longer exists, so the prefix cannot reproduce.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 30, "a");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		write(audit, 12, "a");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/live-tail-mismatch/);
	});

	it("a segment sealed before the checkpoint cannot excuse a rewritten live tail", async () => {
		// Scoping matters: if any file on disk could satisfy a committed tail, an attacker
		// only has to make the live file look like some older segment. A segment that was
		// already closed when the checkpoint was signed was not the live file at that moment.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(join(d, "audit.jsonl.1"), 5, "a");
		write(audit, 5, "a"); // identical shape and hashes to the sealed segment
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		write(audit, 5, "z");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/live-tail-mismatch/);
	});

	it("detects a manifest truncated behind a checkpoint's sealed segment count", async () => {
		// Dropping the newest manifest entries breaks no linkage, because what remains still
		// chains. The checkpoint that committed those segments is the thing that notices.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(join(d, "audit.jsonl.1"), 4, "p");
		write(audit, 4, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		writeFileSync(resolvePaths({ auditPath: audit }).manifestPath, "");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/live-tail-mismatch/);
		expect(anchored?.problems.join(" ")).toMatch(/manifest now holds 0/);
	});

	it("verifies a relative manifest path from an unrelated working directory", async () => {
		// An operator runs verify from wherever they happen to be. Resolving entry paths
		// against the process directory makes the same evidence pass in one shell and fail
		// in another, and the decoy here is what that failure would look like.
		const evidence = tmp();
		const decoy = tmp();
		write(join(decoy, "audit.jsonl.1"), 9, "wrong");
		const cwd = process.cwd();
		try {
			process.chdir(evidence);
			write("audit.jsonl.1", 6, "p");
			write("audit.jsonl", 3, "c");
			await runAnchorPass({ auditPath: "audit.jsonl" }, () => new Date(), okPoster);
		} finally {
			process.chdir(cwd);
		}
		expect(readManifest(join(evidence, "segments.jsonl"))[0].path).toBe("audit.jsonl.1");

		try {
			process.chdir(decoy);
			const report = runVerify({ auditPath: join(evidence, "audit.jsonl") });
			const linked = report.layers.find((l) => l.name === "linked");
			const chained = report.layers.find((l) => l.name === "chained");
			expect(linked?.problems).toEqual([]);
			expect(linked?.ok).toBe(true);
			// 9 records, not the decoy's, and no phantom missing file.
			expect(chained?.detail).toMatch(/9 records across 2 segment\(s\)/);
			expect(chained?.problems.join(" ")).not.toMatch(/missing from disk/);
		} finally {
			process.chdir(cwd);
		}
	});

	it("a duplicate member drops a record from the chain and from the committed live tail", async () => {
		// Smuggling a second member into a record the checkpoint already covered leaves its
		// stored hash untouched, so a verifier that reads the parsed object sees nothing. The
		// record is malformed, counts toward nothing, and the committed prefix is one record
		// shorter than it claims.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 6);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const lines = readFileSync(audit, "utf8").trim().split("\n");
		lines[1] = lines[1].replace('"action":"test"', '"action":"test","action":"exfiltrate"');
		writeFileSync(audit, lines.join("\n") + "\n");
		// The parser hands every later check a single action member, the tampered one.
		expect(JSON.parse(lines[1]).action).toBe("exfiltrate");

		const report = runVerify({ auditPath: audit });
		const chained = report.layers.find((l) => l.name === "chained");
		const anchored = report.layers.find((l) => l.name === "anchored");
		expect(chained?.problems.join(" ")).toMatch(/dup-key/);
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/live-tail-mismatch/);
	});

	it("detects an anchor record whose digest does not describe the checkpoint it carries", async () => {
		// One edit to a field nobody recomputed. The signature still verifies and the proof
		// still parses, because nothing tied the proof to a particular checkpoint: the digest
		// is that tie. Left unchecked, a forger points a record at a checkpoint whose state
		// was never timestamped and keeps a proof that attests to something else entirely.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 8);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const r = resolvePaths({ auditPath: audit });
		const line = JSON.parse(readFileSync(r.anchorLogPath, "utf8").trim());
		const claimed = `0${line.digest.slice(1)}`;
		writeFileSync(r.anchorLogPath, JSON.stringify({ ...line, digest: claimed }) + "\n");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/digest-mismatch/);
	});

	it("refuses a confirmed claim with no proof bytes behind it", async () => {
		// The worst of the acceptance gaps. `status` is what the record says about itself, so
		// counting it means a line of JSON claiming Bitcoin-grade evidence passes with an
		// empty proof directory. Trusting a self-reported status is the overclaim this whole
		// layer exists to refuse.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 8);
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);

		const r = resolvePaths({ auditPath: audit });
		const line = JSON.parse(readFileSync(r.anchorLogPath, "utf8").trim());
		writeFileSync(r.anchorLogPath, JSON.stringify({ ...line, status: "confirmed" }) + "\n");
		rmSync(line.proofPath);

		const report = runVerify({ auditPath: audit });
		const anchored = report.layers.find((l) => l.name === "anchored");
		expect(report.confirmed).toBe(1);
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/proof-missing/);
	});

	it("refuses a proof file that exists but is empty", async () => {
		// Truncating a proof to nothing leaves the recorded path resolving, so an existence
		// check alone passes. Zero bytes attest to nothing.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 8);
		const pass = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		writeFileSync(pass.records?.[0].proofPath as string, "");

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/proof-missing/);
	});

	it("refuses a proof whose bytes do not parse", async () => {
		// Cut inside a length prefix, as the corpus forgery does. Unopened, a proof is a file
		// name, and an anchor backed by a file name is a claim that an HTTP request happened.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 8);
		const pass = await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		const proofPath = pass.records?.[0].proofPath as string;
		const full = readFileSync(proofPath);
		writeFileSync(proofPath, full.subarray(0, full.length - 5));

		const anchored = runVerify({ auditPath: audit }).layers.find((l) => l.name === "anchored");
		expect(anchored?.ok).toBe(false);
		expect(anchored?.problems.join(" ")).toMatch(/proof-parse-error/);
		// A damaged proof is an anchoring failure and nothing else, so the linkage verdict it
		// says nothing about must not move with it.
		expect(runVerify({ auditPath: audit }).layers.find((l) => l.name === "linked")?.ok).toBe(true);
	});

	it("does not demand a proof from a submission that never reached a calendar", async () => {
		// A recorded failure has no proof to point at, and it is already counted as failed.
		// Reporting a missing proof on top would blame the operator's evidence for a third
		// party being unreachable, and bury the failure that actually happened.
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		write(audit, 5);
		await runAnchorPass({ auditPath: audit }, () => new Date(), deadPoster);

		const report = runVerify({ auditPath: audit });
		const anchored = report.layers.find((l) => l.name === "anchored");
		expect(report.failed).toBe(1);
		expect(anchored?.problems.join(" ")).not.toMatch(/proof-missing/);
		expect(anchored?.problems.join(" ")).not.toMatch(/proof-parse-error/);
	});

	it("finds a proof by its recorded base name after the evidence is copied elsewhere", async () => {
		// An operator checks evidence on a machine that is not the one that wrote it, so the
		// absolute path in the record points at a directory that does not exist here. The
		// base name inside the proof directory is what survives the copy; failing here would
		// report every anchor as unproven on any host but the original.
		const origin = tmp();
		const copy = tmp();
		write(join(origin, "audit.jsonl"), 9);
		await runAnchorPass({ auditPath: join(origin, "audit.jsonl") }, () => new Date(), okPoster);
		cpSync(origin, copy, { recursive: true });

		const anchored = runVerify({ auditPath: join(copy, "audit.jsonl") }).layers.find((l) => l.name === "anchored");
		expect(anchored?.problems).toEqual([]);
		expect(anchored?.ok).toBe(true);
		// And it read the proof rather than skipping it: the attestation count comes from the
		// bytes, not from the record's status field.
		expect(anchored?.detail).toMatch(/proofs carry 1 calendar and 0 bitcoin attestation\(s\)/);
	});
});
