import { afterEach, describe, expect, it } from "@jest/globals";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runAnchorPass, runVerify, resolvePaths } from "../src/audit/anchor-service";
import { readManifest } from "../src/audit/rotation";
import type { HttpPoster } from "../src/audit/anchor";

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

/** A calendar that always answers with a plausible proof. */
const okPoster: HttpPoster = {
	post: async () => ({ status: 200, body: Buffer.from("proofbytes-ots") }),
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
		// examples, one tally — not one line per broken record.
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

	it("flags a sealed segment that has gone missing from disk", async () => {
		const d = tmp();
		const audit = join(d, "audit.jsonl");
		const old = join(d, "audit.jsonl.old");
		write(old, 4, "o");
		write(audit, 4, "c");
		await runAnchorPass({ auditPath: audit }, () => new Date(), okPoster);
		rmSync(old);

		const chained = runVerify({ auditPath: audit }).layers.find((l) => l.name === "chained");
		expect(chained?.ok).toBe(false);
		expect(chained?.problems.join(" ")).toMatch(/missing from disk/);
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
});
