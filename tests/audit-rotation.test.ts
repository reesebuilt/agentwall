import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
	adoptExistingSegments,
	readManifest,
	sealSegment,
	summarizeSegment,
	verifyManifest,
} from "../src/audit/rotation";

/**
 * Chain continuity across rotation.
 *
 * The bug: rotating the audit file started a fresh chain at index 0 with previousHash
 * null and nothing tying it to its predecessor. Every segment verified on its own, so
 * the deployment looked healthy while the seam between segments was entirely
 * unprotected. A whole segment could be dropped or reordered and no per-file check
 * would notice.
 *
 * These tests pin the properties that make that visible.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-rot-"));
	dirs.push(d);
	return d;
}
afterEach(() => {
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

/** Minimal audit records; only `integrity` matters to rotation. */
function segment(dir: string, name: string, start: number, count: number, seed = "h"): string {
	const p = join(dir, name);
	const lines = [];
	for (let i = 0; i < count; i++) {
		const idx = start + i;
		lines.push(
			JSON.stringify({
				id: `e${idx}`,
				action: "test",
				integrity: {
					chainIndex: idx,
					hash: `${seed}${idx}`,
					previousHash: i === 0 ? null : `${seed}${idx - 1}`,
					algorithm: "sha256",
					status: "chained-local",
				},
			}),
		);
	}
	writeFileSync(p, lines.join("\n") + "\n");
	return p;
}

describe("rotation manifest", () => {
	it("summarizes a segment's span and final hash", () => {
		const d = tmp();
		const s = summarizeSegment(segment(d, "a.jsonl", 0, 5));
		expect(s).toEqual({ count: 5, firstIndex: 0, lastIndex: 4, finalHash: "h4" });
	});

	it("tolerates a torn final line rather than refusing the whole segment", () => {
		// A hard kill mid-write is normal; refusing to summarize would make an ordinary
		// crash look like tampering.
		const d = tmp();
		const p = segment(d, "a.jsonl", 0, 3);
		writeFileSync(p, readFileSync(p, "utf8") + '{"id":"torn","integ');
		expect(summarizeSegment(p)).toMatchObject({ count: 3, lastIndex: 2 });
	});

	it("links each segment to its predecessor's final hash", () => {
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		sealSegment(segment(d, "a.jsonl", 0, 3, "a"), m);
		sealSegment(segment(d, "b.jsonl", 0, 3, "b"), m);
		const entries = readManifest(m);
		expect(entries).toHaveLength(2);
		expect(entries[0].previousSegmentHash).toBeNull();
		// The link that did not exist before: segment b points back at segment a.
		expect(entries[1].previousSegmentHash).toBe("a2");
		expect(verifyManifest(m)).toMatchObject({ ok: true, segments: 2, records: 6, head: "b2" });
	});

	it("detects a segment removed from the middle", () => {
		// The exact attack the per-file chain could not see.
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		sealSegment(segment(d, "a.jsonl", 0, 2, "a"), m);
		sealSegment(segment(d, "b.jsonl", 0, 2, "b"), m);
		sealSegment(segment(d, "c.jsonl", 0, 2, "c"), m);
		const kept = readManifest(m).filter((e) => !e.path.endsWith("b.jsonl"));
		writeFileSync(m, kept.map((e) => JSON.stringify(e)).join("\n") + "\n");
		const v = verifyManifest(m);
		expect(v.ok).toBe(false);
		expect(v.problems.join(" ")).toMatch(/removed or reordered/);
	});

	it("detects an edited manifest line", () => {
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		sealSegment(segment(d, "a.jsonl", 0, 2, "a"), m);
		const e = readManifest(m);
		e[0].count = 999; // claim more records than were sealed
		writeFileSync(m, JSON.stringify(e[0]) + "\n");
		const v = verifyManifest(m);
		expect(v.ok).toBe(false);
		expect(v.problems.join(" ")).toMatch(/entry hash mismatch/);
	});

	it("re-sealing the same segment is a no-op, so a retried rotation cannot corrupt the chain", () => {
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		const p = segment(d, "a.jsonl", 0, 3, "a");
		sealSegment(p, m);
		sealSegment(p, m);
		expect(readManifest(m)).toHaveLength(1);
	});

	it("adopts pre-existing segments in order, which is the upgrade case", () => {
		// An operator turning rotation on for the first time already has an archived
		// segment beside a live file that restarted at index 0 with previousHash null.
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		const pre = segment(d, "audit.jsonl.1", 0, 72, "p");
		const cur = segment(d, "audit.jsonl", 0, 121, "c");
		const sealed = adoptExistingSegments([pre, cur], m);
		expect(sealed).toHaveLength(2);
		const v = verifyManifest(m);
		expect(v).toMatchObject({ ok: true, segments: 2, records: 193 });
		// The live segment now references the archived one, which is the whole point.
		expect(readManifest(m)[1].previousSegmentHash).toBe("p71");
	});

	it("an empty or missing segment is skipped rather than sealed as a phantom", () => {
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		writeFileSync(join(d, "empty.jsonl"), "");
		expect(sealSegment(join(d, "empty.jsonl"), m)).toBeNull();
		expect(sealSegment(join(d, "absent.jsonl"), m)).toBeNull();
		expect(verifyManifest(m)).toMatchObject({ segments: 0, head: null });
	});

	it("head is what should be anchored: it moves with the newest segment", () => {
		const d = tmp();
		const m = join(d, "manifest.jsonl");
		sealSegment(segment(d, "a.jsonl", 0, 2, "a"), m);
		expect(verifyManifest(m).head).toBe("a1");
		sealSegment(segment(d, "b.jsonl", 0, 2, "b"), m);
		expect(verifyManifest(m).head).toBe("b1");
	});
});
