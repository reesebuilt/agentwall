import { afterEach, describe, expect, it } from "@jest/globals";
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
	anchorCoverage,
	anchorDigest,
	anchorToOpenTimestamps,
	type AnchorRecord,
	type HttpPoster,
} from "../src/audit/anchor";
import { loadOrCreateKeys, signCheckpoint } from "../src/audit/signing";
import { pendingProof } from "./ots-fixtures";

/**
 * Off-box anchoring.
 *
 * The property under test: a network failure produces a VISIBLE gap, never a thrown
 * exception and never a record that claims success. Anchoring exists so a reviewer can
 * tell how far external evidence reaches; a backend that lies when offline defeats the
 * point. The OTS backend additionally must persist the proof bytes it receives, because
 * that response IS the timestamp.
 *
 * No network here. The HTTP transport is injected and returns Buffer, matching the real
 * interface, since an OTS proof is binary and a string round-trip would corrupt it.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-anchor-"));
	dirs.push(d);
	return d;
}
afterEach(() => {
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function checkpoint() {
	const keys = loadOrCreateKeys(join(tmp(), "k.pem"));
	return signCheckpoint(42, "cafebabe", keys);
}

const ok = (body: string): HttpPoster => ({ async post() { return { status: 200, body: Buffer.from(body) }; } });
const failing = (status: number): HttpPoster => ({ async post() { return { status, body: Buffer.from("nope") }; } });
const throwing = (): HttpPoster => ({ async post() { throw new Error("ENETUNREACH"); } });

describe("anchoring", () => {
	it("digest is stable for the same checkpoint and changes when it is altered", () => {
		const cp = checkpoint();
		expect(anchorDigest(cp)).toBe(anchorDigest({ ...cp }));
		expect(anchorDigest({ ...cp, hash: "different" })).not.toBe(anchorDigest(cp));
	});




	it("opentimestamps persists the proof bytes and stays PENDING until a block confirms", async () => {
		// Confirmed would be the lie: nothing is anchored until a Bitcoin block includes
		// the aggregated root. The returned bytes ARE the proof and must be written, or the
		// anchor cannot later be verified or upgraded to a full attestation.
		const dir = tmp();
		const proofBytes = pendingProof("https://alice.btc.calendar.opentimestamps.org");
		const poster: HttpPoster = { async post() { return { status: 200, body: proofBytes }; } };
		const cp = checkpoint();
		const r = await anchorToOpenTimestamps(cp, poster, () => new Date(), dir);
		expect(r.status).toBe("pending");
		expect(r.error).toBeUndefined();
		expect(r.proofPath).toBe(join(dir, `${anchorDigest(cp)}.ots`));
		// Not the chain index. That counter is the sealed segment count, so it stays 0 on a
		// deployment that has never rotated and names every pass's proof identically, which
		// makes each pass delete the evidence the previous one collected.
		expect(r.proofPath).not.toBe(join(dir, `${cp.chainIndex}.ots`));
		expect(readFileSync(r.proofPath as string)).toEqual(proofBytes);
	});

	it("rejects an empty 200 rather than writing a zero-byte proof", async () => {
		// An empty body is not a timestamp; a 0-byte .ots file would masquerade as evidence.
		const r = await anchorToOpenTimestamps(checkpoint(), ok(""), () => new Date(), tmp());
		expect(r.error).toMatch(/empty proof body|all calendars failed/);
		expect(r.proofPath).toBeUndefined();
	});

	it("refuses a 200 whose body is not a parseable proof, instead of filing it as evidence", async () => {
		// A broken calendar, or an on-path answer, returns bytes that lead nowhere. Keeping
		// them would put a file on disk that verify later reports as a corrupt proof, telling
		// the operator their evidence was damaged when it was never a proof. A recorded
		// failure is the honest outcome, and nothing is written for a forger to point at.
		const dir = tmp();
		const r = await anchorToOpenTimestamps(checkpoint(), ok("not a merkle path"), () => new Date(), dir);
		expect(r.error).toMatch(/unparseable proof/);
		expect(r.proofPath).toBeUndefined();
		expect(readdirSync(dir)).toEqual([]);
	});

	it("refuses a proof that parses but reaches no attestation", async () => {
		// Operations alone attest to nothing. Accepting them would count an anchor whose
		// proof names no calendar and no block.
		const noAttestation: HttpPoster = {
			async post() { return { status: 200, body: Buffer.from("f0081122334455667788", "hex") }; },
		};
		const r = await anchorToOpenTimestamps(checkpoint(), noAttestation, () => new Date(), tmp());
		expect(r.error).toMatch(/reaches no attestation|unparseable proof/);
		expect(r.proofPath).toBeUndefined();
	});

	it("opentimestamps reports all calendars failing", async () => {
		const r = await anchorToOpenTimestamps(checkpoint(), failing(500));
		expect(r.error).toMatch(/all calendars failed/);
	});

	it("returns an error record instead of throwing when the calendars are down", async () => {
		// A recorded gap is the point. An exception aborts the caller and leaves no trace
		// that anchoring was attempted, which reads identically to never having tried.
		const log = join(tmp(), "anchors.jsonl");
		const r = await anchorToOpenTimestamps(checkpoint(), throwing());
		expect(r.error).toMatch(/all calendars failed/);
		expect(r.proofPath).toBeUndefined();

		// The failure has to survive serialization into the log, or it is not evidence.
		appendFileSync(log, JSON.stringify(r) + "\n");
		const lines = readFileSync(log, "utf8").trim().split("\n");
		expect(lines).toHaveLength(1);
		expect((JSON.parse(lines[0]) as AnchorRecord).error).toMatch(/all calendars failed/);
	});

	it("coverage reports the highest anchored index, so gaps are visible", async () => {
		const log = join(tmp(), "anchors.jsonl");
		const good: AnchorRecord = {
			backend: "opentimestamps", digest: "d", chainIndex: 10, reference: "u",
			submittedAt: "2026-08-04T00:00:00.000Z", status: "confirmed",
		};
		// A FAILED anchor at a higher index must NOT raise the watermark: those records are
		// unanchored, and claiming otherwise is exactly the overstatement to avoid.
		const bad: AnchorRecord = { ...good, chainIndex: 99, status: "pending", error: "offline" };
		writeFileSync(log, JSON.stringify(good) + "\n" + JSON.stringify(bad) + "\n");
		expect(anchorCoverage(log)).toMatchObject({ total: 2, confirmed: 1, failed: 1, highestAnchoredIndex: 10 });
	});

	it("coverage on a missing log reports nothing anchored rather than throwing", () => {
		expect(anchorCoverage(join(tmp(), "absent.jsonl"))).toMatchObject({ total: 0, highestAnchoredIndex: null });
	});

	it("a torn final line does not abort the summary", () => {
		const log = join(tmp(), "anchors.jsonl");
		const good: AnchorRecord = {
			backend: "opentimestamps", digest: "d", chainIndex: 3, reference: "u",
			submittedAt: "2026-08-04T00:00:00.000Z", status: "confirmed",
		};
		writeFileSync(log, JSON.stringify(good) + "\n" + '{"backend":"rek');
		expect(anchorCoverage(log)).toMatchObject({ total: 1, confirmed: 1, highestAnchoredIndex: 3 });
	});

});
