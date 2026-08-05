import { createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import type { Checkpoint } from "./signing";

/**
 * Off-box anchoring for audit-chain checkpoints.
 *
 * WHY THIS IS THE PIECE THAT MATTERS
 *
 * The hash chain proves internal consistency. A signature proves a key holder vouched.
 * Neither survives an adversary who controls this host: they can rewrite the file and,
 * if they can read the signing key, re-sign it. Every local control has that ceiling.
 *
 * An anchor breaks it by putting a fingerprint somewhere this machine cannot reach back
 * into. After anchoring, rewriting history requires altering a record held by a party
 * the operator does not control.
 *
 * ONE BACKEND: OPENTIMESTAMPS
 *
 * OpenTimestamps batches the digest into a Merkle tree whose root lands in a Bitcoin
 * transaction. No account, no API key, and verification survives any single
 * organisation disappearing. It costs latency: roughly one to six hours for a block.
 *
 * WHY NOT SIGSTORE REKOR, which is the obvious alternative and worth documenting so it
 * is not re-attempted blind. Submitting a bare Ed25519 keypair to the public instance
 * requires, in order: a PEM-encoded public key (base64 DER is rejected), and a SHA-512
 * digest (SHA-256 is rejected for Ed25519). Past those, a hashedrekord entry is still
 * refused with "ed25519: invalid signature" whether the signature covers the payload or
 * the digest bytes. Sigstore's supported path is keyless: an OIDC identity minting a
 * short-lived Fulcio certificate, which needs interactive auth or a workload identity a
 * background service does not have. Taking an OIDC dependency to obtain a WEAKER
 * guarantee than OTS already gives is not a good trade: Rekor requires Sigstore to keep
 * operating, while an OTS proof holds as long as Bitcoin's history does.
 *
 * WHAT ANCHORING DOES NOT PROVE
 *
 * That the log is COMPLETE. An anchor shows what was written was not altered afterwards.
 * It cannot show that everything which should have been written, was. Silent omission at
 * write time is a different problem and this does not solve it. Said plainly here so the
 * receipt does not imply more than it carries.
 *
 * No third-party client libraries: both protocols are plain HTTP, and a dependency in
 * the component whose whole job is being trustworthy is a supply-chain risk we decline.
 */

export type AnchorBackend = "opentimestamps";

export interface AnchorRecord {
	backend: AnchorBackend;
	/** SHA-256 of the canonical checkpoint bytes, hex. What was actually submitted. */
	digest: string;
	chainIndex: number;
	/** Backend handle: the OTS calendar that answered. */
	reference: string;
	/**
	 * Path to the persisted proof, for backends that return one.
	 *
	 * The OpenTimestamps calendar's response body IS the timestamp: the merkle path from
	 * our digest up to its aggregation root. Discard it and the anchor cannot be verified
	 * or later upgraded to a full Bitcoin attestation, which reduces the whole backend to
	 * a claim that we once sent an HTTP request.
	 */
	proofPath?: string;
	submittedAt: string;
	/**
	 * Rekor is immediate. OpenTimestamps is "pending" until a Bitcoin block confirms,
	 * which is a real state and not an error — reporting it as complete would be the lie.
	 */
	status: "confirmed" | "pending";
	/** Set when the submission failed. The record is still written: silence is worse. */
	error?: string;
}

/** Canonical bytes for a checkpoint. Field order is fixed; changing it breaks old anchors. */
export function canonicalCheckpointBytes(cp: Checkpoint): Buffer {
	return Buffer.from(
		JSON.stringify({
			chainIndex: cp.chainIndex,
			hash: cp.hash,
			signedAt: cp.signedAt,
			signature: cp.signature,
			publicKey: cp.publicKey,
		}),
		"utf8",
	);
}

export function anchorDigest(cp: Checkpoint): string {
	return createHash("sha256").update(canonicalCheckpointBytes(cp)).digest("hex");
}

export interface HttpPoster {
	/**
	 * Returns the body as BYTES. The OpenTimestamps calendar replies with a binary
	 * merkle path; decoding it as a string mangles it, and that response IS the proof.
	 */
	post(
		url: string,
		body: Buffer | string,
		headers: Record<string, string>,
	): Promise<{ status: number; body: Buffer }>;
}

/** Default transport. Injectable so tests never touch the network. */
export const fetchPoster: HttpPoster = {
	async post(url, body, headers) {
		const res = await fetch(url, { method: "POST", body, headers });
		return { status: res.status, body: Buffer.from(await res.arrayBuffer()) };
	},
};


const OTS_CALENDARS = [
	"https://alice.btc.calendar.opentimestamps.org/digest",
	"https://bob.btc.calendar.opentimestamps.org/digest",
];

/**
 * Submit to OpenTimestamps calendars.
 *
 * Several calendars are tried because one attestation is enough and any single operator
 * may be down. Status stays "pending" by design: the digest is not anchored until a
 * Bitcoin block includes the aggregated root, and calling that confirmed would overstate
 * what has actually happened.
 *
 * A calendar being unreachable returns a record carrying `error`, never a thrown
 * exception. A gap the operator can see beats an exception that aborts the caller and
 * leaves no trace that anchoring was attempted at all.
 */
export async function anchorToOpenTimestamps(
	cp: Checkpoint,
	poster: HttpPoster = fetchPoster,
	now: () => Date = () => new Date(),
	proofDir?: string,
): Promise<AnchorRecord> {
	const digest = anchorDigest(cp);
	const base: Omit<AnchorRecord, "reference" | "status"> = {
		backend: "opentimestamps",
		digest,
		chainIndex: cp.chainIndex,
		submittedAt: now().toISOString(),
	};
	const failures: string[] = [];
	for (const cal of OTS_CALENDARS) {
		try {
			const res = await poster.post(cal, Buffer.from(digest, "hex"), {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/vnd.opentimestamps.v1",
			});
			if (res.status >= 200 && res.status < 300) {
				if (res.body.length === 0) {
					// An empty 200 is not a proof. Treat it as failure rather than
					// writing a zero-byte file that looks like evidence.
					failures.push(`${cal}: empty proof body`);
					continue;
				}
				let proofPath: string | undefined;
				if (proofDir) {
					mkdirSync(proofDir, { recursive: true, mode: 0o700 });
					// Name the proof after the DIGEST, which is unique per checkpoint, so no
					// pass can overwrite an earlier pass's proof. Naming it after a counter
					// that only advances on rotation collides on every pass of a deployment
					// that has not rotated, and a proof file that can be silently replaced
					// is evidence that can be silently destroyed. The merkle path is the
					// whole value of the anchor; losing it leaves an unverifiable claim.
					proofPath = join(proofDir, `${digest}.ots`);
					writeFileSync(proofPath, res.body, { mode: 0o600 });
				}
				return { ...base, reference: cal, status: "pending", proofPath };
			}
			failures.push(`${cal} HTTP ${res.status}`);
		} catch (err) {
			failures.push(`${cal}: ${(err as Error).message}`);
		}
	}
	return { ...base, reference: "", status: "pending", error: `all calendars failed: ${failures.join("; ")}` };
}

export interface AnchorCoverage {
	total: number;
	confirmed: number;
	pending: number;
	failed: number;
	/** Highest chain index with at least one non-failed anchor. Everything past it is unanchored. */
	highestAnchoredIndex: number | null;
}

/**
 * Summarise the anchor log.
 *
 * highestAnchoredIndex is the honest headline: records beyond it rest on local controls
 * alone. An operator reading a dashboard should see how far the external evidence
 * actually reaches, not just that anchoring is switched on.
 */
export function anchorCoverage(logPath: string): AnchorCoverage {
	const empty: AnchorCoverage = { total: 0, confirmed: 0, pending: 0, failed: 0, highestAnchoredIndex: null };
	if (!existsSync(logPath)) return empty;
	const out = { ...empty };
	for (const line of readFileSync(logPath, "utf8").split("\n")) {
		if (!line.trim()) continue;
		let r: AnchorRecord;
		try {
			r = JSON.parse(line) as AnchorRecord;
		} catch {
			continue; // a torn line is not an anchor; skip rather than abort the summary
		}
		out.total++;
		if (r.error) out.failed++;
		else if (r.status === "confirmed") out.confirmed++;
		else out.pending++;
		if (!r.error && (out.highestAnchoredIndex === null || r.chainIndex > out.highestAnchoredIndex)) {
			out.highestAnchoredIndex = r.chainIndex;
		}
	}
	return out;
}
