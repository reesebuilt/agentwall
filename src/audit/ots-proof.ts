import { createHash } from "crypto";
import { readFileSync, statSync } from "fs";

/**
 * OpenTimestamps proof parsing, per section 3.7 of docs/audit-format.md.
 *
 * WHY A PARSER AT ALL
 *
 * The calendar's response body IS the timestamp: the operations that lead from the digest
 * we submitted up to an attestation. A verifier that only checks the file exists accepts
 * a proof consisting of arbitrary bytes, so an anchor degrades into a claim that some
 * file is on disk. Parsing is what turns those bytes back into the statement they carry.
 *
 * WHY EVERY LENGTH HERE IS CAPPED
 *
 * The proof is attacker-influenced by definition: it arrives over the network and lands
 * in a directory on the host whose history is in dispute. An adversary who can drop a
 * file there can hand the verifier a varint claiming a gigabyte-long append, a fork
 * chain nested a million deep, or an endless run of continuation bytes. Any of those
 * suppress the verdict by exhausting the process instead of by forging anything, so a
 * verifier that its own input can wedge is itself the attack surface. Each cap below
 * turns that class of input into a fast, named parse failure.
 *
 * WHAT A PARSED PROOF DOES AND DOES NOT ESTABLISH
 *
 * A pending attestation says a calendar accepted the submission. It is not proof of
 * anything being timestamped and MUST NOT be reported as such. A Bitcoin attestation
 * yields a block height and the value the operations derive; confirming inclusion means
 * comparing that value against the block's real merkle root, which needs a Bitcoin
 * source this offline path does not fetch.
 */

/**
 * Bounds on what one proof file may ask the verifier to do. Sized so that every proof a
 * calendar legitimately produces fits with room to spare: a real merkle path is a few
 * dozen operations over arguments of tens of bytes.
 */
export const OTS_LIMITS = {
	/** Total proof bytes. A merkle path is short; anything near this is not one. */
	maxFileBytes: 1 << 20,
	/** One append, prepend, or attestation payload. */
	maxVarBytes: 4096,
	/** Fork and operation nesting, bounding recursion depth. */
	maxDepth: 256,
	/** Operations across all branches, bounding total work. */
	maxOps: 4096,
	/** Attestations collected, bounding output growth. */
	maxAttestations: 256,
	/** Working message length, bounding append and hexlify growth. */
	maxMessageBytes: 1 << 16,
	/** Varint bytes, so a run of continuation bytes cannot spin forever. */
	maxVarintBytes: 9,
} as const;

/** The 31 magic bytes that open a full `.ots` file. */
const OTS_MAGIC = Buffer.from([
	0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
	0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

const TAG_PENDING = Buffer.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
const TAG_BITCOIN = Buffer.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);

/** What a proof leads to. Pending and Bitcoin carry different facts, so they differ in shape. */
export type OtsAttestation =
	| { kind: "pending"; uri: string }
	| { kind: "bitcoin"; height: number; value: Buffer };

/**
 * A proof that does not parse. Distinct from every other failure so a caller can report
 * "these bytes are not a proof" rather than blaming the evidence they describe.
 */
export class OtsParseError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "OtsParseError";
	}
}

/** Cursor over proof bytes. Every read is bounds-checked; nothing here trusts a length. */
class Reader {
	private pos = 0;
	private ops = 0;
	private attestations = 0;

	constructor(private readonly data: Buffer) {}

	get offset(): number {
		return this.pos;
	}

	get exhausted(): boolean {
		return this.pos === this.data.length;
	}

	seek(pos: number): void {
		this.pos = pos;
	}

	byte(): number {
		if (this.pos >= this.data.length) throw new OtsParseError("unexpected end of proof");
		return this.data[this.pos++];
	}

	bytes(n: number): Buffer {
		if (n < 0 || this.pos + n > this.data.length) throw new OtsParseError("proof truncated");
		const out = this.data.subarray(this.pos, this.pos + n);
		this.pos += n;
		return out;
	}

	/**
	 * Unsigned little-endian base 128, high bit as continuation.
	 *
	 * The byte count is capped so a file made entirely of continuation bytes terminates,
	 * and a value past exact integer range is refused rather than rounded: a verifier that
	 * reported an approximate block height would be stating a fact it does not hold.
	 */
	varint(): number {
		let value = 0;
		let scale = 1;
		for (let i = 0; ; i++) {
			if (i >= OTS_LIMITS.maxVarintBytes) throw new OtsParseError("varint exceeds length cap");
			const b = this.byte();
			value += (b & 0x7f) * scale;
			if (!Number.isSafeInteger(value)) throw new OtsParseError("varint exceeds exact integer range");
			if ((b & 0x80) === 0) return value;
			scale *= 128;
		}
	}

	/** A varint length then that many bytes, with the length capped before it is trusted. */
	varbytes(): Buffer {
		const n = this.varint();
		if (n > OTS_LIMITS.maxVarBytes) {
			throw new OtsParseError(`varbytes length ${n} exceeds cap ${OTS_LIMITS.maxVarBytes}`);
		}
		return this.bytes(n);
	}

	/**
	 * One timestamp node: a run of fork edges, each prefixed `FF`, then one final edge.
	 * A fork branch gets its own copy of the message, so one branch cannot alter what a
	 * sibling sees.
	 */
	timestamp(msg: Buffer, depth: number, out: OtsAttestation[]): void {
		if (depth > OTS_LIMITS.maxDepth) throw new OtsParseError("proof nesting exceeds depth cap");
		for (;;) {
			const tag = this.byte();
			if (tag !== 0xff) {
				this.edge(tag, msg, depth, out);
				return;
			}
			this.edge(this.byte(), Buffer.from(msg), depth, out);
		}
	}

	/** One edge: an attestation leaf, or an operation whose result feeds a child timestamp. */
	private edge(tag: number, msg: Buffer, depth: number, out: OtsAttestation[]): void {
		if (tag === 0x00) {
			this.attestation(msg, out);
			return;
		}
		this.timestamp(this.applyOp(tag, msg), depth + 1, out);
	}

	/** One operation against the current message. Growth is capped after every step. */
	private applyOp(tag: number, msg: Buffer): Buffer {
		if (++this.ops > OTS_LIMITS.maxOps) throw new OtsParseError("proof exceeds operation cap");
		switch (tag) {
			case 0xf0:
				return capMessage(Buffer.concat([msg, this.varbytes()]));
			case 0xf1:
				return capMessage(Buffer.concat([this.varbytes(), msg]));
			case 0xf2:
				return Buffer.from(msg).reverse();
			case 0xf3:
				return capMessage(Buffer.from(msg.toString("hex"), "utf8"));
			case 0x02:
				return createHash("sha1").update(msg).digest();
			case 0x08:
				return createHash("sha256").update(msg).digest();
			case 0x03:
			case 0x67:
				// RIPEMD-160 and Keccak-256 are declined rather than evaluated. Neither is
				// reliably present in this runtime's crypto provider, so accepting them would
				// make a verdict depend on how the host's OpenSSL was built, and hand-rolling
				// a hash primitive inside the component whose whole value is being trustworthy
				// trades away more than it buys. A proof needing one is unverifiable here, and
				// the independent Go verifier declines them too, so both agree.
				throw new OtsParseError(`op 0x${tag.toString(16)} is not supported by this verifier`);
			default:
				throw new OtsParseError(`unknown op tag 0x${tag.toString(16).padStart(2, "0")}`);
		}
	}

	/**
	 * One attestation: eight tag bytes then a varbytes payload. An unrecognized tag is
	 * skipped using that length, so a type added later is ignored rather than treated as
	 * corruption. It is neither proof nor failure.
	 */
	private attestation(msg: Buffer, out: OtsAttestation[]): void {
		if (++this.attestations > OTS_LIMITS.maxAttestations) {
			throw new OtsParseError("proof exceeds attestation cap");
		}
		const tag = this.bytes(8);
		const payload = this.varbytes();
		if (tag.equals(TAG_PENDING)) {
			out.push({ kind: "pending", uri: new Reader(payload).varbytes().toString("utf8") });
		} else if (tag.equals(TAG_BITCOIN)) {
			out.push({ kind: "bitcoin", height: new Reader(payload).varint(), value: Buffer.from(msg) });
		}
	}
}

function capMessage(b: Buffer): Buffer {
	if (b.length > OTS_LIMITS.maxMessageBytes) {
		throw new OtsParseError(`proof message grew past ${OTS_LIMITS.maxMessageBytes} bytes`);
	}
	return b;
}

/**
 * Parse proof bytes against the digest the anchor record says was submitted.
 *
 * Both container shapes carry the same operations stream and both apply it to that
 * digest, so a full `.ots` file's own embedded digest is skipped rather than believed:
 * the anchor record is what ties the proof to a checkpoint, and a header that disagreed
 * with it would otherwise let a proof for one digest vouch for another.
 *
 * Trailing bytes after the stream are a failure. A proof is exactly the operations that
 * reach an attestation, and unconsumed bytes mean the file is not the thing it claims to
 * be, which is also what catches a proof with a second stream appended.
 *
 * @throws OtsParseError when the container does not parse or exceeds a cap.
 */
export function parseOtsProof(data: Buffer, digest: Buffer): OtsAttestation[] {
	if (data.length > OTS_LIMITS.maxFileBytes) {
		throw new OtsParseError(`proof is ${data.length} bytes, exceeding the ${OTS_LIMITS.maxFileBytes} byte cap`);
	}
	const r = new Reader(data);
	if (data.length >= OTS_MAGIC.length && data.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC)) {
		r.seek(OTS_MAGIC.length);
		r.varint(); // format version
		// File hash-op tag, then the digest it introduces. SHA-1 and RIPEMD-160 are 20 bytes,
		// SHA-256 is 32; the bytes are skipped, not evaluated, so an op unsupported for
		// message hashing is still a legal header here.
		const fileHashOp = r.byte();
		const digestLength = fileHashOp === 0x08 ? 32 : fileHashOp === 0x02 || fileHashOp === 0x03 ? 20 : 0;
		if (digestLength === 0) {
			throw new OtsParseError(`unknown file hash-op tag 0x${fileHashOp.toString(16).padStart(2, "0")}`);
		}
		r.bytes(digestLength);
	}

	const attestations: OtsAttestation[] = [];
	r.timestamp(Buffer.from(digest), 0, attestations);
	if (!r.exhausted) throw new OtsParseError(`${data.length - r.offset} trailing bytes after the timestamp`);
	return attestations;
}

/**
 * Read and parse a proof file.
 *
 * The size is checked before the read, because reading a hostile file into memory to
 * discover it is too large is the exhaustion this cap exists to prevent.
 *
 * @throws OtsParseError when the file is oversized, unreadable, or does not parse.
 */
export function parseOtsProofFile(path: string, digest: Buffer): OtsAttestation[] {
	let size: number;
	try {
		size = statSync(path).size;
	} catch (err) {
		throw new OtsParseError(`proof unreadable: ${(err as Error).message}`);
	}
	if (size > OTS_LIMITS.maxFileBytes) {
		throw new OtsParseError(`proof file is ${size} bytes, exceeding the ${OTS_LIMITS.maxFileBytes} byte cap`);
	}
	return parseOtsProof(readFileSync(path), digest);
}
