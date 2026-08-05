/**
 * OpenTimestamps proof bytes, hand-assembled from section 3.7 of docs/audit-format.md.
 *
 * Built byte by byte rather than by calling the parser's own helpers, so a test proves the
 * parser reads the FORMAT and not merely its own round trip. Shared because three suites
 * need the same shapes and three hand-copied byte strings would drift apart.
 *
 * The operations do not depend on the digest: it is the starting message, so the same
 * bytes are a valid proof for any anchor record.
 */

/** Unsigned little-endian base 128, least significant group first, high bit as continuation. */
function varint(n: number): Buffer {
	const out: number[] = [];
	let v = n;
	do {
		out.push((v % 128) | (v >= 128 ? 0x80 : 0));
		v = Math.floor(v / 128);
	} while (v > 0);
	return Buffer.from(out);
}

/** A varint length then the bytes, the `varbytes` of the grammar. */
function varbytes(b: Buffer): Buffer {
	return Buffer.concat([varint(b.length), b]);
}

/** Append eight bytes, then sha256. The aggregation step every calendar answer starts with. */
const AGGREGATE = Buffer.concat([
	Buffer.from([0xf0]),
	varbytes(Buffer.from("1122334455667788", "hex")),
	Buffer.from([0x08]),
]);

const ATTESTATION = Buffer.from([0x00]);
const TAG_PENDING = Buffer.from("83dfe30d2ef90c8e", "hex");
const TAG_BITCOIN = Buffer.from("0588960d73d71901", "hex");

/** What a calendar returns for a fresh submission: aggregation, then a pending attestation. */
export function pendingProof(calendarUri: string): Buffer {
	return Buffer.concat([
		AGGREGATE,
		ATTESTATION,
		TAG_PENDING,
		varbytes(varbytes(Buffer.from(calendarUri, "utf8"))),
	]);
}

/** An upgraded proof: the same aggregation, then a Bitcoin attestation naming a block. */
export function bitcoinProof(height: number): Buffer {
	return Buffer.concat([AGGREGATE, ATTESTATION, TAG_BITCOIN, varbytes(varint(height))]);
}

/** The 31 magic bytes, version, and file hash-op header that wrap a full `.ots` file. */
export function otsContainer(digest: Buffer, operations: Buffer): Buffer {
	return Buffer.concat([
		Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex"),
		Buffer.from([0x01, 0x08]),
		digest,
		operations,
	]);
}
