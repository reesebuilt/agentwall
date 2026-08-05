import { describe, expect, it } from "@jest/globals";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach } from "@jest/globals";
import {
	OTS_LIMITS,
	OtsParseError,
	parseOtsProof,
	parseOtsProofFile,
	type OtsAttestation,
} from "../src/audit/ots-proof";
import { bitcoinProof, otsContainer, pendingProof } from "./ots-fixtures";

/**
 * OpenTimestamps proof parsing.
 *
 * The property under test: proof bytes are read as the statement they carry, and nothing
 * a hostile file can say makes the parser do unbounded work. Both halves matter. A parser
 * that accepts anything turns an anchor into a claim that a file exists, and a parser that
 * rejects everything is worse, because it passes every forgery test while breaking every
 * real deployment. So the worked examples from the format are asserted alongside the caps.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-ots-"));
	dirs.push(d);
	return d;
}
afterEach(() => {
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

/** The digest of the worked example in section 3.6 of the format. */
const DIGEST = Buffer.from("d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94", "hex");

describe("ots proof parsing", () => {
	it("reads the format's worked pending proof, including the calendar it names", () => {
		// The bytes and the expected reading are both from the specification, so this fails
		// if the parser drifts from the document rather than merely from itself.
		const ops = Buffer.from(
			"f0081122334455667788080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e" +
				"63616c656e6461722e6f70656e74696d657374616d70732e6f7267",
			"hex",
		);
		expect(ops).toHaveLength(67);
		expect(parseOtsProof(ops, DIGEST)).toEqual([
			{ kind: "pending", uri: "https://alice.btc.calendar.opentimestamps.org" },
		]);
	});

	it("reads a Bitcoin attestation as a height plus the value the operations derive", () => {
		// The format's second worked example. The derived value is what an operator compares
		// against a block merkle root, so getting it wrong would hand them the wrong number
		// to check and a false sense that they checked something.
		const attestations = parseOtsProof(Buffer.from("f008112233445566778808000588960d73d7190103d0f033", "hex"), DIGEST);
		expect(attestations).toEqual([
			{
				kind: "bitcoin",
				height: 850000,
				value: Buffer.from("a422fc26d26edb0ea1b4a0b2b421d0d0e7e8d60c814db3d654a5fa2130c0ae00", "hex"),
			},
		]);
	});

	it("reads a full .ots container and a bare calendar response identically", () => {
		// A verifier distinguishes the two shapes by the magic bytes and applies the same
		// operations to the anchor record's digest either way.
		const ops = pendingProof("https://calendar.example.com");
		expect(parseOtsProof(otsContainer(DIGEST, ops), DIGEST)).toEqual(parseOtsProof(ops, DIGEST));
	});

	it("applies the operations to the anchor record's digest, not to a digest the file supplies", () => {
		// The record is what ties a proof to a checkpoint. A container header that could
		// override the starting message would let a proof for one digest vouch for another.
		const other = Buffer.alloc(32, 0xab);
		const ops = bitcoinProof(700000);
		const fromRecord = parseOtsProof(otsContainer(other, ops), DIGEST) as [
			Extract<OtsAttestation, { kind: "bitcoin" }>,
		];
		const fromHeader = parseOtsProof(ops, other) as [Extract<OtsAttestation, { kind: "bitcoin" }>];
		expect(fromRecord[0].value.equals(fromHeader[0].value)).toBe(false);
	});

	it("follows both sides of a fork from the message as it stands", () => {
		// One submission can reach a calendar and a Bitcoin attestation on separate branches.
		// A parser that followed one branch would silently drop half the evidence.
		const proof = Buffer.concat([
			Buffer.from([0xff]),
			pendingProof("https://alice.example.com"),
			bitcoinProof(850000),
		]);
		expect(parseOtsProof(proof, DIGEST).map((a) => a.kind)).toEqual(["pending", "bitcoin"]);
	});

	it("skips an attestation type it does not know rather than calling the proof corrupt", () => {
		// Unknown attestations are neither proof nor failure, which is why the payload carries
		// a length. Treating one as corruption would make a future OTS release unverifiable.
		const unknown = Buffer.concat([
			Buffer.from([0x00]),
			Buffer.from("0102030405060708", "hex"),
			Buffer.from([0x04, 0xde, 0xad, 0xbe, 0xef]),
		]);
		expect(parseOtsProof(unknown, DIGEST)).toEqual([]);
	});

	it("rejects a truncated proof instead of accepting the prefix it managed to read", () => {
		// The forgery in the corpus: cut the file inside a length prefix and a verifier that
		// stops at the first short read reports an anchor backed by a partial file.
		const full = pendingProof("https://alice.btc.calendar.opentimestamps.org/timestamp");
		expect(() => parseOtsProof(full.subarray(0, full.length - 4), DIGEST)).toThrow(OtsParseError);
	});

	it("rejects trailing bytes after the timestamp", () => {
		// A proof is exactly the operations that reach an attestation. Unconsumed bytes mean
		// the file is not that, which is also how a second stream appended to a real proof is
		// caught rather than ignored.
		expect(() => parseOtsProof(Buffer.concat([bitcoinProof(1), Buffer.from([0x08])]), DIGEST)).toThrow(
			/trailing bytes/,
		);
	});

	it("rejects an unknown operation tag", () => {
		expect(() => parseOtsProof(Buffer.from([0x42]), DIGEST)).toThrow(/unknown op tag 0x42/);
	});

	it("declines ripemd160 and keccak256 rather than guessing at the message", () => {
		// Declining is the honest answer when the primitive is not reliably present in this
		// runtime, and it is what the independent verifier does, so the two agree.
		expect(() => parseOtsProof(Buffer.from([0x03]), DIGEST)).toThrow(/not supported/);
		expect(() => parseOtsProof(Buffer.from([0x67]), DIGEST)).toThrow(/not supported/);
	});

	it("stops a varint made of continuation bytes instead of reading forever", () => {
		// A hostile file's cheapest attack: no payload at all, just a run of high bits.
		const endless = Buffer.concat([Buffer.from([0xf0]), Buffer.alloc(64, 0x80)]);
		expect(() => parseOtsProof(endless, DIGEST)).toThrow(/varint exceeds length cap/);
	});

	it("refuses a length prefix larger than any legitimate proof element", () => {
		// Without the cap this asks for a 16 MiB read from a 4 byte file, which is a memory
		// spike a forger gets for free by editing three bytes.
		const huge = Buffer.concat([Buffer.from([0xf0]), Buffer.from([0x80, 0x80, 0x80, 0x08])]);
		expect(() => parseOtsProof(huge, DIGEST)).toThrow(/exceeds cap/);
	});

	it("refuses a fork chain nested past the depth cap instead of exhausting the stack", () => {
		// Parsing is recursive, so nesting depth is attacker-chosen call depth. A stack
		// overflow in the verifier suppresses the verdict, which is what a forger wants.
		const nested = Buffer.concat([Buffer.alloc(OTS_LIMITS.maxDepth + 2, 0x08), bitcoinProof(1)]);
		expect(() => parseOtsProof(nested, DIGEST)).toThrow(/depth cap/);
	});

	it("refuses a proof whose message grows past the working cap", () => {
		// Hexlify doubles the message. Repeated, it turns a small file into a large buffer.
		const growing = Buffer.concat([Buffer.alloc(24, 0xf3), bitcoinProof(1)]);
		expect(() => parseOtsProof(growing, DIGEST)).toThrow(/grew past/);
	});

	it("refuses a proof larger than the total size cap without reading it", () => {
		const oversized = join(tmp(), "big.ots");
		writeFileSync(oversized, Buffer.alloc(OTS_LIMITS.maxFileBytes + 1));
		expect(() => parseOtsProofFile(oversized, DIGEST)).toThrow(/exceeding the/);
	});

	it("reports a missing proof file as a parse failure rather than throwing an fs error", () => {
		// The caller reports on evidence, so an unreadable file has to arrive as the same
		// kind of answer as an unparseable one instead of aborting the whole verify.
		expect(() => parseOtsProofFile(join(tmp(), "absent.ots"), DIGEST)).toThrow(OtsParseError);
	});

	it("parses a real calendar response byte for byte", () => {
		// Captured from an OpenTimestamps calendar: two aggregation appends, a 32 byte
		// prepend, and a pending attestation. A parser that only handles the synthetic
		// fixtures above would pass every test here and reject production evidence.
		const real = Buffer.from(
			"f0084934fe6351fdafa008f01005b72e01b9aae261174d3d82a375aaaa08f1201599b555e14e3656" +
				"b345a00d8d3c17cd4d380f36545296227c7f049fb4a4611b08f1046a72e696f0083dfb21ca601a021" +
				"10083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70" +
				"656e74696d657374616d70732e6f7267",
			"hex",
		);
		expect(real).toHaveLength(137);
		const proofPath = join(tmp(), "real.ots");
		writeFileSync(proofPath, real);
		expect(parseOtsProofFile(proofPath, Buffer.alloc(32, 0x11))).toEqual([
			{ kind: "pending", uri: "https://alice.btc.calendar.opentimestamps.org" },
		]);
	});
});
