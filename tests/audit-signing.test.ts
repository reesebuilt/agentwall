import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, rmSync, statSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
	checkpointPayload,
	loadOrCreateKeys,
	publicKeyFingerprint,
	signCheckpoint,
	verifyCheckpoint,
} from "../src/audit/signing";

/**
 * Checkpoint signing.
 *
 * The hash chain proves internal consistency but not authorship: anyone who can write
 * the file can recompute every hash in it, so the chain catches accident and not an
 * adversary. These tests pin the properties that make a forged checkpoint fail,
 * including the unpinned-key case, which is the one that looks safe and is not.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-sign-"));
	dirs.push(d);
	return d;
}

afterEach(() => {
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

describe("checkpoint signing", () => {
	it("generates a key on first use and reuses it after", () => {
		const path = join(tmp(), "keys", "signing.pem");
		const a = loadOrCreateKeys(path);
		const b = loadOrCreateKeys(path);
		expect(publicKeyFingerprint(a)).toBe(publicKeyFingerprint(b));
	});

	it("writes the private key 0600 regardless of umask", () => {
		const path = join(tmp(), "signing.pem");
		const prior = process.umask(0o000); // hostile umask: would leave 0666 without the chmod
		try {
			loadOrCreateKeys(path);
		} finally {
			process.umask(prior);
		}
		expect(statSync(path).mode & 0o777).toBe(0o600);
	});

	it("signs and verifies a checkpoint", () => {
		const keys = loadOrCreateKeys(join(tmp(), "signing.pem"));
		const cp = signCheckpoint(7, "abc123", keys);
		expect(verifyCheckpoint(cp, publicKeyFingerprint(keys))).toEqual({ ok: true });
	});

	it("rejects a tampered chainIndex", () => {
		const keys = loadOrCreateKeys(join(tmp(), "signing.pem"));
		const cp = signCheckpoint(7, "abc123", keys);
		const forged = { ...cp, chainIndex: 8 };
		expect(verifyCheckpoint(forged, publicKeyFingerprint(keys)).ok).toBe(false);
	});

	it("rejects a tampered hash", () => {
		const keys = loadOrCreateKeys(join(tmp(), "signing.pem"));
		const cp = signCheckpoint(7, "abc123", keys);
		const forged = { ...cp, hash: "deadbeef" };
		expect(verifyCheckpoint(forged, publicKeyFingerprint(keys)).ok).toBe(false);
	});

	it("rejects a checkpoint signed by a DIFFERENT key when the expected key is pinned", () => {
		const good = loadOrCreateKeys(join(tmp(), "good.pem"));
		const attacker = loadOrCreateKeys(join(tmp(), "attacker.pem"));
		const forged = signCheckpoint(7, "abc123", attacker);
		const res = verifyCheckpoint(forged, publicKeyFingerprint(good));
		expect(res.ok).toBe(false);
		expect(res.problem).toMatch(/pinned key/);
	});

	it("a forger's self-signed checkpoint PASSES when no key is pinned", () => {
		// The honest limit, pinned as a test so nobody mistakes unpinned verification for
		// a real check. A signature only means something against a key you expected.
		const attacker = loadOrCreateKeys(join(tmp(), "attacker.pem"));
		const forged = signCheckpoint(999, "attacker-controlled", attacker);
		expect(verifyCheckpoint(forged).ok).toBe(true);
	});

	it("rejects a malformed checkpoint instead of throwing", () => {
		const keys = loadOrCreateKeys(join(tmp(), "signing.pem"));
		const cp = signCheckpoint(1, "abc", keys);
		const res = verifyCheckpoint({ ...cp, publicKey: "not-base64-der!!" });
		expect(res.ok).toBe(false);
		expect(res.problem).toBeDefined();
	});

	it("rejects a non-ed25519 algorithm rather than trusting the label", () => {
		const keys = loadOrCreateKeys(join(tmp(), "signing.pem"));
		const cp = signCheckpoint(1, "abc", keys);
		const res = verifyCheckpoint({ ...cp, algorithm: "hmac" as unknown as "ed25519" });
		expect(res.ok).toBe(false);
		expect(res.problem).toMatch(/unsupported algorithm/);
	});

	it("payload bytes are stable, so signatures stay valid across runs", () => {
		// Field order is load-bearing: reordering silently invalidates every prior
		// signature, which would look like mass tampering rather than a format change.
		const a = checkpointPayload(3, "h", "2026-08-04T00:00:00.000Z").toString("utf8");
		expect(a).toBe('{"chainIndex":3,"hash":"h","signedAt":"2026-08-04T00:00:00.000Z","algorithm":"ed25519"}');
	});

	it("loads an existing key from disk rather than regenerating", () => {
		const path = join(tmp(), "signing.pem");
		const first = loadOrCreateKeys(path);
		const pem = readFileSync(path, "utf8");
		const second = loadOrCreateKeys(path);
		expect(readFileSync(path, "utf8")).toBe(pem);
		// A checkpoint signed before reload still verifies after it.
		const cp = signCheckpoint(1, "x", first);
		expect(verifyCheckpoint(cp, publicKeyFingerprint(second)).ok).toBe(true);
	});

	it("surfaces a corrupt key file as an error, not a silent new key", () => {
		const path = join(tmp(), "signing.pem");
		writeFileSync(path, "not a pem", { mode: 0o600 });
		// Silently generating a fresh key would invalidate every existing checkpoint
		// while reporting success, which is worse than failing.
		expect(() => loadOrCreateKeys(path)).toThrow();
	});
});
