import {
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	sign as cryptoSign,
	verify as cryptoVerify,
	type KeyObject,
} from "crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";

/**
 * Ed25519 signing for audit-chain checkpoints.
 *
 * WHAT THIS BUYS, STATED HONESTLY
 *
 * The hash chain alone proves internal consistency: edit one record and every later
 * link breaks. It does NOT prove authorship, because anyone who can write the file can
 * also recompute the whole chain. A verifying chain therefore establishes internal
 * consistency only: it detects accident and careless edits, not an adversary who
 * rewrote the file end to end.
 *
 * A signature adds authorship: a checkpoint is signed by a key holder. That raises
 * forgery from "rewrite a file" to "rewrite a file AND hold the key".
 *
 * WHAT IT DOES NOT BUY
 *
 * It is not tamper-proofing on a host where the audited principal can read the key. If
 * an agent has root, it can sign anything the operator can sign. Signing is necessary
 * and insufficient; the thing that actually binds is an off-box anchor the local host
 * cannot retroactively rewrite (see anchor.ts). We say so here rather than letting a
 * green checkmark imply more than it proves.
 *
 * Checkpoints rather than per-record signatures: signing every event costs ~50us and
 * buys little, since the chain already links records. Signing the head periodically
 * pins everything behind it.
 */

export interface Checkpoint {
	/** Chain index this checkpoint attests to. */
	chainIndex: number;
	/** Hash of the record at that index. */
	hash: string;
	/** ISO timestamp of signing. Advisory: the signer controls its own clock. */
	signedAt: string;
	/** Ed25519 signature over the canonical form, base64. */
	signature: string;
	/** SPKI public key, base64. Lets a verifier check without a side channel. */
	publicKey: string;
	algorithm: "ed25519";
}

/** Bytes that get signed. Field order is fixed; changing it breaks every prior signature. */
export function checkpointPayload(chainIndex: number, hash: string, signedAt: string): Buffer {
	return Buffer.from(JSON.stringify({ chainIndex, hash, signedAt, algorithm: "ed25519" }), "utf8");
}

export interface SigningKeys {
	privateKey: KeyObject;
	publicKey: KeyObject;
}

/**
 * Load a keypair, generating one on first use.
 *
 * The private key is written 0600. That is table stakes, not protection against the
 * threat model above: on a host where the agent runs as the file owner, 0600 stops
 * other local users and nothing else.
 */
export function loadOrCreateKeys(privateKeyPath: string): SigningKeys {
	if (existsSync(privateKeyPath)) {
		const pem = readFileSync(privateKeyPath, "utf8");
		const privateKey = createPrivateKey(pem);
		return { privateKey, publicKey: createPublicKey(privateKey) };
	}

	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	mkdirSync(dirname(privateKeyPath), { recursive: true, mode: 0o700 });
	writeFileSync(
		privateKeyPath,
		privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		{ mode: 0o600 },
	);
	// Explicit chmod: writeFileSync's mode is subject to umask, so a permissive umask
	// would otherwise leave a private key group- or world-readable.
	chmodSync(privateKeyPath, 0o600);
	return { privateKey, publicKey };
}

export function signCheckpoint(
	chainIndex: number,
	hash: string,
	keys: SigningKeys,
	now: () => Date = () => new Date(),
): Checkpoint {
	const signedAt = now().toISOString();
	const signature = cryptoSign(null, checkpointPayload(chainIndex, hash, signedAt), keys.privateKey);
	return {
		chainIndex,
		hash,
		signedAt,
		signature: signature.toString("base64"),
		publicKey: keys.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
		algorithm: "ed25519",
	};
}

export interface CheckpointVerification {
	ok: boolean;
	/** Present when ok is false. Distinguishes a bad signature from a malformed record. */
	problem?: string;
}

/**
 * Verify a checkpoint's signature.
 *
 * `expectedPublicKey` is optional but strongly recommended. Without it this only proves
 * the checkpoint is internally consistent (self-signed by whatever key it carries),
 * which a forger can trivially satisfy by signing with their own key. Pin the key you
 * expect, or the check is close to decorative.
 */
export function verifyCheckpoint(
	cp: Checkpoint,
	expectedPublicKey?: string,
): CheckpointVerification {
	if (cp.algorithm !== "ed25519") {
		return { ok: false, problem: `unsupported algorithm: ${String(cp.algorithm)}` };
	}
	if (expectedPublicKey && cp.publicKey !== expectedPublicKey) {
		return { ok: false, problem: "public key does not match the pinned key" };
	}
	try {
		const key = createPublicKey({
			key: Buffer.from(cp.publicKey, "base64"),
			format: "der",
			type: "spki",
		});
		const ok = cryptoVerify(
			null,
			checkpointPayload(cp.chainIndex, cp.hash, cp.signedAt),
			key,
			Buffer.from(cp.signature, "base64"),
		);
		return ok ? { ok: true } : { ok: false, problem: "signature does not verify" };
	} catch (err) {
		return { ok: false, problem: `malformed checkpoint: ${(err as Error).message}` };
	}
}

/** Base64 SPKI for pinning, so an operator can record which key to expect. */
export function publicKeyFingerprint(keys: SigningKeys): string {
	return keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
}
