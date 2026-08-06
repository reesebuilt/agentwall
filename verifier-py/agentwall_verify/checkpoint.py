"""Checkpoints: the signature, and what the signature committed to.

A valid signature says a key signed a composite hash. It says nothing about
whether that composite still describes anything on disk, and a verifier that
stops at the signature reports ``anchored`` as passing over evidence the
anchored value no longer matches. So the composite is rebuilt from the files
and the checkpoint is required to match one of the rebuilt values.
"""

from __future__ import annotations

import base64
import os

from . import codes, ed25519
from .canon import sha256_hex
from .chain import RecordFile
from .codes import Problem
from .manifest import Manifest
from .tokens import NUMBER, OBJECT, STRING, Value


class Checkpoint:
    __slots__ = ("chain_index", "hash", "signed_at", "signature", "public_key", "algorithm", "node")

    def __init__(self, node: Value) -> None:
        self.node = node
        self.chain_index = 0
        self.hash = ""
        self.signed_at = ""
        self.signature = ""
        self.public_key = ""
        self.algorithm = ""


def read_checkpoint(node: Value) -> Checkpoint | None:
    """Pull a checkpoint out of an anchor record, or refuse it."""
    if node.kind != OBJECT:
        return None
    index = node.get("chainIndex")
    digest = node.get("hash")
    signed_at = node.get("signedAt")
    signature = node.get("signature")
    public_key = node.get("publicKey")
    algorithm = node.get("algorithm")
    if index is None or index.kind != NUMBER or "." in index.lexeme:
        return None
    for member in (digest, signed_at, signature, public_key, algorithm):
        if member is None or member.kind != STRING:
            return None
    checkpoint = Checkpoint(node)
    checkpoint.chain_index = int(index.lexeme)
    checkpoint.hash = digest.text
    checkpoint.signed_at = signed_at.text
    checkpoint.signature = signature.text
    checkpoint.public_key = public_key.text
    checkpoint.algorithm = algorithm.text
    return checkpoint


def signed_bytes(node: Value) -> str | None:
    """What the Ed25519 signature covers, in the member order the format fixes."""
    return _assemble(node, ("chainIndex", "hash", "signedAt", "algorithm"))


def digest_material(node: Value) -> str | None:
    """What was submitted to the calendar.

    It differs from the signed bytes in two ways that are easy to miss: it
    carries the signature and the public key, and it has no ``algorithm``.
    """
    return _assemble(node, ("chainIndex", "hash", "signedAt", "signature", "publicKey"))


def _assemble(node: Value, names: tuple[str, ...]) -> str | None:
    parts = ["{"]
    for i, name in enumerate(names):
        member = node.get(name)
        if member is None:
            return None
        if i:
            parts.append(",")
        parts.append('"' + name + '":')
        parts.append(member.lexeme)
    parts.append("}")
    return "".join(parts)


def composite(manifest_head: str | None, segments: int, live_tail: tuple[str, int] | None) -> str:
    """The literal bytes the composite hash is taken over."""
    head = "null" if manifest_head is None else '"' + manifest_head + '"'
    if live_tail is None:
        tail = "null"
    else:
        tail = '{"finalHash":"' + live_tail[0] + '","count":' + str(live_tail[1]) + "}"
    return '{"manifestHead":' + head + ',"segments":' + str(segments) + ',"liveTail":' + tail + "}"


def verify_signature(checkpoint: Checkpoint) -> tuple[bool, str]:
    """Check a checkpoint against the key it carries. Returns ok and a reason."""
    if checkpoint.algorithm != "ed25519":
        return False, "names signature algorithm " + repr(checkpoint.algorithm)
    material = signed_bytes(checkpoint.node)
    if material is None:
        return False, "is missing a member the signed bytes need"
    try:
        signature = base64.b64decode(checkpoint.signature, validate=True)
        spki = base64.b64decode(checkpoint.public_key, validate=True)
    except (ValueError, base64.binascii.Error):
        return False, "carries a signature or public key that is not base64"
    if len(signature) != 64:
        return False, "carries a " + str(len(signature)) + " byte signature, not 64"
    raw = ed25519.public_key_from_spki(spki)
    if raw is None:
        return False, "carries a public key that is not a " + str(ed25519.SPKI_LENGTH) + " byte Ed25519 SPKI"
    if not ed25519.verify(raw, signature, material.encode("utf-8")):
        return False, "does not verify against the key it carries"
    return True, ""


class Rebuild:
    """Everything a checkpoint's composite can legitimately be rebuilt from."""

    __slots__ = ("manifest_head", "candidates", "too_short")

    def __init__(self) -> None:
        self.manifest_head: str | None = None
        self.candidates: list[tuple[str, int] | None] = []
        self.too_short = False


def live_tail_candidates(
    chain_index: int,
    manifest: Manifest,
    live: RecordFile,
    unsealed: list[RecordFile],
    segment_files: dict[str, RecordFile],
) -> Rebuild:
    """Enumerate the pairs a checkpoint at ``chain_index`` could have committed.

    The committed pair names a PREFIX, not a length, because every record hash
    folds in the records before it. Records appended after signing leave that
    prefix reproducible, which is why a growing deployment does not fail here.

    Eligibility is the set of files that were the live file at signing or
    closed after it: the live file, segments closed but not yet sealed, and
    manifest entries from ``chain_index`` onward. A segment already sealed when
    the checkpoint was signed was not the live file then, so it is excluded.
    """
    out = Rebuild()
    if chain_index > len(manifest.entries):
        out.too_short = True
        return out
    if chain_index > 0:
        out.manifest_head = manifest.entries[chain_index - 1].final_hash

    out.candidates.append(None)
    eligible: list[RecordFile] = [live]
    eligible.extend(unsealed)
    for entry in manifest.entries[chain_index:]:
        # A rotated segment whose file is gone is already reported as missing,
        # and its recorded pair still covers what the checkpoint committed.
        out.candidates.append((entry.final_hash, entry.count))
        segment = segment_files.get(os.path.realpath(entry.resolved))
        if segment is not None and segment.present:
            eligible.append(segment)

    for record_file in eligible:
        for position, record in enumerate(record_file.records, start=1):
            out.candidates.append((record.hash, position))
    return out


def rebuild_problem(checkpoint: Checkpoint, rebuild: Rebuild) -> Problem | None:
    """Require the checkpoint's hash to equal one rebuilt composite."""
    if rebuild.too_short:
        return Problem(
            codes.MANIFEST_TOO_SHORT,
            "checkpoint at "
            + checkpoint.signed_at
            + " commits "
            + str(checkpoint.chain_index)
            + " sealed segments and the manifest now holds fewer",
        )
    for candidate in rebuild.candidates:
        if sha256_hex(composite(rebuild.manifest_head, checkpoint.chain_index, candidate)) == checkpoint.hash:
            return None
    return Problem(
        codes.LIVE_TAIL_MISMATCH,
        "checkpoint at "
        + checkpoint.signed_at
        + " commits a composite no eligible file reproduces",
    )
