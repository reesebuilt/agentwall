"""The OpenTimestamps proof grammar.

A proof is the operations that lead from the submitted digest up to an
attestation. This module runs them and reports where they arrive. It decides
nothing about whether an anchor is confirmed by reading a field: it decides by
following the bytes, which is the only reason keeping the proof file is worth
anything.

Every proof this parser sees is attacker-influenced by definition, so it works
under caps: on the size of one operation argument, on the length the message
may reach, on total operations, and on how deep forks may nest. A proof that
exceeds a cap is a parse error, not something to keep following.
"""

from __future__ import annotations

from .hashes import keccak256, ripemd160, sha1, sha256

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")

PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")

MAX_ARGUMENT = 4096
MAX_MESSAGE = 4096
MAX_OPERATIONS = 10000
MAX_FORK_DEPTH = 256

_HASH_OPS = {
    0x02: ("sha1", sha1, 20),
    0x03: ("ripemd160", ripemd160, 20),
    0x08: ("sha256", sha256, 32),
    0x67: ("keccak256", keccak256, 32),
}


class ProofError(Exception):
    """The proof file cannot be read as a proof."""


class Attestation:
    """One endpoint of the proof, with the message value that reached it."""

    __slots__ = ("kind", "message", "uri", "height", "tag", "payload")

    def __init__(self, kind: str, message: bytes) -> None:
        self.kind = kind
        self.message = message
        self.uri: str | None = None
        self.height: int | None = None
        self.tag: bytes = b""
        self.payload: bytes = b""


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ProofError("proof ends where a tag byte was expected")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, count: int) -> bytes:
        if count > self.remaining:
            raise ProofError("proof ends inside a " + str(count) + " byte field")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def varint(self) -> int:
        """Unsigned little-endian base 128, seven bits per byte."""
        value = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise ProofError("proof ends inside a varint")
            byte = self.data[self.pos]
            self.pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise ProofError("varint is longer than any value this format uses")

    def varbytes(self, cap: int) -> bytes:
        length = self.varint()
        if length > cap:
            raise ProofError("field of " + str(length) + " bytes exceeds the " + str(cap) + " byte cap")
        return self.take(length)


class _Run:
    """Shared budget across every branch of one proof."""

    __slots__ = ("operations", "attestations")

    def __init__(self) -> None:
        self.operations = 0
        self.attestations: list[Attestation] = []

    def spend(self) -> None:
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            raise ProofError("proof asks for more than " + str(MAX_OPERATIONS) + " operations")


def parse_proof(data: bytes, digest: bytes) -> list[Attestation]:
    """Run a proof file from the anchor's digest and collect every endpoint.

    Both container shapes carry the same operations stream and both start from
    the raw digest bytes, so the container only decides where the stream begins.
    """
    if data.startswith(MAGIC):
        reader = _Reader(data)
        reader.take(len(MAGIC))
        reader.varint()  # file version, unconstrained by the format
        tag = reader.byte()
        if tag not in _HASH_OPS:
            raise ProofError("container names hash op 0x" + format(tag, "02x") + ", which is not a hash op")
        name, _, size = _HASH_OPS[tag]
        embedded = reader.take(size)
        if embedded != digest:
            raise ProofError(
                "container timestamps " + embedded.hex()[:16] + " but the anchor submitted " + digest.hex()[:16]
            )
        stream = data[reader.pos :]
    else:
        # A raw calendar response is the operations stream alone, with the
        # submitted digest understood rather than repeated.
        stream = data

    run = _Run()
    _branch(_Reader(stream), digest, run, 0)
    return run.attestations


def _branch(reader: _Reader, message: bytes, run: _Run, depth: int) -> None:
    """Follow one branch until it reaches an attestation or runs out."""
    if depth > MAX_FORK_DEPTH:
        raise ProofError("proof forks deeper than " + str(MAX_FORK_DEPTH) + " levels")
    while True:
        if reader.remaining == 0:
            raise ProofError("branch ends without reaching an attestation")
        tag = reader.byte()

        if tag == 0xFF:
            # The message continues down another branch as well. The nested
            # branch consumes its own bytes, then this one carries on from the
            # message as it stands.
            run.spend()
            _branch(reader, message, run, depth + 1)
            continue

        if tag == 0x00:
            attestation = _attestation(reader, message)
            run.attestations.append(attestation)
            # An attestation is a leaf, which is what lets a fork know where
            # its nested branch stopped.
            return

        run.spend()
        if tag == 0xF0:
            message = message + reader.varbytes(MAX_ARGUMENT)
        elif tag == 0xF1:
            message = reader.varbytes(MAX_ARGUMENT) + message
        elif tag == 0xF2:
            message = message[::-1]
        elif tag == 0xF3:
            message = message.hex().encode("ascii")
        elif tag in _HASH_OPS:
            message = _HASH_OPS[tag][1](message)
        else:
            raise ProofError("unknown operation 0x" + format(tag, "02x"))

        if len(message) > MAX_MESSAGE:
            raise ProofError("proof grows the message past " + str(MAX_MESSAGE) + " bytes")


def _attestation(reader: _Reader, message: bytes) -> Attestation:
    tag = reader.take(8)
    payload = reader.varbytes(MAX_ARGUMENT)

    if tag == PENDING_TAG:
        attestation = Attestation("pending", message)
        inner = _Reader(payload)
        uri = inner.varbytes(MAX_ARGUMENT)
        try:
            attestation.uri = uri.decode("utf-8")
        except UnicodeDecodeError:
            raise ProofError("pending attestation names a calendar that is not UTF-8")
        attestation.tag = tag
        attestation.payload = payload
        return attestation

    if tag == BITCOIN_TAG:
        attestation = Attestation("bitcoin", message)
        attestation.height = _Reader(payload).varint()
        attestation.tag = tag
        attestation.payload = payload
        return attestation

    # An attestation nobody here recognizes is skipped using the length that
    # precedes it, which is exactly why the length is there. It is neither
    # proof nor failure.
    attestation = Attestation("unknown", message)
    attestation.tag = tag
    attestation.payload = payload
    return attestation
