"""The proof grammar, against the worked examples and against hostile input."""

from __future__ import annotations

import pytest

from agentwall_verify.ots import MAGIC, MAX_OPERATIONS, ProofError, parse_proof

DIGEST = bytes.fromhex("d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94")
REACHED = "a422fc26d26edb0ea1b4a0b2b421d0d0e7e8d60c814db3d654a5fa2130c0ae00"

PENDING_PROOF = bytes.fromhex(
    "f0081122334455667788080083dfe30d2ef90c8e2e2d"
    "68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
)
BITCOIN_PROOF = bytes.fromhex("f00811223344556677880800" "0588960d73d71901" "03" "d0f033")
FULL_CONTAINER = MAGIC + bytes.fromhex("0108") + DIGEST + PENDING_PROOF


def test_spec_pending_proof():
    assert len(PENDING_PROOF) == 67
    reached = parse_proof(PENDING_PROOF, DIGEST)
    assert len(reached) == 1
    assert reached[0].kind == "pending"
    assert reached[0].message.hex() == REACHED
    assert reached[0].uri == "https://alice.btc.calendar.opentimestamps.org"


def test_spec_bitcoin_proof():
    assert len(BITCOIN_PROOF) == 24
    reached = parse_proof(BITCOIN_PROOF, DIGEST)
    assert len(reached) == 1
    assert reached[0].kind == "bitcoin"
    assert reached[0].height == 850000
    assert reached[0].message.hex() == REACHED


def test_spec_full_container_carries_the_same_stream():
    assert len(FULL_CONTAINER) == 132
    container = parse_proof(FULL_CONTAINER, DIGEST)
    raw = parse_proof(PENDING_PROOF, DIGEST)
    assert [(a.kind, a.message, a.uri) for a in container] == [(a.kind, a.message, a.uri) for a in raw]


def test_container_must_timestamp_the_digest_the_anchor_submitted():
    other = bytes.fromhex("00" * 32)
    with pytest.raises(ProofError):
        parse_proof(FULL_CONTAINER, other)


def test_a_truncated_proof_is_a_parse_error():
    with pytest.raises(ProofError):
        parse_proof(PENDING_PROOF[:-10], DIGEST)


def test_a_branch_that_never_attests_is_a_parse_error():
    with pytest.raises(ProofError):
        parse_proof(bytes.fromhex("08"), DIGEST)


def test_an_unknown_operation_is_a_parse_error():
    with pytest.raises(ProofError):
        parse_proof(bytes.fromhex("aa"), DIGEST)


def test_a_fork_yields_two_attestations_from_the_same_message():
    # ff introduces a branch that consumes its own bytes, then the parent
    # carries on from the message as it stands.
    branch = bytes.fromhex("0083dfe30d2ef90c8e0201" "41")
    proof = bytes.fromhex("ff") + branch + bytes.fromhex("0800") + bytes.fromhex("0588960d73d7190102" "8206")
    reached = parse_proof(proof, DIGEST)
    assert [a.kind for a in reached] == ["pending", "bitcoin"]
    # The pending branch saw the digest untouched; the bitcoin one saw it hashed.
    assert reached[0].message == DIGEST
    assert reached[1].message != DIGEST


def test_an_unrecognised_attestation_is_skipped_by_its_length():
    proof = bytes.fromhex("00" "0102030405060708" "03" "aabbcc")
    reached = parse_proof(proof, DIGEST)
    assert [a.kind for a in reached] == ["unknown"]
    assert reached[0].payload.hex() == "aabbcc"


def test_an_oversized_operation_argument_is_refused():
    proof = bytes.fromhex("f0") + b"\xff\xff\xff\x7f"
    with pytest.raises(ProofError, match="cap"):
        parse_proof(proof, DIGEST)


def test_total_work_is_bounded():
    # A proof that can wedge a verifier is an attack surface, so the budget is
    # spent across the whole run rather than per branch.
    proof = bytes.fromhex("08") * (MAX_OPERATIONS + 10)
    with pytest.raises(ProofError, match="operations"):
        parse_proof(proof, DIGEST)


def test_fork_depth_is_bounded():
    proof = bytes.fromhex("ff") * 5000
    with pytest.raises(ProofError):
        parse_proof(proof, DIGEST)


def test_message_growth_is_bounded():
    append = bytes.fromhex("f0") + bytes([0x80, 0x08]) + b"\x00" * 1024
    with pytest.raises(ProofError):
        parse_proof(append * 8, DIGEST)


def test_hexlify_and_reverse_change_the_message():
    reverse = bytes.fromhex("f2") + bytes.fromhex("00" "0102030405060708" "00")
    assert parse_proof(reverse, DIGEST)[0].message == DIGEST[::-1]
    hexlify = bytes.fromhex("f3") + bytes.fromhex("00" "0102030405060708" "00")
    assert parse_proof(hexlify, DIGEST)[0].message == DIGEST.hex().encode()
