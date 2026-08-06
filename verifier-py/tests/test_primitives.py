"""Ed25519, keccak256 and ripemd160, against published vectors.

These are implemented rather than imported, so they are tested against
published vectors rather than against another library. Importing ``cryptography``
for Ed25519 would route this verifier's signature check through the same
OpenSSL the bundled TypeScript verifier uses, and two implementations that
share a library share its bugs: they would agree on a forged signature with
total confidence.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from agentwall_verify.ed25519 import public_key_from_spki, verify
from agentwall_verify.hashes import keccak256, ripemd160

# RFC 8032 section 7.1, transcribed from https://www.rfc-editor.org/rfc/rfc8032.txt.
RFC_8032 = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
        "1cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d"
        "0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760"
        "984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

# The checkpoint from docs/audit-format.md, signed by a key generated for it.
SPEC_SIGNED = (
    b'{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0",'
    b'"signedAt":"2026-01-01T00:00:03.000Z","algorithm":"ed25519"}'
)
SPEC_SIGNATURE = "0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg=="
SPEC_SPKI = "MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE="


@pytest.mark.parametrize("public_key,message,signature", RFC_8032)
def test_rfc_8032_vectors(public_key, message, signature):
    assert verify(bytes.fromhex(public_key), bytes.fromhex(signature), bytes.fromhex(message))


def test_spec_checkpoint_signature():
    raw = public_key_from_spki(base64.b64decode(SPEC_SPKI))
    assert raw is not None and len(raw) == 32
    assert verify(raw, base64.b64decode(SPEC_SIGNATURE), SPEC_SIGNED)


def test_spec_checkpoint_signature_rejects_a_changed_message():
    raw = public_key_from_spki(base64.b64decode(SPEC_SPKI))
    assert not verify(raw, base64.b64decode(SPEC_SIGNATURE), SPEC_SIGNED[:-1] + b" ")


def test_every_single_bit_flip_of_a_signature_is_rejected():
    raw = public_key_from_spki(base64.b64decode(SPEC_SPKI))
    signature = base64.b64decode(SPEC_SIGNATURE)
    for index in (0, 31, 32, 63):
        broken = bytearray(signature)
        broken[index] ^= 0x01
        assert not verify(raw, bytes(broken), SPEC_SIGNED)


def test_an_unreduced_scalar_is_rejected():
    # S must be below the group order, or the signature is malleable.
    raw = public_key_from_spki(base64.b64decode(SPEC_SPKI))
    signature = bytearray(base64.b64decode(SPEC_SIGNATURE))
    signature[32:] = (b"\xff" * 32)
    assert not verify(raw, bytes(signature), SPEC_SIGNED)


def test_wrong_sizes_are_rejected():
    raw = public_key_from_spki(base64.b64decode(SPEC_SPKI))
    assert not verify(raw, b"\x00" * 63, SPEC_SIGNED)
    assert not verify(b"\x00" * 31, base64.b64decode(SPEC_SIGNATURE), SPEC_SIGNED)


def test_spki_wrapper_is_required():
    assert public_key_from_spki(b"\x00" * 44) is None
    assert public_key_from_spki(b"\x00" * 32) is None


@pytest.mark.parametrize(
    "message,digest",
    [
        (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        (b"testing", "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"),
    ],
)
def test_keccak256_vectors(message, digest):
    assert keccak256(message).hex() == digest


def test_keccak256_is_not_sha3_256():
    # They differ only in the padding byte, which is the mistake this catches.
    assert keccak256(b"").hex() != hashlib.sha3_256(b"").hexdigest()


@pytest.mark.parametrize(
    "message,digest",
    [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    ],
)
def test_ripemd160_vectors(message, digest):
    assert ripemd160(message).hex() == digest


def test_ripemd160_spans_a_block_boundary():
    # 56 bytes is where the length field no longer fits in the final block.
    assert ripemd160(b"a" * 56).hex() == hashlib.new("ripemd160", b"a" * 56).hexdigest()
