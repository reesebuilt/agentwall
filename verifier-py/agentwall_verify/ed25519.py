"""Ed25519 signature verification, from RFC 8032, with no dependency.

Python's standard library has no Ed25519, and the obvious fix is to import
``cryptography``, which would route this check through the same OpenSSL the
bundled TypeScript verifier already uses. Two verifiers that agree because they
called one shared library have not agreed about anything. So the curve
arithmetic is here, in about a hundred lines, and the only thing borrowed is
SHA-512 from ``hashlib``.

Verification is public work on public bytes: there is no secret to leak, so the
absence of constant-time arithmetic is not a weakness here. Correctness is the
whole requirement, and the worked example in ``docs/audit-format.md`` carries a
real signature this module is tested against.
"""

from __future__ import annotations

import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)

_BASE_Y = 4 * pow(5, _P - 2, _P) % _P

# The DER SPKI wrapper an Ed25519 public key arrives in: SEQUENCE, AlgorithmIdentifier
# holding OID 1.3.101.112, then a BIT STRING of the 32 raw key bytes.
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SPKI_LENGTH = 44


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        # A non-canonical encoding is rejected rather than folded into range.
        return None
    numerator = (y * y - 1) % _P
    denominator = (_D * y * y + 1) % _P
    if denominator == 0:
        return None
    x2 = numerator * pow(denominator, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_MINUS_ONE % _P
    if (x * x - x2) % _P != 0:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y, 1, _recover_x(_BASE_Y, 0) * _BASE_Y % _P)

Point = tuple


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: Point) -> Point:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: Point, q: Point) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decompress(encoded: bytes) -> Point | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def public_key_from_spki(spki: bytes) -> bytes | None:
    """Pull the 32 raw key bytes out of the DER SPKI a checkpoint carries."""
    if len(spki) != SPKI_LENGTH or not spki.startswith(_SPKI_PREFIX):
        return None
    return spki[-32:]


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """RFC 8032 verification: is [S]B equal to R + [k]A?"""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    if point_a is None:
        return False
    encoded_r = signature[:32]
    point_r = _decompress(encoded_r)
    if point_r is None:
        return False
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= _L:
        # A signature with an unreduced scalar is malleable, so it is refused.
        return False
    k = int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _L
    return _equal(_mul(scalar_s, _BASE), _add(point_r, _mul(k, point_a)))
