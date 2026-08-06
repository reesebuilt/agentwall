"""The hash operations the proof grammar names, none of them optional.

``hashlib`` covers sha1 and sha256 everywhere. It does not cover keccak256 at
all, because ``sha3_256`` is the padded FIPS variant and produces a different
digest, and its ripemd160 depends on whether the local OpenSSL build still
enables the legacy provider. Leaving either to the environment would make a
verdict about evidence depend on how somebody compiled Python, so both are
implemented here and tested against published vectors.
"""

from __future__ import annotations

import hashlib

_MASK64 = (1 << 64) - 1
_MASK32 = (1 << 32) - 1

_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_KECCAK_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)


def _rotl64(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(lanes: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        # theta
        column = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        delta = [column[(x + 4) % 5] ^ _rotl64(column[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                lanes[x + y] ^= delta[x]
        # rho and pi
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(lanes[x + 5 * y], _KECCAK_ROTATIONS[x + 5 * y])
        # chi
        for y in range(0, 25, 5):
            row = rotated[y : y + 5]
            for x in range(5):
                lanes[x + y] = row[x] ^ ((~row[(x + 1) % 5] & _MASK64) & row[(x + 2) % 5])
        # iota
        lanes[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Original Keccak with the 0x01 pad, not the FIPS SHA3 0x06 pad."""
    rate = 136
    lanes = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f1600(lanes)
    out = bytearray()
    for i in range(4):
        out += lanes[i].to_bytes(8, "little")
    return bytes(out)


_RIPEMD_LEFT_INDEX = (
    tuple(range(16))
    + (7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8)
    + (3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12)
    + (1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2)
    + (4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
)
_RIPEMD_RIGHT_INDEX = (
    (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12)
    + (6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2)
    + (15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13)
    + (8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14)
    + (12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
)
_RIPEMD_LEFT_SHIFT = (
    (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8)
    + (7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12)
    + (11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5)
    + (11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12)
    + (9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
)
_RIPEMD_RIGHT_SHIFT = (
    (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6)
    + (9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11)
    + (9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5)
    + (15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8)
    + (8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
)
_RIPEMD_LEFT_K = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RIPEMD_RIGHT_K = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rotl32(value: int, shift: int) -> int:
    value &= _MASK32
    return ((value << shift) | (value >> (32 - shift))) & _MASK32


def _ripemd_f(round_index: int, x: int, y: int, z: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    if round_index < 32:
        return (x & y) | (~x & _MASK32 & z)
    if round_index < 48:
        return (x | (~y & _MASK32)) ^ z
    if round_index < 64:
        return (x & z) | (y & (~z & _MASK32))
    return x ^ (y | (~z & _MASK32))


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160, implemented rather than borrowed from the OpenSSL build."""
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = bytearray(data)
    bit_length = (len(data) * 8) & ((1 << 64) - 1)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += bit_length.to_bytes(8, "little")

    for offset in range(0, len(padded), 64):
        words = [int.from_bytes(padded[offset + i * 4 : offset + i * 4 + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = state
        ar, br, cr, dr, er = state
        for i in range(80):
            band = i // 16
            temp = (al + _ripemd_f(i, bl, cl, dl) + words[_RIPEMD_LEFT_INDEX[i]] + _RIPEMD_LEFT_K[band]) & _MASK32
            temp = (_rotl32(temp, _RIPEMD_LEFT_SHIFT[i]) + el) & _MASK32
            al, bl, cl, dl, el = el, temp, bl, _rotl32(cl, 10), dl
            temp = (ar + _ripemd_f(79 - i, br, cr, dr) + words[_RIPEMD_RIGHT_INDEX[i]] + _RIPEMD_RIGHT_K[band]) & _MASK32
            temp = (_rotl32(temp, _RIPEMD_RIGHT_SHIFT[i]) + er) & _MASK32
            ar, br, cr, dr, er = er, temp, br, _rotl32(cr, 10), dr
        temp = (state[1] + cl + dr) & _MASK32
        state[1] = (state[2] + dl + er) & _MASK32
        state[2] = (state[3] + el + ar) & _MASK32
        state[3] = (state[4] + al + br) & _MASK32
        state[4] = (state[0] + bl + cr) & _MASK32
        state[0] = temp

    return b"".join(word.to_bytes(4, "little") for word in state)


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
