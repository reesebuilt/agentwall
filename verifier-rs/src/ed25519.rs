//! Ed25519 signature verification, RFC 8032, pure verification only.
//!
//! There is no signing here and no key generation: a verifier of this format never needs
//! either. `docs/audit-format.md` says only that the signature is "the base64 of the raw
//! Ed25519 signature over exactly those bytes" and that "Ed25519 needs no separate pre-hash,
//! so a verifier passes the byte string itself to its verify function", which is PureEd25519
//! as specified in RFC 8032 section 5.1.7.
//!
//! Nothing here is constant time and nothing needs to be. Every input is a public value read
//! from a file on disk: the message, the signature, and the public key are all things an
//! attacker already has. There is no secret to leak through timing.
//!
//! Field arithmetic is modulo p = 2^255 - 19 on four 64-bit limbs, little endian, with u128
//! intermediates. Reduction uses 2^256 = 38 (mod p).

use crate::sha2::sha512;

type Fe = [u64; 4];

const P: Fe = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// d = -121665/121666 (mod p), the twisted Edwards curve constant of edwards25519.
const D: Fe = [
    0x75eb_4dca_1359_78a3,
    0x0070_0a4d_4141_d8ab,
    0x8cc7_4079_7779_e898,
    0x5203_6cee_2b6f_fe73,
];

/// sqrt(-1) mod p, needed when the first square root candidate is off by a factor of i.
const SQRT_M1: Fe = [
    0xc4ee_1b27_4a0e_a0b0,
    0x2f43_1806_ad2f_e478,
    0x2b4d_0099_3dfb_d7a7,
    0x2b83_2480_4fc1_df0b,
];

/// Base point B of the prime-order subgroup.
const BX: Fe = [
    0xc956_2d60_8f25_d51a,
    0x692c_c760_9525_a7b2,
    0xc0a4_e231_fdd6_dc5c,
    0x2169_36d3_cd6e_53fe,
];
const BY: Fe = [
    0x6666_6666_6666_6658,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
];

/// L, the order of the prime-order subgroup: 2^252 + 27742317777372353535851937790883648493.
const L: Fe = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

const ZERO: Fe = [0, 0, 0, 0];
const ONE: Fe = [1, 0, 0, 0];

#[inline]
fn mac(carry: u64, a: u64, b: u64, acc: u64) -> (u64, u64) {
    let t = (a as u128) * (b as u128) + (acc as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

fn ge(a: &Fe, b: &Fe) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub_raw(a: &Fe, b: &Fe) -> Fe {
    let mut out = ZERO;
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1) + u64::from(b2);
    }
    out
}

fn add_raw(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut out = ZERO;
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        out[i] = s;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry)
}

/// Bring a value below p. The input may exceed p by a small multiple, never by more than 2p.
fn canon(mut v: Fe) -> Fe {
    while ge(&v, &P) {
        v = sub_raw(&v, &P);
    }
    v
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let (mut s, carry) = add_raw(a, b);
    if carry == 1 {
        // 2^256 = 38 (mod p).
        let (s2, c2) = add_raw(&s, &[38, 0, 0, 0]);
        debug_assert_eq!(c2, 0);
        s = s2;
    }
    canon(s)
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let a = canon(*a);
    let b = canon(*b);
    if ge(&a, &b) {
        sub_raw(&a, &b)
    } else {
        let (t, _) = add_raw(&a, &P);
        sub_raw(&t, &b)
    }
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, c) = mac(carry, a[i], b[j], t[i + j]);
            t[i + j] = lo;
            carry = c;
        }
        t[i + 4] = carry;
    }

    // Fold the high 256 bits: value = lo + hi * 2^256 = lo + hi * 38 (mod p).
    let mut acc = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..4 {
        let (lo, c) = mac(carry, t[4 + i], 38, t[i]);
        acc[i] = lo;
        carry = c;
    }
    acc[4] = carry;

    let mut out: Fe = [acc[0], acc[1], acc[2], acc[3]];
    let mut spill = acc[4].wrapping_mul(38);
    while spill != 0 {
        let (s, c) = add_raw(&out, &[spill, 0, 0, 0]);
        out = s;
        spill = c.wrapping_mul(38);
    }
    canon(out)
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&ZERO, a)
}

fn fe_eq(a: &Fe, b: &Fe) -> bool {
    canon(*a) == canon(*b)
}

fn fe_is_zero(a: &Fe) -> bool {
    canon(*a) == ZERO
}

fn fe_is_odd(a: &Fe) -> bool {
    canon(*a)[0] & 1 == 1
}

/// base^exp mod p, exponent given as little-endian limbs, square and multiply from the top bit.
fn fe_pow(base: &Fe, exp: &Fe) -> Fe {
    let mut result = ONE;
    let mut started = false;
    for limb in (0..4).rev() {
        for bit in (0..64).rev() {
            let b = (exp[limb] >> bit) & 1;
            if started {
                result = fe_sq(&result);
            }
            if b == 1 {
                result = if started {
                    fe_mul(&result, base)
                } else {
                    *base
                };
                started = true;
            }
        }
    }
    if started {
        result
    } else {
        ONE
    }
}

fn fe_invert(a: &Fe) -> Fe {
    // p - 2
    let e = sub_raw(&P, &[2, 0, 0, 0]);
    fe_pow(a, &e)
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut out = ZERO;
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        out[i] = u64::from_le_bytes(w);
    }
    out
}

fn fe_to_bytes(a: &Fe) -> [u8; 32] {
    let v = canon(*a);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&v[i].to_le_bytes());
    }
    out
}

/// A point in extended twisted Edwards coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z, xy = T/Z.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point {
    x: ZERO,
    y: ONE,
    z: ONE,
    t: ZERO,
};

/// add-2008-hwcd-3 for a = -1. Complete on edwards25519 because d is a non-square, so the same
/// routine serves for doubling and there is no exceptional case to special-case.
fn point_add(p1: &Point, p2: &Point) -> Point {
    let a = fe_mul(&fe_sub(&p1.y, &p1.x), &fe_sub(&p2.y, &p2.x));
    let b = fe_mul(&fe_add(&p1.y, &p1.x), &fe_add(&p2.y, &p2.x));
    let c = fe_mul(&fe_mul(&p1.t, &p2.t), &fe_add(&D, &D));
    let d = fe_mul(&fe_mul(&p1.z, &p2.z), &[2, 0, 0, 0]);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        t: fe_mul(&e, &h),
        z: fe_mul(&f, &g),
    }
}

fn point_neg(p: &Point) -> Point {
    Point {
        x: fe_neg(&p.x),
        y: p.y,
        z: p.z,
        t: fe_neg(&p.t),
    }
}

/// [k]P by double and add over the 253 significant bits of a reduced scalar.
fn scalar_mul(k: &Fe, p: &Point) -> Point {
    let mut acc = IDENTITY;
    let mut started = false;
    for limb in (0..4).rev() {
        for bit in (0..64).rev() {
            if started {
                acc = point_add(&acc, &acc);
            }
            if (k[limb] >> bit) & 1 == 1 {
                acc = if started { point_add(&acc, p) } else { *p };
                started = true;
            }
        }
    }
    acc
}

fn point_encode(p: &Point) -> [u8; 32] {
    let zinv = fe_invert(&p.z);
    let x = fe_mul(&p.x, &zinv);
    let y = fe_mul(&p.y, &zinv);
    let mut out = fe_to_bytes(&y);
    if fe_is_odd(&x) {
        out[31] |= 0x80;
    }
    out
}

/// RFC 8032 section 5.1.3. Rejects a non-canonical y and an all-zero x with the sign bit set.
fn point_decode(bytes: &[u8; 32]) -> Option<Point> {
    let sign = bytes[31] >> 7;
    let mut yb = *bytes;
    yb[31] &= 0x7f;
    let y = fe_from_bytes(&yb);
    if ge(&y, &P) {
        return None;
    }

    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &ONE);
    let v = fe_add(&fe_mul(&D, &y2), &ONE);

    // x = (u/v)^((p+3)/8), computed as u*v^3 * (u*v^7)^((p-5)/8).
    let v3 = fe_mul(&fe_sq(&v), &v);
    let v7 = fe_mul(&fe_sq(&v3), &v);
    let uv7 = fe_mul(&u, &v7);
    // (p-5)/8 = 2^252 - 3
    let exp = sub_raw(&[0, 0, 0, 0x1000_0000_0000_0000], &[3, 0, 0, 0]);
    let mut x = fe_mul(&fe_mul(&u, &v3), &fe_pow(&uv7, &exp));

    let check = fe_mul(&v, &fe_sq(&x));
    if !fe_eq(&check, &u) {
        x = fe_mul(&x, &SQRT_M1);
        let check2 = fe_mul(&v, &fe_sq(&x));
        if !fe_eq(&check2, &u) {
            return None;
        }
    }

    if fe_is_zero(&x) && sign == 1 {
        return None;
    }
    if fe_is_odd(&x) != (sign == 1) {
        x = fe_neg(&x);
    }

    Some(Point {
        x,
        y,
        z: ONE,
        t: fe_mul(&x, &y),
    })
}

/// Reduce a 64-byte little-endian integer modulo L by binary long division.
///
/// Slow and obvious on purpose. A verifier performs a handful of signature checks per run, so
/// 512 shift-and-subtract steps cost nothing measurable, and the alternative (a hand-unrolled
/// Barrett reduction) is the kind of code whose bugs only show on rare inputs.
fn scalar_reduce_wide(wide: &[u8; 64]) -> Fe {
    let mut r = ZERO;
    for byte_index in (0..64).rev() {
        for bit in (0..8).rev() {
            // r = r*2 + bit. r stays below L < 2^253, so r*2 + 1 < 2^254 and never overflows.
            let mut shifted = ZERO;
            let mut carry = 0u64;
            for i in 0..4 {
                shifted[i] = (r[i] << 1) | carry;
                carry = r[i] >> 63;
            }
            debug_assert_eq!(carry, 0);
            let b = u64::from((wide[byte_index] >> bit) & 1);
            let (with_bit, c) = add_raw(&shifted, &[b, 0, 0, 0]);
            debug_assert_eq!(c, 0);
            r = if ge(&with_bit, &L) {
                sub_raw(&with_bit, &L)
            } else {
                with_bit
            };
        }
    }
    r
}

/// Verify a PureEd25519 signature. `signature` is the raw 64 bytes, `public_key` the raw 32.
///
/// The check is cofactorless, as RFC 8032 section 5.1.7 step 3 describes it: recompute
/// [S]B - [k]A and compare its encoding with R. A malleable S (one at or above L) is rejected
/// before anything else, so a second encoding of the same signature cannot verify.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    let s = fe_from_bytes(&s_bytes);
    if ge(&s, &L) {
        return false;
    }

    let a = match point_decode(public_key) {
        Some(p) => p,
        None => return false,
    };
    // R is decoded to confirm it is a well formed point encoding; the comparison itself is on
    // the encoded bytes, which is what RFC 8032 specifies.
    if point_decode(&r_bytes).is_none() {
        return false;
    }

    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&r_bytes);
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(message);
    let k = scalar_reduce_wide(&sha512(&preimage));

    let b = Point {
        x: BX,
        y: BY,
        z: ONE,
        t: fe_mul(&BX, &BY),
    };
    let sb = scalar_mul(&s, &b);
    let ka = scalar_mul(&k, &a);
    let recomputed = point_add(&sb, &point_neg(&ka));

    point_encode(&recomputed) == r_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64;
    use crate::hex::from_hex;

    fn key32(hex: &str) -> [u8; 32] {
        let v = from_hex(hex).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    fn sig64(hex: &str) -> [u8; 64] {
        let v = from_hex(hex).unwrap();
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn field_arithmetic_basics() {
        // p - 1 + 1 = 0
        let pm1 = sub_raw(&P, &ONE);
        assert!(fe_is_zero(&fe_add(&pm1, &ONE)));
        // 2 * ((p+1)/2) = 1
        let half = fe_invert(&[2, 0, 0, 0]);
        assert!(fe_eq(&fe_mul(&half, &[2, 0, 0, 0]), &ONE));
        // (p-1)^2 = 1
        assert!(fe_eq(&fe_sq(&pm1), &ONE));
        // SQRT_M1^2 = -1
        assert!(fe_eq(&fe_sq(&SQRT_M1), &fe_neg(&ONE)));
    }

    #[test]
    fn base_point_has_order_l() {
        let b = Point {
            x: BX,
            y: BY,
            z: ONE,
            t: fe_mul(&BX, &BY),
        };
        let lb = scalar_mul(&L, &b);
        // [L]B is the identity, encoded as y = 1 with a clear sign bit.
        assert_eq!(point_encode(&lb), point_encode(&IDENTITY));
    }

    #[test]
    fn rfc8032_test_vectors() {
        // RFC 8032 section 7.1, TEST 1: empty message.
        assert!(verify(
            &key32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            b"",
            &sig64(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        ));

        // TEST 2: one byte message.
        assert!(verify(
            &key32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            &[0x72],
            &sig64(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        ));

        // TEST 3: two byte message.
        assert!(verify(
            &key32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            &[0xaf, 0x82],
            &sig64(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            )
        ));

        // TEST SHA(abc): a 64-byte message, so the SHA-512 inside verification spans blocks.
        assert!(verify(
            &key32("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
            &from_hex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
            .unwrap(),
            &sig64(
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
            )
        ));
    }

    #[test]
    fn rejects_tampering() {
        let pk = key32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let good = sig64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        assert!(verify(&pk, &[0x72], &good));

        // A flipped message byte.
        assert!(!verify(&pk, &[0x73], &good));

        // A flipped bit in R and a flipped bit in S, checked separately: the two halves of the
        // signature fail through different paths.
        let mut bad_r = good;
        bad_r[0] ^= 0x01;
        assert!(!verify(&pk, &[0x72], &bad_r));
        let mut bad_s = good;
        bad_s[32] ^= 0x01;
        assert!(!verify(&pk, &[0x72], &bad_s));

        // A different, valid public key.
        let other = key32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(!verify(&other, &[0x72], &good));

        // S >= L must be refused rather than reduced.
        let mut malleable = good;
        malleable[32..].copy_from_slice(&fe_to_bytes(&L));
        assert!(!verify(&pk, &[0x72], &malleable));
    }

    #[test]
    fn verifies_the_spec_worked_example_checkpoint() {
        // docs/audit-format.md, "Worked example: a checkpoint". The signed bytes, the signature
        // and the key are all quoted verbatim in the document.
        let signed = concat!(
            r#"{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","#,
            r#""signedAt":"2026-01-01T00:00:03.000Z","algorithm":"ed25519"}"#
        );
        let der =
            base64::decode("MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=").unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&der[12..]);
        let raw = base64::decode(
            "0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==",
        )
        .unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&raw);

        assert!(verify(&pk, signed.as_bytes(), &sig));

        // "Flipping one byte of the signed bytes ... makes it fail; that is the check."
        let mut tampered = signed.as_bytes().to_vec();
        tampered[20] ^= 0x01;
        assert!(!verify(&pk, &tampered, &sig));
    }
}
