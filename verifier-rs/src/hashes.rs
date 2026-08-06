//! SHA-1, RIPEMD-160 and Keccak-256: the other three hash operations in the OpenTimestamps
//! operation grammar.
//!
//! `docs/audit-format.md` lists `02` sha1, `03` ripemd160, `08` sha256 and `67` keccak256 as
//! operations a proof may contain. The Agentwall writer only ever produces proofs whose calendar
//! responses use sha256, so it would be easy to implement one operation and call the rest
//! unsupported. That would be a verifier that stops reading at the first unfamiliar byte and
//! reports a parse error over a proof that is fine, which is a false alarm on real evidence, so
//! all four are here. Each is checked against its published vectors below rather than assumed
//! correct because the corpus never exercises it.
//!
//! Keccak-256 is the original Keccak padding (`0x01`), not SHA3-256's (`0x06`). OpenTimestamps
//! took the operation from Ethereum, which predates the SHA-3 padding change.

pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_be_bytes());

    let mut w = [0u32; 80];
    for block in padded.chunks_exact(64) {
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const RMD_RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, //
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, //
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, //
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RMD_RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, //
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, //
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, //
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, //
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const RMD_SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, //
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, //
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, //
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, //
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const RMD_SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, //
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, //
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, //
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, //
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const RMD_KL: [u32; 5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const RMD_KR: [u32; 5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

fn rmd_f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | ((!x) & z),
        2 => (x | (!y)) ^ z,
        3 => (x & z) | (y & (!z)),
        _ => x ^ (y | (!z)),
    }
}

pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_le_bytes());

    for block in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);

        for i in 0..80 {
            let round = i / 16;
            let tl = al
                .wrapping_add(rmd_f(round, bl, cl, dl))
                .wrapping_add(x[RMD_RL[i]])
                .wrapping_add(RMD_KL[round])
                .rotate_left(RMD_SL[i])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = tl;

            let tr = ar
                .wrapping_add(rmd_f(4 - round, br, cr, dr))
                .wrapping_add(x[RMD_RR[i]])
                .wrapping_add(RMD_KR[round])
                .rotate_left(RMD_SR[i])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = tr;
        }

        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(er);
        h[2] = h[3].wrapping_add(el).wrapping_add(ar);
        h[3] = h[4].wrapping_add(al).wrapping_add(br);
        h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROT: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

fn keccak_f(state: &mut [u64; 25]) {
    for &rc in KECCAK_RC.iter() {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(KECCAK_ROT[x + 5 * y]);
            }
        }
        // chi
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        state[0] ^= rc;
    }
}

/// The keccak-f[1600] sponge at rate 136 with a 256-bit output. `pad` is the domain separation
/// byte: `0x01` for original Keccak, `0x06` for SHA3. Only Keccak is used in production; SHA3
/// exists so the tests can check this permutation against a source outside this crate, which
/// no published Keccak-256 vector longer than one block was available to do.
fn sponge256(input: &[u8], pad: u8) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];

    let mut padded = input.to_vec();
    padded.push(pad);
    while !padded.len().is_multiple_of(RATE) {
        padded.push(0);
    }
    let last = padded.len() - 1;
    padded[last] |= 0x80;

    for block in padded.chunks_exact(RATE) {
        for (i, word) in block.chunks_exact(8).enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(word);
            state[i] ^= u64::from_le_bytes(w);
        }
        keccak_f(&mut state);
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    sponge256(input, 0x01)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::to_hex;

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            to_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            to_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn ripemd160_vectors() {
        // From the RIPEMD-160 reference test suite.
        assert_eq!(
            to_hex(&ripemd160(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            to_hex(&ripemd160(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
        assert_eq!(
            to_hex(&ripemd160(b"message digest")),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        );
        assert_eq!(
            to_hex(&ripemd160(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
        );
        assert_eq!(
            to_hex(&ripemd160(&vec![b'a'; 1_000_000])),
            "52783243c1697bdbe16d37f97f68f08325dc1528"
        );
    }

    #[test]
    fn keccak256_vectors() {
        // Original Keccak padding, the variant Ethereum and OpenTimestamps use.
        assert_eq!(
            to_hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            to_hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            to_hex(&keccak256(b"The quick brown fox jumps over the lazy dog")),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );
    }

    #[test]
    fn keccak_permutation_matches_sha3_256() {
        // Keccak-256 and SHA3-256 differ only in the domain separation byte, so checking the
        // SHA3 side against Python's hashlib checks this crate's permutation, rate and
        // absorb loop against an implementation nobody here wrote. Published Keccak-256
        // vectors above pin the one byte SHA3 cannot: the padding constant.
        let sha3 = |m: &[u8]| to_hex(&sponge256(m, 0x06));
        assert_eq!(
            sha3(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            sha3(b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        // Exactly one rate block, so padding forces a second permutation.
        assert_eq!(
            sha3(&[0u8; 136]),
            "e772c9cf9eb9c991cdfcf125001b454fdbc0a95f188d1b4c844aa032ad6e075e"
        );
        // Two blocks with a partial tail.
        assert_eq!(
            sha3(&[0u8; 200]),
            "2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e"
        );
        assert_eq!(
            sha3(&vec![b'a'; 1_000_000]),
            "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
        );
    }
}
