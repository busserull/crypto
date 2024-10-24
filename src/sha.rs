use std::slice::ChunksExact;

const SHA256K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_digest(input: &[u8]) -> [u8; 32] {
    do_sha256_digest(input, None, 0)
}

pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    do_sha1_digest(input, None, 0)
}

pub fn sha1_digest_from_state(input: &[u8], state: &[u8; 20], head_bytes: usize) -> [u8; 20] {
    do_sha1_digest(input, Some(state), head_bytes)
}

fn do_sha1_digest(input: &[u8], state: Option<&[u8; 20]>, extra_byte_length: usize) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    if let Some(state) = state {
        for (slot, bytes) in h.iter_mut().zip(state.chunks_exact(4)) {
            let mut word = [0; 4];
            word.copy_from_slice(bytes);

            *slot = u32::from_be_bytes(word);
        }
    }

    for block in Sha1Blocks::new(input, extra_byte_length) {
        let w = sha1_schedule(&block);

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut t;

        for i in 0..80 {
            t = a
                .rotate_left(5)
                .wrapping_add(sha1_ft(i, b, c, d))
                .wrapping_add(e)
                .wrapping_add(sha1_kt(i))
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut digest = [0; 20];

    (&mut digest[0..4]).copy_from_slice(&h[0].to_be_bytes());
    (&mut digest[4..8]).copy_from_slice(&h[1].to_be_bytes());
    (&mut digest[8..12]).copy_from_slice(&h[2].to_be_bytes());
    (&mut digest[12..16]).copy_from_slice(&h[3].to_be_bytes());
    (&mut digest[16..20]).copy_from_slice(&h[4].to_be_bytes());

    digest
}

fn sha1_schedule(m: &[u32; 16]) -> [u32; 80] {
    let mut w = [0; 80];

    for i in 0..16 {
        w[i] = m[i];
    }

    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    w
}

fn sha1_ft(t: usize, x: u32, y: u32, z: u32) -> u32 {
    match t {
        0..20 => (x & y) ^ ((!x) & z),
        20..40 => x ^ y ^ z,
        40..60 => (x & y) ^ (x & z) ^ (y & z),
        60..80 => x ^ y ^ z,
        _ => unreachable!(),
    }
}

fn sha1_kt(t: usize) -> u32 {
    match t {
        0..20 => 0x5a827999,
        20..40 => 0x6ed9eba1,
        40..60 => 0x8f1bbcdc,
        60..80 => 0xca62c1d6,
        _ => unreachable!(),
    }
}

struct Sha1Blocks<'a> {
    chunks: ChunksExact<'a, u8>,
    tail_block: Option<[u32; 16]>,
    bit_length: u64,
    done: bool,
}

impl<'a> Sha1Blocks<'a> {
    fn new(input: &'a [u8], extra_byte_length: usize) -> Self {
        Self {
            chunks: input.chunks_exact(64),
            tail_block: None,
            bit_length: (input.len() + extra_byte_length) as u64 * 8,
            done: false,
        }
    }
}

impl<'a> Iterator for Sha1Blocks<'a> {
    type Item = [u32; 16];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            let tail_block = self.tail_block;
            self.tail_block = None;

            return tail_block;
        }

        let mut block: [u32; 16] = [0; 16];

        if let Some(bytes) = self.chunks.next() {
            place_bytes_in_block(&mut block, bytes);

            return Some(block);
        }

        let tail = self.chunks.remainder();
        let tail_bytes = tail.len();

        place_bytes_in_block(&mut block, tail);

        let length_bytes = self.bit_length.to_be_bytes();
        let length_upper = u32::from_be_bytes((&length_bytes[0..4]).try_into().unwrap());
        let length_lower = u32::from_be_bytes((&length_bytes[4..8]).try_into().unwrap());

        if tail_bytes > 55 {
            let mut tail_block = [0; 16];

            tail_block[14] = length_upper;
            tail_block[15] = length_lower;

            self.tail_block = Some(tail_block);
        } else {
            block[14] = length_upper;
            block[15] = length_lower;
        }

        self.done = true;

        Some(block)
    }
}

fn do_sha256_digest(input: &[u8], state: Option<&[u8; 32]>, extra_byte_length: usize) -> [u8; 32] {
    let mut hbig: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    if let Some(state) = state {
        for (slot, bytes) in hbig.iter_mut().zip(state.chunks_exact(4)) {
            let mut word = [0; 4];
            word.copy_from_slice(bytes);

            *slot = u32::from_be_bytes(word);
        }
    }

    for mut block in Sha256Blocks::new(input, extra_byte_length) {
        sha256_schedule(&mut block);

        let mut a = hbig[0];
        let mut b = hbig[1];
        let mut c = hbig[2];
        let mut d = hbig[3];
        let mut e = hbig[4];
        let mut f = hbig[5];
        let mut g = hbig[6];
        let mut h = hbig[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(SHA256K[i])
                .wrapping_add(block[i]);

            let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        hbig[0] = hbig[0].wrapping_add(a);
        hbig[1] = hbig[1].wrapping_add(b);
        hbig[2] = hbig[2].wrapping_add(c);
        hbig[3] = hbig[3].wrapping_add(d);
        hbig[4] = hbig[4].wrapping_add(e);
        hbig[5] = hbig[5].wrapping_add(f);
        hbig[6] = hbig[6].wrapping_add(g);
        hbig[7] = hbig[7].wrapping_add(h);
    }

    let mut digest = [0; 32];

    (&mut digest[0..4]).copy_from_slice(&hbig[0].to_be_bytes());
    (&mut digest[4..8]).copy_from_slice(&hbig[1].to_be_bytes());
    (&mut digest[8..12]).copy_from_slice(&hbig[2].to_be_bytes());
    (&mut digest[12..16]).copy_from_slice(&hbig[3].to_be_bytes());
    (&mut digest[16..20]).copy_from_slice(&hbig[4].to_be_bytes());
    (&mut digest[20..24]).copy_from_slice(&hbig[5].to_be_bytes());
    (&mut digest[24..28]).copy_from_slice(&hbig[6].to_be_bytes());
    (&mut digest[28..32]).copy_from_slice(&hbig[7].to_be_bytes());

    digest
}

fn sha256_schedule(block: &mut [u32; 64]) {
    for i in 16..64 {
        let s1 = block[i - 2];
        let s0 = block[i - 15];

        block[i] = (s1.rotate_right(17) ^ s1.rotate_right(19) ^ s1.wrapping_shr(10))
            .wrapping_add(block[i - 7])
            .wrapping_add(s0.rotate_right(7) ^ s0.rotate_right(18) ^ s0.wrapping_shr(3))
            .wrapping_add(block[i - 16]);
    }
}

struct Sha256Blocks<'a> {
    chunks: ChunksExact<'a, u8>,
    tail_block: Option<[u32; 64]>,
    bit_length: u64,
    done: bool,
}

impl<'a> Sha256Blocks<'a> {
    fn new(input: &'a [u8], extra_byte_length: usize) -> Self {
        Self {
            chunks: input.chunks_exact(256),
            tail_block: None,
            bit_length: (input.len() + extra_byte_length) as u64 * 8,
            done: false,
        }
    }
}

impl<'a> Iterator for Sha256Blocks<'a> {
    type Item = [u32; 64];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            let tail_block = self.tail_block;
            self.tail_block = None;

            return tail_block;
        }

        let mut block: [u32; 64] = [0; 64];

        if let Some(bytes) = self.chunks.next() {
            place_bytes_in_block(&mut block, bytes);

            return Some(block);
        }

        let tail = self.chunks.remainder();
        let tail_bytes = tail.len();

        place_bytes_in_block(&mut block, tail);

        let length_bytes = self.bit_length.to_be_bytes();
        let length_upper = u32::from_be_bytes((&length_bytes[0..4]).try_into().unwrap());
        let length_lower = u32::from_be_bytes((&length_bytes[4..8]).try_into().unwrap());

        if tail_bytes > 55 {
            let mut tail_block = [0; 64];

            tail_block[14] = length_upper;
            tail_block[15] = length_lower;

            self.tail_block = Some(tail_block);
        } else {
            block[14] = length_upper;
            block[15] = length_lower;
        }

        self.done = true;

        Some(block)
    }
}

fn place_bytes_in_block(block: &mut [u32], bytes: &[u8]) {
    let mut bytes = bytes
        .iter()
        .copied()
        .chain([0x80])
        .chain([0].into_iter().cycle());

    for slot in block.iter_mut() {
        let word_bytes: [u8; 4] = [
            bytes.next().unwrap(),
            bytes.next().unwrap(),
            bytes.next().unwrap(),
            bytes.next().unwrap(),
        ];

        *slot = u32::from_be_bytes(word_bytes);
    }
}
