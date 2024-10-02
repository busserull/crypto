use std::slice::ChunksExact;

pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    do_sha1_digest(input, None)
}

pub fn sha1_digest_from_state(input: &[u8], initial_state: &[u8; 20]) -> [u8; 20] {
    do_sha1_digest(input, Some(initial_state))
}

fn do_sha1_digest(input: &[u8], state: Option<&[u8; 20]>) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    if let Some(state) = state {
        for (slot, bytes) in h.iter_mut().zip(state.chunks_exact(4)) {
            let mut word = [0; 4];
            word.copy_from_slice(bytes);

            *slot = u32::from_be_bytes(word);
        }
    }

    for block in Sha1Blocks::new(input) {
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
    fn new(input: &'a [u8]) -> Self {
        Self {
            chunks: input.chunks_exact(64),
            tail_block: None,
            bit_length: input.len() as u64 * 8,
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

fn place_bytes_in_block(block: &mut [u32; 16], bytes: &[u8]) {
    let mut bytes = bytes
        .iter()
        .copied()
        .chain([0x80])
        .chain([0].into_iter().cycle())
        .take(64);

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
