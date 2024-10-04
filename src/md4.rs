use std::slice::ChunksExact;

pub fn md4_digest(input: &[u8]) -> [u8; 16] {
    do_md4_digest(input, None, 0)
}

pub fn md4_digest_from_state(input: &[u8], state: &[u8; 16], head_bytes: usize) -> [u8; 16] {
    do_md4_digest(input, Some(state), head_bytes)
}

macro_rules! r1 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:literal, $s:literal) => {
        $a = $a
            .wrapping_add(md4_f($b, $c, $d))
            .wrapping_add($x[$i])
            .rotate_left($s);
    };
}

macro_rules! r2 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:literal, $s:literal) => {
        $a = $a
            .wrapping_add(md4_g($b, $c, $d))
            .wrapping_add($x[$i])
            .wrapping_add(0x5a827999)
            .rotate_left($s);
    };
}

macro_rules! r3 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:literal, $s:literal) => {
        $a = $a
            .wrapping_add(md4_h($b, $c, $d))
            .wrapping_add($x[$i])
            .wrapping_add(0x6ed9eba1)
            .rotate_left($s);
    };
}

fn do_md4_digest(input: &[u8], state: Option<&[u8; 16]>, extra_byte_length: usize) -> [u8; 16] {
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    if let Some(state) = state {
        for (slot, bytes) in h.iter_mut().zip(state.chunks_exact(4)) {
            let mut word = [0; 4];
            word.copy_from_slice(bytes);

            *slot = u32::from_le_bytes(word);
        }
    }

    for block in Md4Blocks::new(input, extra_byte_length) {
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];

        /* Round 1 */
        r1![a, b, c, d, block, 0, 3];
        r1![d, a, b, c, block, 1, 7];
        r1![c, d, a, b, block, 2, 11];
        r1![b, c, d, a, block, 3, 19];
        r1![a, b, c, d, block, 4, 3];
        r1![d, a, b, c, block, 5, 7];
        r1![c, d, a, b, block, 6, 11];
        r1![b, c, d, a, block, 7, 19];
        r1![a, b, c, d, block, 8, 3];
        r1![d, a, b, c, block, 9, 7];
        r1![c, d, a, b, block, 10, 11];
        r1![b, c, d, a, block, 11, 19];
        r1![a, b, c, d, block, 12, 3];
        r1![d, a, b, c, block, 13, 7];
        r1![c, d, a, b, block, 14, 11];
        r1![b, c, d, a, block, 15, 19];

        /* Round 2 */
        r2![a, b, c, d, block, 0, 3];
        r2![d, a, b, c, block, 4, 5];
        r2![c, d, a, b, block, 8, 9];
        r2![b, c, d, a, block, 12, 13];
        r2![a, b, c, d, block, 1, 3];
        r2![d, a, b, c, block, 5, 5];
        r2![c, d, a, b, block, 9, 9];
        r2![b, c, d, a, block, 13, 13];
        r2![a, b, c, d, block, 2, 3];
        r2![d, a, b, c, block, 6, 5];
        r2![c, d, a, b, block, 10, 9];
        r2![b, c, d, a, block, 14, 13];
        r2![a, b, c, d, block, 3, 3];
        r2![d, a, b, c, block, 7, 5];
        r2![c, d, a, b, block, 11, 9];
        r2![b, c, d, a, block, 15, 13];

        /* Round 3 */
        r3![a, b, c, d, block, 0, 3];
        r3![d, a, b, c, block, 8, 9];
        r3![c, d, a, b, block, 4, 11];
        r3![b, c, d, a, block, 12, 15];
        r3![a, b, c, d, block, 2, 3];
        r3![d, a, b, c, block, 10, 9];
        r3![c, d, a, b, block, 6, 11];
        r3![b, c, d, a, block, 14, 15];
        r3![a, b, c, d, block, 1, 3];
        r3![d, a, b, c, block, 9, 9];
        r3![c, d, a, b, block, 5, 11];
        r3![b, c, d, a, block, 13, 15];
        r3![a, b, c, d, block, 3, 3];
        r3![d, a, b, c, block, 11, 9];
        r3![c, d, a, b, block, 7, 11];
        r3![b, c, d, a, block, 15, 15];

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    let mut digest = [0; 16];

    (&mut digest[0..4]).copy_from_slice(&h[0].to_le_bytes());
    (&mut digest[4..8]).copy_from_slice(&h[1].to_le_bytes());
    (&mut digest[8..12]).copy_from_slice(&h[2].to_le_bytes());
    (&mut digest[12..16]).copy_from_slice(&h[3].to_le_bytes());

    digest
}

fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

struct Md4Blocks<'a> {
    chunks: ChunksExact<'a, u8>,
    tail_block: Option<[u32; 16]>,
    bit_length: u64,
    done: bool,
}

impl<'a> Md4Blocks<'a> {
    fn new(input: &'a [u8], extra_byte_length: usize) -> Self {
        Self {
            chunks: input.chunks_exact(64),
            tail_block: None,
            bit_length: (input.len() + extra_byte_length) as u64 * 8,
            done: false,
        }
    }
}

impl<'a> Iterator for Md4Blocks<'a> {
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

        let length_bytes = self.bit_length.to_le_bytes();
        let length_upper = u32::from_le_bytes((&length_bytes[0..4]).try_into().unwrap());
        let length_lower = u32::from_le_bytes((&length_bytes[4..8]).try_into().unwrap());

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

        *slot = u32::from_le_bytes(word_bytes);
    }
}
