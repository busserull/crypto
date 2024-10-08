use super::pkcs7;

pub struct AesCtrIter {
    key_schedule: Vec<u32>,
    block: Block,
    nonce: u64,
    counter: u64,
    index: usize,
}

impl AesCtrIter {
    pub fn new(key: &AesKey, nonce: u64) -> Self {
        Self {
            key_schedule: key.schedule(),
            block: Block([0; 16]),
            nonce,
            counter: 0,
            index: 16,
        }
    }

    fn make_block(&mut self) {
        let mut block = Block([0; 16]);

        (&mut block.0[..8]).copy_from_slice(&self.nonce.to_le_bytes());
        (&mut block.0[8..]).copy_from_slice(&self.counter.to_le_bytes());

        self.block = cipher(block, &self.key_schedule);
        self.counter += 1;
        self.index = 0;
    }
}

impl Iterator for AesCtrIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index > 15 {
            self.make_block();
        }

        let byte = self.block.0[self.index];
        self.index += 1;

        Some(byte)
    }
}

pub fn aes_ctr<I: AsRef<[u8]>>(input: I, key: &AesKey, nonce: u64) -> Vec<u8> {
    let mut output = Vec::new();

    let key_schedule = key.schedule();

    let mut gen_block = Block([0; 16]);

    for (i, block) in input.as_ref().chunks(16).enumerate() {
        (&mut gen_block.0[..8]).copy_from_slice(&nonce.to_le_bytes());
        (&mut gen_block.0[8..]).copy_from_slice(&(i as u64).to_le_bytes());

        gen_block = cipher(gen_block, &key_schedule);

        let mut xor_block = Block([0; 16]);
        let input_block_len = block.len();
        (&mut xor_block.0[..input_block_len]).copy_from_slice(block);

        xor_block.xor_inplace(&gen_block);

        output.extend_from_slice(&xor_block.0[..input_block_len]);
    }

    output
}

pub fn aes_cbc_encrypt<I: AsRef<[u8]>, V: AsRef<[u8]>>(
    input: I,
    key: &AesKey,
    iv: V,
) -> Result<Vec<u8>, AesError> {
    if iv.as_ref().len() != 16 {
        return Err(AesError::WrongSizeIv);
    }

    let mut iv_block: [u8; 16] = [0; 16];
    iv_block.copy_from_slice(iv.as_ref());

    let key_schedule = key.schedule();

    let mut last_cipher_block = Block(iv_block);
    let mut ciphertext = Vec::new();

    for block in BlockIter::padded(input.as_ref()) {
        let block = block.xor(&last_cipher_block);
        last_cipher_block = cipher(block, &key_schedule);

        ciphertext.extend_from_slice(last_cipher_block.as_ref());
    }

    Ok(ciphertext)
}

pub fn aes_cbc_decrypt<I: AsRef<[u8]>, V: AsRef<[u8]>>(
    input: I,
    key: &AesKey,
    iv: V,
) -> Result<Vec<u8>, AesError> {
    if input.as_ref().len() % 16 != 0 {
        return Err(AesError::IrregularDecryptLength);
    }

    let mut iv_block: [u8; 16] = [0; 16];
    iv_block.copy_from_slice(iv.as_ref());

    let key_schedule = key.schedule();

    let mut last_cipher_block = Block(iv_block);
    let mut cleartext = Vec::new();

    for block in BlockIter::exact(input.as_ref()) {
        let inv_cipher_block = inv_cipher(block, &key_schedule);
        let clear_block = inv_cipher_block.xor(&last_cipher_block);

        last_cipher_block = block;

        cleartext.extend_from_slice(clear_block.as_ref());
    }

    let cleartext_end = pkcs7::unpad_length(&cleartext);

    if cleartext_end == cleartext.len() {
        return Err(AesError::PaddingError);
    }

    cleartext.truncate(cleartext_end);

    Ok(cleartext)
}

pub fn aes_ecb_encrypt<I: AsRef<[u8]>>(input: I, key: &AesKey) -> Vec<u8> {
    let key_schedule = key.schedule();

    BlockIter::padded(input.as_ref())
        .into_iter()
        .map(|block| cipher(block, &key_schedule))
        .collect()
}

pub fn aes_ecb_decrypt<I: AsRef<[u8]>>(input: I, key: &AesKey) -> Result<Vec<u8>, AesError> {
    if input.as_ref().len() % 16 != 0 {
        return Err(AesError::IrregularDecryptLength);
    }

    let key_schedule = key.schedule();

    Ok(BlockIter::exact(input.as_ref())
        .into_iter()
        .map(|block| inv_cipher(block, &key_schedule))
        .collect())
}

struct BlockIter<'a> {
    create_padded_block: bool,
    chunks: std::slice::ChunksExact<'a, u8>,
}

impl<'a> BlockIter<'a> {
    fn padded(input: &'a [u8]) -> Self {
        Self {
            create_padded_block: true,
            chunks: input.chunks_exact(16),
        }
    }

    fn exact(input: &'a [u8]) -> Self {
        Self {
            create_padded_block: false,
            chunks: input.chunks_exact(16),
        }
    }
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.chunks.next(), self.create_padded_block) {
            (Some(chunk), _) => {
                let mut block: [u8; 16] = [0; 16];
                block.copy_from_slice(chunk);

                Some(Block(block))
            }

            (None, true) => {
                self.create_padded_block = false;

                let rest = self.chunks.remainder();
                let bytes_to_copy = rest.len();

                let mut block: [u8; 16] = [0; 16];
                (&mut block[0..bytes_to_copy]).copy_from_slice(&rest);

                pkcs7::pad_inplace(&mut block, bytes_to_copy);

                Some(Block(block))
            }

            (None, false) => None,
        }
    }
}

#[derive(Debug)]
pub enum AesError {
    NonstandardKeyLength,
    IrregularDecryptLength,
    WrongSizeIv,
    PaddingError,
}

pub enum AesKey {
    Aes128([u8; 16]),
    Aes192([u8; 24]),
    Aes256([u8; 32]),
}

impl AesKey {
    pub fn from(bytes: &[u8]) -> Result<Self, AesError> {
        use AesError::*;
        use AesKey::*;

        match bytes.len() {
            16 => {
                let mut key = [0; 16];
                key.copy_from_slice(&bytes);
                Ok(Aes128(key))
            }

            24 => {
                let mut key = [0; 24];
                key.copy_from_slice(&bytes);
                Ok(Aes192(key))
            }

            32 => {
                let mut key = [0; 32];
                key.copy_from_slice(&bytes);
                Ok(Aes256(key))
            }

            _ => Err(NonstandardKeyLength),
        }
    }

    fn schedule(&self) -> Vec<u32> {
        use AesKey::*;

        match self {
            Aes128(bytes) => key_expansion(bytes),
            Aes192(bytes) => key_expansion(bytes),
            Aes256(bytes) => key_expansion(bytes),
        }
    }
}

impl AsRef<[u8]> for AesKey {
    fn as_ref(&self) -> &[u8] {
        use AesKey::*;

        match self {
            Aes128(bytes) => bytes,
            Aes192(bytes) => bytes,
            Aes256(bytes) => bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct Block([u8; 16]);

impl Block {
    fn at(&mut self, row: usize, col: usize) -> &mut u8 {
        &mut self.0[4 * row + col]
    }

    fn add_round_key(&mut self, round_key: &[u32]) {
        let round_key: &[u32; 4] = round_key.try_into().unwrap();

        for col in 0..4 {
            for row in 0..4 {
                let key_byte = round_key[row].wrapping_shr(8 * (3 - col as u32)) as u8;
                *self.at(row, col) ^= key_byte;
            }
        }
    }

    fn sub_bytes(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = sbox(*byte);
        }
    }

    fn inv_sub_bytes(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = inv_sbox(*byte);
        }
    }

    fn shift_rows(&mut self) {
        let mut copy: [u8; 16] = [0; 16];
        copy.copy_from_slice(&self.0);

        self.0[1] = copy[5];
        self.0[2] = copy[10];
        self.0[3] = copy[15];
        self.0[5] = copy[9];
        self.0[6] = copy[14];
        self.0[7] = copy[3];
        self.0[9] = copy[13];
        self.0[10] = copy[2];
        self.0[11] = copy[7];
        self.0[13] = copy[1];
        self.0[14] = copy[6];
        self.0[15] = copy[11];
    }

    fn inv_shift_rows(&mut self) {
        let mut copy: [u8; 16] = [0; 16];
        copy.copy_from_slice(&self.0);

        self.0[1] = copy[13];
        self.0[2] = copy[10];
        self.0[3] = copy[7];
        self.0[5] = copy[1];
        self.0[6] = copy[14];
        self.0[7] = copy[11];
        self.0[9] = copy[5];
        self.0[10] = copy[2];
        self.0[11] = copy[15];
        self.0[13] = copy[9];
        self.0[14] = copy[6];
        self.0[15] = copy[3];
    }

    fn mix_columns(&mut self) {
        for row in 0..4 {
            let a: [u8; 4] = [
                *self.at(row, 0),
                *self.at(row, 1),
                *self.at(row, 2),
                *self.at(row, 3),
            ];

            let mut b: [u8; 4] = [0; 4];

            for i in 0..4 {
                b[i] = xtimes(a[i]);
            }

            *self.at(row, 0) = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
            *self.at(row, 1) = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
            *self.at(row, 2) = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
            *self.at(row, 3) = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
        }
    }

    fn inv_mix_columns(&mut self) {
        for row in 0..4 {
            let a = *self.at(row, 0);
            let b = *self.at(row, 1);
            let c = *self.at(row, 2);
            let d = *self.at(row, 3);

            *self.at(row, 0) = xmul(a, 0x0e) ^ xmul(b, 0x0b) ^ xmul(c, 0x0d) ^ xmul(d, 0x09);
            *self.at(row, 1) = xmul(a, 0x09) ^ xmul(b, 0x0e) ^ xmul(c, 0x0b) ^ xmul(d, 0x0d);
            *self.at(row, 2) = xmul(a, 0x0d) ^ xmul(b, 0x09) ^ xmul(c, 0x0e) ^ xmul(d, 0x0b);
            *self.at(row, 3) = xmul(a, 0x0b) ^ xmul(b, 0x0d) ^ xmul(c, 0x09) ^ xmul(d, 0x0e);
        }
    }

    fn xor(&self, rhs: &Self) -> Self {
        let mut block: [u8; 16] = [0; 16];

        for (slot, (a, b)) in block.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *slot = a ^ b;
        }

        Self(block)
    }

    fn xor_inplace(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromIterator<Block> for Vec<u8> {
    fn from_iter<T: IntoIterator<Item = Block>>(iter: T) -> Self {
        let mut vec = Vec::new();

        for block in iter.into_iter() {
            vec.extend_from_slice(&block.0);
        }

        vec
    }
}

fn xtimes(byte: u8) -> u8 {
    byte.wrapping_shl(1) ^ byte.wrapping_shr(7).wrapping_mul(0x1b)
}

fn xmul(a: u8, b: u8) -> u8 {
    (b & 1).wrapping_mul(a)
        ^ (b.wrapping_shr(1) & 1).wrapping_mul(xtimes(a))
        ^ (b.wrapping_shr(2) & 1).wrapping_mul(xtimes(xtimes(a)))
        ^ (b.wrapping_shr(3) & 1).wrapping_mul(xtimes(xtimes(xtimes(a))))
}

fn cipher(mut state: Block, key_schedule: &[u32]) -> Block {
    let rounds = key_schedule.len() / 4 - 1;

    state.add_round_key(&key_schedule[0..4]);

    for round in 1..=rounds - 1 {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&key_schedule[4 * round..4 * round + 4]);
    }

    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&key_schedule[4 * rounds..4 * rounds + 4]);

    state
}

fn inv_cipher(mut state: Block, key_schedule: &[u32]) -> Block {
    let rounds = key_schedule.len() / 4 - 1;

    state.add_round_key(&key_schedule[4 * rounds..4 * rounds + 4]);

    for round in (1..rounds).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&key_schedule[4 * round..4 * round + 4]);
        state.inv_mix_columns();
    }

    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&key_schedule[0..4]);

    state
}

fn sbox(byte: u8) -> u8 {
    let lut: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    lut[byte as usize]
}

fn inv_sbox(byte: u8) -> u8 {
    let lut: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    lut[byte as usize]
}

fn subword(word: u32) -> u32 {
    let mut bytes = word.to_be_bytes();

    for byte in bytes.iter_mut() {
        *byte = sbox(*byte);
    }

    u32::from_be_bytes(bytes)
}

fn key_expansion(key: &[u8]) -> Vec<u32> {
    let mut key_words: Vec<u32> = key
        .chunks_exact(4)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
        .collect();

    let nk = key_words.len();

    let rounds = match nk {
        4 => 10,
        6 => 12,
        8 => 14,
        _ => unreachable!(),
    };

    let rcon: [u32; 11] = [
        0x0000_0000,
        0x0100_0000,
        0x0200_0000,
        0x0400_0000,
        0x0800_0000,
        0x1000_0000,
        0x2000_0000,
        0x4000_0000,
        0x8000_0000,
        0x1b00_0000,
        0x3600_0000,
    ];

    for i in nk..4 * rounds + 4 {
        let mut word = key_words[i - 1];

        if i % nk == 0 {
            word = subword(word.rotate_left(8)) ^ rcon[i / nk];
        } else if nk > 6 && i % nk == 4 {
            word = subword(word);
        }

        key_words.push(key_words[i - nk] ^ word);
    }

    key_words
}
