mod aes;
mod base64;
mod chunk_pair_iter;
mod key_value;
mod pkcs7;
mod urandom;

use aes::{aes_ecb_decrypt, aes_ecb_encrypt, AesKey};
use chunk_pair_iter::ChunkPairIter;
use key_value::KeyValue;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::hint::black_box;
use std::path::Path;

struct Buffer(Vec<u8>);

impl Buffer {
    fn from_file_base64<P: AsRef<Path>>(path: P) -> Self {
        let input = std::fs::read_to_string(&path)
            .expect(&format!("Cannot read {}", path.as_ref().to_string_lossy()));

        Self::from_base64(&input)
    }

    fn from_hex(string: &str) -> Self {
        Self(hex::decode(string).unwrap())
    }

    fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    fn from_base64(encoding: &str) -> Self {
        Self(base64::base64_to_bytes(encoding))
    }

    fn to_base64(&self) -> String {
        base64::bytes_to_base64(&self.0)
    }

    fn xor(&self, rhs: &Self) -> Self {
        let new_buffer_size = std::cmp::max(self.0.len(), rhs.0.len());

        Self(
            self.0
                .iter()
                .cycle()
                .zip(rhs.0.iter().cycle())
                .take(new_buffer_size)
                .map(|(a, b)| a ^ b)
                .collect(),
        )
    }

    fn hamming_distance(&self, rhs: &Self) -> usize {
        hamming_distance(&self.0, &rhs.0)
    }

    fn predict_repeated_xor_key_size(&self, min: usize, max: usize) -> usize {
        let mut lowest_penalty = f64::INFINITY;
        let mut predicted_keysize = min;

        for key_size in min..=max {
            let pairs = ChunkPairIter::new(&self.0, key_size);
            let pair_count = pairs.pair_count();

            if pair_count == 0 {
                break;
            }

            let hamming_sum: usize = pairs.into_iter().map(|(a, b)| hamming_distance(a, b)).sum();
            let normalization = pair_count * key_size;

            let penalty = hamming_sum as f64 / normalization as f64;

            if penalty < lowest_penalty {
                lowest_penalty = penalty;
                predicted_keysize = key_size;
            }
        }

        predicted_keysize
    }

    fn transpose(&self, size: usize) -> Vec<Self> {
        let mut t: Vec<Vec<u8>> = vec![Vec::new(); size];

        for (byte, into) in self.0.iter().zip((0..size).cycle()) {
            t[into].push(*byte);
        }

        t.into_iter().map(|buffer| Buffer(buffer)).collect()
    }

    fn repeated_block_start(&self, block_size: usize) -> Option<usize> {
        for start in 0..self.0.len() {
            if start + 2 * block_size > self.0.len() {
                return None;
            }

            let head = &self.0[start..start + block_size];
            let next = &self.0[start + block_size..start + 2 * block_size];

            if head == next {
                return Some(start);
            }
        }

        None
    }

    fn rfind(&self, sequence: &[u8]) -> Option<usize> {
        if sequence.len() > self.0.len() {
            return None;
        }

        for start in (0..self.0.len() - sequence.len()).rev() {
            if &self.0[start..start + sequence.len()] == sequence {
                return Some(start);
            }
        }

        None
    }

    fn printable_english_mismatch(&self) -> f64 {
        let english = [
            (b'a', 0.06633756394386363),
            (b'b', 0.014060607265779448),
            (b'c', 0.019563880893316697),
            (b'd', 0.03194748939033141),
            (b'e', 0.09884018632583158),
            (b'f', 0.017709570989909836),
            (b'g', 0.017744370371475113),
            (b'h', 0.05261335069988185),
            (b'i', 0.0563981977234576),
            (b'j', 0.0009876395910906955),
            (b'k', 0.006951590746015885),
            (b'l', 0.035942789816706684),
            (b'm', 0.020442150999487953),
            (b'n', 0.05593420596925392),
            (b'o', 0.059487057115727826),
            (b'p', 0.014851050361333579),
            (b'q', 0.0015162587682013193),
            (b'r', 0.04416704365996696),
            (b's', 0.05390755627142855),
            (b't', 0.07436959263181095),
            (b'u', 0.02275216709005914),
            (b'v', 0.0074768956963107685),
            (b'w', 0.018761838003907474),
            (b'x', 0.0011019804162337458),
            (b'y', 0.014599169123337294),
            (b'z', 0.0004474206201249795),
            (b' ', 0.19108837551515512),
        ];

        let mut observed = HashMap::<u8, usize>::new();

        for byte in self.0.iter() {
            observed
                .entry(*byte)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }

        english
            .iter()
            .map(|(ch, f)| {
                f64::powi(
                    f - (observed.get(ch).cloned().unwrap_or_default() as f64
                        / self.0.len() as f64),
                    2,
                )
            })
            .sum()
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Buffer {
    fn from(value: &[u8]) -> Self {
        Self(Vec::from(value))
    }
}

impl FromIterator<u8> for Buffer {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

fn hamming_distance(first: &[u8], second: &[u8]) -> usize {
    first
        .into_iter()
        .zip(second.into_iter())
        .map(|(a, b)| (a ^ b).count_ones() as usize)
        .sum()
}

fn single_xor_key_decipher(buffer: Buffer) -> (f64, u8, Buffer) {
    let mut best_key = 0;
    let mut lowest_penalty = f64::INFINITY;

    for key_byte in 0..u8::MAX {
        let key = Buffer(vec![key_byte]);
        let deciphered = buffer.xor(&key);

        let penalty = deciphered.printable_english_mismatch();

        if penalty < lowest_penalty {
            lowest_penalty = penalty;
            best_key = key_byte;
        }
    }

    let key = Buffer(vec![best_key]);
    let deciphered = buffer.xor(&key);

    (lowest_penalty, best_key, deciphered)
}

fn encryption_oracle<H, I>(head: H, cleartext: I, key: &AesKey) -> Vec<u8>
where
    H: AsRef<[u8]>,
    I: AsRef<[u8]>,
{
    let random_byte_count = urandom::range(5, 19);
    let random_bytes = urandom::bytes(random_byte_count as usize);

    let to_encrypt: Vec<u8> = random_bytes
        .into_iter()
        .chain(head.as_ref().into_iter().copied())
        .chain(cleartext.as_ref().into_iter().copied())
        .collect();

    aes::aes_ecb_encrypt(&to_encrypt, key)
}

fn find_last_repeated_block(input: &[u8], block_size: usize) -> Option<usize> {
    if 2 * block_size > input.len() {
        return None;
    }

    let mut found: Option<usize> = None;

    for (i, head) in input.chunks_exact(block_size).enumerate() {
        for (j, next) in input.chunks_exact(block_size).enumerate().skip(i + 1) {
            match (found.is_some(), head == next) {
                (_, true) => found = Some(j * block_size),
                (true, false) => return found,
                _ => (),
            }
        }
    }

    found
}

fn snoop_block_count(text: &[u8], key: &AesKey, block_size: usize) -> usize {
    let mut length_test_cipher = vec![0];
    let mut last_zero_block_start: Option<usize> = None;

    while last_zero_block_start.is_none() {
        length_test_cipher = encryption_oracle(&vec![0; 2 * block_size], &text, &key);
        last_zero_block_start = find_last_repeated_block(&length_test_cipher, block_size);
    }

    (length_test_cipher.len() - last_zero_block_start.unwrap() - block_size) / block_size
}

fn create_oracle_marker(text: &[u8], key: &AesKey, plaintext_marker: &[u8]) -> Vec<u8> {
    let block_size = plaintext_marker.len();

    let test: Vec<u8> = [0]
        .repeat(2 * block_size)
        .into_iter()
        .chain(plaintext_marker.iter().copied())
        .collect();

    let mut test_cipher = vec![0];
    let mut last_zero_block_start: Option<usize> = None;

    while last_zero_block_start.is_none() {
        test_cipher = encryption_oracle(&test, &text, &key);
        last_zero_block_start = find_last_repeated_block(&test_cipher, block_size);
    }

    let i = last_zero_block_start.unwrap();

    Vec::from(&test_cipher[i + block_size..i + 2 * block_size])
}

fn find_marker(input: &[u8], marker: &[u8]) -> Option<usize> {
    for (i, next) in input.chunks_exact(marker.len()).enumerate() {
        if next == marker {
            return Some(i * marker.len());
        }
    }

    None
}

struct QuoteOutIter<'a> {
    input: std::slice::Iter<'a, u8>,
    escaped: Option<u8>,
}

impl<'a> QuoteOutIter<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input: input.iter(),
            escaped: None,
        }
    }
}

impl<'a> Iterator for QuoteOutIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(byte) = self.escaped {
            self.escaped = None;
            return Some(byte);
        }

        let next = self.input.next();

        match next {
            Some(b';') | Some(b'=') => {
                self.escaped = next.copied();
                Some(b'\\')
            }

            Some(&byte) => Some(byte),

            None => None,
        }
    }
}

fn submit_userdata(input: &[u8], key: &AesKey, iv: &[u8]) -> Vec<u8> {
    let cleartext: Vec<u8> = b"comment1=cooking%20MCs;userdata="
        .into_iter()
        .copied()
        .chain(QuoteOutIter::new(input).into_iter())
        .chain(
            b";comment2=%20like%20a%20pound%20of%20bacon"
                .into_iter()
                .copied(),
        )
        .collect();

    aes::aes_cbc_encrypt(&cleartext, key, iv).unwrap()
}

fn is_admin(input: &[u8], key: &AesKey, iv: &[u8]) -> bool {
    let decrypted = aes::aes_cbc_decrypt(input, key, iv).unwrap();

    decrypted
        .windows(12)
        .filter_map(|w| (w == b";admin=true;").then_some(true))
        .next()
        .is_some()
}

struct CbcPaddingOracle {
    key: AesKey,
    iv: Vec<u8>,
    cleartext: Buffer,
}

impl CbcPaddingOracle {
    fn new(string: usize) -> Self {
        let strings = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];

        let cleartext = Buffer::from_base64(strings[string]);

        let key = AesKey::from(&urandom::bytes(16)).unwrap();

        let iv = urandom::bytes(16);

        Self { key, iv, cleartext }
    }

    fn iv(&self) -> Vec<u8> {
        self.iv.clone()
    }

    fn ciphertext(&self) -> Vec<u8> {
        aes::aes_cbc_encrypt(self.cleartext.as_ref(), &self.key, &self.iv).unwrap()
    }

    fn correctly_padded(&self, ciphertext: &[u8]) -> bool {
        aes::aes_cbc_decrypt(&ciphertext, &self.key, &self.iv).is_ok()
    }
}

fn shape_tail(cipher_block: &mut [u8], zero_iv: &[u8], tail: u8) {
    for (cipher_byte, known) in cipher_block.iter_mut().zip(zero_iv.iter()) {
        *cipher_byte ^= known;
    }

    for cipher_byte in cipher_block.iter_mut().rev().take(tail as usize - 1) {
        *cipher_byte ^= tail;
    }
}

fn last_cleartext_byte(oracle: &CbcPaddingOracle, two_blocks: &[u8; 32]) -> u8 {
    let mut ws: [u8; 32] = [0; 32];
    ws.copy_from_slice(two_blocks);

    for byte in 1..u8::MAX {
        ws[15] ^= byte;

        if oracle.correctly_padded(&ws) {
            ws[14] ^= 0x01;

            if oracle.correctly_padded(&ws) {
                return byte;
            }

            ws[14] ^= 0x01;
        }

        ws[15] ^= byte;
    }

    unreachable!();
}

fn decrypt_last_block(oracle: &CbcPaddingOracle, two_blocks: &[u8]) -> Vec<u8> {
    let mut ws: [u8; 32] = [0; 32];
    ws.copy_from_slice(two_blocks.try_into().unwrap());

    let mut zero_iv = vec![0; 16];
    zero_iv[15] = last_cleartext_byte(oracle, &ws) ^ 0x01;

    for i in (0..15).rev() {
        let target_byte = 16 - i as u8;

        shape_tail(&mut ws[0..16], &zero_iv, target_byte);

        let mut byte = 0;

        loop {
            ws[i] ^= byte;

            let target_reached = oracle.correctly_padded(&ws);

            ws[i] ^= byte;

            if target_reached {
                break;
            }

            byte += 1;
        }

        shape_tail(&mut ws[0..16], &zero_iv, target_byte);

        zero_iv[i] = byte ^ target_byte;
    }

    Vec::from(zero_iv)
}

fn main() {
    for cleartext_index in 0..10 {
        let oracle = CbcPaddingOracle::new(cleartext_index);

        let (iv, ciphertext) = (oracle.iv(), oracle.ciphertext());

        let mut decrypted = Vec::new();

        let zero_block_prepadded: Vec<u8> = iv.into_iter().chain(ciphertext.into_iter()).collect();

        for block_pair_start in (0..=zero_block_prepadded.len() - 32).rev().step_by(16) {
            let decrypted_block = decrypt_last_block(
                &oracle,
                &zero_block_prepadded[block_pair_start..block_pair_start + 32],
            );

            decrypted.extend(decrypted_block.iter().rev());
        }

        decrypted.reverse();

        let length_without_padding = pkcs7::unpad_length(&decrypted);
        decrypted.truncate(length_without_padding);

        println!(
            "{}: {}",
            cleartext_index,
            String::from_utf8_lossy(&decrypted)
        );
    }
}
