#![allow(dead_code)]

mod aes;
mod base64;
mod chunk_pair_iter;
mod key_value;
mod md4;
mod pkcs7;
mod random;
mod sha;
mod urandom;

use aes::{aes_ctr, AesCtrIter, AesKey};
use chunk_pair_iter::ChunkPairIter;
use random::MersenneStream;
use random::MersenneTwister;
use sha::{sha1_digest, sha1_digest_from_state};

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::BufRead;
use std::ops::BitAnd;
use std::ops::Shl;
use std::path::Path;
use std::time::{Duration, SystemTime};

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

    fn aes_ctr(&self, key: &AesKey, nonce: u64) -> Self {
        Buffer(aes_ctr(&self.0, key, nonce))
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

struct EnglishPenalty([f64; 256]);

impl EnglishPenalty {
    fn new() -> Self {
        Self([0.0; 256])
    }

    fn best(&self) -> u8 {
        self.0
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .unwrap()
            .0 as u8
    }

    fn print_matches(&self, count: usize) {
        let mut matches: [(u8, f64); 256] = [(0, 0.0); 256];

        for (i, &penalty) in self.0.iter().enumerate() {
            matches[i] = (i as u8, penalty);
        }

        matches.sort_unstable_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap());

        for (byte, penalty) in matches.iter().take(count) {
            println!("{:02x}: {:1.5}", byte, penalty);
        }
    }
}

impl std::ops::Index<usize> for EnglishPenalty {
    type Output = f64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl std::ops::IndexMut<usize> for EnglishPenalty {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

fn form_same_key_byte_penalty(texts: &[Buffer], index: usize) -> EnglishPenalty {
    let mut penalty = EnglishPenalty::new();

    for (bi, b) in (0..=u8::MAX).enumerate() {
        let slots: Vec<u8> = texts
            .iter()
            .filter_map(|text| text.0.get(index).map(|tb| tb ^ b))
            .collect();

        for &l in slots.iter() {
            if l < ' ' as u8 {
                penalty[bi] += 2.0;
            }

            if l > 'z' as u8 {
                penalty[bi] += 1.0;
            }

            if l >= '"' as u8 && l <= '+' as u8 {
                penalty[bi] += 1.0;
            }

            if l > '/' as u8 && l <= '>' as u8 {
                penalty[bi] += 1.0;
            }

            if l >= '[' as u8 && l <= '`' as u8 {
                penalty[bi] += 1.0;
            }

            if l == '@' as u8 {
                penalty[bi] += 1.0;
            }
        }

        penalty[bi] += Buffer(slots).printable_english_mismatch();
    }

    penalty
}

fn random_aes_128_key() -> AesKey {
    AesKey::from(&urandom::bytes(16)).unwrap()
}

fn ctr_edit(ciphertext: &mut [u8], key: &AesKey, nonce: u64, offset: usize, newtext: &[u8]) {
    for ((slot, key), byte) in ciphertext
        .iter_mut()
        .skip(offset)
        .zip(AesCtrIter::new(key, nonce).into_iter().skip(offset))
        .zip(newtext.iter())
    {
        *slot = key ^ byte;
    }
}

fn exploit_edit_to_recover_key(ciphertext: &[u8], key: &AesKey, nonce: u64) -> Vec<u8> {
    let mut recovered = Vec::from(ciphertext);
    let zeros = [0u8].repeat(ciphertext.len());

    ctr_edit(&mut recovered, key, nonce, 0, &zeros);

    recovered
}

struct InsecureApplication {
    key: AesKey,
    nonce: u64,
}

impl InsecureApplication {
    fn new() -> Self {
        Self {
            key: random_aes_128_key(),
            nonce: urandom::range(0, u32::MAX) as u64,
        }
    }

    fn create_user(&self, name: &str) -> Vec<u8> {
        let name = name.replace('=', "\\=").replace('&', "\\&");
        let id = urandom::range(5, 987968971);

        aes_ctr(
            format!("id={}&name={}&type=user", id, name)
                .bytes()
                .collect::<Vec<u8>>(),
            &self.key,
            self.nonce,
        )
    }

    fn is_admin(&self, input: &[u8]) -> bool {
        let decrypted = aes_ctr(input, &self.key, self.nonce);
        let decoded = String::from_utf8_lossy(&decrypted);

        decoded.contains("&admin=true")
    }
}

enum DecryptError {
    HighAsciiError(Vec<u8>),
    GenericError,
}

fn cbc_encrypt_key_as_iv(input: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = key;
    let key = AesKey::from(key).unwrap();

    aes::aes_cbc_encrypt(input, &key, iv).unwrap()
}

fn cbc_decrypt_key_as_iv(input: &[u8], key: &[u8]) -> Result<(), DecryptError> {
    let iv = key;
    let key = AesKey::from(key).unwrap();

    let decrypt = match aes::aes_cbc_decrypt(input, &key, iv) {
        Ok(result) => result,
        Err(_) => return Err(DecryptError::GenericError),
    };

    for byte in decrypt.iter() {
        if *byte > 127 {
            return Err(DecryptError::HighAsciiError(decrypt));
        }
    }

    Ok(())
}

fn create_malicious_payload(ciphertext: &[u8]) -> Vec<u8> {
    ciphertext
        .iter()
        .take(16)
        .copied()
        .chain([0].repeat(16))
        .chain(ciphertext.iter().copied())
        .collect()
}

fn sha1_mac(key: &AesKey, input: &[u8]) -> [u8; 20] {
    let input: Vec<u8> = key
        .as_ref()
        .iter()
        .copied()
        .chain(input.iter().copied())
        .collect();

    sha1_digest(&input)
}

fn message_valid(key: &AesKey, message: &[u8], mac: &[u8]) -> bool {
    let new_mac = sha1_mac(key, message);
    new_mac == mac
}

fn make_sha1_glue_padding(key_byte_length: usize, message: &[u8]) -> Vec<u8> {
    let length = key_byte_length + message.len();
    let remainder = length % 64;

    let padding_length = if remainder > 55 {
        128 - remainder
    } else {
        64 - remainder
    };

    let bit_length = u64::to_be_bytes((length * 8) as u64);

    [0x80]
        .iter()
        .copied()
        .chain([0].iter().copied().cycle())
        .take(padding_length - 8)
        .chain(bit_length)
        .collect()
}

fn main() {
    let input = b"upstate";

    println!("{}", hex::encode(md4::md4_digest(input)));

    /*
    let key = random_aes_128_key();

    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    let mac = sha1_mac(&key, message);

    let assumed_key_length = 16;

    let glue_padding = make_sha1_glue_padding(assumed_key_length, message);
    let our_message = b";admin=true";

    let extra_byte_length = glue_padding.len() + message.len() + assumed_key_length;

    let faked_mac = sha1_digest_from_state(our_message, &mac, extra_byte_length);

    let faked: Vec<u8> = message
        .iter()
        .copied()
        .chain(glue_padding.iter().copied())
        .chain(our_message.iter().copied())
        .collect();

    println!(
        "Message is '{}': {}",
        String::from_utf8_lossy(message),
        message_valid(&key, message, &mac)
    );

    println!(
        "Message is '{}': {}",
        String::from_utf8_lossy(&faked),
        message_valid(&key, &faked, &faked_mac)
    );
    */
}
