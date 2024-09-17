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

    fn repeated_ecb_mismatch(&self) -> usize {
        let mut lowest_hamming = usize::MAX;

        for (i, head) in self.0.chunks_exact(16).enumerate() {
            for block in self.0.chunks_exact(16).skip(i + 1) {
                let hamming_distance = hamming_distance(head, block);

                if hamming_distance < lowest_hamming {
                    lowest_hamming = hamming_distance;
                }
            }
        }

        lowest_hamming
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

fn random_aes_key() -> AesKey {
    AesKey::from(&urandom::bytes(16)).unwrap()
}

fn encryption_oracle<H, I>(head: H, cleartext: I, key: &AesKey) -> Vec<u8>
where
    H: AsRef<[u8]>,
    I: AsRef<[u8]>,
{
    let to_encrypt: Vec<u8> = head
        .as_ref()
        .into_iter()
        .copied()
        .chain(cleartext.as_ref().into_iter().copied())
        .collect();

    aes::aes_ecb_encrypt(&to_encrypt, key)
}

fn profile_for(email: &str) -> KeyValue {
    let email = email.replace(['&', '='], "");
    KeyValue::from(&[("email", &email), ("uid", "10"), ("role", "user")])
}

fn main() {
    let unknown_key = AesKey::from(&urandom::bytes(16)).unwrap();

    let admin_cipher = aes::aes_ecb_encrypt(
        &profile_for("          admin           ").to_string(),
        &unknown_key,
    );

    let email = "a@example.com";
    let profile_cipher = aes::aes_ecb_encrypt(&profile_for(&email).to_string(), &unknown_key);

    let mut exploit_cipher = Vec::new();

    exploit_cipher.extend_from_slice(&profile_cipher[0..32]);
    exploit_cipher.extend_from_slice(&admin_cipher[16..32]);

    let decoded = KeyValue::parse(
        &String::from_utf8(aes::aes_ecb_decrypt(&exploit_cipher, &unknown_key).unwrap()).unwrap(),
    );

    println!("{}", decoded);
}
