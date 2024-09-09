mod sextet_iter;

use sextet_iter::SextetIter;

use std::collections::HashMap;
use std::fs;

struct Buffer(Vec<u8>);

impl Buffer {
    fn from_hex(string: &str) -> Self {
        Self(hex::decode(string).unwrap())
    }

    fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    fn to_base64(&self) -> String {
        let mut encoding = String::new();

        for sextet in SextetIter::new(&self.0).into_iter() {
            let ch = match sextet {
                0..=25 => ('A' as u8 + sextet) as char,
                26..=51 => ('a' as u8 + sextet - 26) as char,
                52..=61 => ('0' as u8 + sextet - 52) as char,
                62 => '+',
                63 => '\\',
                _ => unreachable!(),
            };

            encoding.push(ch);
        }

        while encoding.len() % 4 != 0 {
            encoding.push('=');
        }

        encoding
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

    fn printable_frequencies(&self) -> HashMap<char, f64> {
        let mut frequencies = HashMap::new();

        for byte in self.0.iter() {
            let ch = (*byte as char).to_ascii_lowercase();

            if matches!(ch, 'a'..='z' | ' ') {
                frequencies
                    .entry(ch)
                    .and_modify(|count| *count += 1.0)
                    .or_insert(1.0);
            }
        }

        for (_, f) in frequencies.iter_mut() {
            *f /= self.0.len() as f64;
        }

        frequencies
    }
}

fn single_xor_key_decipher(buffer: Buffer) -> (f64, u8, Buffer) {
    let english: HashMap<char, f64> = [
        ('a', 0.06633756394386363),
        ('b', 0.014060607265779448),
        ('c', 0.019563880893316697),
        ('d', 0.03194748939033141),
        ('e', 0.09884018632583158),
        ('f', 0.017709570989909836),
        ('g', 0.017744370371475113),
        ('h', 0.05261335069988185),
        ('i', 0.0563981977234576),
        ('j', 0.0009876395910906955),
        ('k', 0.006951590746015885),
        ('l', 0.035942789816706684),
        ('m', 0.020442150999487953),
        ('n', 0.05593420596925392),
        ('o', 0.059487057115727826),
        ('p', 0.014851050361333579),
        ('q', 0.0015162587682013193),
        ('r', 0.04416704365996696),
        ('s', 0.05390755627142855),
        ('t', 0.07436959263181095),
        ('u', 0.02275216709005914),
        ('v', 0.0074768956963107685),
        ('w', 0.018761838003907474),
        ('x', 0.0011019804162337458),
        ('y', 0.014599169123337294),
        ('z', 0.0004474206201249795),
        (' ', 0.19108837551515512),
    ]
    .into_iter()
    .collect();

    let mut best_key = 0;
    let mut lowest_penalty = f64::INFINITY;

    for key_byte in 0..u8::MAX {
        let key = Buffer(vec![key_byte]);
        let deciphered = buffer.xor(&key);

        let frequencies = deciphered.printable_frequencies();

        let penalty = english
            .iter()
            .map(|(ch, f)| f64::powi(f - frequencies.get(&ch).cloned().unwrap_or_default(), 2))
            .sum();

        if penalty < lowest_penalty {
            lowest_penalty = penalty;
            best_key = key_byte;
        }
    }

    let key = Buffer(vec![best_key]);
    let deciphered = buffer.xor(&key);

    (lowest_penalty, best_key, deciphered)
}

fn main() {
    let mut lowest_penalty = f64::INFINITY;
    let mut best_candidate = Buffer(Vec::new());

    for line in fs::read_to_string("4.txt").unwrap().split_whitespace() {
        let buffer = Buffer::from_hex(line);

        let (penalty, _, deciphered) = single_xor_key_decipher(buffer);

        if penalty < lowest_penalty {
            lowest_penalty = penalty;
            best_candidate = deciphered;
        }
    }

    println!("{}", String::from_utf8_lossy(&best_candidate.0));
}
