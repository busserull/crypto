mod sextet_iter;

use sextet_iter::SextetIter;

use std::ops::BitXor;

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
}

impl BitXor for Buffer {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
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
}

fn main() {
    let b1 = Buffer::from_hex("1c0111001f010100061a024b53535009181c");
    let b2 = Buffer::from_hex("686974207468652062756c6c277320657965");

    let xor = b1 ^ b2;

    assert_eq!(xor.to_hex(), "746865206b696420646f6e277420706c6179");

    println!("{}", xor.to_hex());
}
