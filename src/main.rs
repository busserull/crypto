mod sextet_iter;

use sextet_iter::SextetIter;

struct Buffer(Vec<u8>);

impl Buffer {
    fn from_hex(string: &str) -> Self {
        Self(hex::decode(string).unwrap())
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

fn main() {
    let buffer = Buffer::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

    let base64 = buffer.to_base64();

    assert_eq!(
        base64,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    println!("{}", String::from_utf8_lossy(&buffer.0));
}
