pub fn bytes_to_base64(bytes: &[u8]) -> String {
    SextetIter::new(bytes)
        .into_iter()
        .map(|s| sextet_to_base64(s))
        .chain(['='].repeat((3 - (bytes.len() % 3)) % 3))
        .collect()
}

pub fn base64_to_bytes(encoding: &str) -> Vec<u8> {
    EncodingIter::new(encoding).into_iter().collect()
}

fn sextet_to_base64(sextet: u8) -> char {
    match sextet {
        0..=25 => ('A' as u8 + sextet) as char,
        26..=51 => ('a' as u8 + sextet - 26) as char,
        52..=61 => ('0' as u8 + sextet - 52) as char,
        62 => '+',
        63 => '/',
        _ => unreachable!(),
    }
}

fn base64_to_sextet(ch: char) -> u8 {
    match ch {
        'A'..='Z' => ch as u8 - 'A' as u8,
        'a'..='z' => ch as u8 - 'a' as u8 + 26,
        '0'..='9' => ch as u8 - '0' as u8 + 52,
        '+' => 62,
        '/' => 63,
        _ => unreachable!(),
    }
}

struct SextetIter<'a> {
    bytes: std::slice::Iter<'a, u8>,
    head: [u8; 4],
    sextets_in_head: u8,
    sextet_index: usize,
}

impl<'a> SextetIter<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self {
            bytes: buffer.iter(),
            head: [0; 4],
            sextets_in_head: 0,
            sextet_index: 0,
        }
    }

    fn convert_available_bytes(&mut self) {
        let bytes_left = self.bytes.len();

        let bytes: [u8; 3] = [
            self.bytes.next().copied().unwrap_or_default(),
            self.bytes.next().copied().unwrap_or_default(),
            self.bytes.next().copied().unwrap_or_default(),
        ];

        self.head[0] = bytes[0].wrapping_shr(2);
        self.head[1] = (bytes[0].wrapping_shl(4) & 0x30) | bytes[1].wrapping_shr(4);
        self.head[2] = (bytes[1].wrapping_shl(2) & 0x3c) | bytes[2].wrapping_shr(6);
        self.head[3] = bytes[2] & 0x3f;

        self.sextets_in_head = match bytes_left {
            0 => 0,
            1 => 2,
            2 => 3,
            _ => 4,
        };

        self.sextet_index = 0;
    }
}

impl<'a> Iterator for SextetIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.sextets_in_head == 0 {
            self.convert_available_bytes();
        }

        if self.sextets_in_head == 0 {
            return None;
        }

        let sextet = self.head[self.sextet_index];

        self.sextets_in_head -= 1;
        self.sextet_index += 1;

        Some(sextet)
    }
}

struct EncodingIter<'a> {
    encoding: std::str::Chars<'a>,
    head: [u8; 3],
    bytes_in_head: usize,
    byte_index: usize,
}

impl<'a> EncodingIter<'a> {
    fn new(string: &'a str) -> Self {
        Self {
            encoding: string.chars(),
            head: [0; 3],
            bytes_in_head: 0,
            byte_index: 0,
        }
    }

    fn convert_available_chars(&mut self) {
        let mut sextets: [u8; 4] = [0; 4];
        let mut valid_slots = 0;

        for slot in sextets.iter_mut() {
            if let Some(ch) = self
                .encoding
                .find(|ch| matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/'))
            {
                *slot = base64_to_sextet(ch);
                valid_slots += 1;
            }
        }

        self.head[0] = sextets[0].wrapping_shl(2) | sextets[1].wrapping_shr(4);
        self.head[1] = sextets[1].wrapping_shl(4) | sextets[2].wrapping_shr(2);
        self.head[2] = sextets[2].wrapping_shl(6) | sextets[3];

        self.bytes_in_head = match valid_slots {
            0 => 0,
            2 => 1,
            3 => 2,
            4 => 3,
            _ => unreachable!(),
        };

        self.byte_index = 0;
    }
}

impl<'a> Iterator for EncodingIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte_index == self.bytes_in_head {
            self.convert_available_chars();
        }

        if self.byte_index == self.bytes_in_head {
            return None;
        }

        let byte = self.head[self.byte_index];

        self.byte_index += 1;

        Some(byte)
    }
}
