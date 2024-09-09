pub struct SextetIter<'a> {
    bytes: std::slice::Iter<'a, u8>,
    head: [u8; 4],
    sextets_in_head: u8,
    sextet_index: usize,
}

impl<'a> SextetIter<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
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
