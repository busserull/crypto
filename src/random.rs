pub struct MersenneTwister {
    index: usize,
    state: [u32; 624],
}

impl MersenneTwister {
    pub fn new(seed: u32) -> Self {
        let mut state = [0; 624];

        state[0] = seed;

        let mut seed = seed;

        for (i, slot) in state.iter_mut().enumerate().skip(1) {
            seed = 1812433253u32
                .wrapping_mul(seed ^ (seed.wrapping_shr(30)))
                .wrapping_add(i as u32);

            *slot = seed;
        }

        Self { index: 0, state }
    }

    pub fn from_state(state: &[u32; 624]) -> Self {
        Self {
            index: 0,
            state: state.clone(),
        }
    }

    pub fn get(&mut self) -> u32 {
        let x = (self.state[self.index] & 0x8000_0000)
            | (self.state[(self.index + 1) % 624] & 0x7fff_ffff);

        let mut xa = x.wrapping_shr(1);

        if (x & 1) > 0 {
            xa ^= 0x9908_b0df;
        }

        let x = self.state[(self.index + 397) % 624] ^ xa;

        self.state[self.index] = x;

        self.index = (self.index + 1) % 624;

        let mut y = x;

        y ^= x.wrapping_shr(11);
        y ^= y.wrapping_shl(7) & 0x9d2c_5680;
        y ^= y.wrapping_shl(15) & 0xefc6_0000;
        y ^ y.wrapping_shr(18)
    }
}

pub struct MersenneStream {
    twister: MersenneTwister,
    bytes: [u8; 4],
    index: usize,
}

impl MersenneStream {
    pub fn new(seed: u16) -> Self {
        Self {
            twister: MersenneTwister::new(seed as u32),
            bytes: [0; 4],
            index: 4,
        }
    }
}

impl Iterator for MersenneStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index > 3 {
            self.bytes
                .copy_from_slice(&self.twister.get().to_be_bytes());
            self.index = 0;
        }

        let byte = self.bytes[self.index];
        self.index += 1;

        Some(byte)
    }
}
