use std::fmt;
use std::ops::{Add, Mul};

pub struct Ubig(Vec<u8>);

impl Ubig {
    pub fn new(int: &str) -> Self {
        let mut bytes = hex::decode(int).unwrap();
        bytes.reverse();

        Self(bytes)
    }
}

impl fmt::Display for Ubig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl Add for Ubig {
    type Output = Self;

    fn add(self, rhs: Ubig) -> Self::Output {
        let length = std::cmp::max(self.0.len(), rhs.0.len());

        let mut result = Vec::with_capacity(length + 1);
        let mut carry = 0u16;

        for (a, b) in self
            .0
            .into_iter()
            .chain([0].into_iter().cycle())
            .zip(rhs.0.into_iter().cycle())
            .take(length)
        {
            let a = a as u16;
            let b = b as u16;

            let c = a + b + carry;

            result.push((c & 0xff) as u8);
            carry = c.wrapping_shr(8);
        }

        if carry != 0 {
            result.push(carry as u8);
        }

        Self(result)
    }
}

impl Mul for Ubig {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // let length = std::cmp
        self
    }
}
