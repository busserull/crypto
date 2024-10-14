use std::cmp::Ordering;
use std::fmt;
use std::iter::Rev;
use std::ops::{Add, Mul, Rem, ShlAssign, ShrAssign, SubAssign};

#[derive(Clone)]
pub struct Ubig(Vec<u8>);

impl Ubig {
    pub fn new(int: &str) -> Self {
        let mut bytes = hex::decode(int).unwrap();
        bytes.reverse();

        Self(bytes)
    }

    pub fn modexp(base: Self, mut exponent: Self, modulus: Self) -> Self {
        let mut res = Self(vec![1]);
        let mut base = base % &modulus;

        let two = Self(vec![2]);

        while exponent.not_zero() {
            if (exponent.clone() % &two).is_one() {
                res = (res * base.clone()) % &modulus;
            }

            exponent >>= 1;

            base = (base.clone() * base) % &modulus;
        }

        res
    }

    fn not_zero(&self) -> bool {
        for byte in self.0.iter() {
            if *byte != 0 {
                return true;
            }
        }

        false
    }

    fn is_one(&self) -> bool {
        let leading_zeros = self.0.iter().rev().take_while(|byte| **byte == 0).count();
        let bytes = &self.0[0..self.0.len() - leading_zeros];

        bytes.len() == 1 && *bytes.first().unwrap() == 1
    }
}

impl From<&[u8]> for Ubig {
    fn from(value: &[u8]) -> Self {
        Self(Vec::from(value))
    }
}

impl From<Ubig> for Vec<u8> {
    fn from(value: Ubig) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for Ubig {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ubig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "0");
        }

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
        let length = std::cmp::max(self.0.len(), rhs.0.len());

        let mut work = vec![0u8; 2 * length];

        for (ia, a) in self.0.into_iter().enumerate() {
            for (ib, b) in rhs.0.iter().enumerate() {
                let mul = (a as u16) * (*b as u16) + work[ia + ib] as u16;

                let slot = mul as u8;
                work[ia + ib] = slot;

                let mut carry = mul.wrapping_shr(8) as u8;

                for s in (&mut work[ia + ib + 1..]).iter_mut() {
                    if carry == 0 {
                        break;
                    }

                    let sum = *s as u16 + carry as u16;

                    *s = sum as u8;
                    carry = sum.wrapping_shr(8) as u8;
                }
            }
        }

        while let Some(0) = work.last() {
            work.pop();
        }

        Self(work)
    }
}

impl Rem<&Ubig> for Ubig {
    type Output = Self;

    fn rem(self, rhs: &Ubig) -> Self::Output {
        let mut rem = Self(vec![0u8]);

        for byte in self.0.into_iter().rev() {
            for i in 0..8 {
                rem <<= 1;

                let s = rem.0.first_mut().unwrap();
                *s |= byte.wrapping_shr(7 - i) & 0x01;

                if rem >= *rhs {
                    rem -= rhs;
                }
            }
        }

        let leading_zeros = rem.0.iter().rev().take_while(|byte| **byte == 0).count();

        rem.0.truncate(rem.0.len() - leading_zeros);

        rem
    }
}

impl ShlAssign<u32> for Ubig {
    fn shl_assign(&mut self, rhs: u32) {
        let mut shift_in_bytes = vec![0u8; rhs as usize / 8];
        let shift = rhs % 8;

        if shift != 0 {
            let mut carry = 0u8;

            for byte in self.0.iter_mut() {
                let new_carry = byte.wrapping_shr(8 - shift);
                *byte = byte.wrapping_shl(shift) | carry;
                carry = new_carry;
            }

            if carry != 0 {
                self.0.push(carry);
            }
        }

        shift_in_bytes.extend_from_slice(&self.0);

        self.0 = shift_in_bytes;
    }
}

impl ShrAssign<u32> for Ubig {
    fn shr_assign(&mut self, rhs: u32) {
        let drop = (rhs / 8) as usize;
        let shift = rhs % 8;

        if shift != 0 {
            let mut carry = 0;

            for byte in self.0.iter_mut().rev() {
                let new_carry = byte.wrapping_shl(8 - shift);
                *byte = byte.wrapping_shr(shift) | carry;
                carry = new_carry;
            }
        }

        let leading_zeros = self.0.iter().rev().take_while(|byte| **byte == 0).count();

        self.0 = Vec::from(&self.0[drop..self.0.len() - leading_zeros]);
    }
}

impl SubAssign<&Ubig> for Ubig {
    fn sub_assign(&mut self, rhs: &Ubig) {
        let mut loan = 0;

        for (byte, sub) in self
            .0
            .iter_mut()
            .zip(rhs.0.iter().chain([0].iter().cycle()))
        {
            let mut res = *byte as i32 - loan as i32 - *sub as i32;
            loan = 0;

            if res < 0 {
                res += 256;
                loan = 1;
            }

            *byte = res as u8;
        }
    }
}

impl PartialEq for Ubig {
    fn eq(&self, other: &Self) -> bool {
        let length = std::cmp::max(self.0.len(), other.0.len());

        for (a, b) in self
            .0
            .iter()
            .chain([0].iter().cycle())
            .zip(other.0.iter().chain([0].iter().cycle()))
            .take(length)
        {
            if a != b {
                return false;
            }
        }

        true
    }
}

impl PartialOrd for Ubig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let length = std::cmp::max(self.0.len(), other.0.len());

        let lhs = LeadingZeroRevIter::new(&self.0, length);
        let rhs = LeadingZeroRevIter::new(&other.0, length);

        for (a, b) in lhs.into_iter().zip(rhs.into_iter()) {
            if a > b {
                return Some(Ordering::Greater);
            } else if b > a {
                return Some(Ordering::Less);
            }
        }

        Some(Ordering::Equal)
    }
}

struct LeadingZeroRevIter<'a> {
    body: Rev<std::slice::Iter<'a, u8>>,
    leading_zeros: usize,
}

impl<'a> LeadingZeroRevIter<'a> {
    fn new(input: &'a [u8], length: usize) -> Self {
        let leading_zeros = length - input.len();
        let body = input.iter().rev();

        Self {
            body,
            leading_zeros,
        }
    }
}

impl<'a> Iterator for LeadingZeroRevIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.leading_zeros > 0 {
            self.leading_zeros -= 1;
            return Some(0);
        }

        self.body.next().copied()
    }
}
