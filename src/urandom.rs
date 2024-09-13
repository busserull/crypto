use std::fs::File;
use std::io::Read;

pub fn bytes(byte_count: usize) -> Vec<u8> {
    let mut bytes = vec![0; byte_count];
    fill_bytes(&mut bytes);

    bytes
}

pub fn range(min: u32, max: u32) -> u32 {
    let (min, max) = if min > max { (max, min) } else { (min, max) };

    if min == max {
        return min;
    }

    let mut bytes: [u8; 4] = [0; 4];
    fill_bytes(&mut bytes);

    let mut rn = u32::from_be_bytes(bytes);

    let unbiased_top = (u32::MAX / (max - min)) * (max - min);

    while rn > unbiased_top {
        rn = rn.wrapping_shr(1);
    }

    min + rn % (max - min)
}

pub fn coin_flip() -> bool {
    let mut byte: [u8; 1] = [0; 1];
    fill_bytes(&mut byte);

    (byte[0] & 1u8) != 0
}

fn fill_bytes(byte_buffer: &mut [u8]) {
    let mut urandom = File::open("/dev/urandom").unwrap();
    urandom.read_exact(byte_buffer).unwrap();
}
