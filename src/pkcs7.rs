pub fn pad_inplace(input: &mut [u8], from: usize) {
    let pad_length = input.len() - from;
    (&mut input[from..]).copy_from_slice(&[pad_length as u8].repeat(pad_length));
}

pub fn unpad_length(input: &[u8]) -> usize {
    let last_byte = input.last().copied().unwrap_or_default();

    let equal_bytes = input
        .iter()
        .rev()
        .take_while(|byte| **byte == last_byte)
        .count();

    if last_byte as usize == equal_bytes {
        input.len() - last_byte as usize
    } else {
        input.len()
    }
}

pub fn pad(input: &[u8], to_length: usize) -> Vec<u8> {
    let pad_byte_count = to_length.saturating_sub(input.len());

    input
        .iter()
        .copied()
        .chain([pad_byte_count as u8].repeat(pad_byte_count))
        .collect()
}

pub fn unpad(input: &[u8]) -> Vec<u8> {
    Vec::from(&input[0..unpad_length(input)])
}
