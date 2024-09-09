pub struct ChunkPairIter<'a> {
    chunks: std::slice::ChunksExact<'a, u8>,
    pair_count: usize,
    pairs_left: usize,
}

impl<'a> ChunkPairIter<'a> {
    pub fn new(buffer: &'a [u8], size: usize) -> Self {
        let pair_count = buffer.len() / (2 * size);

        Self {
            chunks: buffer.chunks_exact(size),
            pair_count,
            pairs_left: pair_count,
        }
    }

    pub fn pair_count(&self) -> usize {
        self.pair_count
    }
}

impl<'a> Iterator for ChunkPairIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pairs_left == 0 {
            return None;
        }

        self.pairs_left -= 1;

        let first = self.chunks.next();
        let second = self.chunks.next();

        match (first, second) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }
}
