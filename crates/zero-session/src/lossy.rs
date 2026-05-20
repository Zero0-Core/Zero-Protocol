/// Manages lossy packet streams, typically used for real-time audio/video.
/// Messages sent here are NOT buffered for retransmission.
pub struct LossyStream {
    pub current_sequence: u16,
}

impl LossyStream {
    pub fn new() -> Self {
        Self {
            current_sequence: 0,
        }
    }

    pub fn next_seq(&mut self) -> u16 {
        let seq = self.current_sequence;
        self.current_sequence = self.current_sequence.wrapping_add(1);
        seq
    }
}
