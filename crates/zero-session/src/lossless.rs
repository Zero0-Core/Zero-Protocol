use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MAX_RETRIES: u32 = 5;
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

pub struct PendingMessage {
    pub sequence_number: u64,
    pub data: Vec<u8>,
    pub last_sent: Instant,
    pub retries: u32,
}

/// Reliable in-order delivery queue with ACK tracking and retransmission.
/// Mirrors the Tox lossless packet mechanism but over our Noise-encrypted channel.
pub struct LosslessQueue {
    /// Messages we have sent but not yet received an ACK for
    pub unacked_messages: BTreeMap<u64, PendingMessage>,
    /// Tracks our current send sequence number
    pub next_send_seq: u64,
    /// Tracks the highest received sequence number (for ordered delivery)
    pub next_recv_seq: u64,
    /// Buffer for out-of-order packets that arrived before we're ready
    pub recv_buffer: BTreeMap<u64, Vec<u8>>,
}

impl LosslessQueue {
    pub fn new() -> Self {
        Self {
            unacked_messages: BTreeMap::new(),
            next_send_seq: 0,
            next_recv_seq: 0,
            recv_buffer: BTreeMap::new(),
        }
    }

    /// Enqueues an outgoing message and assigns it a sequence number.
    pub fn enqueue_outgoing(&mut self, data: Vec<u8>) -> u64 {
        let seq = self.next_send_seq;
        self.unacked_messages.insert(seq, PendingMessage {
            sequence_number: seq,
            data,
            last_sent: Instant::now(),
            retries: 0,
        });
        self.next_send_seq += 1;
        seq
    }

    /// Marks a sequence number as acknowledged, removing it from the retry queue.
    pub fn receive_ack(&mut self, seq: u64) {
        self.unacked_messages.remove(&seq);
    }

    /// Delivers an incoming packet, buffering out-of-order arrivals.
    /// Returns a Vec of in-order payloads ready for delivery to the application.
    pub fn receive_packet(&mut self, seq: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        // Buffer the incoming packet
        self.recv_buffer.insert(seq, data);

        // Drain in-order packets ready for application delivery
        let mut ready = Vec::new();
        while let Some(payload) = self.recv_buffer.remove(&self.next_recv_seq) {
            ready.push(payload);
            self.next_recv_seq += 1;
        }
        ready
    }

    /// Returns a list of sequence numbers that need to be retransmitted.
    pub fn get_retransmit_queue(&mut self) -> Vec<(u64, Vec<u8>)> {
        let now = Instant::now();
        let mut retransmit = Vec::new();

        for (seq, msg) in self.unacked_messages.iter_mut() {
            if msg.retries >= MAX_RETRIES {
                // Give up — connection is considered dead
                continue;
            }
            if now.duration_since(msg.last_sent) >= RETRY_INTERVAL {
                msg.last_sent = now;
                msg.retries += 1;
                retransmit.push((*seq, msg.data.clone()));
            }
        }

        retransmit
    }

    /// Drops messages that have exceeded the maximum retry count (dead session cleanup)
    pub fn prune_dead_messages(&mut self) {
        self.unacked_messages.retain(|_, msg| msg.retries < MAX_RETRIES);
    }
}

impl Default for LosslessQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Outgoing / ACK ────────────────────────────────────────────────────

    #[test]
    fn test_enqueue_assigns_sequential_seqs() {
        let mut q = LosslessQueue::new();
        let s0 = q.enqueue_outgoing(b"hello".to_vec());
        let s1 = q.enqueue_outgoing(b"world".to_vec());
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
    }

    #[test]
    fn test_ack_removes_from_unacked() {
        let mut q = LosslessQueue::new();
        let seq = q.enqueue_outgoing(b"ping".to_vec());
        assert!(q.unacked_messages.contains_key(&seq));
        q.receive_ack(seq);
        assert!(!q.unacked_messages.contains_key(&seq));
    }

    #[test]
    fn test_ack_nonexistent_seq_is_safe() {
        let mut q = LosslessQueue::new();
        q.receive_ack(999); // should not panic
    }

    // ── In-Order Delivery ─────────────────────────────────────────────────

    #[test]
    fn test_in_order_delivery() {
        let mut q = LosslessQueue::new();
        let delivered = q.receive_packet(0, b"msg0".to_vec());
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], b"msg0");

        let delivered = q.receive_packet(1, b"msg1".to_vec());
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], b"msg1");
    }

    #[test]
    fn test_out_of_order_buffering_then_delivery() {
        let mut q = LosslessQueue::new();

        // Arrive out of order: seq=1 before seq=0
        let d1 = q.receive_packet(1, b"world".to_vec());
        assert_eq!(d1.len(), 0, "seq=1 should be buffered, not delivered yet");

        let d2 = q.receive_packet(0, b"hello".to_vec());
        assert_eq!(d2.len(), 2, "seq=0 arrival should flush both buffered packets");
        assert_eq!(d2[0], b"hello");
        assert_eq!(d2[1], b"world");
    }

    #[test]
    fn test_gap_prevents_delivery_of_later_packets() {
        let mut q = LosslessQueue::new();

        // seq=0 delivered, then seq=2 arrives (gap at seq=1)
        q.receive_packet(0, b"a".to_vec());
        let buffered = q.receive_packet(2, b"c".to_vec());
        assert_eq!(buffered.len(), 0, "seq=2 should be buffered pending seq=1");

        // Filling the gap delivers seq=1 and seq=2 together
        let flushed = q.receive_packet(1, b"b".to_vec());
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0], b"b");
        assert_eq!(flushed[1], b"c");
    }

    // ── Retransmit Queue ──────────────────────────────────────────────────

    #[test]
    fn test_fresh_message_not_in_retransmit_queue() {
        let mut q = LosslessQueue::new();
        q.enqueue_outgoing(b"recent".to_vec());
        // Retransmit interval is 2s — a freshly-sent message should NOT appear
        let retransmits = q.get_retransmit_queue();
        assert_eq!(retransmits.len(), 0);
    }

    #[test]
    fn test_exhausted_retries_not_retransmitted() {
        let mut q = LosslessQueue::new();
        q.enqueue_outgoing(b"dead".to_vec());

        // Manually set retries to MAX_RETRIES on the message
        for msg in q.unacked_messages.values_mut() {
            msg.retries = MAX_RETRIES;
            msg.last_sent = Instant::now() - Duration::from_secs(10);
        }

        let retransmits = q.get_retransmit_queue();
        assert_eq!(retransmits.len(), 0, "Exhausted messages should not be retransmitted");
    }

    // ── Dead Message Pruning ──────────────────────────────────────────────

    #[test]
    fn test_prune_dead_messages_removes_exhausted() {
        let mut q = LosslessQueue::new();
        q.enqueue_outgoing(b"dead".to_vec());
        q.enqueue_outgoing(b"alive".to_vec());

        // Max out retries on seq=0 only
        q.unacked_messages.get_mut(&0).unwrap().retries = MAX_RETRIES;

        q.prune_dead_messages();

        assert!(!q.unacked_messages.contains_key(&0), "Dead message should be pruned");
        assert!(q.unacked_messages.contains_key(&1), "Alive message should remain");
    }
}
