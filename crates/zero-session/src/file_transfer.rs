use std::collections::HashMap;
use std::collections::BTreeMap;
use std::time::Instant;

pub const MAX_FILE_CHUNK_SIZE: usize = 65536; // 64KB chunks
pub const MAX_TRANSFER_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4GB limit
pub const MAX_AUTO_ACCEPT_SIZE: u64 = 50 * 1024 * 1024; // 50MB auto-accept max

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// Awaiting user approval on the receiver side
    Pending,
    /// Transfer is actively running
    Active,
    /// Transfer completed successfully
    Completed,
    /// Transfer was rejected or cancelled
    Cancelled,
    /// Transfer failed with an error
    Failed(String),
}

#[derive(Debug)]
pub struct FileTransfer {
    pub file_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub bytes_transferred: u64,
    pub is_sender: bool,
    pub state: TransferState,
    pub started_at: Instant,
    /// Received chunks indexed by their byte offset for out-of-order reassembly
    pub received_chunks: BTreeMap<u64, Vec<u8>>,
}

impl FileTransfer {
    pub fn new_outgoing(file_id: [u8; 16], file_name: String, file_size: u64) -> Self {
        Self {
            file_id,
            file_name,
            file_size,
            bytes_transferred: 0,
            is_sender: true,
            state: TransferState::Active,
            started_at: Instant::now(),
            received_chunks: BTreeMap::new(),
        }
    }

    pub fn new_incoming(file_id: [u8; 16], file_name: String, file_size: u64) -> Result<Self, &'static str> {
        // Policy: Never auto-accept files beyond the size limit
        if file_size > MAX_TRANSFER_SIZE {
            return Err("File exceeds maximum allowed transfer size (4GB)");
        }
        
        let initial_state = if file_size <= MAX_AUTO_ACCEPT_SIZE {
            TransferState::Active
        } else {
            TransferState::Pending // User must approve large files
        };

        Ok(Self {
            file_id,
            file_name,
            file_size,
            bytes_transferred: 0,
            is_sender: false,
            state: initial_state,
            started_at: Instant::now(),
            received_chunks: BTreeMap::new(),
        })
    }

    pub fn progress_percent(&self) -> f32 {
        if self.file_size == 0 {
            return 100.0;
        }
        (self.bytes_transferred as f32 / self.file_size as f32) * 100.0
    }

    pub fn accept(&mut self) -> Result<(), &'static str> {
        if self.state == TransferState::Pending && !self.is_sender {
            self.state = TransferState::Active;
            Ok(())
        } else {
            Err("Transfer cannot be accepted in its current state")
        }
    }

    pub fn cancel(&mut self) {
        self.state = TransferState::Cancelled;
    }

    /// Ingests an incoming chunk into the ordered reassembly buffer
    pub fn receive_chunk(&mut self, offset: u64, data: Vec<u8>) -> Result<(), &'static str> {
        if self.state != TransferState::Active {
            return Err("Transfer is not active");
        }
        let chunk_size = data.len() as u64;
        if offset + chunk_size > self.file_size {
            return Err("Chunk exceeds file boundary");
        }
        for (&e_offset, chunk) in &self.received_chunks {
            let e_size = chunk.len() as u64;
            if offset < e_offset + e_size && e_offset < offset + chunk_size {
                return Err("Overlapping chunk detected");
            }
        }
        if !self.received_chunks.contains_key(&offset) {
            self.received_chunks.insert(offset, data);
            self.bytes_transferred = self.received_chunks.values().map(|v| v.len() as u64).sum();
            if self.bytes_transferred == self.file_size {
                self.state = TransferState::Completed;
            }
        }
        Ok(())
    }

    /// Attempts to assemble all received chunks into the final file bytes
    pub fn assemble(&self) -> Option<Vec<u8>> {
        if self.state != TransferState::Completed {
            return None;
        }
        let mut result = vec![0u8; self.file_size as usize];
        for (&offset, chunk) in &self.received_chunks {
            let start = offset as usize;
            let end = start + chunk.len();
            if end <= result.len() {
                result[start..end].copy_from_slice(chunk);
            }
        }
        Some(result)
    }
}

pub struct FileTransferManager {
    active_transfers: HashMap<[u8; 16], FileTransfer>,
}

impl FileTransferManager {
    pub fn new() -> Self {
        Self {
            active_transfers: HashMap::new(),
        }
    }

    pub fn register_outgoing(&mut self, file_id: [u8; 16], file_name: String, file_size: u64) {
        let transfer = FileTransfer::new_outgoing(file_id, file_name, file_size);
        self.active_transfers.insert(file_id, transfer);
    }

    pub fn register_incoming(&mut self, file_id: [u8; 16], file_name: String, file_size: u64) -> Result<(), &'static str> {
        let transfer = FileTransfer::new_incoming(file_id, file_name, file_size)?;
        self.active_transfers.insert(file_id, transfer);
        Ok(())
    }

    pub fn accept(&mut self, file_id: &[u8; 16]) -> Result<(), &'static str> {
        self.active_transfers.get_mut(file_id)
            .ok_or("Transfer not found")
            .and_then(|t| t.accept())
    }

    pub fn cancel(&mut self, file_id: &[u8; 16]) {
        if let Some(t) = self.active_transfers.get_mut(file_id) {
            t.cancel();
        }
    }

    pub fn receive_chunk(&mut self, file_id: &[u8; 16], offset: u64, data: Vec<u8>) -> Result<(), &'static str> {
        self.active_transfers.get_mut(file_id)
            .ok_or("Transfer not found")
            .and_then(|t| t.receive_chunk(offset, data))
    }

    pub fn get(&self, file_id: &[u8; 16]) -> Option<&FileTransfer> {
        self.active_transfers.get(file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    // ── Auto-Accept Policy ────────────────────────────────────────────────

    #[test]
    fn test_small_file_auto_accepted() {
        let ft = FileTransfer::new_incoming(file_id(1), "small.txt".into(), 1024).unwrap();
        assert_eq!(ft.state, TransferState::Active);
    }

    #[test]
    fn test_large_file_requires_approval() {
        let ft = FileTransfer::new_incoming(file_id(2), "big.iso".into(), 200 * 1024 * 1024).unwrap();
        assert_eq!(ft.state, TransferState::Pending);
    }

    #[test]
    fn test_file_exceeding_max_rejected() {
        let result = FileTransfer::new_incoming(file_id(3), "huge.bin".into(), 5 * 1024 * 1024 * 1024);
        assert!(result.is_err());
    }

    // ── Accept Flow ───────────────────────────────────────────────────────

    #[test]
    fn test_accept_pending_transfer() {
        let mut ft = FileTransfer::new_incoming(file_id(4), "big.zip".into(), 100 * 1024 * 1024).unwrap();
        assert_eq!(ft.state, TransferState::Pending);
        ft.accept().unwrap();
        assert_eq!(ft.state, TransferState::Active);
    }

    #[test]
    fn test_cannot_accept_already_active() {
        let mut ft = FileTransfer::new_incoming(file_id(5), "small.txt".into(), 1024).unwrap();
        assert!(ft.accept().is_err()); // already Active
    }

    #[test]
    fn test_sender_cannot_accept() {
        let mut ft = FileTransfer::new_outgoing(file_id(6), "out.txt".into(), 1024);
        assert!(ft.accept().is_err());
    }

    // ── Chunk Reception & Assembly ────────────────────────────────────────

    #[test]
    fn test_single_chunk_completes_transfer() {
        let data = vec![0xABu8; 1024];
        let mut ft = FileTransfer::new_incoming(file_id(7), "f.bin".into(), 1024).unwrap();
        ft.receive_chunk(0, data.clone()).unwrap();
        assert_eq!(ft.state, TransferState::Completed);
        assert_eq!(ft.assemble().unwrap(), data);
    }

    #[test]
    fn test_out_of_order_chunks_assembled_correctly() {
        let chunk_a = vec![0xAAu8; 512];
        let chunk_b = vec![0xBBu8; 512];
        let mut ft = FileTransfer::new_incoming(file_id(8), "f.bin".into(), 1024).unwrap();

        // Receive second chunk first, then first chunk
        ft.receive_chunk(512, chunk_b.clone()).unwrap();
        assert_eq!(ft.state, TransferState::Active);
        ft.receive_chunk(0, chunk_a.clone()).unwrap();
        assert_eq!(ft.state, TransferState::Completed);

        let assembled = ft.assemble().unwrap();
        assert_eq!(&assembled[0..512], chunk_a.as_slice());
        assert_eq!(&assembled[512..1024], chunk_b.as_slice());
    }

    #[test]
    fn test_chunk_exceeding_file_boundary_rejected() {
        let mut ft = FileTransfer::new_incoming(file_id(9), "f.bin".into(), 1024).unwrap();
        let result = ft.receive_chunk(500, vec![0u8; 600]); // 500 + 600 = 1100 > 1024
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_chunk_ignored() {
        let chunk = vec![0xCCu8; 512];
        let mut ft = FileTransfer::new_incoming(file_id(10), "f.bin".into(), 1024).unwrap();
        ft.receive_chunk(0, chunk.clone()).unwrap();
        ft.receive_chunk(0, vec![0xFFu8; 512]).unwrap(); // duplicate — should not overwrite
        assert_eq!(&ft.received_chunks[&0], &chunk); // original preserved
    }

    #[test]
    fn test_progress_percent() {
        let mut ft = FileTransfer::new_incoming(file_id(11), "f.bin".into(), 1000).unwrap();
        ft.receive_chunk(0, vec![0u8; 500]).unwrap();
        let pct = ft.progress_percent();
        assert!((pct - 50.0).abs() < 0.01, "Expected ~50%, got {}", pct);
    }

    // ── Cancellation ──────────────────────────────────────────────────────

    #[test]
    fn test_cancelled_transfer_rejects_chunks() {
        let mut ft = FileTransfer::new_incoming(file_id(12), "f.bin".into(), 1024).unwrap();
        ft.cancel();
        assert_eq!(ft.state, TransferState::Cancelled);
        let result = ft.receive_chunk(0, vec![0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_assemble_returns_none_if_not_complete() {
        let ft = FileTransfer::new_incoming(file_id(13), "f.bin".into(), 1024).unwrap();
        assert!(ft.assemble().is_none());
    }

    #[test]
    fn test_overlapping_chunks_rejected() {
        let mut ft = FileTransfer::new_incoming(file_id(14), "f.bin".into(), 1024).unwrap();
        ft.receive_chunk(0, vec![0u8; 100]).unwrap();
        
        let res = ft.receive_chunk(50, vec![0u8; 100]);
        assert!(res.is_err());
    }
}
