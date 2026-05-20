use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceSyncBlob {
    pub message_history_patch: Vec<u8>,
    pub contact_list_patch: Vec<u8>,
    pub group_state_patch: Vec<u8>,
}

pub struct MultiDeviceSyncManager {
    // In a full implementation, this manages the encrypted channel 
    // between the user's primary and secondary devices.
}

impl MultiDeviceSyncManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Prepares an encrypted state diff to be sent via the zero-offload DHT
    /// to a secondary linked device.
    pub fn prepare_sync_blob(&self) -> DeviceSyncBlob {
        DeviceSyncBlob {
            message_history_patch: vec![],
            contact_list_patch: vec![],
            group_state_patch: vec![],
        }
    }
}
