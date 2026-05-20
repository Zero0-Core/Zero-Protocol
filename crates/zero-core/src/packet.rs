#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Standard DHT ping to verify node liveness
    Ping = 0x01,
    /// Request the closest nodes to a specific DHT key
    FindNode = 0x02,
    /// Response containing routing table entries
    FindNodeResponse = 0x03,
    /// 3-hop Onion encrypted discovery request
    OnionRequest = 0x04,
    /// 3-hop Onion encrypted discovery response
    OnionResponse = 0x05,
    /// Store an encrypted message for an offline peer
    OffloadStore = 0x06,
    /// Retrieve stored offline messages
    OffloadRetrieve = 0x07,
    /// Double-Ratchet encrypted 1-on-1 session message
    SessionMessage = 0x08,
    /// Invalid packet identifier
    Unknown = 0xFF,
}

impl From<u8> for PacketType {
    fn from(byte: u8) -> Self {
        match byte {
            0x01 => PacketType::Ping,
            0x02 => PacketType::FindNode,
            0x03 => PacketType::FindNodeResponse,
            0x04 => PacketType::OnionRequest,
            0x05 => PacketType::OnionResponse,
            0x06 => PacketType::OffloadStore,
            0x07 => PacketType::OffloadRetrieve,
            0x08 => PacketType::SessionMessage,
            _ => PacketType::Unknown,
        }
    }
}

/// Format:
/// [Byte 0]     -> PacketType Identifier
/// [Byte 1]     -> Padding Length (n)
/// [Bytes 2-n]  -> Random padding
/// [Bytes n+2+] -> Payload
pub fn decode_packet(raw: &[u8]) -> Result<(PacketType, &[u8]), &'static str> {
    if raw.len() < 2 {
        return Err("Packet too small (no header)");
    }

    let packet_type = PacketType::from(raw[0]);
    if packet_type == PacketType::Unknown {
        return Err("Unknown packet type");
    }

    let padding_len = raw[1] as usize;
    if raw.len() < 2 + padding_len {
        return Err("Packet too small for claimed padding length");
    }

    let payload = &raw[2 + padding_len..];

    Ok((packet_type, payload))
}

pub fn encode_packet(packet_type: PacketType, payload: &[u8]) -> Vec<u8> {
    // We want the total length (1 + 1 + padding_len + payload.len()) to be a multiple of 64.
    // Length = 2 + P + L = 64 * k
    // P = (64 - ( (2 + L) % 64)) % 64
    let payload_len = payload.len();
    let padding_len = (64 - ((2 + payload_len) % 64)) % 64;

    let mut buffer = Vec::with_capacity(2 + padding_len + payload_len);

    // 1. Packet Type
    buffer.push(packet_type as u8);

    // 2. Padding Length
    buffer.push(padding_len as u8);

    // 3. Random Padding
    let mut padding = vec![0u8; padding_len];
    if padding_len > 0 {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
    }
    buffer.extend_from_slice(&padding);

    // 4. Payload
    buffer.extend_from_slice(payload);

    buffer
}
