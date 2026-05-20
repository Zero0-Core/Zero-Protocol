use crate::ZeroError;
use blake2::{Blake2s256, Digest};
use subtle::ConstantTimeEq;

/// Generates a Proof-of-Work token matching a difficulty requirement.
/// Difficulty is specified in number of leading zero bits.
pub fn generate_pow(context: &[u8], difficulty_bits: u32) -> ([u8; 32], u64) {
    let mut nonce: u64 = 0;
    loop {
        let mut h = Blake2s256::new();
        h.update(context);
        h.update(&nonce.to_le_bytes());
        let hash: [u8; 32] = h.finalize().into();

        if check_difficulty(&hash, difficulty_bits) {
            return (hash, nonce);
        }
        nonce += 1;
    }
}

/// Verifies a Proof-of-Work token against a difficulty requirement.
pub fn verify_pow(
    context: &[u8],
    nonce: u64,
    expected_hash: &[u8; 32],
    difficulty_bits: u32,
) -> Result<(), ZeroError> {
    if !check_difficulty(expected_hash, difficulty_bits) {
        return Err(ZeroError::InvalidProofOfWork);
    }

    let mut h = Blake2s256::new();
    h.update(context);
    h.update(&nonce.to_le_bytes());
    let hash: [u8; 32] = h.finalize().into();

    if hash.ct_eq(expected_hash).into() {
        Ok(())
    } else {
        Err(ZeroError::InvalidProofOfWork)
    }
}

fn check_difficulty(hash: &[u8; 32], difficulty_bits: u32) -> bool {
    let mut bits_checked = 0;
    for &byte in hash.iter() {
        if bits_checked >= difficulty_bits {
            return true;
        }
        let remaining = difficulty_bits - bits_checked;
        if remaining >= 8 {
            if byte != 0 {
                return false;
            }
            bits_checked += 8;
        } else {
            let shift = 8 - remaining;
            return (byte >> shift) == 0;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow() {
        let context = b"test-pow";
        let difficulty = 10; // small difficulty for fast tests
        let (hash, nonce) = generate_pow(context, difficulty);

        assert!(verify_pow(context, nonce, &hash, difficulty).is_ok());

        // Invalid nonce
        assert!(verify_pow(context, nonce + 1, &hash, difficulty).is_err());
    }
}
