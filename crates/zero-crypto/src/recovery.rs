use bip39::Mnemonic;
use crate::keypair::StaticKeypair;
use crate::ZeroError;

/// Generates a 24-word BIP39 mnemonic recovery phrase from the identity keypair.
pub fn generate_recovery_phrase(keypair: &StaticKeypair) -> Result<String, ZeroError> {
    let mnemonic = Mnemonic::from_entropy(keypair.private.as_ref())
        .map_err(|_| ZeroError::InvalidKeyLength)?;
    Ok(mnemonic.to_string())
}

/// Recovers a StaticKeypair from a 24-word BIP39 mnemonic phrase.
pub fn recover_from_phrase(phrase: &str) -> Result<StaticKeypair, ZeroError> {
    let mnemonic: Mnemonic = phrase.parse()
        .map_err(|_| ZeroError::InvalidKeyLength)?;
        
    let entropy = mnemonic.to_entropy();
    
    if entropy.len() != 32 {
        return Err(ZeroError::InvalidKeyLength);
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&entropy);
    Ok(StaticKeypair::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_recovery() {
        let original = StaticKeypair::generate();
        let phrase = generate_recovery_phrase(&original).unwrap();
        let recovered = recover_from_phrase(&phrase).unwrap();
        
        assert_eq!(original.public, recovered.public);
        assert_eq!(original.private.as_ref(), recovered.private.as_ref());
    }
}
