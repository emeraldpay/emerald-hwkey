use bitcoin::secp256k1::PublicKey;
use crate::errors::HWKeyError;

pub fn as_compact(pubkey: &PublicKey) -> Result<PublicKey, HWKeyError> {
    PublicKey::from_slice(&pubkey.serialize())
        .map_err(|_| HWKeyError::CryptoError("Invalid public key".to_string()))
}