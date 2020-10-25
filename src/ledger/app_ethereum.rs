use crate::errors::HWKeyError;
use crate::ledger::apdu::ApduBuilder;
use std::str::from_utf8;
use crate::ledger::comm::sendrecv;
use crate::ledger::manager::{LedgerKey, CHUNK_SIZE};
use std::convert::TryFrom;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

const COMMAND_GET_ADDRESS: u8 = 0x02;
const COMMAND_SIGN_TRANSACTION: u8 = 0x04;

pub type SignatureBytes = [u8; ECDSA_SIGNATURE_BYTES];

pub struct EthereumApp {
    ledger: LedgerKey
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressResponse {
    pub pubkey: Vec<u8>,
    pub address: String,
}

impl TryFrom<Vec<u8>> for AddressResponse {
    type Error = HWKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(HWKeyError::EncodingError("Empty data".to_string()))
        }
        let pubkey_len = value[0] as usize;
        if 1 + pubkey_len > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Pubkey cutoff. {:?} > {:?} for {:?}", 1 + pubkey_len, value.len(), pubkey_len)
            ))
        }
        let pubkey = &value[1..pubkey_len+1];

        let address_len = value[pubkey_len + 1] as usize;
        let address_start = 1 + pubkey_len + 1;
        let address_end = address_start + address_len;
        if address_end > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Address cutoff. {:?} > {:?} as {:?}..{:?} for {:?}", address_end, value.len(), address_start, address_end, address_len)
            ))
        }
        let address = &value[address_start..address_end];
        let address = from_utf8(address).map(|a| a.to_string())
            .map_err(|e| HWKeyError::EncodingError(format!("Can't parse address: {}", e.to_string()))
        )?;

        Ok(AddressResponse {
            pubkey: pubkey.to_vec(), address
        })
    }
}

impl EthereumApp {

    pub fn new(ledger: LedgerKey) -> EthereumApp {
        EthereumApp {
            ledger
        }
    }

    /// Get address
    ///
    /// # Arguments:
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(&self, hd_path: Vec<u8>) -> Result<AddressResponse, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_GET_ADDRESS)
            .with_data(&hd_path)
            .build();
        let handle = self.ledger.open()?;
        sendrecv(&handle, &apdu)
            .and_then(|res| AddressResponse::try_from(res))
    }

    /// Sign transaction
    ///
    /// # Arguments:
    /// tx - RLP encoded transaction
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    pub fn sign_transaction(
        &self,
        tx: &[u8],
        hd_path: Vec<u8>,
    ) -> Result<SignatureBytes, HWKeyError> {

        let _mock = Vec::new();
        let (init, cont) = match tx.len() {
            0..=CHUNK_SIZE => (tx, _mock.as_slice()),
            _ => tx.split_at(CHUNK_SIZE - hd_path.len()),
        };

        let init_apdu = ApduBuilder::new(COMMAND_SIGN_TRANSACTION)
            .with_p1(0x00)
            .with_data(&hd_path)
            .with_data(init)
            .build();

        if !self.ledger.have_device() {
            return Err(HWKeyError::OtherError("Device not selected".to_string()));
        }

        let handle = self.ledger.open()?;
        let mut res = sendrecv(&handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(COMMAND_SIGN_TRANSACTION)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&handle, &apdu_cont)?;
        }
        debug!("Received signature: {:?}", hex::encode(&res));
        match res.len() {
            ECDSA_SIGNATURE_BYTES => {
                let mut val: SignatureBytes = [0; ECDSA_SIGNATURE_BYTES];
                val.copy_from_slice(&res);

                Ok(val)
            }
            v => Err(HWKeyError::CryptoError(format!(
                "Invalid signature length. Expected: {}, received: {}",
                ECDSA_SIGNATURE_BYTES, v
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ledger::app_ethereum::AddressResponse;
    use std::convert::TryFrom;

    #[test]
    fn decode_std_address() {
        let resp = hex::decode("4104b28217096d8ad3dd25461404c3941a5196ac8f089f1be5bcb62df2ce08a71ba1ca4b879ee38217cced7ef1c9dc5c15cb804ab159503514f73559d1a1192ba1fc2835416434323366356562343733353431356339336630636535326636653263313342443641353030900000000000003514").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("5Ad423f5eb4735415c93f0ce52f6e2c13BD6A500".to_string(), parsed.address);
        assert_eq!(
            "04b28217096d8ad3dd25461404c3941a5196ac8f089f1be5bcb62df2ce08a71ba1ca4b879ee38217cced7ef1c9dc5c15cb804ab159503514f73559d1a1192ba1fc",
            hex::encode(parsed.pubkey));
    }

    #[test]
    fn decode_std_address_2() {
        let resp = hex::decode("4104452ae4b222d10cb80c269d0677f7165c548e49113d91b26848ae01a7732f15ff88379573411237d1a9dfb9603d2f40d7a56bf12b1bf5f6ae3b69d7bfebd45689283364363634383362344361643335313838363130323946663836613338376542633437303531373290000000000000f5f6").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("3d66483b4Cad3518861029Ff86a387eBc4705172".to_string(), parsed.address);
        assert_eq!(
            "04452ae4b222d10cb80c269d0677f7165c548e49113d91b26848ae01a7732f15ff88379573411237d1a9dfb9603d2f40d7a56bf12b1bf5f6ae3b69d7bfebd45689",
            hex::encode(parsed.pubkey));
    }
}