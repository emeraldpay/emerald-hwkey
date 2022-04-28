use crate::errors::HWKeyError;
use crate::ledger::apdu::ApduBuilder;
use std::str::from_utf8;
use crate::ledger::comm::sendrecv;
use crate::ledger::manager::{LedgerKey, CHUNK_SIZE};
use std::convert::TryFrom;
use hdpath::{HDPath, AccountHDPath, Purpose};
use bitcoin::secp256k1::PublicKey;
use crate::ledger::traits::{AsPubkey, AsChainCode, AsExtendedKey, PubkeyAddressApp, LedgerApp};
use crate::ledger::commons::as_compact;
use bitcoin::util::bip32::ChainCode;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

const COMMAND_GET_ADDRESS: u8 = 0x02;
const COMMAND_SIGN_TRANSACTION: u8 = 0x04;
const COMMAND_APP_CONFIG: u8 = 0x06;

pub type SignatureBytes = [u8; ECDSA_SIGNATURE_BYTES];

pub struct EthereumApp<'a> {
    ledger: &'a LedgerKey
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressResponse {
    pub pubkey: PublicKey,
    pub address: String,
    pub chaincode: ChainCode
}

impl AsPubkey for AddressResponse {
    fn as_pubkey(&self) -> &PublicKey {
        &self.pubkey
    }
}

impl AsChainCode for AddressResponse {
    fn as_chaincode(&self) -> &ChainCode {
        &self.chaincode
    }
}

impl AsExtendedKey for AddressResponse {}

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
        let pubkey = PublicKey::from_slice(pubkey)
            .map_err(|_| HWKeyError::CryptoError("Invalid public key".to_string()))?;
        let pubkey_comp = as_compact(&pubkey)?;

        let address_len = value[pubkey_len + 1] as usize;
        let address_start = 1 + pubkey_len + 1;
        let address_end = address_start + address_len;
        if address_end > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Address cutoff. {:?} > {:?} as {:?}..{:?} for {:?}", address_end, value.len(), address_start, address_end, address_len)
            ))
        }
        let address = &value[address_start..address_end];
        let address = from_utf8(address)
            .map(|a| a.to_string())
            .map(|a| if a.starts_with("0x") { a } else { format!("0x{}", a)} )
            .map_err(|e| HWKeyError::EncodingError(format!("Can't parse address: {}", e.to_string())))?;

        let chaincode_len = 32 as usize;
        let chaincode_start = address_end;
        let chaincode_end = chaincode_start + chaincode_len;
        if chaincode_end > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Chaincode cutoff. {:?} > {:?}", chaincode_end, value.len())
            ))
        }
        let chaincode = (&value[chaincode_start..chaincode_end]).to_vec();
        let chaincode = ChainCode::from(chaincode.as_slice());

        Ok(AddressResponse {
            pubkey: pubkey_comp, address, chaincode
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppVersion {
    ///  arbitrary data signature enabled by user
    pub data_sign_enabled: bool,
    /// ERC 20 Token information needs to be provided externally
    pub external_erc20: bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_patch: u8,
}

impl TryFrom<Vec<u8>> for AppVersion {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(())
        }
        let flags = value[0];
        Ok(AppVersion {
            data_sign_enabled: flags & 0x01 > 0,
            external_erc20: flags & 0x02 > 0,
            version_major: value[1],
            version_minor: value[2],
            version_patch: value[3]
        })
    }
}

impl EthereumApp<'_> {

    pub fn new(ledger: &LedgerKey) -> EthereumApp {
        EthereumApp {
            ledger
        }
    }

    /// Get address
    ///
    /// # Arguments:
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(&self, hd_path: &dyn HDPath, confirm: bool) -> Result<AddressResponse, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_GET_ADDRESS)
            // 00 : return address
            // 01 : display address and confirm before returning
            .with_p1(if confirm {0x01} else {0x00})
            // 01 : return the chain code
            .with_p2(0x01)
            .with_data(hd_path.to_bytes().as_slice())
            .build();
        let mut handle = self.ledger.open()?;
        sendrecv(&mut handle, &apdu)
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
        hd_path: &dyn HDPath,
    ) -> Result<SignatureBytes, HWKeyError> {

        let _mock = Vec::new();
        let (init, cont) = match tx.len() {
            0..=CHUNK_SIZE => (tx, _mock.as_slice()),
            _ => tx.split_at(CHUNK_SIZE - hd_path.to_bytes().len()),
        };

        let init_apdu = ApduBuilder::new(COMMAND_SIGN_TRANSACTION)
            .with_p1(0x00)
            .with_data(hd_path.to_bytes().as_slice())
            .with_data(init)
            .build();

        if !self.ledger.have_device() {
            return Err(HWKeyError::OtherError("Device not selected".to_string()));
        }

        let mut handle = self.ledger.open()?;
        let mut res = sendrecv(&mut handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(COMMAND_SIGN_TRANSACTION)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&mut handle, &apdu_cont)?;
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

    pub fn get_version(&self) -> Result<AppVersion, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_APP_CONFIG)
            .build();
        let mut handle = self.ledger.open()?;
        let resp = sendrecv(&mut handle, &apdu)?;
        AppVersion::try_from(resp).map_err(|_| HWKeyError::EncodingError("Invalid version config".to_string()))
    }

    fn is_path_available(&self, hd_path: &dyn HDPath) -> bool {
        self.get_address(hd_path, false)
            .map_or(false, |_| true)
    }
}

impl PubkeyAddressApp for EthereumApp<'_> {
    fn get_extkey_at(&self, hd_path: &dyn HDPath) -> Result<Box<dyn AsExtendedKey>, HWKeyError> {
        let address = self.get_address(hd_path, false)?;
        Ok(Box::new(address))
    }
}

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
pub enum EthereumApps {
    Ethereum,
    EthereumClassic
}

impl LedgerApp for EthereumApp<'_> {
    type Category = EthereumApps;

    fn is_open(&self) -> Option<Self::Category> {
        self.get_version().ok().and_then(|_| {
            // ETC app gives address for both m/44'/60' and m/44'/61'
            // but ETH app gives only address for m/44'/60'

            let has_60 = self.is_path_available(
                &AccountHDPath::try_new(Purpose::Pubkey, 60, 0).expect("no-eth-acc")
            );
            let has_61 = self.is_path_available(
                &AccountHDPath::try_new(Purpose::Pubkey, 61, 0).expect("no-etc-acc")
            );

            if has_60 && has_61 {
                Some(EthereumApps::EthereumClassic)
            } else if has_60 && !has_61 {
                Some(EthereumApps::Ethereum)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ledger::app_ethereum::AddressResponse;
    use std::convert::TryFrom;

    #[test]
    fn decode_std_address() {
        let resp = hex::decode("4104b28217096d8ad3dd25461404c3941a5196ac8f089f1be5bcb62df2ce08a71ba1ca4b879ee38217cced7ef1c9dc5c15cb804ab159503514f73559d1a1192ba1fc28354164343233663565623437333534313563393366306365353266366532633133424436413530309000000000000035140000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("0x5Ad423f5eb4735415c93f0ce52f6e2c13BD6A500".to_string(), parsed.address);
        assert_eq!(
            "04b28217096d8ad3dd25461404c3941a5196ac8f089f1be5bcb62df2ce08a71ba1ca4b879ee38217cced7ef1c9dc5c15cb804ab159503514f73559d1a1192ba1fc",
            hex::encode(parsed.pubkey.serialize_uncompressed().to_vec()));
    }

    #[test]
    fn decode_std_address_2() {
        let resp = hex::decode("4104452ae4b222d10cb80c269d0677f7165c548e49113d91b26848ae01a7732f15ff88379573411237d1a9dfb9603d2f40d7a56bf12b1bf5f6ae3b69d7bfebd45689283364363634383362344361643335313838363130323946663836613338376542633437303531373290000000000000f5f60000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("0x3d66483b4Cad3518861029Ff86a387eBc4705172".to_string(), parsed.address);
        assert_eq!(
            "04452ae4b222d10cb80c269d0677f7165c548e49113d91b26848ae01a7732f15ff88379573411237d1a9dfb9603d2f40d7a56bf12b1bf5f6ae3b69d7bfebd45689",
            hex::encode(parsed.pubkey.serialize_uncompressed().to_vec()));
    }
}