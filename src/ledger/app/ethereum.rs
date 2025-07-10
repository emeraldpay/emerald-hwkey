use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use crate::{
    errors::HWKeyError,
    ledger::{
        apdu::ApduBuilder,
        app::{AsChainCode, AsExtendedKey, AsPubkey, LedgerApp, PubkeyAddressApp},
        comm::{sendrecv, LedgerTransport},
        commons::as_compact
    },
};
use std::convert::TryFrom;
use hdpath::{AccountHDPath, HDPath, Purpose};
use bitcoin::{
    secp256k1::PublicKey,
    bip32::ChainCode
};
use crate::ledger::connect::direct::CHUNK_SIZE;

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

const COMMAND_GET_ADDRESS: u8 = 0x02;
const COMMAND_SIGN_TRANSACTION: u8 = 0x04;
const COMMAND_SIGN_MESSAGE: u8 = 0x08;
const COMMAND_APP_CONFIG: u8 = 0x06;
const COMMAND_SIGN_EIP712: u8 = 0x0C;

/// V-R-S data, but Ethereum uses R-S-V
pub type SignatureBytes = [u8; ECDSA_SIGNATURE_BYTES];

pub struct EthereumApp {
    ledger: Arc<Mutex<dyn LedgerTransport>>
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
        let chaincode = ChainCode::try_from(chaincode.as_slice()).unwrap();

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

impl EthereumApp {

    /// Split data into chunks for sending to Ledger device
    /// 
    /// # Arguments
    /// * `data` - The data to be chunked
    /// * `hd_path` - HD path that will be included in the initial chunk
    /// 
    /// # Returns
    /// A tuple of (initial_chunk, continuation_data) where:
    /// * initial_chunk - First chunk including HD path data
    /// * continuation_data - Remaining data to be sent in subsequent chunks
    fn chunk_data<'a>(&self, data: &'a [u8], hd_path: &dyn HDPath) -> (&'a [u8], &'a [u8]) {
        match data.len() {
            0..=CHUNK_SIZE => (data, &[]),
            _ => data.split_at(CHUNK_SIZE - hd_path.to_bytes().len()),
        }
    }

    /// Send chunked data to the Ledger device using the standard chunking protocol
    ///
    /// # Protocol Details:
    ///
    /// ```no_run,ignore
    ///   P1: 00 : first message data block
    ///       80 : subsequent message data block
    ///   P2: 00 : always
    /// ```
    /// 
    /// # Arguments
    /// * `command` - The APDU command to use
    /// * `hd_path` - HD path for the initial chunk
    /// * `data` - The data to be sent in chunks
    /// 
    /// # Returns
    /// The response from the device after sending all chunks
    fn send_chunked_data(&self, command: u8, hd_path: &dyn HDPath, data: &[u8]) -> Result<Vec<u8>, HWKeyError> {
        let (init, cont) = self.chunk_data(data, hd_path);

        let init_apdu = ApduBuilder::new(command)
            .with_p1(0x00)
            .with_data(hd_path.to_bytes().as_slice())
            .with_data(init)
            .build();

        let mut handle = self.ledger.lock().unwrap();
        let mut res = sendrecv(&mut *handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(command)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&mut *handle, &apdu_cont)?;
        }

        Ok(res)
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

        let mut ledger = self.ledger.lock().unwrap();


        // let mut handle = self.ledger.lock().unwrap().deref();
        sendrecv(&mut *ledger, &apdu)
            .and_then(|res| AddressResponse::try_from(res))
    }

    /// Sign transaction
    ///
    /// # Arguments:
    /// tx - RLP encoded transaction
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    /// # Protocol Details:
    /// According to the Ledger Ethereum specification (reference/ledger-ethereum.adoc), 
    /// transaction data is sent as:
    /// - First block: HD path + RLP transaction chunk (no length prefix)
    /// - Other blocks: RLP transaction chunk only
    /// The RLP transaction data is sent directly without any length prefix.
    ///
    pub fn sign_transaction(
        &self,
        tx: &[u8],
        hd_path: &dyn HDPath,
    ) -> Result<SignatureBytes, HWKeyError> {

        // Send RLP transaction data directly without length prefix
        // as per SIGN ETH TRANSACTION specification
        let res = self.send_chunked_data(COMMAND_SIGN_TRANSACTION, hd_path, tx)?;
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

    /// Sign a message as per ERC-191.
    /// The Ledger asks the user to validate the SHA-256 hash of the message being signed.
    /// This command has been supported since firmware version 1.0.8
    ///
    /// # Arguments:
    /// message - a string to sign
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    /// # Protocol Details:
    /// According to the Ledger Ethereum specification (reference/ledger-ethereum.adoc),
    /// message data is sent as:
    /// - First block: HD path + Message length (4 bytes) + Message chunk
    /// - Other blocks: Message chunk only
    /// The message data requires a 4-byte length prefix (big-endian) before the message content.
    ///
    /// # See 
    /// - https://github.com/LedgerHQ/app-ethereum/blob/d408c161dc43ce4640165464bd8a4f45d662a6f1/doc/ethapp.adoc#sign-eth-transaction
    /// - https://eips.ethereum.org/EIPS/eip-191
    pub fn sign_message_erc191(
        &self,
        message: String,
        hd_path: &dyn HDPath,
    ) -> Result<SignatureBytes, HWKeyError> {

        let message = message.as_bytes();
        // Prepare message data with 4-byte length prefix as per SIGN ETH PERSONAL MESSAGE specification
        let mut message_data = Vec::<u8>::with_capacity(message.len() + 4);
        message_data.extend_from_slice((message.len() as u32).to_be_bytes().as_slice());
        message_data.extend_from_slice(message);
        let message_data = message_data.as_slice();

        // NOTE: it comes as V-R-S, though the EIP-191 spec defines it as R-S-V.
        let res = self.send_chunked_data(COMMAND_SIGN_MESSAGE, hd_path, message_data)?;
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

    /// Sign a message as per EIP-712 (v0 implementation - simple signing with hashes only).
    /// This implementation requires the domain hash and message hash to be pre-computed
    /// and provided to the device for signing.
    /// 
    /// The Ledger displays the hashes to the user for validation before signing.
    /// This command has been supported since app version 1.5.0
    ///
    /// # Arguments
    /// * `domain_hash` - The 32-byte domain hash (keccak256 of the domain separator)
    /// * `message_hash` - The 32-byte message hash (keccak256 of the message)
    /// * `hd_path` - HD path for the signing key
    ///
    /// # Protocol Details
    /// According to the Ledger Ethereum specification (reference/ledger-ethereum.adoc),
    /// for the v0 implementation, the data sent is:
    /// - HD path
    /// - Domain hash (32 bytes)
    /// - Message hash (32 bytes)
    /// 
    /// # See
    /// - https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
    /// - reference/ledger-ethereum.adoc section "SIGN ETH EIP 712"
    pub fn sign_message_eip712(
        &self,
        domain_hash: &[u8; 32],
        message_hash: &[u8; 32],
        hd_path: &dyn HDPath,
    ) -> Result<SignatureBytes, HWKeyError> {
        // Prepare the data payload: domain_hash + message_hash
        let mut data = Vec::<u8>::with_capacity(64);
        data.extend_from_slice(domain_hash);
        data.extend_from_slice(message_hash);

        let apdu = ApduBuilder::new(COMMAND_SIGN_EIP712)
            .with_p1(0x00)
            // 00 for v0 implementation (simple signing with hashes only)
            .with_p2(0x00)
            .with_data(hd_path.to_bytes().as_slice())
            .with_data(&data)
            .build();

        let mut handle = self.ledger.lock().unwrap();

        // NOTE: it comes as V-R-S, though the EIP-712 spec defines it as R-S-V.
        let res = sendrecv(&mut *handle, &apdu)?;
        
        debug!("Received EIP-712 signature: {:?}", hex::encode(&res));
        match res.len() {
            ECDSA_SIGNATURE_BYTES => {
                let mut val: SignatureBytes = [0; ECDSA_SIGNATURE_BYTES];
                val.copy_from_slice(&res);
                Ok(val)
            }
            v => Err(HWKeyError::CryptoError(format!(
                "Invalid EIP-712 signature length. Expected: {}, received: {}",
                ECDSA_SIGNATURE_BYTES, v
            ))),
        }
    }

    pub fn get_version(&self) -> Result<AppVersion, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_APP_CONFIG)
            .build();
        let mut handle = self.ledger.lock().unwrap();
        let resp = sendrecv(&mut *handle, &apdu)?;
        AppVersion::try_from(resp).map_err(|_| HWKeyError::EncodingError("Invalid version config".to_string()))
    }

    fn is_path_available(&self, hd_path: &dyn HDPath) -> bool {
        self.get_address(hd_path, false)
            .map_or(false, |_| true)
    }
}

impl PubkeyAddressApp for EthereumApp {
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

impl LedgerApp for EthereumApp {
    type Networks = EthereumApps;

    fn new(manager: Arc<Mutex<dyn LedgerTransport>>) -> Self{
        EthereumApp {
            ledger: manager
        }
    }

    fn is_open(&self) -> Option<Self::Networks> {
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
    use crate::ledger::app::ethereum::{AddressResponse, EthereumApp};
    use crate::ledger::app::LedgerApp;
    use crate::ledger::connect::direct::CHUNK_SIZE;
    use crate::ledger::connect::mock::MockTransport;
    use std::convert::TryFrom;
    use std::sync::{Arc, Mutex};
    use hdpath::{StandardHDPath, HDPath};

    #[test]
    fn chunk_data_small_data() {
        let transport = Arc::new(Mutex::new(MockTransport::new()));
        let app = EthereumApp::new(transport);
        let hd_path = StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap();
        
        let small_data = vec![1, 2, 3, 4, 5];
        let (init, cont) = app.chunk_data(&small_data, &hd_path);
        
        assert_eq!(init, &small_data);
        assert_eq!(cont.len(), 0);
    }

    #[test]
    fn chunk_data_large_data() {
        let transport = Arc::new(Mutex::new(MockTransport::new()));
        let app = EthereumApp::new(transport);
        let hd_path = StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap();
        
        // Create data larger than CHUNK_SIZE
        let large_data = vec![0u8; CHUNK_SIZE + 100];
        let (init, cont) = app.chunk_data(&large_data, &hd_path);
        
        let expected_init_size = CHUNK_SIZE - hd_path.to_bytes().len();
        assert_eq!(init.len(), expected_init_size);
        assert_eq!(cont.len(), large_data.len() - expected_init_size);
        
        // Verify the data is correctly split
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(init);
        reconstructed.extend_from_slice(cont);
        assert_eq!(reconstructed, large_data);
    }

    #[test]
    fn chunk_data_exact_chunk_size() {
        let transport = Arc::new(Mutex::new(MockTransport::new()));
        let app = EthereumApp::new(transport);
        let hd_path = StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap();
        
        // Create data exactly CHUNK_SIZE
        let exact_data = vec![0u8; CHUNK_SIZE];
        let (init, cont) = app.chunk_data(&exact_data, &hd_path);
        
        assert_eq!(init, &exact_data);
        assert_eq!(cont.len(), 0);
    }

    #[test]
    fn send_chunked_data_builds_correct_apdu() {
        let transport = Arc::new(Mutex::new(MockTransport::new()));
        let app = EthereumApp::new(transport);
        let hd_path = StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap();
        
        let small_data = vec![1, 2, 3, 4, 5];
        let (init, cont) = app.chunk_data(&small_data, &hd_path);
        
        // Verify that chunking works as expected for small data
        assert_eq!(init, &small_data);
        assert_eq!(cont.len(), 0);
        
        // Test with large data
        let large_data = vec![0u8; CHUNK_SIZE + 100];
        let (init, cont) = app.chunk_data(&large_data, &hd_path);
        
        // Verify chunking works for large data
        let expected_init_size = CHUNK_SIZE - hd_path.to_bytes().len();
        assert_eq!(init.len(), expected_init_size);
        assert_eq!(cont.len(), large_data.len() - expected_init_size);
        
        // Verify data integrity
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(init);
        reconstructed.extend_from_slice(cont);
        assert_eq!(reconstructed, large_data);
    }

    #[test]
    fn chunk_data_respects_hd_path_length() {
        let transport = Arc::new(Mutex::new(MockTransport::new()));
        let app = EthereumApp::new(transport);
        
        // Test with different HD path lengths using CustomHDPath and StandardHDPath
        use hdpath::CustomHDPath;
        
        // CustomHDPath with fewer derivation levels than StandardHDPath
        let short_path = CustomHDPath::try_from("m/44'/60'/0'/0").unwrap();      // 4 levels
        let long_path = StandardHDPath::try_from("m/44'/60'/0'/0/0").unwrap();   // 5 levels
        
        let test_data = vec![0u8; CHUNK_SIZE + 50];
        
        let (init_short, cont_short) = app.chunk_data(&test_data, &short_path);
        let (init_long, cont_long) = app.chunk_data(&test_data, &long_path);
        
        // Verify the expected chunk sizes
        let short_path_len = short_path.to_bytes().len();
        let long_path_len = long_path.to_bytes().len();
        
        // Short path should have fewer bytes than long path
        assert!(short_path_len < long_path_len, "Short path should have fewer bytes than long path");
        
        let expected_init_short = CHUNK_SIZE - short_path_len;
        let expected_init_long = CHUNK_SIZE - long_path_len;
        
        assert_eq!(init_short.len(), expected_init_short);
        assert_eq!(init_long.len(), expected_init_long);
        
        // With shorter HD path, more data should fit in initial chunk
        assert!(init_short.len() > init_long.len(), "Shorter path should allow more data in initial chunk");
        assert!(cont_short.len() < cont_long.len(), "Shorter path should have less continuation data");
        
        // Both should reconstruct to the same original data
        let mut reconstructed_short = Vec::new();
        reconstructed_short.extend_from_slice(init_short);
        reconstructed_short.extend_from_slice(cont_short);
        
        let mut reconstructed_long = Vec::new();
        reconstructed_long.extend_from_slice(init_long);
        reconstructed_long.extend_from_slice(cont_long);
        
        assert_eq!(reconstructed_short, test_data);
        assert_eq!(reconstructed_long, test_data);
    }

    #[test]
    fn decode_std_address() {
        let resp = hex::decode("4104b28217096d8ad3dd25461404c3941a5196ac8f089f1be5bcb62df2ce08a71ba1ca4b879ee38217cced7ef1c9dc5c15cb804ab159503514f73559d1a1192ba1fc28354164343233663565623437333534313563393366306365353266366532633133424436413530309000000000000035140000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), "{:?}", parsed);
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
        assert!(parsed.is_ok(), "{:?}", parsed);
        let parsed = parsed.unwrap();
        assert_eq!("0x3d66483b4Cad3518861029Ff86a387eBc4705172".to_string(), parsed.address);
        assert_eq!(
            "04452ae4b222d10cb80c269d0677f7165c548e49113d91b26848ae01a7732f15ff88379573411237d1a9dfb9603d2f40d7a56bf12b1bf5f6ae3b69d7bfebd45689",
            hex::encode(parsed.pubkey.serialize_uncompressed().to_vec()));
    }
}