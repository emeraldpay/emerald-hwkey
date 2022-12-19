use crate::{
    errors::HWKeyError,
    ledger::{
        apdu::ApduBuilder,
        manager::{LedgerKey, CHUNK_SIZE},
        comm::{sendrecv}
    }
};
use std::convert::TryFrom;
use std::str::{from_utf8};
use bitcoin::{
    Transaction,
    Script,
    Address,
    Network,
    VarInt,
    PublicKey,
    EcdsaSighashType,
    TxIn,
    consensus::{serialize},
    blockdata::{
        script::Builder,
        witness::Witness,
        opcodes
    },
    util::psbt::serialize::Serialize
};
use byteorder::{WriteBytesExt, LittleEndian};
use hdpath::{StandardHDPath, HDPath};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use bitcoin::util::bip32::{ChainCode};
use crate::ledger::comm::LedgerConnection;
use crate::ledger::commons::as_compact;
use crate::ledger::traits::{AsPubkey, AsChainCode, PubkeyAddressApp, AsExtendedKey, LedgerApp};

const COMMAND_GET_ADDRESS: u8 = 0x40;
const COMMAND_COIN_VERSION: u8 = 0x16;
#[allow(dead_code)]
const COMMAND_GET_UNTRUSTED_INPUT: u8 = 0x42;
const COMMAND_UNTRUSTED_HASH_TX: u8 = 0x44;
const COMMAND_UNTRUSTED_HASH_SIGN: u8 = 0x48;
const COMMAND_HASH_INPUT_FINALIZE_FULL: u8 = 0x4A;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum AddressType {
    ///  legacy address
    Legacy = 0,
    /// P2SH-P2WPKH address
    SegwitCompat = 1,
    // Bech32 encoded P2WPKH address
    Bench32 = 2
}

pub struct BitcoinApp<'a> {
    ledger: &'a LedgerKey
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressResponse {
    pub pubkey: PublicKey,
    pub address: Address,
    pub chaincode: ChainCode
}

impl AsPubkey for AddressResponse {
    fn as_pubkey(&self) -> &bitcoin::secp256k1::PublicKey {
        &self.pubkey.inner
    }
}

impl AsChainCode for AddressResponse {
    fn as_chaincode(&self) -> &ChainCode {
        &self.chaincode
    }
}

impl AsExtendedKey for AddressResponse {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GetAddressOpts {
    pub address_type: AddressType,
    pub confirmation: bool,
    pub verify_string: bool,
    pub network: Network,
}

impl Default for GetAddressOpts {
    fn default() -> Self {
        GetAddressOpts {
            address_type: AddressType::Bench32,
            confirmation: false,
            verify_string: true,
            network: Network::Bitcoin
        }
    }
}

impl GetAddressOpts {
    pub fn confirm() -> GetAddressOpts {
        GetAddressOpts {
            confirmation: true,
            ..GetAddressOpts::default()
        }
    }

    pub fn compat_address() -> GetAddressOpts {
        GetAddressOpts {
            address_type: AddressType::SegwitCompat,
            ..GetAddressOpts::default()
        }
    }
}

pub fn hash160(value: &[u8]) -> Vec<u8> {
    let mut hash256 = Sha256::new();
    hash256.update(value);
    let mut hash160 = Ripemd160::new();
    hash160.update(hash256.finalize());
    hash160.finalize().to_vec()
}

impl TryFrom<(Vec<u8>, GetAddressOpts)> for AddressResponse {
    type Error = HWKeyError;

    fn try_from(full: (Vec<u8>, GetAddressOpts)) -> Result<Self, Self::Error> {
        let value = full.0;
        let opts = full.1;
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
        let pubkey_comp = PublicKey::new(as_compact(&pubkey.inner)?);

        let address_len = value[pubkey_len + 1] as usize;
        let address_start = 1 + pubkey_len + 1;
        let address_end = address_start + address_len;
        if address_end > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Address cutoff. {:?} > {:?} as {:?}..{:?} for {:?}", address_end, value.len(), address_start, address_end, address_len)
            ))
        }

        let address = match opts.address_type {
            AddressType::Bench32 => Address::p2wpkh(&pubkey_comp, opts.network)
                .map_err(|_| HWKeyError::CryptoError("Invalid Pubkey".to_string()))?,
            AddressType::SegwitCompat => {
                let script = Builder::new()
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_slice(hash160(pubkey_comp.serialize().as_slice()).as_slice())
                    .into_script();
                Address::p2sh(&script, opts.network)
                    .map_err(|_| HWKeyError::CryptoError("Invalid Pubkey".to_string()))?
            },
            AddressType::Legacy => Address::p2pkh(&pubkey_comp, opts.network)
        };

        if opts.verify_string {
            let address_value = &value[address_start..address_end];
            let address_str = from_utf8(address_value).map(|a| a.to_string())
                .map_err(|e| HWKeyError::EncodingError(format!("Can't parse address: {}", e.to_string()))
                )?;
            if address.to_string() != address_str {
                return Err(HWKeyError::EncodingError(
                    format!("Address inconsistency {} != {}", address.to_string(), address_str)
                ));
            }
        }

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

#[derive(Clone)]
pub struct SignTx {
    pub network: Network,
    pub inputs: Vec<UnsignedInput>,
}

#[derive(Clone)]
pub struct UnsignedInput {
    pub index: usize,
    pub amount: u64,
    pub hd_path: StandardHDPath
}

#[derive(Clone)]
struct InputDetails {
    prev_tx: TxIn,
    amount: u64,
    from_address: AddressResponse,
    redeem: Script,
    hd_path: StandardHDPath
}

impl BitcoinApp<'_> {

    pub fn new(ledger: &LedgerKey) -> BitcoinApp {
        BitcoinApp { ledger }
    }

    /// Get address
    ///
    /// # Arguments:
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(&self, hd_path: &dyn HDPath, opts: GetAddressOpts) -> Result<AddressResponse, HWKeyError> {
        let mut handle = self.ledger.open()?;
        BitcoinApp::get_address_internal(&mut handle, hd_path, opts)
    }

    fn get_address_internal(device: &mut dyn LedgerConnection, hd_path: &dyn HDPath, opts: GetAddressOpts) -> Result<AddressResponse, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_GET_ADDRESS)
            .with_data(hd_path.to_bytes().as_slice())
            .with_p1(if opts.confirmation {1} else {0})
            .with_p2(opts.address_type as u8)
            .build();
        sendrecv(device, &apdu)
            .and_then(|res| AddressResponse::try_from((res, opts)))
    }

    fn witness_redeem(pubkey: &PublicKey, network: Network) -> Script {
        let address = Address::p2wpkh(&PublicKey::from_slice(&pubkey.inner.serialize()).unwrap(), network).unwrap();
        let base = address.script_pubkey();

        Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&base[2..])
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Supports only Trusted Segwit tx.
    /// Trusted Segwit is supported only after 1.4 of the Ledger Firmware
    pub fn sign_tx(&self, tx: &mut Transaction, config: &SignTx) -> Result<Vec<Vec<u8>>, HWKeyError> {
        let mut device = self.ledger.open()?;
        // Protocol:
        // 1. The transaction shall be processed first with all inputs having a null script length
        //    (to be done twice if the dongle has been powercycled to retrieve the authorization code)
        // 2. Then each input to sign shall be processed as part of a pseudo transaction with a single
        //    input and no outputs.

        let mut inputs: Vec<InputDetails> = Vec::with_capacity(tx.input.len());

        for ui in config.inputs.iter() {
            let address = BitcoinApp::get_address_internal(&mut device, &ui.hd_path, GetAddressOpts {
                network: config.network,
                ..GetAddressOpts::default()
            })?;

            inputs.push(InputDetails {
                prev_tx: tx.input[ui.index].clone(),
                amount: ui.amount,
                from_address: address.clone(),
                hd_path: ui.hd_path.clone(),
                redeem: BitcoinApp::witness_redeem(&address.pubkey, config.network)
            });
        }

        self.start_untrusted_hash_tx(&mut device, true, &inputs, &tx, false)?;

        // finalize to get hash
        self.finalize_outputs(&mut device, &tx)?;

        // make actual signatures
        let mut signatures = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let ic = input.clone();
            self.start_untrusted_hash_tx(&mut device, false,&vec![ic], &tx, true)?;
            let mut signature = self.untrusted_hash_sign(&mut device, input, tx.lock_time.to_u32())?;
            // Signed hash, as ASN-1 encoded R & S components. Mask first byte with 0xFE
            signature[0] = signature[0] & 0xfe;
            tx.input[i].witness = Witness::from_vec(vec![
                signature.clone(), input.from_address.pubkey.serialize().to_vec()
            ]);
            signatures.push(signature);
        }

        Ok(signatures)
    }

    // see https://github.com/LedgerHQ/app-bitcoin/blob/master/doc/btc.asc#untrusted-hash-transaction-input-start
    fn start_untrusted_hash_tx(&self, device: &mut dyn LedgerConnection, is_new_tx: bool, inputs: &Vec<InputDetails>, tx: &Transaction, second_pass: bool) -> Result<(), HWKeyError> {
        let mut data: Vec<u8> = Vec::new();
        // needs version
        data.write_u32::<LittleEndian>(tx.version as u32)
            .map_err(|_| HWKeyError::EncodingError("Failed to encode version".to_string()))?;
        data.extend_from_slice(serialize(&VarInt(inputs.len() as u64)).as_slice());
        for ti in inputs.iter() {
            // 0x02 if the input is passed as a Segregated Witness Input
            data.push(0x02);
            // original 36 bytes prevout
            data.extend_from_slice(serialize(&ti.prev_tx.previous_output).as_slice());
            // and the original 8 bytes little endian amount associated to this input
            data.write_u64::<LittleEndian>(ti.amount)
                .map_err(|_| HWKeyError::EncodingError("Failed to encode amount".to_string()))?;

            // The transaction shall be processed first with all inputs having a null script length
            // Then each input to sign shall be processed as part of a pseudo transaction with a single input and no outputs.
            // i.e. include scripts only on second pass
            if second_pass {
                // must be witness redeem
                // serialize() encodes size
                data.extend_from_slice(serialize(&ti.redeem).as_slice());
            } else {
                // provide only 0 size
                data.extend_from_slice(serialize(&VarInt(0u64)).as_slice());
            };
            // sequence
            data.extend_from_slice(serialize(&ti.prev_tx.sequence).as_slice());
        }


        let outputs_count: u64 = if second_pass {
            // no outputs on second pass
            0
        } else {
            tx.output.len() as u64
        };
        data.extend_from_slice(serialize(&VarInt(outputs_count)).as_slice());


        let data = data.chunks(CHUNK_SIZE - 28);
        for (i, chunk) in data.enumerate() {
            let first = i == 0;
            // 00 : first transaction data block
            // 80 : subsequent transaction data block
            let p1 = if first {
                0x00
            } else {
                0x80
            };
            // for the first block only:
            // 00 : start signing a new transaction
            // 02 : start signing a new transaction containing Segregated Witness Inputs
            // 80 : continue signing another input of the current transaction
            let p2 = if first {
                if is_new_tx {
                    0x02
                } else {
                    0x80
                }
            } else {
                0x00
            };
            let apdu = ApduBuilder::new(COMMAND_UNTRUSTED_HASH_TX)
                .with_p1(p1)
                .with_p2(p2)
                .with_data(chunk)
                .build();
            sendrecv(device, &apdu)?;
        }
        Ok(())
    }

    fn untrusted_hash_sign(&self, device: &mut dyn LedgerConnection, input: &InputDetails, locktime: u32) -> Result<Vec<u8>, HWKeyError> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(input.hd_path.to_bytes().as_slice());
        data.push(0x00); // RFU (0x00)
        data.write_u32::<LittleEndian>(locktime) //locktime
            .map_err(|_| HWKeyError::EncodingError("Failed to encode locktime".to_string()))?;
        data.push(EcdsaSighashType::All as u8); //SigHashType
        let apdu = ApduBuilder::new(COMMAND_UNTRUSTED_HASH_SIGN)
            .with_p1(0x00)
            .with_p2(0x00)
            .with_data(data.as_slice())
            .build();
        sendrecv(device, &apdu)
    }

    fn finalize_outputs(&self, device: &mut dyn LedgerConnection, tx: &Transaction) -> Result<(), HWKeyError> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(serialize(&VarInt(tx.output.len() as u64)).as_slice());
        for output in &tx.output {
            data.write_u64::<LittleEndian>(output.value)
                .map_err(|_| HWKeyError::EncodingError("Failed to encode amount".to_string()))?;
            let script = &output.script_pubkey;
            // serialize() encodes script size
            data.extend_from_slice(serialize(script).as_slice());
        }

        let data = data.chunks(CHUNK_SIZE - 28);
        let data_len = data.len();
        for (i, chunk) in data.enumerate() {
            let last =  i == data_len - 1;
            let apdu = ApduBuilder::new(COMMAND_HASH_INPUT_FINALIZE_FULL)
                // 00 : more input data to be sent
                // 80 : last input data block to be sent
                // FF : BIP 32 path specified for the change address
                .with_p1(if !last {0x00} else {0x80})
                .with_p2(0x00)
                .with_data(chunk)
                .build();
            let result = sendrecv(device, &apdu)?;
            if last {
                if result.ne(&vec![0x00u8, 0x00u8]) {
                    return Err(HWKeyError::CryptoError("Validation required".to_string()))
                }
            }
        }
        Ok(())
    }

    fn get_version(&self) -> Option<AppVersion> {
        let apdu = ApduBuilder::new(COMMAND_COIN_VERSION)
            .build();
        let device = self.ledger.open();
        if device.is_err() {
            return None
        }
        let mut device = device.unwrap();
        let resp = sendrecv(&mut device, &apdu);
        if resp.is_err() {
            return None
        }
        AppVersion::try_from(resp.unwrap()).ok()
    }
}

impl PubkeyAddressApp for BitcoinApp<'_> {
    fn get_extkey_at(&self, hd_path: &dyn HDPath) -> Result<Box<dyn AsExtendedKey>, HWKeyError> {
        let address = self.get_address(hd_path, GetAddressOpts {
            // disable verification since it needs only pubkey, and the app may be running different blockchain with different address format
            verify_string: false,
            confirmation: false,
            ..GetAddressOpts::default()
        })?;
        Ok(Box::new(address))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BitcoinApps {
    Mainnet,
    Testnet
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AppVersion {
    p2pkh: [u8; 2],
    p2sh: [u8; 2],
    family: u8,
    name: String,
    ticker: String
}

impl TryFrom<Vec<u8>> for AppVersion {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut expected_len = 2 + 2 + 1 + 1;
        if value.len() < expected_len {
            return Err(())
        }
        let p2pkh: [u8; 2] = [value[0], value[1]];
        let p2sh: [u8; 2] = [value[2], value[3]];
        let family = value[4];
        let name_len = value[5] as usize;
        expected_len = expected_len + name_len;
        if value.len() < expected_len {
            return Err(())
        }
        let name = String::from_utf8(value[6..6+name_len].to_vec()).map_err(|_| ())?;
        let ticker_len = value[6 + name_len] as usize;
        let ticker_start = 6 + name_len + 1;
        expected_len = expected_len + ticker_len;
        if value.len() < expected_len {
            return Err(())
        }
        let ticker = String::from_utf8(value[ticker_start..ticker_start+ticker_len].to_vec()).map_err(|_| ())?;
        Ok(AppVersion {
            p2pkh, p2sh,
            family,
            name, ticker
        })
    }
}

impl LedgerApp for BitcoinApp<'_> {
    type Category = BitcoinApps;

    fn is_open(&self) -> Option<Self::Category> {
        self.get_version().and_then(|ver| {
            if ver.family == 1 && ver.name == "Bitcoin" {
                match ver.ticker.as_str() {
                    "BTC" => Some(BitcoinApps::Mainnet),
                    "TEST" => Some(BitcoinApps::Testnet),
                    _ => None
                }
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ledger::app_bitcoin::{AddressResponse, GetAddressOpts, AppVersion};
    use std::convert::TryFrom;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::Address;
    use std::str::FromStr;

    #[test]
    fn decode_btc_app() {
        let resp = hex::decode("000000050107426974636f696e03425443").unwrap();
        let app_ver = AppVersion::try_from(resp);
        assert!(app_ver.is_ok());
        assert_eq!(
            AppVersion {
                p2pkh: [0, 0],
                p2sh: [0, 5],
                family: 1,
                name: "Bitcoin".to_string(),
                ticker: "BTC".to_string()
            },
            app_ver.unwrap()
        )
    }

    #[test]
    fn decode_btctest_app() {
        let resp = hex::decode("000000050107426974636f696e0454455354").unwrap();
        let app_ver = AppVersion::try_from(resp);
        assert!(app_ver.is_ok());
        assert_eq!(
            AppVersion {
                p2pkh: [0, 0],
                p2sh: [0, 5],
                family: 1,
                name: "Bitcoin".to_string(),
                ticker: "TEST".to_string()
            },
            app_ver.unwrap()
        )
    }

    #[test]
    fn decode_segwit_address_1() {
        let resp = hex::decode("410465fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406198798942cc6ccac5cc1933b584b23a82f66278513f38a4765e0cdf44b11d5eb2a6263317161616179796b7272783834636c676e706366717530306e6d663267336d6637663533706b336ee115bac4f8c9019b63a1dbec0edf5c22ed14bf94508ff082926964c123c0906c9000000000000000000000000000000000000000000000000000000000000000c901").unwrap();
        let parsed = AddressResponse::try_from((resp, GetAddressOpts::default()));
        assert!(parsed.is_ok(), "{:?}", parsed);
        let parsed = parsed.unwrap();
        assert_eq!(Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap(), parsed.address);
        assert_eq!(
            "0365fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406",
            hex::encode(parsed.pubkey.serialize()));
        assert_eq!(
            "e115bac4f8c9019b63a1dbec0edf5c22ed14bf94508ff082926964c123c0906c",
            hex::encode(parsed.chaincode.as_bytes())
        )
    }

    #[test]
    fn decode_segwit_address_2() {
        let resp = hex::decode("410423e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb548bac4825b5175c971a4bcae42d75ba622f130048860099a2548980e6e9c06402a6263317175746e616c63776a6561397a6633387667637a6b6e6377387376646339677a79736c6176776e40b2f931e05f7d88850de2ca6f3a5cb68a95740139944d8e5fb91f7b6e23772090000000000000000000000000000000000000000000000000000000000000005f7d").unwrap();
        let parsed = AddressResponse::try_from((resp, GetAddressOpts::default()));
        assert!(parsed.is_ok(), "{:?}", parsed);
        let parsed = parsed.unwrap();
        assert_eq!(Address::from_str("bc1qutnalcwjea9zf38vgczkncw8svdc9gzyslavwn").unwrap(), parsed.address);
        assert_eq!(
            "0223e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb5",
            hex::encode(parsed.pubkey.serialize()));
        assert_eq!(
            "40b2f931e05f7d88850de2ca6f3a5cb68a95740139944d8e5fb91f7b6e237720",
            hex::encode(parsed.chaincode.as_bytes())
        )
    }

    #[test]
    fn decode_segwit_address_3() {
        let resp = hex::decode("4104cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323833595ea361631ffeef009b8fa760073a7943a904e04b5dca373fdfd91b1d8342a626331717472346d37776d33336334777a79776833746774706b6b706430776e64326c6d79797166396d8ea6ceaac3341fd23f07c23702ab4303683cce2ddb9d8a4bdb080d4c27b53cae9000000000000000000000000000000000000000000000000000000000000000341f").unwrap();
        let parsed = AddressResponse::try_from((resp, GetAddressOpts::default()));
        assert!(parsed.is_ok(), "{:?}", parsed);
        let parsed = parsed.unwrap();
        assert_eq!(Address::from_str("bc1qtr4m7wm33c4wzywh3tgtpkkpd0wnd2lmyyqf9m").unwrap(), parsed.address);
        assert_eq!(
            "02cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323",
            hex::encode(parsed.pubkey.serialize()));
        assert_eq!(
            "8ea6ceaac3341fd23f07c23702ab4303683cce2ddb9d8a4bdb080d4c27b53cae",
            hex::encode(parsed.chaincode.as_bytes())
        )
    }

    #[test]
    fn decode_compat_address_1() {
        let resp = hex::decode("41047311bac2b7908931e73f5b8d02ca9cf8ff294bfad6d2e1e5bba707757d97be3591b954c37b9db706700667d9c15ec31d11053bcc644102fee05f2331c4f28b82223336725948586a72517035754a56665a666457355933467671474446445668746d73dae818a01fbfce0d8bf2deaae7d462a6a79a3be90ec011a79c65ec7251ffab2c90000000000000000000000000000000000000000000000000000000000000000000000000000000d462").unwrap();
        let parsed = AddressResponse::try_from((resp, GetAddressOpts::compat_address()));
        assert!(parsed.is_ok(), "{:?}", parsed);
        let parsed = parsed.unwrap();
        assert_eq!(Address::from_str("36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms").unwrap(), parsed.address);
        assert_eq!(
            "027311bac2b7908931e73f5b8d02ca9cf8ff294bfad6d2e1e5bba707757d97be35",
            hex::encode(parsed.pubkey.serialize()));
        assert_eq!(
            "dae818a01fbfce0d8bf2deaae7d462a6a79a3be90ec011a79c65ec7251ffab2c",
            hex::encode(parsed.chaincode.as_bytes())
        )
    }
}