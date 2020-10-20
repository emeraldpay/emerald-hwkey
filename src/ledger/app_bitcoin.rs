use crate::ledger::manager::LedgerKey;
use crate::ledger::apdu::ApduBuilder;
use crate::errors::HWKeyError;
use crate::ledger::comm::sendrecv;
use std::convert::TryFrom;
use std::str::from_utf8;

const COMMAND_GET_ADDRESS: u8 = 0x40;

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum AddressType {
    ///  legacy address
    Legacy = 0,
    /// P2SH-P2WPKH address
    SegwitCompat = 1,
    // Bech32 encoded P2WPKH address
    Bench32 = 2
}

pub struct BitcoinApp {
    ledger: LedgerKey
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddressResponse {
    pub pubkey: Vec<u8>,
    pub address: String,
    pub chaincode: Vec<u8>
}

pub struct GetAddressOpts {
    pub address_type: AddressType,
    pub confirmation: bool
}

impl Default for GetAddressOpts {
    fn default() -> Self {
        GetAddressOpts {
            address_type: AddressType::Bench32,
            confirmation: false
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

        let chaincode_len = 32 as usize;
        let chaincode_start = address_end;
        let chaincode_end = chaincode_start + chaincode_len;
        if chaincode_end > value.len() {
            return Err(HWKeyError::EncodingError(
                format!("Chaincode cutoff. {:?} > {:?}", chaincode_end, value.len())
            ))
        }
        let chaincode = (&value[chaincode_start..chaincode_end]).to_vec();

        Ok(AddressResponse {
            pubkey: pubkey.to_vec(), address, chaincode
        })
    }
}

impl BitcoinApp {

    pub fn new(ledger: LedgerKey) -> BitcoinApp {
        BitcoinApp { ledger }
    }

    /// Get address
    ///
    /// # Arguments:
    /// hd_path - HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(&self, hd_path: Vec<u8>, opts: GetAddressOpts) -> Result<AddressResponse, HWKeyError> {
        let apdu = ApduBuilder::new(COMMAND_GET_ADDRESS)
            .with_data(&hd_path)
            .with_p1(if opts.confirmation {1} else {0})
            .with_p2(opts.address_type as u8)
            .build();
        let handle = self.ledger.open()?;
        sendrecv(&handle, &apdu)
            .and_then(|res| AddressResponse::try_from(res))
    }

}

#[cfg(test)]
mod tests {
    use crate::ledger::app_bitcoin::AddressResponse;
    use std::convert::TryFrom;

    #[test]
    fn decode_segwit_address_1() {
        let resp = hex::decode("410465fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406198798942cc6ccac5cc1933b584b23a82f66278513f38a4765e0cdf44b11d5eb2a6263317161616179796b7272783834636c676e706366717530306e6d663267336d6637663533706b336ee115bac4f8c9019b63a1dbec0edf5c22ed14bf94508ff082926964c123c0906c9000000000000000000000000000000000000000000000000000000000000000c901").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n".to_string(), parsed.address);
        assert_eq!(
            "0465fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406198798942cc6ccac5cc1933b584b23a82f66278513f38a4765e0cdf44b11d5eb",
            hex::encode(parsed.pubkey));
        assert_eq!(
            "e115bac4f8c9019b63a1dbec0edf5c22ed14bf94508ff082926964c123c0906c",
            hex::encode(parsed.chaincode)
        )
    }

    #[test]
    fn decode_segwit_address_2() {
        let resp = hex::decode("410423e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb548bac4825b5175c971a4bcae42d75ba622f130048860099a2548980e6e9c06402a6263317175746e616c63776a6561397a6633387667637a6b6e6377387376646339677a79736c6176776e40b2f931e05f7d88850de2ca6f3a5cb68a95740139944d8e5fb91f7b6e23772090000000000000000000000000000000000000000000000000000000000000005f7d").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("bc1qutnalcwjea9zf38vgczkncw8svdc9gzyslavwn".to_string(), parsed.address);
        assert_eq!(
            "0423e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb548bac4825b5175c971a4bcae42d75ba622f130048860099a2548980e6e9c0640",
            hex::encode(parsed.pubkey));
        assert_eq!(
            "40b2f931e05f7d88850de2ca6f3a5cb68a95740139944d8e5fb91f7b6e237720",
            hex::encode(parsed.chaincode)
        )
    }

    #[test]
    fn decode_segwit_address_3() {
        let resp = hex::decode("4104cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323833595ea361631ffeef009b8fa760073a7943a904e04b5dca373fdfd91b1d8342a626331717472346d37776d33336334777a79776833746774706b6b706430776e64326c6d79797166396d8ea6ceaac3341fd23f07c23702ab4303683cce2ddb9d8a4bdb080d4c27b53cae9000000000000000000000000000000000000000000000000000000000000000341f").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("bc1qtr4m7wm33c4wzywh3tgtpkkpd0wnd2lmyyqf9m".to_string(), parsed.address);
        assert_eq!(
            "04cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323833595ea361631ffeef009b8fa760073a7943a904e04b5dca373fdfd91b1d834",
            hex::encode(parsed.pubkey));
        assert_eq!(
            "8ea6ceaac3341fd23f07c23702ab4303683cce2ddb9d8a4bdb080d4c27b53cae",
            hex::encode(parsed.chaincode)
        )
    }

    #[test]
    fn decode_compat_address_1() {
        let resp = hex::decode("41047311bac2b7908931e73f5b8d02ca9cf8ff294bfad6d2e1e5bba707757d97be3591b954c37b9db706700667d9c15ec31d11053bcc644102fee05f2331c4f28b82223336725948586a72517035754a56665a666457355933467671474446445668746d73dae818a01fbfce0d8bf2deaae7d462a6a79a3be90ec011a79c65ec7251ffab2c90000000000000000000000000000000000000000000000000000000000000000000000000000000d462").unwrap();
        let parsed = AddressResponse::try_from(resp);
        assert!(parsed.is_ok(), format!("{:?}", parsed));
        let parsed = parsed.unwrap();
        assert_eq!("36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms".to_string(), parsed.address);
        assert_eq!(
            "047311bac2b7908931e73f5b8d02ca9cf8ff294bfad6d2e1e5bba707757d97be3591b954c37b9db706700667d9c15ec31d11053bcc644102fee05f2331c4f28b82",
            hex::encode(parsed.pubkey));
        assert_eq!(
            "dae818a01fbfce0d8bf2deaae7d462a6a79a3be90ec011a79c65ec7251ffab2c",
            hex::encode(parsed.chaincode)
        )
    }
}