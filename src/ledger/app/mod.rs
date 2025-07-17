extern crate bitcoin as bitcoin_lib;

use std::sync::{Arc, Mutex};
use bitcoin_lib::{
    NetworkKind,
    bip32::{ChainCode, ChildNumber, Xpub, Fingerprint},
    secp256k1::PublicKey
};
use hdpath::{CustomHDPath, HDPath, PathValue};
use crate::{
    errors::HWKeyError,
    ledger::{
        comm::LedgerTransport
    }
};

// #[path="ethereum.rs"]
pub mod ethereum;
// #[path="bitcoin.rs"]
pub mod bitcoin;

pub use {
    ethereum::EthereumApp,
    bitcoin::BitcoinApp,
};

pub trait LedgerApp {
    type Networks;

    ///
    /// Try to access a particular App on the Ledger.
    /// Note that it's not guarantied that the app is actually launched, and it's even dangerous to try to use
    /// commands specific for an app if it's not launched. Because same command may lead to different results with different apps
    /// and sometimes Ledger may stuck (ex. waiting for some action that would never produced).
    fn new(manager: Arc<Mutex<dyn LedgerTransport>>) -> Self;

    ///
    /// Get actual blockchain version available with the app.
    /// An app may have a general type (ex. Bitcoin), but may provide access to different networks (Bitcoin Mainnet or Bitcoin Testnet)
    fn is_open(&self) -> Option<Self::Networks>;
}

pub trait AsPubkey {
    fn as_pubkey(&self) -> &PublicKey;
}

pub trait AsChainCode {
    fn as_chaincode(&self) -> &ChainCode;
}

pub trait AsExtendedKey: AsPubkey + AsChainCode {}

pub trait PubkeyAddressApp {

    ///
    /// Get key at hd path
    fn get_extkey_at(&self, hd_path: &dyn HDPath) -> Result<Box<dyn AsExtendedKey>, HWKeyError>;

    /// Get XPub at the specified hd path (usually it's a path to an account)
    /// `network` is applicable to _Bitcoin_ blockchain, and it only affects how XPub is serialized.
    /// For non-bitcoin blockchains `Bitcoin::Mainnet` may be used.
    fn get_xpub(&self, hd_path: &dyn HDPath, network: NetworkKind) -> Result<Xpub, HWKeyError> {
        let pubkey = self.get_extkey_at(hd_path)?;
        let index = hd_path.get(hd_path.len() - 1).unwrap();

        let parent_fingerprint = if hd_path.len() > 0 {
            let mut parent_hd_path = Vec::with_capacity(hd_path.len() as usize - 1);
            for i in 0..hd_path.len()-1 {
                parent_hd_path.push(hd_path.get(i).unwrap());
            }
            let parent_hd_path = CustomHDPath::try_new(parent_hd_path)
                .expect("No parent HD Path");
            let parent_key = self.get_extkey_at(&parent_hd_path)?;
            let fp = bitcoin::hash160(&parent_key.as_pubkey().serialize());
            Fingerprint::try_from(&fp[0..4]).unwrap()
        } else {
            Fingerprint::default()
        };

        let result = Xpub {
            network,
            depth: hd_path.len(),
            public_key: *pubkey.as_pubkey(),
            chain_code: *pubkey.as_chaincode(),
            child_number: match index {
                PathValue::Hardened(i) => ChildNumber::from_hardened_idx(i).unwrap(),
                PathValue::Normal(i) => ChildNumber::from_normal_idx(i).unwrap(),
            },
            parent_fingerprint,
        };
        Ok(result)
    }
}