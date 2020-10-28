use bitcoin::secp256k1::PublicKey;
use crate::errors::HWKeyError;
use hdpath::{HDPath, CustomHDPath, PathValue};
use bitcoin::util::bip32::{ExtendedPubKey, Fingerprint, ChildNumber, ChainCode};
use crate::ledger::app_bitcoin::hash160;
use bitcoin::Network;

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
    fn get_extkey_at<P: HDPath>(&self, hd_path: &P) -> Result<Box<dyn AsExtendedKey>, HWKeyError>;

    /// Get XPub at the specified hd path (usually it's a path to an account)
    /// `network` is applicable to _Bitcoin_ blockchain, and it only affects how XPub is serialized.
    /// For non-bitcoin blockchains `Bitcoin::Mainnet` may be used.
    fn get_xpub<P: HDPath>(&self, hd_path: &P, network: Network) -> Result<ExtendedPubKey, HWKeyError> {
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
            let fp = hash160(&parent_key.as_pubkey().serialize());
            Fingerprint::from(&fp[0..4])
        } else {
            Fingerprint::default()
        };

        let result = ExtendedPubKey {
            network,
            depth: hd_path.len(),
            public_key: bitcoin::PublicKey { key: pubkey.as_pubkey().clone(), compressed: true },
            chain_code: pubkey.as_chaincode().clone(),
            child_number: match index {
                PathValue::Hardened(i) => ChildNumber::from_hardened_idx(i).unwrap(),
                PathValue::Normal(i) => ChildNumber::from_normal_idx(i).unwrap(),
            },
            parent_fingerprint,
        };
        Ok(result)
    }
}

pub trait LedgerApp {
    type Category;

    fn is_open(&self) -> Option<Self::Category>;
}