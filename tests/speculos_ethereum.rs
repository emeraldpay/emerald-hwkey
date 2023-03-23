#![allow(unused_imports)]
#![allow(dead_code)]

use std::convert::TryFrom;
use std::sync::mpsc;
use std::thread::spawn;
use hdpath::StandardHDPath;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use emerald_hwkey::ledger::app_ethereum::EthereumApp;
use emerald_hwkey::ledger::manager::LedgerKey;
#[cfg(feature = "speculos")]
use emerald_hwkey::ledger::speculos::{Button, Speculos};

#[test]
#[cfg(all(ethereum, integration_test, feature = "speculos"))]
pub fn get_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D");
    assert_eq!(hex::encode(act.pubkey.serialize()), "02ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547");

    let hdpath = StandardHDPath::try_from("m/44'/60'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0x204e73c731f06cF38C2486A768c579aC3fa412ba");
    assert_eq!(hex::encode(act.pubkey.serialize()), "0378cd117abe05a0c33e79cac3b2014ac30a65f959abf72b55f5bc8265bac4d0f0");
}

#[test]
#[cfg(all(ethereum, integration_test, feature = "speculos"))]
pub fn sign_tx() {
    // send 1 ETH to 0x78296F1058dD49C5D6500855F59094F0a2876397 paying 20gwei for gas and nonce 3

    let (channel_tx, channel_rx) = mpsc::channel();
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let speculos = Speculos::create_env();

    spawn(move || {
        let app = manager.access::<EthereumApp>().unwrap();
        let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/1").expect("Invalid HDPath");
        let tx: Vec<u8> = hex::decode("ec038504a817c8008252089478296f1058dd49c5d6500855f59094f0a2876397880de0b6b3a764000080018080").unwrap();
        let signed = app.sign_transaction(tx.as_slice(), &hdpath);
        channel_tx.send(signed);
    });

    speculos.accept_on_screen().unwrap();

    let signed = channel_rx.recv().unwrap();

    assert!(signed.is_ok());
    let signature = signed.unwrap();

    assert_eq!("2613ad946bd71c273f54efd87f5852c4ae275a80b644f921879fc4b7ee4d3e574829c34a51194ff20102aa4e93e698d01bf49ca4672005e73fb012792bc9dd5a27", hex::encode(signature));
}

#[test]
#[cfg(all(ethereum, integration_test, feature = "speculos"))]
pub fn sign_tx_eip1559() {
    // send 1 ETH to 0x78296F1058dD49C5D6500855F59094F0a2876397 paying 20gwei max + 1gwei priority for gas and nonce 3

    let (channel_tx, channel_rx) = mpsc::channel();
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let speculos = Speculos::create_env();

    spawn(move || {
        let app = manager.access::<EthereumApp>().unwrap();
        let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/1").expect("Invalid HDPath");
        let tx: Vec<u8> = hex::decode("02f00103843b9aca008504a817c8008252089478296f1058dd49c5d6500855f59094f0a2876397880de0b6b3a764000080c0").unwrap();
        let signed = app.sign_transaction(tx.as_slice(), &hdpath);
        channel_tx.send(signed);
    });

    speculos.accept_on_screen().unwrap();

    let signed = channel_rx.recv().unwrap();

    assert!(signed.is_ok());
    let signature = signed.unwrap();

    assert_eq!("008c0a3d0f9410ab3a77cc4d2e824a9b689e39de4d7deb6d5006046dc2ba42f0907a15d04bad09f1b29689fd3e09cbe384e615296314581f16b6c6148c4c48c05b", hex::encode(signature));
}