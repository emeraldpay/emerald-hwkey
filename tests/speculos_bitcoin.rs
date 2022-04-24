#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use hdpath::StandardHDPath;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use emerald_hwkey::ledger::manager::LedgerKey;
use emerald_hwkey::ledger::app_bitcoin::{AddressResponse, GetAddressOpts, AppVersion, BitcoinApp, BitcoinApps, UnsignedInput, SignTx};
use std::convert::TryFrom;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid, TxIn, TxOut};
use std::str::FromStr;
use std::sync::{Arc, mpsc, Mutex};
use std::thread;
use std::thread::spawn;
use std::time::Duration;
use emerald_hwkey::ledger::traits::LedgerApp;
#[cfg(feature = "speculos")]
use emerald_hwkey::ledger::speculos::{Speculos, Button};

lazy_static! {
    static ref LOG_CONF: () = SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
}

#[test]
#[cfg(all(bitcoin, integration_test, feature = "speculos"))]
pub fn is_bitcoin_open() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(&manager);
    let open = app.is_open();
    assert_eq!(Some(BitcoinApps::Mainnet), open);
}

#[test]
#[cfg(all(bitcoin, integration_test, feature = "speculos"))]
pub fn get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(&manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qqtl9jlrwcr3fsfcjj2du7pu6fcgaxl5dsw2vyg").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "031869567d5e88d988ff7baf6827983f89530ddd79dbaeadaa6ec538a8f03dea8b");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qfw40lw34279da7c5vwpe0n9w2pxuqrw2wsyfyh").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0239daaa23f25002a17f40adac8df385dd5701e5df708c78ec0b7c28a2bfc9412f");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qxqfdqh8nz2ledrmnemhwlwcly05w0gzfutqsah").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "02e1c5b650702d3099b397b423935c9442b30c78235c4fa888a1db244b2bc716a5");
}

#[test]
#[cfg(all(bitcoin, integration_test, feature = "speculos"))]
pub fn get_bitcoin_address_confirmed() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");

    let speculos = Speculos::create_env();

    // let mut act: Arc<Mutex<Option<AddressResponse>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::channel();
    spawn(move || {
        let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
        let app = BitcoinApp::new(&manager);
        let act = app.get_address(&hdpath, GetAddressOpts::confirm()).expect("Failed to get address");
        tx.send(act).unwrap();
    });
    thread::sleep(Duration::from_millis(100));
    // address takes 3 pages to show
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    // on the last page we have a confirmation button
    speculos.press(Button::Both).unwrap();
    let act = rx.recv().unwrap();

    assert_eq!(act.address, Address::from_str("bc1qqtl9jlrwcr3fsfcjj2du7pu6fcgaxl5dsw2vyg").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "031869567d5e88d988ff7baf6827983f89530ddd79dbaeadaa6ec538a8f03dea8b");
}
