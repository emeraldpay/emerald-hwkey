#![allow(unused_imports)]
#![allow(dead_code)]

extern crate emerald_hwkey;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate simple_logger;
#[macro_use]
extern crate lazy_static;

use std::thread;
use std::time::Duration;
use std::fs;
use hdpath::StandardHDPath;
use hex;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::convert::TryFrom;
use emerald_hwkey::ledger::{
    app::ethereum::{AddressResponse, EthereumApp},
    connect::LedgerKey,
};
use std::str::FromStr;
use emerald_hwkey::ledger::app::LedgerApp;
use emerald_hwkey::ledger::app::ethereum::EthereumApps;
use emerald_hwkey::ledger::connect::direct::LedgerHidKey;
use emerald_hwkey::ledger::connect::LedgerKeyShared;
use crate::emerald_hwkey::ledger::app::PubkeyAddressApp;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Network;
use hdpath::AccountHDPath;

lazy_static! {
    static ref LOG_CONF: () = SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
}

#[derive(Deserialize)]
struct TestAddress {
    pub hdpath: String,
    pub address: String,
}

#[derive(Deserialize)]
struct TestTx {
    pub id: String,
    pub description: Option<String>,
    pub from: Option<String>,
    pub raw: String,
    pub unsigned: String,
    pub signature: String,
}

fn read_test_addresses() -> Vec<TestAddress> {
    let json = fs::read_to_string("./testdata/ledger/address.json")
        .expect("./testdata/ledger/address.json is not available");
    let result: Vec<TestAddress> = serde_json::from_str(json.as_str()).expect("Invalid JSON");
    result
}

fn read_test_txes() -> Vec<TestTx> {
    let json = fs::read_to_string("./testdata/ledger/tx.json")
        .expect("./testdata/ledger/tx.json is not available");
    let result: Vec<TestTx> = serde_json::from_str(json.as_str()).expect("Invalid JSON");
    result
}

#[test]
#[cfg(ledger_ethereum)]
pub fn get_ethereum_address() {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    let addresses = read_test_addresses();
    for address in addresses {
        let hdpath = StandardHDPath::try_from(address.hdpath.as_str()).expect("Invalid HDPath");
        let act = app.get_address(&hdpath, false).unwrap();
        assert_eq!(act.address, address.address);
    }
}

#[test]
#[cfg(ledger_ethereum)]
pub fn sign_1eth_to_78296f10() {
    let test_txes = read_test_txes();
    internal_tx_sign(&test_txes[0]);
}

#[test]
#[cfg(ledger_ethereum_classic)]
pub fn sign_1etc_to_78296f10() {
    let test_txes = read_test_txes();
    internal_tx_sign(&test_txes[1]);
}

#[test]
#[cfg(ledger_ethereum)]
pub fn sign_1kovan_to_78296f10() {
    let test_txes = read_test_txes();
    internal_tx_sign(&test_txes[2]);
}

#[test]
#[cfg(ledger_ethereum)]
pub fn get_xpub_0() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();

    thread::sleep(Duration::from_millis(2500));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    let hdpath = AccountHDPath::try_from("m/44'/60'/0'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    let exp = ExtendedPubKey::from_str("xpub6CPa3HQTW3vRGMbtqMyoRFmegyaA12RH7U3bwixGVK6oz68MeiLY5sxqZZUfzJkGarAduDJhgEtXmpDKHL6Ytv3a79jg1mkAkexCbQdMNnA").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_ethereum_classic)]
pub fn get_xpub_etc_1() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();

    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    let hdpath = AccountHDPath::try_from("m/44'/61'/1'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    let exp = ExtendedPubKey::from_str("xpub6C5G8hBLBcnGpELb51nXjbvtCZbrPYU8riKw2Gb7L3ML8vyr1zV9dzYKGLoS2DbJLLgLzvaqdvzbfmgppKQB9RXaF4mCXmcRkkJkriX2WDP").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_ethereum)]
pub fn is_ethereum_open() {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_eq!(Some(EthereumApps::Ethereum), open);
}

#[test]
#[cfg(all(integration_test, not(ledger_ethereum)))]
pub fn is_ethereum_closed() {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(EthereumApps::Ethereum), open);
}

#[test]
#[cfg(ledger_ethereum_classic)]
pub fn is_ethereum_classic_open() {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_eq!(Some(EthereumApps::EthereumClassic), open);
}

#[test]
#[cfg(all(integration_test, not(ledger_ethereum_classic)))]
pub fn is_ethereum_classic_closed() {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(EthereumApps::EthereumClassic), open);
}

// ------ internal

fn internal_tx_sign(exp: &TestTx) {
    thread::sleep(Duration::from_millis(2000));
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    println!("Test: {:}", exp.id);
    let from = exp.from.as_ref().unwrap();
    let from = StandardHDPath::try_from(from.as_str()).expect("invalid from");

    let rlp = hex::decode(&exp.unsigned).unwrap();
    let sign = app
        .sign_transaction(&rlp, &from)
        .unwrap().to_vec();

    assert_eq!(exp.signature, hex::encode(sign));
}