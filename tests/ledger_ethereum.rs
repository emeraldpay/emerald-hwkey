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

use std::{fs};
use hdpath::StandardHDPath;
use hex;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::convert::TryFrom;
use emerald_hwkey::{
    ledger::{
        manager::LedgerKey,
        app_ethereum::{EthereumApp, AddressResponse},
    }
};
use std::str::FromStr;

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

fn hex_address(a: AddressResponse) -> String {
    format!("0x{:}", a.address)
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
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = EthereumApp::new(manager);

    let addresses = read_test_addresses();
    for address in addresses {
        let hdpath = StandardHDPath::try_from(address.hdpath.as_str()).expect("Invalid HDPath");
        let act = app.get_address(&hdpath)
            .map(hex_address).unwrap();
        assert_eq!(act.to_string(), address.address);
    }
}

#[test]
#[cfg(ledger_ethereum)]
pub fn sign_1eth_to_78296f10() {
    let test_txes = read_test_txes();
    test_tx_sign(&test_txes[0]);
}

#[test]
#[cfg(ledger_ethereum)]
pub fn sign_1etc_to_78296f10() {
    let test_txes = read_test_txes();
    test_tx_sign(&test_txes[1]);
}

#[test]
#[cfg(ledger_ethereum)]
pub fn sign_1kovan_to_78296f10() {
    let test_txes = read_test_txes();
    test_tx_sign(&test_txes[2]);
}

fn test_tx_sign(exp: &TestTx) {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = EthereumApp::new(manager);

    println!("Test: {:}", exp.id);
    let from = exp.from.as_ref().unwrap();
    let from = StandardHDPath::try_from(from.as_str()).expect("invalid from");

    let rlp = hex::decode(&exp.unsigned).unwrap();
    let sign = app
        .sign_transaction(&rlp, &from)
        .unwrap().to_vec();

    assert_eq!(exp.signature, hex::encode(sign));
}