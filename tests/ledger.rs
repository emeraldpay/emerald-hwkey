extern crate emerald_hwkey;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate simple_logger;

use std::{env, fs};
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
use emerald_hwkey::ledger::app_bitcoin::{BitcoinApp, GetAddressOpts};

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

fn is_ledger_enabled() -> bool {
    match env::var("EMRLD_HWKEY_TEST_LEDGER") {
        Ok(v) => v == "true",
        Err(_) => false,
    }
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
pub fn get_ethereum_address() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = EthereumApp::new(manager);

    let addresses = read_test_addresses();
    for address in addresses {
        let hdpath = StandardHDPath::try_from(address.hdpath.as_str()).expect("Invalid HDPath");
        let act = app.get_address(hdpath.to_bytes())
            .map(hex_address).unwrap();
        assert_eq!(act.to_string(), address.address);
    }
}

#[test]
pub fn get_bitcoin_address() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, "bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n".to_string());
    assert_eq!(hex::encode(act.pubkey), "0465fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406198798942cc6ccac5cc1933b584b23a82f66278513f38a4765e0cdf44b11d5eb");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, "bc1qutnalcwjea9zf38vgczkncw8svdc9gzyslavwn".to_string());
    assert_eq!(hex::encode(act.pubkey), "0423e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb548bac4825b5175c971a4bcae42d75ba622f130048860099a2548980e6e9c0640");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, "bc1qtr4m7wm33c4wzywh3tgtpkkpd0wnd2lmyyqf9m".to_string());
    assert_eq!(hex::encode(act.pubkey), "04cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323833595ea361631ffeef009b8fa760073a7943a904e04b5dca373fdfd91b1d834");
}

#[test]
pub fn confirm_get_bitcoin_address() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::confirm()).expect("Failed to get address");
    assert_eq!(act.address, "bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n".to_string());
}

#[test]
pub fn compat_get_bitcoin_address() {
    SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/49'/3'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::compat_address()).expect("Failed to get address");
    assert_eq!(act.address, "36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms".to_string());
}

#[test]
pub fn sign_1eth_to_78296f10() {
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }

    let test_txes = read_test_txes();
    test_tx_sign(&test_txes[0]);
}

#[test]
pub fn sign_1etc_to_78296f10() {
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }

    let test_txes = read_test_txes();
    test_tx_sign(&test_txes[1]);
}

#[test]
pub fn sign_1kovan_to_78296f10() {
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }

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
        .sign_transaction(&rlp, from.to_bytes())
        .unwrap().to_vec();

    assert_eq!(exp.signature, hex::encode(sign));
}