extern crate emerald_hwkey;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

use std::{env, fs, fmt};
use hdpath::StandardHDPath;
use hex;
use log::{Level, LevelFilter};
use simple_logger::init_with_level;
use std::convert::TryFrom;
use emerald_hwkey::ledger::manager::{LedgerKey};
use std::str::FromStr;
use std::fmt::{Display, Formatter};

const ETC_DERIVATION_PATH: [u8; 21] = [
    5, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0x02, 0x73, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0,
]; // 44'/60'/160720'/0/0

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

struct HexAddress(String);

impl FromStr for HexAddress {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HexAddress(format!("0x{:}", s)))
    }
}

impl Display for HexAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn is_ledger_enabled() -> bool {
    match env::var("EMRLD_HWKEY_TEST_LEDGER") {
        Ok(v) => v == "true",
        Err(_) => false,
    }
}

/// Config:
/// * ADDR0 - address on 44'/60'/160720'/0'/0
/// * SIGN1 - hex of a signed transaction, 1 ETH to 78296F1058dD49C5D6500855F59094F0a2876397, nonce 0, gas_price 21 gwei, gas 21000
fn get_ledger_conf(name: &str) -> String {
    let mut path = String::new();
    path.push_str("EMRLD_HWKEY_TEST_LEDGER_");
    path.push_str(name);
    match env::var(path) {
        Ok(v) => v,
        Err(_) => "NOT_SET".to_string(),
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
pub fn should_get_address_with_ledger() {
    simple_logger::init_with_level(Level::Trace).unwrap();
    if !is_ledger_enabled() {
        warn!("Ledger test is disabled");
        return;
    }
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");

    assert!(!manager.devices().is_empty());

    let fd = &manager.devices()[0].1;

    let addresses = read_test_addresses();
    for address in addresses {
        let hdpath = StandardHDPath::try_from(address.hdpath.as_str()).expect("Invalid HDPath");
        let act = manager.get_address::<HexAddress>(fd, hdpath.to_bytes()).unwrap();
        assert_eq!(act.to_string(), address.address);
    }
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

    println!("Test: {:}", exp.id);
    let from = exp.from.as_ref().unwrap();
    let from = StandardHDPath::try_from(from.as_str()).expect("invalid from");

    let rlp = hex::decode(&exp.unsigned).unwrap();
    let fd = &manager.devices()[0].1;
    let sign = manager
        .sign_transaction(&fd, &rlp, from.to_bytes())
        .unwrap().to_vec();

    assert_eq!(exp.signature, hex::encode(sign));
}