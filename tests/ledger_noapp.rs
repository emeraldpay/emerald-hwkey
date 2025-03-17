#![allow(unused_imports)]
#![allow(dead_code)]
#![cfg(all(integration_test, test_noapp))]

use std::thread;
use std::time::Duration;
use log::Level;
use emerald_hwkey::ledger::app::ethereum::EthereumApps;
use emerald_hwkey::ledger::app::{BitcoinApp, EthereumApp, LedgerApp};
use emerald_hwkey::ledger::app::bitcoin::BitcoinApps;
use emerald_hwkey::ledger::connect::direct::LedgerHidKey;
use emerald_hwkey::ledger::connect::LedgerKey;

mod common;

#[test]
pub fn reads_ledger_version() {
    common::init();

    let mut manager = common::create_instance();
    manager.connect().expect("Not connected");
    let ledger = manager.get_ledger_version();
    assert!(ledger.is_ok());
    println!("Ledger: {:?}", ledger)
}

#[test]
pub fn is_ethereum_closed() {
    common::init();

    let mut manager = common::create_instance();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(EthereumApps::Ethereum), open);
}

#[test]
pub fn is_ethereum_classic_closed() {
    common::init();

    let mut manager = common::create_instance();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(EthereumApps::EthereumClassic), open);
}

#[test]
pub fn is_bitcoin_closed() {
    common::init();

    let mut manager = common::create_instance();
    manager.connect().expect("Not connected");
    let app = manager.access::<BitcoinApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(BitcoinApps::Mainnet), open);
}