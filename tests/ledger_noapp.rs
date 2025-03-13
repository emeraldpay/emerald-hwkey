#![allow(unused_imports)]
#![allow(dead_code)]

use log::Level;
use emerald_hwkey::ledger::connect::direct::LedgerHidKey;
use emerald_hwkey::ledger::connect::LedgerKey;

#[test]
#[cfg(all(integration_test, ledger_noapp))]
pub fn reads_ledger_version() {
    simple_logger::init_with_level(Level::Trace).unwrap();
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let ledger = manager.get_ledger_version();
    assert!(ledger.is_ok());
    println!("Ledger: {:?}", ledger)
}