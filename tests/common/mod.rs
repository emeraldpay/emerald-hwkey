use std::sync::OnceLock;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use emerald_hwkey::ledger::connect::{LedgerKeyShared, LedgerHidKey};

#[cfg(feature = "speculos")]
pub mod speculos_container;

static LOGGER: OnceLock<()> = OnceLock::new();

pub fn init() {
    LOGGER.get_or_init(|| {
        SimpleLogger::new()
            .with_level(LevelFilter::Info)
            .with_module_level("emerald_hwkey", LevelFilter::Trace)
            .init().unwrap();
    });
    log::debug!("-------------------------------------------------------")
}

#[cfg(test_hid)]
pub fn create_instance() -> LedgerHidKey {
    LedgerHidKey::new().unwrap()
}

#[cfg(not(test_hid))]
pub fn create_instance() -> LedgerKeyShared<LedgerHidKey> {
    LedgerKeyShared::<LedgerHidKey>::instance().unwrap()
}