use std::sync::{Arc, Mutex};
use crate::{
    ledger::{
        connect::{
            LedgerKey,
            speculos_api::Speculos
        }
    },
    errors::HWKeyError,
};

/// `Wallet Manager` to handle all interaction with HD wallet
pub struct LedgerSpeculosKey {
    speculos: Arc<Mutex<Speculos>>,
}

impl LedgerSpeculosKey {

    pub fn new() -> Result<Self, HWKeyError> {
        Self::create()
    }

    pub fn have_device(&self) -> bool {
        let conn = self.open_exclusive();
        if conn.is_err() {
            return false
        }
        let conn = conn.unwrap();
        let conn = conn.lock();
        if conn.is_err() {
            return false
        }
        let conn = conn.unwrap();
        conn.is_available().unwrap_or_default()
    }

}

impl LedgerKey for LedgerSpeculosKey {
    type Transport = Speculos;

    fn create() -> Result<Self, HWKeyError> {
        Ok(Self {
            speculos: Arc::new(Mutex::new(Speculos::create_env())),
        })
    }

    fn connect(&mut self) -> Result<(), HWKeyError> {
        let conn = self.open_exclusive()?;
        let conn = conn.lock();
        if conn.is_err() {
            return Err(HWKeyError::Unavailable)
        }
        let conn = conn.unwrap();

        let connected = conn.is_available()?;
        if connected {
            Ok(())
        } else {
            Err(HWKeyError::Unavailable)
        }
    }

    fn open_exclusive(&self) -> Result<Arc<Mutex<Speculos>>, HWKeyError> {
        Ok(self.speculos.clone())
    }

}