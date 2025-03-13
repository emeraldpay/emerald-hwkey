use std::sync::{Arc, Mutex};
use crate::errors::HWKeyError;
use crate::ledger::apdu::APDU;
use crate::ledger::comm::{sendrecv_timeout, LedgerTransport};
use direct::AppDetails;
use crate::ledger::app::LedgerApp;

pub mod direct;
pub mod shared;
#[cfg(feature = "speculos")]
mod speculos;
#[cfg(feature = "speculos")]
pub mod speculos_api;

pub use {
    direct::LedgerHidKey,
    shared::LedgerKeyShared,
};

#[cfg(feature = "speculos")]
pub use {
    speculos::LedgerSpeculosKey,
};

pub trait LedgerKey {

    type Transport: LedgerTransport;

    fn create() -> Result<Self, HWKeyError> where Self: Sized;

    /// Update device list
    fn connect(&mut self) -> Result<(), HWKeyError>;

    ///
    /// Get information about the currently running app on Ledger
    /// If no app is running it produces the same info from the OS.
    fn get_app_details(&self) -> Result<AppDetails, HWKeyError> {
        let apdu = APDU {
            cla: 0xb0,
            ins: 0x01,
            ..APDU::default()
        };
        let device = self.open_exclusive()?;
        let mut conn = device.lock()
            .map_err(|_| HWKeyError::Unavailable)?;
        match sendrecv_timeout(&mut *conn, &apdu, 100) {
            Err(e) => match e {
                HWKeyError::EmptyResponse => Ok(AppDetails::default()),
                _ => Err(e),
            }
            Ok(resp) => AppDetails::try_from(resp)
        }
    }

    fn open_exclusive(&self) -> Result<Arc<Mutex<Self::Transport>>, HWKeyError>;

    ///
    /// Access a particular type of app. Please ensure that the app is actually launched with [get_app_details] before accessing it.
    fn access<A>(&self) -> Result<A, HWKeyError> where A: LedgerApp, Self::Transport: 'static {
        let conn = self.open_exclusive()?;
        Ok(A::new(conn))
    }
}