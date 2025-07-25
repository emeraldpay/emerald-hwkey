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
#[cfg(test)]
pub mod mock;

pub use {
    direct::LedgerHidKey,
    shared::LedgerKeyShared,
};

#[cfg(feature = "speculos")]
pub use {
    speculos::LedgerSpeculosKey,
};
use crate::ledger::connect::direct::LedgerDetails;

pub trait LedgerKey {

    type Transport: LedgerTransport;

    fn create() -> Result<Self, HWKeyError> where Self: Sized;

    /// Establishes connection to the Ledger device.
    /// 
    /// This method MUST be called before using any other Ledger operations.
    /// All subsequent operations (read, write, get_app_details, etc.) will fail
    /// with `HWKeyError::Unavailable` if the device is not connected.
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
        let conn = device.lock()
            .map_err(|_| HWKeyError::Unavailable)?;
        match sendrecv_timeout(&*conn, &apdu, 100) {
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

    ///
    /// Get information about the Ledger itself.
    /// It's available _only if no app_ is launched.
    fn get_ledger_version(&self) -> Result<LedgerDetails, HWKeyError> {
        let apdu = APDU {
            cla: 0xe0,
            ins: 0x01,
            ..APDU::default()
        };
        let device = self.open_exclusive()?;
        let conn = device.lock()
            .map_err(|_| HWKeyError::Unavailable)?;
        let resp = sendrecv_timeout(&*conn, &apdu, 100)?;
        LedgerDetails::try_from(resp)
    }
}