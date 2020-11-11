/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! # Module to work with `Ledger hardware Wallets`
//!
use crate::{
    ledger::{
        comm::ping,
    },
    errors::HWKeyError,
};
use hidapi::{HidApi, HidDevice, DeviceInfo};
use std::{
    thread,
    time,
    sync::{Arc, Mutex}
};
use std::ops::Deref;

pub const CHUNK_SIZE: usize = 255;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_S_PID_1: u16 = 0x0001; // for Nano S model with Bitcoin App
const LEDGER_S_PID_2: u16 = 0x1011; // for Nano S model without any app
const LEDGER_S_PID_3: u16 = 0x1015; // for Nano S model with Ethereum or Ethereum Classic App

const LEDGER_X_PID_1: u16 = 0x4011; // for Nano X model (official)
const LEDGER_X_PID_2: u16 = 0x0004; // for Nano X model (in the wild)

/// Type used for device listing,
/// String corresponds to file descriptor of the device
pub type DevicesList = Vec<(String, String)>;

///
#[derive(Debug)]
struct Device {
    ///
    fd: String,
    ///
    address: String,
    ///
    hid_info: DeviceInfo,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.fd == other.fd
    }
}

impl From<&DeviceInfo> for Device {
    fn from(hid_info: &DeviceInfo) -> Self {
        let info = hid_info.clone();
        Device {
            fd: info.path().to_string_lossy().to_string(),
            address: "".to_string(),
            hid_info: info,
        }
    }
}

/// `Wallet Manager` to handle all interaction with HD wallet
pub struct LedgerKey {
    /// HID point used for communication
    hid: Arc<Mutex<HidApi>>,
    /// List of available wallets
    device: Option<Device>,
}

lazy_static! {
    // Keep a copy of the HidApi. Creating a new one is expensive, and if on existing was not closed, it
    // fails to create a new instance for a new use.
    static ref SHARED_HID: Option<Arc<Mutex<HidApi>>> = HidApi::new()
        .ok()
        .map(|h| Arc::new(Mutex::new(h)));
}

impl LedgerKey {
    /// Create new `Ledger Key Manager`
    pub fn new() -> Result<LedgerKey, HWKeyError> {
        let hid = SHARED_HID.as_ref()
            .ok_or(HWKeyError::CommError("HID API is not available".to_string()))?
            .clone();
        Ok(Self {
            hid,
            device: None,
        })
    }

    /// Create new `Ledger Key Manager` and try to connect to actual ledger. Return error otherwise.
    pub fn new_connected() -> Result<LedgerKey, HWKeyError> {
        let mut instance = LedgerKey::new()?;
        instance.connect()?;
        Ok(instance)
    }

    /// List all available devices
    pub fn devices(&self) -> DevicesList {
        self.device
            .iter()
            .map(|d| (d.address.clone(), d.fd.clone()))
            .collect()
    }

    pub fn have_device(&self) -> bool {
        self.device.is_some()
    }

    /// Update device list
    pub fn connect(&mut self) -> Result<(), HWKeyError> {
        let mut hid = self.hid.deref().lock().unwrap();
        hid.refresh_devices()
            .map_err(|_| HWKeyError::CommError("Failed to refresh".to_string()))?;

        let current = hid.device_list().find(|hid_info| {
            debug!("device {:?}", hid_info);
            hid_info.vendor_id() == LEDGER_VID
                && (hid_info.product_id() == LEDGER_S_PID_1
                || hid_info.product_id() == LEDGER_S_PID_2
                || hid_info.product_id() == LEDGER_S_PID_3
                || hid_info.product_id() == LEDGER_X_PID_1
                || hid_info.product_id() == LEDGER_X_PID_2)
        });

        if current.is_none() {
            debug!("No device connected");
            self.device = None;
            return Err(HWKeyError::Unavailable);
        }

        let hid_info = current.unwrap();
        let d = Device::from(hid_info);
        self.device = Some(d);

        Ok(())
    }

    pub fn open(&self) -> Result<HidDevice, HWKeyError> {
        if self.device.is_none() {
            return Err(HWKeyError::Unavailable);
        }
        let target = self.device.as_ref().unwrap();
        // up to 10 tries, starting from 50ms increasing by 25ms, in total 19250ms max
        let mut retry_delay = 50;
        for _ in 0..11 {
            //
            //serial number is always 0001
            if let Ok(h) = self
                .hid.lock().unwrap()
                .open(target.hid_info.vendor_id(), target.hid_info.product_id())
            {
                match ping(&h) {
                    Ok(v) => {
                        if v {
                            return Ok(h);
                        }
                    }
                    Err(_) => {}
                }
            }
            thread::sleep(time::Duration::from_millis(retry_delay));
            retry_delay += 25;
        }

        // used by another application
        Err(HWKeyError::CommError(format!(
            "Can't open device: {:?}",
            target.hid_info
        )))
    }
}