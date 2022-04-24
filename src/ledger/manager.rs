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


// reference:
// - https://github.com/LedgerHQ/ledger-live/blob/ff0897c2d317d06f5d439e0884dc48ad9ae7315a/android/app/src/main/res/xml/usb_device_filter.xml
//
const LEDGER_VID: u16 = 0x2c97; // 11415
const LEDGER_S_PID_1: u16 = 0x0001; // 1    - for Nano S model with Bitcoin App
const LEDGER_S_PID_2: u16 = 0x1011; // 4113 - for Nano S model without any app. also called Nano S16 in Ledger sources
const LEDGER_S_PID_3: u16 = 0x1015; // 4117 - for Nano S model with Ethereum or Ethereum Classic App

const LEDGER_X_PID_1: u16 = 0x0004; // 4     - Nano X model, official
const LEDGER_X_PID_2: u16 = 0x4011; // 16401 - Nano X model, some versions
const LEDGER_X_PID_3: u16 = 0x4015; // 16405 - Nano X model, some versions, with Ethereum App or Bitcoin App
const LEDGER_X_PID_4: u16 = 0x40;   // 64    - Nano X, new official

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
    #[cfg(not(feature = "speculos"))]
    hid: Arc<Mutex<HidApi>>,
    /// List of available wallets
    device: Option<Device>,
}

impl LedgerKey {

    /// Create new `Ledger Key Manager`
    /// Make sure you have only one instance at a time, because when it's created it locks HID API to the instance.
    #[cfg(not(feature = "speculos"))]
    pub fn new() -> Result<LedgerKey, HWKeyError> {
        let hid = HidApi::new().map_err(|_| HWKeyError::CommError("HID API is not available".to_string()))?;
        Ok(Self {
            hid: Arc::new(Mutex::new(hid)),
            device: None,
        })
    }

    #[cfg(feature = "speculos")]
    pub fn new() -> Result<LedgerKey, HWKeyError> {
        Ok(Self {
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
    #[cfg(not(feature = "speculos"))]
    pub fn connect(&mut self) -> Result<(), HWKeyError> {
        let hid_mutex = self.hid.deref();
        let mut hid = hid_mutex.lock()
            .map_err(|_| HWKeyError::CommError("HID API is locked".to_string()))?;
        hid.refresh_devices()
            .map_err(|_| HWKeyError::CommError("Failed to refresh".to_string()))?;

        let current = hid.device_list().find(|hid_info| {
            debug!("device {:?}", hid_info);
            hid_info.vendor_id() == LEDGER_VID
                && (hid_info.product_id() == LEDGER_S_PID_1
                || hid_info.product_id() == LEDGER_S_PID_2
                || hid_info.product_id() == LEDGER_S_PID_3
                || hid_info.product_id() == LEDGER_X_PID_1
                || hid_info.product_id() == LEDGER_X_PID_2
                || hid_info.product_id() == LEDGER_X_PID_3
                || hid_info.product_id() == LEDGER_X_PID_4)
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

    #[cfg(feature = "speculos")]
    pub fn connect(&mut self) -> Result<(), HWKeyError> {
        let connected = self.open()?.is_available()?;
        if connected {
            Ok(())
        } else {
            Err(HWKeyError::Unavailable)
        }
    }

    #[cfg(not(feature = "speculos"))]
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
            if let Ok(mut h) = self
                .hid.lock().unwrap()
                .open(target.hid_info.vendor_id(), target.hid_info.product_id())
            {
                match ping(&mut h) {
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
            "Device is locked by another application: {:?}",
            target.hid_info
        )))
    }

    #[cfg(feature = "speculos")]
    pub fn open(&self) -> Result<crate::ledger::speculos::Speculos, HWKeyError> {
        Ok(crate::ledger::speculos::Speculos::create_env())
    }
}