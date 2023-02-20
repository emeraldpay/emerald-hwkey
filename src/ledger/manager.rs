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
        apdu::APDU,
        comm::ping, comm::sendrecv_timeout
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
use std::convert::TryFrom;

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

#[derive(Clone, Debug)]
pub struct AppDetails {
    pub name: String,
    pub version: String,
    pub flags: String,
}

impl Default for AppDetails {
    fn default() -> Self {
        AppDetails {
            name: "".to_string(),
            version: "".to_string(),
            flags: "".to_string(),
        }
    }
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

    #[cfg(not(feature = "speculos"))]
    pub fn have_device(&self) -> bool {
        self.device.is_some()
    }

    #[cfg(feature = "speculos")]
    pub fn have_device(&self) -> bool {
        let conn = self.open();
        if conn.is_err() {
            return false
        }
        let conn = conn.unwrap();
        if let Ok(avail) = conn.is_available() {
            avail
        } else {
            false
        }
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
            trace!("device {:?}", hid_info);
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
        match &self.device {
            None => Err(HWKeyError::Unavailable),
            Some(target) => {
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
        }
    }

    #[cfg(feature = "speculos")]
    pub fn open(&self) -> Result<crate::ledger::speculos::Speculos, HWKeyError> {
        Ok(crate::ledger::speculos::Speculos::create_env())
    }

    ///
    /// Get information about the currently running app on Ledger
    /// If no app is running it produces the same info from the OS.
    pub fn get_app_details(&self) -> Result<AppDetails, HWKeyError> {
        let apdu = APDU {
            cla: 0xb0,
            ins: 0x01,
            ..APDU::default()
        };
        let mut device = self.open()?;
        match sendrecv_timeout(&mut device, &apdu, 100) {
            Err(e) => match e {
                HWKeyError::EmptyResponse => Ok(AppDetails::default()),
                _ => Err(e),
            }
            Ok(resp) => AppDetails::try_from(resp)
        }
    }

}

fn read_string(pos: usize, buf: &Vec<u8>) -> Result<(String, usize), HWKeyError> {
    if buf.len() <= pos {
        return Ok(("".to_string(), pos));
    }
    let len = buf[pos] as usize;

    // in general the 0x90 must be cut because of the data length in the frame, but sometimes it produces the whole response
    if len == 0 || len == 0x90 {
        return Ok(("".to_string(), pos + 1));
    }
    if len + pos + 1 > buf.len() {
        return Err(HWKeyError::EncodingError(format!("Cannot read {} at {} from {}", len, pos + 1, buf.len())));
    }
    let codes = &buf[pos+1..pos+1+len];

    // Some apps (BOLOS for example) has a bug that produces the zero-terminator into the output so we just cut it off here
    let codes = if let Some(nul_pos) = codes.into_iter().position(|c| *c == 0u8) {
        &codes[0..nul_pos]
    } else {
        &codes
    };

    let s = String::from_utf8(codes.to_vec())
        .map_err(|_| HWKeyError::EncodingError(format!("Not a string at {}..{}", pos + 1, pos + 1 + len)))?;
    Ok((s, pos + 1 + len))
}

impl TryFrom<Vec<u8>> for AppDetails {
    type Error = HWKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let is_ok = value[0] == 0x01;
        if !is_ok {
            return Err(HWKeyError::EncodingError("No App Version provided".to_string()));
        }
        let name = read_string(1, &value)?;
        let version = read_string(name.1, &value)?;
        let flags = read_string(version.1, &value)?;
        Ok(
            AppDetails {
                name: name.0,
                version: version.0,
                flags: flags.0,
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::ledger::{
        manager::{LedgerKey, AppDetails},
        apdu::{ApduBuilder, APDU},
        comm::{sendrecv}
    };
    use core::convert::TryFrom;
    use log::Level;

    #[test]
    pub fn parse_ethereum_version() {
        let raw = hex::decode("0108457468657265756d06312e322e3133").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.name, "Ethereum");
        assert_eq!(act.version, "1.2.13");
        assert_eq!(act.flags, "");
    }

    #[test]
    pub fn parse_ethereum_classic_version() {
        let raw = hex::decode("0110457468657265756d20436c617373696306312e322e3133").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.name, "Ethereum Classic");
        assert_eq!(act.version, "1.2.13");
        assert_eq!(act.flags, "");
    }

    #[test]
    pub fn parse_bitcoin_version() {
        let raw = hex::decode("0107426974636f696e05312e342e37").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.name, "Bitcoin");
        assert_eq!(act.version, "1.4.7");
        assert_eq!(act.flags, "");
    }

    #[test]
    pub fn parse_bitcoin_testnet_version() {
        let raw = hex::decode("010c426974636f696e205465737405312e342e37").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.name, "Bitcoin Test");
        assert_eq!(act.version, "1.4.7");
        assert_eq!(act.flags, "");
    }

    #[test]
    pub fn parse_no_app_version_broken() {
        let raw = hex::decode("01054f4c4f5300072e322e342d3100").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        // for a some reason the ledger wiht BOLOS 1.2.4-1 produces a corrupted response.
        // so that's ok here to verify with such a weird expected values
        assert_eq!(act.name, "OLOS");
        assert_eq!(act.version, ".2.4-1");
        assert_eq!(act.flags, "");
    }

    #[test]
    pub fn parse_no_app_whole_frame() {
        let raw = hex::decode("01054f4c4f5300072e322e342d3100900000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let act = AppDetails::try_from(raw);
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.name, "OLOS");
        assert_eq!(act.version, ".2.4-1");
        assert_eq!(act.flags, "");
    }

    #[test]
    #[cfg(integration_test)]
    /// Just for testing the responses from an actual device
    pub fn check_version() {
        simple_logger::init_with_level(Level::Trace).unwrap();
        let mut manager = LedgerKey::new_connected().unwrap();
        let apdu = APDU {
            cla: 0xb0,
            ins: 0x01,
            ..APDU::default()
        };
        let mut device = manager.open().expect("Cannot open");

        let resp = sendrecv(&mut device, &apdu).unwrap();
        println!("resp app version: {:}", hex::encode(resp));

        let apdu = APDU {
            cla: 0xe0,
            ins: 0x01,
            ..APDU::default()
        };
        let resp = sendrecv(&mut device, &apdu).unwrap();
        println!("resp hw version: {:}", hex::encode(resp));
    }
}