/*
Copyright 2019 ETCDEV GmbH
Copyright 2020 EmeraldPay, Inc
Copyright 2025 EmeraldPay Ltd

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

use crate::{
    errors::HWKeyError,
    ledger::comm::ping,
};
use hidapi::{DeviceInfo, HidApi, HidDevice};
use std::{
    sync::{Arc, Mutex},
    thread,
    time
};
use std::convert::TryFrom;
use crate::errors::ResponseError;
use crate::ledger::comm::LedgerTransport;
use crate::ledger::connect::LedgerKey;

pub const CHUNK_SIZE: usize = 255;
pub const LEDGER_VID: u16 = 0x2c97; // 11415

/// Ledger device interface types based on the MMII pattern
/// Uses the II (interface bitfield) part of the product ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LedgerInterface {
    /// Legacy interface for older devices (no bitfield)
    Legacy,
    /// Defined interface using the II bitfield pattern
    Defined(u16),
}

impl LedgerInterface {
    /// Check if Generic HID is supported
    pub fn has_generic_hid(&self) -> bool {
        match self {
            LedgerInterface::Legacy => true,
            LedgerInterface::Defined(bits) => (bits & 0x01) != 0,
        }
    }

    /// Check if Keyboard HID is supported
    pub fn has_keyboard_hid(&self) -> bool {
        match self {
            LedgerInterface::Legacy => false,
            LedgerInterface::Defined(bits) => (bits & 0x02) != 0,
        }
    }

    /// Check if U2F is supported
    pub fn has_u2f(&self) -> bool {
        match self {
            LedgerInterface::Legacy => false,
            LedgerInterface::Defined(bits) => (bits & 0x04) != 0,
        }
    }

    /// Check if CCID is supported
    pub fn has_ccid(&self) -> bool {
        match self {
            LedgerInterface::Legacy => false,
            LedgerInterface::Defined(bits) => (bits & 0x08) != 0,
        }
    }

    /// Check if WebUSB is supported
    pub fn has_webusb(&self) -> bool {
        match self {
            LedgerInterface::Legacy => false,
            LedgerInterface::Defined(bits) => (bits & 0x10) != 0,
        }
    }
}

/// Ledger device models with their supported interfaces
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LedgerDevice {
    /// Ledger Blue device
    Blue(LedgerInterface),
    /// Ledger Nano S device
    Nano(LedgerInterface),
    /// Ledger Nano X device
    NanoX(LedgerInterface),
    /// Ledger Nano S+ device
    NanoSPlus(LedgerInterface),
    /// Ledger Stax device
    Stax(LedgerInterface),
    /// Ledger Flex device
    Flex(LedgerInterface),
}

impl TryFrom<u16> for LedgerDevice {
    type Error = HWKeyError;

    fn try_from(pid: u16) -> Result<Self, Self::Error> {
        match pid {
            // Legacy devices (< 0xff)
            0x0000 => Ok(LedgerDevice::Blue(LedgerInterface::Legacy)),
            0x0001 => Ok(LedgerDevice::Nano(LedgerInterface::Legacy)),
            0x0004 => Ok(LedgerDevice::NanoX(LedgerInterface::Legacy)),
            0x0005 => Ok(LedgerDevice::NanoSPlus(LedgerInterface::Legacy)),
            0x0006 => Ok(LedgerDevice::Stax(LedgerInterface::Legacy)),
            0x0007 => Ok(LedgerDevice::Flex(LedgerInterface::Legacy)),

            // Special case for Nano X legacy
            // TODO do we still need this? verify
            0x0040 => Ok(LedgerDevice::NanoX(LedgerInterface::Legacy)),
            
            // MMII pattern devices (>= 0xff)
            pid if pid >= 0xff => {
                let mm = (pid >> 8) & 0xff;
                let ii = pid & 0xff;
                let interface = LedgerInterface::Defined(ii);
                
                match mm {
                    0x00 => Ok(LedgerDevice::Blue(interface)),
                    0x10 => Ok(LedgerDevice::Nano(interface)),
                    0x40 => Ok(LedgerDevice::NanoX(interface)),
                    0x50 => Ok(LedgerDevice::NanoSPlus(interface)),
                    0x60 => Ok(LedgerDevice::Stax(interface)),
                    0x70 => Ok(LedgerDevice::Flex(interface)),
                    _ => Err(HWKeyError::Unsupported(pid)),
                }
            }
            
            _ => Err(HWKeyError::Unsupported(pid)),
        }
    }
}

impl LedgerDevice {
    /// Get the device interface
    pub fn interface(&self) -> &LedgerInterface {
        match self {
            LedgerDevice::Blue(interface) => interface,
            LedgerDevice::Nano(interface) => interface,
            LedgerDevice::NanoX(interface) => interface,
            LedgerDevice::NanoSPlus(interface) => interface,
            LedgerDevice::Stax(interface) => interface,
            LedgerDevice::Flex(interface) => interface,
        }
    }

    /// Get the device model name
    pub fn model_name(&self) -> &'static str {
        match self {
            LedgerDevice::Blue(_) => "Ledger Blue",
            LedgerDevice::Nano(_) => "Ledger Nano S",
            LedgerDevice::NanoX(_) => "Ledger Nano X",
            LedgerDevice::NanoSPlus(_) => "Ledger Nano S+",
            LedgerDevice::Stax(_) => "Ledger Stax",
            LedgerDevice::Flex(_) => "Ledger Flex",
        }
    }
}

/// Type used for device listing,
/// String corresponds to file descriptor of the device
pub type DevicesList = Vec<(String, String)>;

/// Device information for connected Ledger devices
#[derive(Debug)]
struct ConnectedDevice {
    /// File descriptor path
    fd: String,
    /// Device address
    address: String,
    /// HID device information
    hid_info: DeviceInfo,
    /// Ledger device type
    ledger_device: LedgerDevice,
}

#[derive(Clone, Debug)]
pub struct AppDetails {
    pub name: String,
    pub version: String,
    pub flags: String,
}

#[derive(Clone, Debug)]
pub struct LedgerDetails {
    pub firmware_version: String,
    pub mcu_version: String,
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

impl PartialEq for ConnectedDevice {
    fn eq(&self, other: &ConnectedDevice) -> bool {
        self.fd == other.fd
    }
}

impl TryFrom<&DeviceInfo> for ConnectedDevice {
    type Error = HWKeyError;
    
    fn try_from(hid_info: &DeviceInfo) -> Result<Self, Self::Error> {
        let info = hid_info.clone();
        Self::try_from(info)
    }
}

impl TryFrom<DeviceInfo> for ConnectedDevice {
    type Error = HWKeyError;
    
    fn try_from(hid_info: DeviceInfo) -> Result<Self, Self::Error> {
        let ledger_device = LedgerDevice::try_from(hid_info.product_id())?;
        Ok(ConnectedDevice {
            fd: hid_info.path().to_string_lossy().to_string(),
            address: "".to_string(),
            ledger_device,
            hid_info,
        })
    }
}

/// `Wallet Manager` to handle all interaction with HD wallet
pub struct LedgerHidKey {
    /// HID point used for communication
    hid: Arc<Mutex<HidApi>>,

    /// List of available wallets
    device: Option<ConnectedDevice>,
}

///
/// A direct connection to a Ledger Key connected via USB (using HID protocol).
///
/// WARNING: On macOS connection cannon be used from different threads, even two different instances of the `LedgerHidKey` should not be used.
/// For a shared instance use [crate::ledger::connect::LedgerKeyShared].
impl LedgerHidKey {

    /// Create new `Ledger Key Manager`
    /// Make sure you have only one instance at a time, because when it's created it locks HID API to the instance.
    pub fn new() -> Result<Self, HWKeyError> {
        Self::create()
    }

    /// Create new `Ledger Key Manager` and try to connect to actual ledger. Return error otherwise.
    pub fn new_connected() -> Result<LedgerHidKey, HWKeyError> {
        let mut instance = LedgerHidKey::new()?;
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

    /// Get the connected Ledger device type
    pub fn ledger_device(&self) -> Option<&LedgerDevice> {
        self.device.as_ref().map(|d| &d.ledger_device)
    }

    pub(crate) fn device(&self) -> Result<HidDevice, HWKeyError> {
        match &self.device {
            None => Err(HWKeyError::Unavailable),
            Some(target) => {
                let hid = self.hid.lock().expect("Failed to lock HID access");
                hid.open(target.hid_info.vendor_id(), target.hid_info.product_id())
                    .map_err(|_| HWKeyError::CommError("Failed to open device".to_string()))
            }
        }
    }

}

pub(crate) fn read_slice(pos: usize, buf: &Vec<u8>) -> Result<(Vec<u8>, usize), HWKeyError> {
    if buf.len() <= pos {
        return Ok((vec![], pos));
    }
    let len = buf[pos] as usize;

    // in general the 0x90 must be cut because of the data length in the frame, but sometimes it produces the whole response
    if len == 0 || len == 0x90 {
        return Ok((vec![], pos + 1));
    }
    let end = pos + 1 + len;
    if end > buf.len() {
        return Err(HWKeyError::EncodingError(format!("Cannot read {} at {} ({}..{}) from {}", len, pos + 1, pos+1, end, buf.len())));
    }
    let codes = &buf[pos+1..end];
    Ok((codes.to_vec(), end))
}

pub(crate) fn read_string(pos: usize, buf: &Vec<u8>) -> Result<(String, usize), HWKeyError> {
    let (codes, end) = read_slice(pos, buf)?;

    // Some apps (BOLOS for example) has a bug that produces the zero-terminator into the output so we just cut it off here
    let codes = if let Some(nul_pos) = codes.iter().position(|c| *c == 0u8) {
        codes[0..nul_pos].to_vec()
    } else {
        codes
    };

    let s = String::from_utf8(codes)
        .map_err(|_| HWKeyError::EncodingError(format!("Not a string at {}..{}", pos + 1, end)))?;
    Ok((s, end))
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

impl LedgerKey for LedgerHidKey {
    type Transport = HidDevice;

    fn create() -> Result<Self, HWKeyError> {
        let hid = HidApi::new_without_enumerate()
            .map_err(|_| HWKeyError::CommError("HID API is not available".to_string()))?;
        Ok(Self {
            hid: Arc::new(Mutex::new(hid)),
            device: None,
        })
    }

    fn connect(&mut self) -> Result<(), HWKeyError> {
        let current = {
            let mut hid = self.hid.lock()
                .map_err(|_| HWKeyError::CommError("HID API is locked".to_string()))?;

            hid.refresh_devices()
                .map_err(|_| HWKeyError::CommError("Failed to refresh".to_string()))?;

            let device = hid.device_list().find(|hid_info| {
                trace!("device {:?}", hid_info);
                hid_info.vendor_id() == LEDGER_VID
                    && LedgerDevice::try_from(hid_info.product_id()).is_ok()
            }).map(|hid_info| hid_info.clone());

            device
        };

        if current.is_none() {
            debug!("No device connected");
            self.device = None;

            return Err(HWKeyError::Unavailable);
        }

        debug!("Connecting to {:?}", current.as_ref().unwrap());

        let hid_info = current.unwrap();
        let d = ConnectedDevice::try_from(hid_info)?;
        self.device = Some(d);

        Ok(())
    }

    fn open_exclusive(&self) -> Result<Arc<Mutex<HidDevice>>, HWKeyError> {
        // up to 10 tries, starting from 50ms increasing by 25ms, in total 19250ms max
        let mut retry_delay = 50;
        for _ in 0..11 {
            {
                //
                //serial number is always 0001
                let mut h = self.device()?;
                match ping(&mut h) {
                    Ok(v) => {
                        if v {
                            //
                            // HidDevice keeps a lock of the HidApi so it should be ok to give a Mutex over the HidDevice itself
                            //
                            return Ok(Arc::new(Mutex::new(h)));
                        }
                    }
                    Err(_) => {}
                }
            }
            thread::sleep(time::Duration::from_millis(retry_delay));
            retry_delay += 25;
        }
        // used by another application
        Err(HWKeyError::CommError("Device is locked by another application".to_string()))
    }

}

impl LedgerTransport for HidDevice {
    fn write(&self, data: &[u8]) -> Result<usize, HWKeyError> {
        HidDevice::write(self, data)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        HidDevice::read(self, buf)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }

    fn read_timeout(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HWKeyError> {
        HidDevice::read_timeout(self, buf, timeout_ms)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }
}

impl TryFrom<Vec<u8>> for LedgerDetails {

    type Error = HWKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() < 5 {
            return Err(HWKeyError::InvalidResponse(ResponseError::ShortLedgerVersion))
        }
        // TODO unclear what is in the first 4 bytes. It seems that it supposed to show the type of connection,
        // but there is no reference for those values
        let pos = 4;
        let (firmware_version, pos) = read_string(pos, &value)?;
        // TODO another unknown block
        let (_, pos) = read_slice(pos, &value)?;
        let (mcu_version, _) = read_string(pos, &value)?;

        Ok(LedgerDetails {
            firmware_version,
            mcu_version,
        })
    }
}


#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use core::convert::TryFrom;
    use crate::ledger::connect::direct::{AppDetails, LedgerDetails, LedgerDevice, LedgerInterface};
    use crate::ledger::connect::direct::{read_string, read_slice};

    #[test]
    pub fn can_read_string() {
        assert_eq!(
            read_string(0, &hex::decode("07312e322e342d31").unwrap()).unwrap(),
            ("1.2.4-1".to_string(), 8)
        );
        assert_eq!(
            read_string(0, &hex::decode("03322e38").unwrap()).unwrap(),
            ("2.8".to_string(), 4)
        );
        assert_eq!(
            read_string(1, &hex::decode("0003322e38").unwrap()).unwrap(),
            ("2.8".to_string(), 5)
        );
        assert_eq!(
            read_string(17, &hex::decode("3300000407312e322e342d3104a600000003322e38").unwrap()).unwrap(),
            ("2.8".to_string(), 21)
        );
    }

    #[test]
    pub fn can_read_slice() {
        assert_eq!(
            read_slice(0, &hex::decode("07312e322e342d31").unwrap()).unwrap(),
            (hex::decode("312e322e342d31").unwrap(), 8)
        );
        assert_eq!(
            read_slice(17, &hex::decode("3300000407312e322e342d3104a600000003322e38").unwrap()).unwrap(),
            (hex::decode("322e38").unwrap(), 21)
        );
    }

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
    pub fn parse_ledger() {
        let raw = hex::decode("3300000407312e322e342d3104a600000003322e38").unwrap();
        let act = LedgerDetails::try_from(raw);
        if !act.is_ok() {
            println!("Error: {}", act.clone().err().unwrap())
        }
        assert!(act.is_ok());
        let act = act.unwrap();
        assert_eq!(act.firmware_version, "1.2.4-1");
        assert_eq!(act.mcu_version, "2.8");
    }

    #[test]
    pub fn test_ledger_device_from_pid() {
        // Test legacy devices
        assert_eq!(LedgerDevice::try_from(0x0000).unwrap(), LedgerDevice::Blue(LedgerInterface::Legacy));
        assert_eq!(LedgerDevice::try_from(0x0001).unwrap(), LedgerDevice::Nano(LedgerInterface::Legacy));
        assert_eq!(LedgerDevice::try_from(0x0004).unwrap(), LedgerDevice::NanoX(LedgerInterface::Legacy));
        assert_eq!(LedgerDevice::try_from(0x0040).unwrap(), LedgerDevice::NanoX(LedgerInterface::Legacy));
        
        // Test MMII pattern devices
        assert_eq!(LedgerDevice::try_from(0x1011).unwrap(), LedgerDevice::Nano(LedgerInterface::Defined(0x11)));
        assert_eq!(LedgerDevice::try_from(0x1015).unwrap(), LedgerDevice::Nano(LedgerInterface::Defined(0x15)));
        assert_eq!(LedgerDevice::try_from(0x4011).unwrap(), LedgerDevice::NanoX(LedgerInterface::Defined(0x11)));
        assert_eq!(LedgerDevice::try_from(0x4015).unwrap(), LedgerDevice::NanoX(LedgerInterface::Defined(0x15)));
        
        // Test unknown device
        match LedgerDevice::try_from(0xFFFF) {
            Err(crate::errors::HWKeyError::Unsupported(pid)) => {
                assert_eq!(pid, 0xFFFF);
            },
            _ => panic!("Expected Unsupported error"),
        }
    }

    #[test]
    pub fn test_ledger_interface_features() {
        let legacy = LedgerInterface::Legacy;
        assert!(legacy.has_generic_hid());
        assert!(!legacy.has_keyboard_hid());
        assert!(!legacy.has_u2f());
        assert!(!legacy.has_ccid());
        assert!(!legacy.has_webusb());
        
        let defined = LedgerInterface::Defined(0x15); // HID + U2F + WebUSB
        assert!(defined.has_generic_hid());
        assert!(!defined.has_keyboard_hid());
        assert!(defined.has_u2f());
        assert!(!defined.has_ccid());
        assert!(defined.has_webusb());
    }

    #[test]
    pub fn test_ledger_device_methods() {
        let device = LedgerDevice::Nano(LedgerInterface::Defined(0x11));
        assert_eq!(device.model_name(), "Ledger Nano S");
        assert_eq!(device.interface(), &LedgerInterface::Defined(0x11));
        
        let device_x = LedgerDevice::NanoX(LedgerInterface::Legacy);
        assert_eq!(device_x.model_name(), "Ledger Nano X");
        assert_eq!(device_x.interface(), &LedgerInterface::Legacy);
    }


    #[test]
    #[cfg(integration_test)]
    /// Just for testing the responses from an actual device
    pub fn check_app_version() {
        simple_logger::init_with_level(Level::Trace).unwrap();
        let mut manager = LedgerHidKey::new_connected().unwrap();
        let apdu = APDU {
            cla: 0xb0,
            ins: 0x01,
            ..APDU::default()
        };
        let device = manager.open_exclusive()
            .expect("Cannot open");
        let mut device = device.lock().unwrap();

        let resp = sendrecv(&mut *device, &apdu).unwrap();
        println!("resp app version: {:}", hex::encode(resp));

        let apdu = APDU {
            cla: 0xe0,
            ins: 0x01,
            ..APDU::default()
        };
        let resp = sendrecv(&mut *device, &apdu).unwrap();
        println!("resp hw version: {:}", hex::encode(resp));
    }

    // #[test]
    // #[cfg(integration_test)]
    // //Just for testing the responses from an actual device
    // pub fn check_ledger_version() {
    //     simple_logger::init_with_level(Level::Trace).unwrap();
    //     let mut manager = LedgerKey::new_connected().unwrap();
    //
    //     let device = manager.open()
    //         .expect("Cannot open");
    //     let mut device = device.lock().unwrap();
    //
    //     for i in 0u8..255 {
    //         let apdu = APDU {
    //             cla: 0xb0,
    //             ins: i,
    //             ..APDU::default()
    //         };
    //
    //         let resp = sendrecv(&mut *device, &apdu);
    //         if resp.is_ok() {
    //             println!("\nresp for {}: {:}\n", i, hex::encode(resp.unwrap()));
    //         }
    //     }
    //
    // }
}