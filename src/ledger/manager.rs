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

//! # Module to work with `HD Wallets`
//!
//! Currently supports only Ledger Nano S & Ledger Blue
//! `HD(Hierarchical Deterministic) Wallet` specified in
//! [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

use crate::{
    ledger::{
        comm::ping,
        apdu::ApduBuilder,
        comm::sendrecv
    },
    errors::HWKeyError,
};
use hex;
use hidapi::{HidApi, HidDevice, DeviceInfo};
use std::{
    str::{from_utf8, FromStr},
    thread,
    time,
};

/// ECDSA crypto signature length in bytes
pub const ECDSA_SIGNATURE_BYTES: usize = 65;

const GET_ETH_ADDRESS: u8 = 0x02;
const SIGN_ETH_TRANSACTION: u8 = 0x04;
const CHUNK_SIZE: usize = 255;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_S_PID_1: u16 = 0x0001; // for Nano S model with Bitcoin App
const LEDGER_S_PID_2: u16 = 0x1011; // for Nano S model without any app
const LEDGER_S_PID_3: u16 = 0x1015; // for Nano S model with Ethereum or Ethereum Classic App

const LEDGER_X_PID_1: u16 = 0x4011; // for Nano X model (official)
const LEDGER_X_PID_2: u16 = 0x0004; // for Nano X model (in the wild)

/// Type used for device listing,
/// String corresponds to file descriptor of the device
pub type DevicesList = Vec<(String, String)>;

pub type SignatureBytes = [u8; ECDSA_SIGNATURE_BYTES];

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
    hid: HidApi,
    /// List of available wallets
    device: Option<Device>,
}

impl LedgerKey {
    /// Creates new `Ledger Key Manager`
    pub fn new() -> Result<LedgerKey, HWKeyError> {
        Ok(Self {
            hid: HidApi::new()?,
            device: None,
        })
    }

    /// Get address
    ///
    /// # Arguments:
    /// fd - file descriptor to corresponding HID device
    /// hd_path - optional HD path, prefixed with count of derivation indexes
    ///
    pub fn get_address(
        &self,
        _fd: &str,
        hd_path: Vec<u8>,
    ) -> Result<String, HWKeyError> {

        let apdu = ApduBuilder::new(GET_ETH_ADDRESS)
            .with_data(&hd_path)
            .build();

        let handle = self.open()?;
        let addr = sendrecv(&handle, &apdu)
            .and_then(|res| match res.len() {
                107 => Ok(res),
                _ => Err(HWKeyError::CommError(
                    "Address read returned invalid data length".to_string(),
                )),
            })
            .and_then(|res: Vec<u8>| {
                from_utf8(&res[67..107])
                    .map(|ptr| ptr.to_string())
                    .map_err(|e| {
                        HWKeyError::EncodingError(format!("Can't parse address: {}", e.to_string()))
                    })
            })?;

        Ok(addr)
    }

    /// Sign transaction
    ///
    /// # Arguments:
    /// fd - file descriptor to corresponding HID device
    /// tr - RLP packed transaction
    /// hd_path - optional HD path, prefixed with count of derivation indexes
    ///
    pub fn sign_transaction(
        &self,
        _fd: &str,
        tr: &[u8],
        hd_path: Vec<u8>,
    ) -> Result<SignatureBytes, HWKeyError> {

        let _mock = Vec::new();
        let (init, cont) = match tr.len() {
            0...CHUNK_SIZE => (tr, _mock.as_slice()),
            _ => tr.split_at(CHUNK_SIZE - hd_path.len()),
        };

        let init_apdu = ApduBuilder::new(SIGN_ETH_TRANSACTION)
            .with_p1(0x00)
            .with_data(&hd_path)
            .with_data(init)
            .build();

        if self.device.is_none() {
            return Err(HWKeyError::OtherError("Device not selected".to_string()));
        }

        let handle = self.open()?;
        let mut res = sendrecv(&handle, &init_apdu)?;

        for chunk in cont.chunks(CHUNK_SIZE) {
            let apdu_cont = ApduBuilder::new(SIGN_ETH_TRANSACTION)
                .with_p1(0x80)
                .with_data(chunk)
                .build();
            res = sendrecv(&handle, &apdu_cont)?;
        }
        debug!("Received signature: {:?}", hex::encode(&res));
        match res.len() {
            ECDSA_SIGNATURE_BYTES => {
                let mut val: SignatureBytes = [0; ECDSA_SIGNATURE_BYTES];
                val.copy_from_slice(&res);

                Ok(val)
            }
            v => Err(HWKeyError::CryptoError(format!(
                "Invalid signature length. Expected: {}, received: {}",
                ECDSA_SIGNATURE_BYTES, v
            ))),
        }
    }

    /// List all available devices
    pub fn devices(&self) -> DevicesList {
        self.device
            .iter()
            .map(|d| (d.address.clone(), d.fd.clone()))
            .collect()
    }

    /// Update device list
    pub fn connect(&mut self) -> Result<(), HWKeyError> {
        self.hid.refresh_devices();

        let current = self.hid.device_list().find(|hid_info| {
            debug!("device {:?}", hid_info);
            hid_info.vendor_id() == LEDGER_VID
                && (hid_info.product_id() == LEDGER_S_PID_1
                || hid_info.product_id() == LEDGER_S_PID_2
                || hid_info.product_id() == LEDGER_S_PID_3
                || hid_info.product_id() == LEDGER_X_PID_1
                || hid_info.product_id() == LEDGER_X_PID_2)
        });

        if current.is_none() {
            self.device = None;
            return Err(HWKeyError::Unavailable);
        }

        let hid_info = current.unwrap();
        let d = Device::from(hid_info);
        self.device = Some(d);

        Ok(())
    }

    fn open(&self) -> Result<HidDevice, HWKeyError> {
        if self.device.is_none() {
            return Err(HWKeyError::Unavailable);
        }
        let target = self.device.as_ref().unwrap();
        // up to 10 tries, starting from 100ms increasing by 75ms, in total 1450ms max
        let mut retry_delay = 100;
        for _ in 0..10 {
            //
            //serial number is always 0001
            if let Ok(h) = self
                .hid
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
            retry_delay += 75;
        }

        // used by another application
        Err(HWKeyError::CommError(format!(
            "Can't open device: {:?}",
            target.hid_info
        )))
    }
}

#[cfg(test)]
pub mod tests {

}