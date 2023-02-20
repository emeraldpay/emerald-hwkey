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
//! # Module providing commnication using HID API
//!

use hex;
use hidapi::HidDevice;
use log;
use std::{cmp::min, mem::size_of_val, slice};
use crate::errors::HWKeyError;
use crate::ledger::apdu::APDU;

///
pub const HID_RPT_SIZE: usize = 64;

///
pub const INIT_HEADER_SIZE: usize = 7;

/// Size of data chunk expected in Init USB HID Packets
const INIT_DATA_SIZE: usize = HID_RPT_SIZE - 12;

/// Size of data chunk expected in Cont USB HID Packets
const CONT_DATA_SIZE: usize = HID_RPT_SIZE - 5;

// ISO 7816-4 defined response status words
// See: https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/

/// Wrong length
pub const SW_WRONG_LENGTH: [u8; 2] =            [0x67, 0x00];
/// Conditions of use not satisfied
pub const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] =[0x69, 0x85];
/// The parameters in the data field are incorrect.
pub const SW_WRONG_DATA: [u8; 2] =              [0x6A, 0x80];
/// Lc inconsistent with TLV structure
pub const SW_USER_CANCEL: [u8; 2] =             [0x6A, 0x85];
/// Lc inconsistent with P1-P2
pub const SW_INCONSISTENT_PS: [u8; 2] =         [0x6A, 0x87];
/// Wrong parameter(s) P1-P2
pub const SW_WRONG_PS: [u8; 2] =                [0x6b, 0x00];
pub const SW_NO_ERROR: [u8; 2] =                [0x90, 0x00];

/// Packs header with Ledgers magic numbers
fn get_hid_header(channel: u16, index: usize) -> [u8; 5] {
    [
        (channel >> 8) as u8,
        (channel & 0xff) as u8, //channel
        0x05,                   //tag
        (index >> 8) as u8,
        (index & 0xff) as u8, //length
    ]
}

///
fn check_recv_frame(frame: &[u8], channel: u16, index: usize) -> Result<(), HWKeyError> {
    if size_of_val(frame) < 5
        || frame[0] != (channel >> 8) as u8
        || frame[1] != (channel & 0xff) as u8
        || frame[2] != 0x05
    {
        return Err(HWKeyError::CommError("Invalid frame header size".to_string()));
    }

    let seq = (frame[3] as usize) << 8 | (frame[4] as usize);
    if seq != index {
        return Err(HWKeyError::CommError(format!(
            "Invalid sequence. {:?}  != {:?} (act != exp) of {:}",
            seq, index, hex::encode(&frame)
        )));
    }

    if index == 0 && size_of_val(frame) < 7 {
        return Err(HWKeyError::CommError(format!("Invalid frame size: {:}", size_of_val(frame))));
    }

    Ok(())
}

fn get_init_header(apdu: &APDU) -> [u8; INIT_HEADER_SIZE] {
    let mut buf = [0u8; INIT_HEADER_SIZE];
    buf[0] = (apdu.len() >> 8) as u8;
    buf[1] = (apdu.len() & 0xff) as u8;
    buf[2..].clone_from_slice(apdu.raw_header().as_slice());
    buf
}

fn set_data(data: &mut [u8], itr: &mut slice::Iter<u8>, max: usize) {
    let available = itr.size_hint().0;

    for i in 0..min(max, available) {
        data[i] = *itr.next().unwrap();
    }
}

/// Check `status word`, if invalid coverts it
/// to the proper error message
pub fn sw_to_error(sw_h: u8, sw_l: u8) -> Result<(), HWKeyError> {
    match [sw_l, sw_h] {
        SW_NO_ERROR => Ok(()),
        SW_WRONG_LENGTH => Err(HWKeyError::CommError("Incorrect length".to_string())),
        SW_WRONG_DATA => Err(HWKeyError::CommError("Invalid data".to_string())),
        SW_INCONSISTENT_PS => Err(HWKeyError::CommError("Inconsistent parameters".to_string())),
        SW_WRONG_PS => Err(HWKeyError::CommError("Wrong parameters".to_string())),
        SW_USER_CANCEL => Err(HWKeyError::CommError("Canceled by user".to_string())),
        SW_CONDITIONS_NOT_SATISFIED => {
            Err(HWKeyError::CommError("Conditions not satisfied()".to_string()))
        }
        v => Err(HWKeyError::CommError(format!(
            "Internal communication error: {:?}",
            v
        ))),
    }
}

pub trait LedgerConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize, HWKeyError>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, HWKeyError>;
    fn read_timeout(&mut self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HWKeyError>;
}

#[cfg(not(feature = "speculos"))]
impl LedgerConnection for HidDevice {
    fn write(&mut self, data: &[u8]) -> Result<usize, HWKeyError> {
        HidDevice::write(self, data)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        HidDevice::read(self, buf)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }

    fn read_timeout(&mut self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HWKeyError> {
        HidDevice::read_timeout(self, buf, timeout_ms)
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
    }
}

pub fn send(dev: &mut dyn LedgerConnection, apdu: &APDU) -> Result<(), HWKeyError> {
    let mut frame_index: usize = 0;
    let mut data_itr = apdu.data.iter();
    let mut init_sent = false;
    let channel = 0x101;

    debug!(">> senrecv input: {:?}", &apdu);
    // Write Data.
    while !init_sent || data_itr.size_hint().0 != 0 {
        // Add 1 to HID_RPT_SIZE since we need to prefix this with a record
        // index.
        let mut frame: [u8; (HID_RPT_SIZE + 1) as usize] = [0; (HID_RPT_SIZE + 1) as usize];

        frame[1..6].clone_from_slice(&get_hid_header(channel, frame_index));
        if !init_sent {
            frame[6..13].clone_from_slice(&get_init_header(&apdu));
            init_sent = true;
            set_data(&mut frame[13..], &mut data_itr, INIT_DATA_SIZE);
        } else {
            set_data(&mut frame[6..], &mut data_itr, CONT_DATA_SIZE);
        }

        if log_enabled!(log::Level::Trace) {
            trace!(">> USB send: {}", hex::encode(frame.to_vec()));
        }

        if let Err(err) = dev.write(&frame) {
            return Err(err.into());
        };
        frame_index += 1;
    }
    Ok(())
}

pub fn recv_direct(dev: &mut dyn LedgerConnection, timeout: i32) -> Result<Vec<u8>, HWKeyError> {
    let mut frame_index: usize = 0;
    let channel = 0x101;

    debug!("<< read response");
    let mut data: Vec<u8> = Vec::new();
    let datalen: usize;
    let mut recvlen: usize = 0;
    let mut frame: [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
    let frame_size = dev.read_timeout(&mut frame, timeout)?;
    if frame_size == 0 {
        return Err(HWKeyError::EmptyResponse)
    }
    check_recv_frame(&frame, channel, frame_index)?;
    datalen = (frame[5] as usize) << 8 | (frame[6] as usize);
    data.extend_from_slice(&frame[7..frame_size]);

    recvlen += frame_size;
    frame_index += 1;
    debug!(
        "<<\t|-- recvlen: {}, datalen: {}",
        recvlen,
        datalen
    );
    debug!(
        "<<\t|-- init data: {:?}",
        hex::encode(&data)
    );

    while recvlen < datalen {
        frame = [0u8; HID_RPT_SIZE];
        let frame_size = dev.read_timeout(&mut frame, timeout)?;

        if frame_size == 0 {
            return Err(HWKeyError::EmptyResponse)
        }

        check_recv_frame(&frame, channel, frame_index)?;
        data.extend_from_slice(&frame[5..frame_size]);
        recvlen += frame_size;
        frame_index += 1;
        debug!(
            "<<\t|-- cont_{:?} size:{:?}, data: {:?}",
            frame_index,
            data.len(),
            hex::encode(&data)
        );
    }
    data.truncate(datalen);
    Ok(data)
}

pub fn recv(dev: &mut dyn LedgerConnection, timeout: i32) -> Result<Vec<u8>, HWKeyError> {
    let mut data = recv_direct(dev, timeout)?;
    match sw_to_error(data.pop().unwrap(), data.pop().unwrap()) {
        Ok(_) => Ok(data),
        Err(e) => Err(e),
    }
}

///
pub fn sendrecv(dev: &mut dyn LedgerConnection, apdu: &APDU) -> Result<Vec<u8>, HWKeyError> {
    send(dev, apdu)?;
    recv(dev, -1)
}

pub fn sendrecv_timeout(dev: &mut dyn LedgerConnection, apdu: &APDU, timeout: i32) -> Result<Vec<u8>, HWKeyError> {
    send(dev, apdu)?;
    recv(dev, timeout)
}

/// Ping Ledger device, returns `Ok(true)` if available. `Ok(false)` is unavailable (i.e., ping
/// response is not zero). Or `Err` if failed to connect
pub fn ping(dev: &mut dyn LedgerConnection) -> Result<bool, HWKeyError> {
    let mut frame: [u8; (HID_RPT_SIZE + 1) as usize] = [0; (HID_RPT_SIZE + 1) as usize];
    let channel: u16 = 0x101;
    frame[1] = (channel >> 8) as u8;
    frame[2] = (channel & 0xff) as u8;
    frame[3] = 0x02;
    if log_enabled!(log::Level::Trace) {
        let parts: Vec<String> = frame.iter().map(|byte| format!("{:02x}", byte)).collect();
        trace!(">> PING USB send: {}", parts.join(""));
    }
    if let Err(err) = dev.write(&frame) {
        return Err(err.into());
    };
    let mut frame: [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
    let frame_size = dev.read(&mut frame)?;
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&frame[7..frame_size]);

    if log_enabled!(log::Level::Trace) {
        trace!("\t\t|-- PING response: {:?}", hex::encode(&data));
    }

    Ok(data[0] == 0)
}
