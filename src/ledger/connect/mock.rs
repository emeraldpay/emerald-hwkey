/*
Copyright 2025 EmeraldPay

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

//! Mock transport implementation for testing

use crate::ledger::comm::LedgerTransport;
use crate::errors::HWKeyError;

/// Mock transport for testing Ledger communication
pub struct MockTransport {
    pub call_count: std::cell::RefCell<usize>,
    pub last_command: std::cell::RefCell<Option<u8>>,
    pub last_p1: std::cell::RefCell<Option<u8>>,
    pub response: Vec<u8>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Create a new MockTransport with default success response
    pub fn new() -> Self {
        MockTransport {
            call_count: std::cell::RefCell::new(0),
            last_command: std::cell::RefCell::new(None),
            last_p1: std::cell::RefCell::new(None),
            response: vec![0x90, 0x00], // Success response
        }
    }

    /// Create a MockTransport with custom response
    pub fn with_response(response: Vec<u8>) -> Self {
        MockTransport {
            call_count: std::cell::RefCell::new(0),
            last_command: std::cell::RefCell::new(None),
            last_p1: std::cell::RefCell::new(None),
            response,
        }
    }
}

impl LedgerTransport for MockTransport {
    fn write(&self, data: &[u8]) -> Result<usize, HWKeyError> {
        *self.call_count.borrow_mut() += 1;
        // Extract command and P1 from APDU data
        if data.len() >= 8 {
            // Skip HID header (5 bytes) and length (2 bytes) to get to APDU
            let apdu_start = 7;
            if data.len() > apdu_start + 1 {
                *self.last_command.borrow_mut() = Some(data[apdu_start + 1]);
                *self.last_p1.borrow_mut() = Some(data[apdu_start + 2]);
            }
        }
        Ok(data.len())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        let copy_len = std::cmp::min(buf.len(), self.response.len());
        buf[..copy_len].copy_from_slice(&self.response[..copy_len]);
        Ok(copy_len)
    }

    fn read_timeout(&self, buf: &mut [u8], _timeout_ms: i32) -> Result<usize, HWKeyError> {
        self.read(buf)
    }
}