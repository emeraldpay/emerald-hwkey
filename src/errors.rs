use std::{io, fmt, error};

#[derive(Debug, PartialEq, Clone)]
pub enum HWKeyError {
    /// Device is unavailable
    Unavailable,

    /// Device is unsupported
    Unsupported(u16),

    DeviceLocked,

    /// Received an empty frame. Usually means a timeout.
    EmptyResponse,
    /// An unsupported cipher
    CryptoError(String),
    /// Error from HID communication
    CommError(String),
    /// Communication encoding error
    EncodingError(String),
    /// Something else
    OtherError(String),
    /// On invalid input to the library
    InputError(String),

    InvalidResponse(ResponseError)
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ResponseError {
    ShortLedgerVersion,
}

impl From<io::Error> for HWKeyError {
    fn from(err: io::Error) -> Self {
        HWKeyError::CommError(err.to_string())
    }
}

impl<'a> From<&'a str> for HWKeyError {
    fn from(err: &str) -> Self {
        HWKeyError::OtherError(err.to_string())
    }
}

impl From<hidapi::HidError> for HWKeyError {
    fn from(err: hidapi::HidError) -> Self {
        HWKeyError::CommError(err.to_string())
    }
}

impl fmt::Display for HWKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HWKeyError::Unavailable => write!(f, "HWKey Unavailable"),
            HWKeyError::Unsupported(pid) => write!(f, "HWKey Unsupported device with PID: 0x{:04x}", pid),
            HWKeyError::EmptyResponse => write!(f, "HWKey no answer"),
            HWKeyError::CryptoError(ref str) => write!(f, "HWKey error: {}", str),
            HWKeyError::CommError(ref str) => write!(f, "Communication protocol error: {}", str),
            HWKeyError::EncodingError(ref str) => write!(f, "Encoding error: {}", str),
            HWKeyError::OtherError(ref str) => write!(f, "HWKey other error: {}", str),
            HWKeyError::InputError(ref str) => write!(f, "HWKey invalid input: {}", str),
            HWKeyError::InvalidResponse(e) => write!(f, "HWKey invalid resp: {:?}", e),
            HWKeyError::DeviceLocked => write!(f, "HWKey Locked"),
        }
    }
}

impl error::Error for HWKeyError {
    fn description(&self) -> &str {
        "HWKey error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            _ => None,
        }
    }
}