use std::{io, fmt, error};

#[derive(Debug, PartialEq, Clone)]
pub enum HWKeyError {
    /// Device is unavailable
    Unavailable,
    /// An unsupported cipher
    CryptoError(String),
    /// Error from HID communication
    CommError(String),
    /// Communication encoding error
    EncodingError(String),
    /// Something else
    OtherError(String),
    /// On invalid input to the library
    InputError(String)
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
            HWKeyError::CryptoError(ref str) => write!(f, "HWKey error: {}", str),
            HWKeyError::CommError(ref str) => write!(f, "Communication protocol error: {}", str),
            HWKeyError::EncodingError(ref str) => write!(f, "Encoding error: {}", str),
            HWKeyError::OtherError(ref str) => write!(f, "HWKey other error: {}", str),
            HWKeyError::InputError(ref str) => write!(f, "HWKey invalid input: {}", str)
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