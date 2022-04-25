use serde::de::DeserializeOwned;
use serde::Serialize;
use ureq::post;
use crate::errors::HWKeyError;
use crate::ledger::comm::LedgerConnection;
use std::env;

#[derive(Serialize, Clone, Debug)]
struct ApduRequest {
    data: String
}

#[derive(Deserialize, Clone, Debug)]
struct ApduResponse {
    data: String
}

#[derive(Debug)]
pub enum Button {
    Left,
    Right,
    Both
}

impl Button {
    fn name(&self) -> String {
        match self {
            Button::Left => "left",
            Button::Right => "right",
            Button::Both => "both"
        }.to_string()
    }
}

#[derive(Serialize, Debug, Clone, Copy)]
enum ButtonAction {
    #[serde(rename="press-and-release")]
    PressAndRelease
}

#[derive(Serialize, Clone, Debug)]
struct ButtonRequest {
    action: ButtonAction
}

#[derive(Deserialize, Clone, Debug)]
struct ButtonResponse {}

#[derive(Deserialize, Clone, Debug)]
struct EventResponse {
    text: String,
    x: usize,
    y: usize
}

pub struct Speculos {
    url: String,
    in_buf: Vec<u8>,
    in_frame_seq: usize,
    out_buf: Vec<u8>,
    out_len: usize,
}

///
/// Speculos controller
impl Speculos {

    ///
    /// Create from environment variables, where `SPECULOS_URL` can specify URL to an instance of Speculos.
    /// By default it connects to `http://localhost:5000`
    pub fn create_env() -> Speculos {
        let default = Speculos::default();
        let url = match env::var("SPECULOS_URL") {
            Ok(v) => v,
            Err(_) => default.url
        };
        Speculos {
            url,
            ..default
        }
    }

    fn post<T: Serialize + Sized, R: DeserializeOwned + Sized>(&self, path: &str, command: T) -> Result<R, HWKeyError> {
        let resp = ureq::post(
            format!("{}/{}", &self.url, path).as_str()
        ).send_json(command);
        match resp {
            Ok(v) => if v.status() != 200 {
                Err(HWKeyError::CommError(format!("HTTP Status: {}", v.status())))
            } else {
                v.into_json::<R>().map_err(|e| HWKeyError::CommError(format!("Failed to read JSON: {}", e)))
            },
            Err(e) => Err(HWKeyError::CommError(format!("Failed to make a request: {}", e)))
        }
    }

    fn apdu(&self, data: &Vec<u8>) -> Result<Vec<u8>, HWKeyError> {
        let req = ApduRequest {
            data: hex::encode(data)
        };
        debug!("Send: {}", req.data);
        let resp: ApduResponse = self.post("apdu", req)?;
        let resp: Vec<u8> = hex::decode(resp.data).map_err(|_| HWKeyError::EncodingError("Invalid hex".to_string()))?;
        debug!("Received: {}", hex::encode(&resp));
        Ok(resp)
    }

    pub fn press(&self, button: Button) -> Result<(), HWKeyError> {
        let req = ButtonRequest {
            action: ButtonAction::PressAndRelease
        };
        let _: ButtonResponse = self.post(format!("button/{}", button.name()).as_str(), req)?;
        Ok(())
    }

    pub fn is_available(&self) -> Result<bool, HWKeyError> {
        let resp = ureq::get(
            format!("{}/{}", &self.url, "events").as_str()
        ).call();
        match resp {
            Ok(v) => if v.status() != 200 {
                Ok(false)
            } else {
                Ok(true)
            },
            Err(e) => Ok(false)
        }
    }
}

impl Default for Speculos {
    fn default() -> Self {
        Speculos {
            url: "http://127.0.0.1:5000".to_string(),
            in_buf: Vec::new(),
            in_frame_seq: 0,
            out_buf: Vec::new(),
            out_len: 0
        }
    }
}

impl LedgerConnection for Speculos {
    fn write(&mut self, data: &[u8]) -> Result<usize, HWKeyError> {
        //-----
        // Buffer all frames to send as a single APDU command
        //-----
        if self.out_len == 0 {
            self.out_len = (data[6] as usize) << 8 | (data[7] as usize);
            self.out_buf.extend_from_slice(&data[8..]);
        } else {
            self.out_buf.extend_from_slice(&data[6..]);
        }
        let finalized = self.out_buf.len() >= self.out_len;
        debug!("APDU Frame processed. Expected: {}. Current frame: {}. Finalized: {}", self.out_len, self.out_buf.len(), finalized);
        if !finalized {
            return Ok(0)
        }

        let result = self.apdu(&self.out_buf)?;
        self.out_buf.clear();
        self.out_len = 0;
        self.in_buf = result;
        self.in_frame_seq = 0;
        Ok(data.len())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        //-----
        // Split APDU response into multiple frames and read one by one from memory
        //-----
        let first_frame = self.in_frame_seq == 0;
        let channel = 0x101;

        // standard header
        buf[0] = (channel >> 8) as u8;
        buf[1] = (channel & 0xff) as u8;
        buf[2] = 0x05;

        // current frame index
        buf[3] = (self.in_frame_seq >> 8) as u8;
        buf[4] = (self.in_frame_seq & 0xff) as u8;

        // when data started prepend it with its size
        if first_frame {
            buf[5] = (self.in_buf.len() >> 8) as u8;
            buf[6] = (self.in_buf.len() & 0xff) as u8;
        }

        let header_size = if first_frame {
            7
        } else {
            5
        };

        let mut size = self.in_buf.len();
        let limit = buf.len() - header_size;
        if size > limit {
            size = limit
        }

        buf[header_size..size+header_size].copy_from_slice(&self.in_buf[0..size]);

        if size == self.in_buf.len() {
            self.in_buf.clear();
        } else {
            self.in_buf = self.in_buf[size..].to_vec()
        }
        self.in_frame_seq += 1;
        Ok(size + header_size)
    }
}