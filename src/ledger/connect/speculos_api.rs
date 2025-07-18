use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::errors::HWKeyError;
use crate::ledger::comm::LedgerTransport;
use std::env;
use std::sync::{Arc, Mutex};

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

#[derive(Deserialize, Clone, Debug)]
struct EventsListResponse {
    events: Vec<EventResponse>
}

#[derive(Clone)]
pub struct Speculos {
    url: String,
    state: Arc<Mutex<DataState>>
}

struct DataState {
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
    /// By default it connects to `http://localhost:8080`
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

    pub fn delete_events(&self) -> Result<(), HWKeyError> {
        ureq::delete(
            format!("{}/events", &self.url).as_str()
            ).call()
            .map_err(|e| HWKeyError::CommError(format!("{}", e)))
            .map(|_| ())
    }

    pub fn get_events(&self, clear: bool) -> Result<Vec<String>, HWKeyError> {
        let resp = ureq::get(
            format!("{}/events", &self.url).as_str()
            )
            .call().map_err(|e| HWKeyError::CommError(format!("Failed to make a request: {}", e)))?
            .into_string().map_err(|_| HWKeyError::CommError("Not a string".to_string()))?;
        let events: Vec<String> = serde_json::from_str::<EventsListResponse>(resp.as_str()).unwrap()
            .events.iter()
            .map(|event| event.text.clone())
            .collect();

        if clear {
            self.delete_events()?;
        }
        Ok(events)
    }

    pub fn press_right_until<F>(&self, limit: usize, check: F) -> Result<(), ()>
        where F: Fn((String, String)) -> bool {
        let found = false;
        let mut tries = 0;
        while !found && tries < limit {
            tries += 1;
            let current = self.get_events(true).map_err(|_| ())?;
            let pair = if current.len() > 1 {
                (current[current.len()-2].clone(), current[current.len()-1].clone())
            } else if current.len() == 1 {
                (current[current.len()-1].clone(), "".to_string())
            } else {
                ("".to_string(), "".to_string())
            };
            if check(pair) {
                return Ok(())
            }
            self.press(Button::Right).map_err(|_| ())?;
        }
        Err(())
    }

    pub fn accept_on_screen(&self) -> Result<(), HWKeyError> {
        self.press_right_until(10, |e| e.0.eq("Accept"))
            .map_err(|_| HWKeyError::CommError("Accept button not found".to_string()))?;
        self.press(Button::Both)?;
        Ok(())
    }

    pub fn reject_on_screen(&self) -> Result<(), HWKeyError> {
        self.press_right_until(10, |e| e.0.eq("Reject"))
            .map_err(|_| HWKeyError::CommError("Reject button not found".to_string()))?;
        self.press(Button::Both)?;
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
            Err(_) => Ok(false)
        }
    }
}

impl Default for Speculos {
    fn default() -> Self {
        Speculos {
            url: "http://127.0.0.1:8080".to_string(),
            state: Arc::new(Mutex::new(DataState {
                in_buf: Vec::new(),
                in_frame_seq: 0,
                out_buf: Vec::new(),
                out_len: 0
            }))
        }
    }
}

impl LedgerTransport for Speculos {
    fn write(&self, data: &[u8]) -> Result<usize, HWKeyError> {
        let mut state = self.state.lock().unwrap();
        //-----
        // Buffer all frames to send as a single APDU command
        //-----
        if state.out_len == 0 {
            state.out_len = ((data[6] as usize) << 8) | (data[7] as usize);
            state.out_buf.extend_from_slice(&data[8..]);
        } else {
            state.out_buf.extend_from_slice(&data[6..]);
        }
        let finalized = state.out_buf.len() >= state.out_len;
        debug!("APDU Frame processed. Expected: {}. Current frame: {}. Finalized: {}", state.out_len, state.out_buf.len(), finalized);
        if !finalized {
            return Ok(0)
        }

        let result = self.apdu(&state.out_buf)?;
        state.out_buf.clear();
        state.out_len = 0;
        state.in_buf = result;
        state.in_frame_seq = 0;
        Ok(data.len())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        let mut state = self.state.lock().unwrap();
        //-----
        // Split APDU response into multiple frames and read one by one from memory
        //-----
        let first_frame = state.in_frame_seq == 0;
        let channel = 0x101;

        // standard header
        buf[0] = (channel >> 8) as u8;
        buf[1] = (channel & 0xff) as u8;
        buf[2] = 0x05;

        // current frame index
        buf[3] = (state.in_frame_seq >> 8) as u8;
        buf[4] = (state.in_frame_seq & 0xff) as u8;

        // when data started prepend it with its size
        if first_frame {
            buf[5] = (state.in_buf.len() >> 8) as u8;
            buf[6] = (state.in_buf.len() & 0xff) as u8;
        }

        let header_size = if first_frame {
            7
        } else {
            5
        };

        let mut size = state.in_buf.len();
        let limit = buf.len() - header_size;
        if size > limit {
            size = limit
        }

        buf[header_size..size+header_size].copy_from_slice(&state.in_buf[0..size]);

        if size == state.in_buf.len() {
            state.in_buf.clear();
        } else {
            state.in_buf = state.in_buf[size..].to_vec()
        }
        state.in_frame_seq += 1;
        Ok(size + header_size)
    }

    fn read_timeout(&self, buf: &mut [u8], _timeout_ms: i32) -> Result<usize, HWKeyError> {
        self.read(buf)
    }

}