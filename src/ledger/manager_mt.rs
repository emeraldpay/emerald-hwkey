use std::thread;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use hidapi::HidDevice;
use crate::errors::HWKeyError;
use crate::ledger::apdu::APDU;
use crate::ledger::comm;
use crate::ledger::comm::{sendrecv_timeout, LedgerConnection};
use crate::ledger::manager::{AppDetails, LedgerKey};
use crate::ledger::traits::LedgerApp;
use std::convert::TryFrom;
use log;

static INSTANCE: OnceLock<LedgerKeyShared> = OnceLock::new();
static INSTANCE_LOCKED: OnceLock<Arc<Mutex<LedgerKeyShared>>> = OnceLock::new();

#[derive(Clone)]
pub struct LedgerKeyShared {
    channel: Sender<Command>,
    state: Arc<RwLock<State>>,
}

enum Command {
    Stop,
    Connect(Sender<Result<(), HWKeyError>>),
    HaveDevice(Sender<bool>),
    Write(Vec<u8>, Sender<Result<usize, HWKeyError>>),
    Read(i32, Sender<Result<Vec<u8>, HWKeyError>>),
}

#[derive(Clone, Eq, PartialEq)]
enum State {
    Init,
    Working,
    Disconnected,
    Stopped,
}

///
/// An instance of LedgerKey that can be safely used between different threads because it opens the device and executes all commands in its own thread.
/// This is important on macOS where the HID device is not thread safe (and sometimes it even needs to "sleep" between uses from different threads,
/// so a Mutex doesn't always help), and when a HID device is used improperly it could panic with SIGILL.
///
impl LedgerKeyShared {

    ///
    /// Get (or create on the first call) a shared instance to access LedgerKey
    pub fn instance() -> Result<LedgerKeyShared, HWKeyError> {
        let instance = INSTANCE.get_or_init(|| {
            let value = Self::new();
            let connected = value.connect();
            if connected.is_ok() {
                let _ = comm::ping(&value);
            }
            value
        });

        let _locked = INSTANCE_LOCKED.get_or_init(|| {
            Arc::new(Mutex::new(instance.clone()))
        });

        Ok(instance.clone())
    }

    fn new() -> Self {
        let (tx, rx) = channel();
        let state = Arc::new(RwLock::new(State::Init));
        Self::run(rx, state.clone());
        Self { channel: tx, state }
    }

    fn is_working(&self) -> bool {
        let r = self.state.read().unwrap();
        *r != State::Init
    }

    fn is_disconnected(&self) -> bool {
        let r = self.state.read().unwrap();
        *r == State::Disconnected
    }

    fn ensure_working(&self) -> Result<(), HWKeyError> {
        if !self.is_working() {
            return Err(HWKeyError::Unavailable)
        }
        Ok(())
    }

    fn try_connect(&self) -> Result<(), HWKeyError> {
        {
            let r = self.state.read().unwrap();
            if *r != State::Disconnected {
                return Ok(())
            }
        }
        self.connect()
    }

    pub fn connect(&self) -> Result<(), HWKeyError> {
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::Connect(tx)) {
            log::error!("Error sending command: {:?}", e);
            return Err(HWKeyError::Unavailable)
        }
        rx.recv().unwrap_or_else(|e| {
            log::error!("Error receiving response: {:?}", e);
            Err(HWKeyError::Unavailable)
        })
    }

    pub fn is_connected(&self) -> bool {
        if self.ensure_working().is_err() {
            return false
        }
        let _ = self.try_connect();
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::HaveDevice(tx)) {
            log::error!("Error sending command: {:?}", e);
            return false
        }
        if let Ok(connected) = rx.recv() {
            connected
        } else {
            false
        }
    }

    pub fn get_app_details(&self) -> Result<AppDetails, HWKeyError> {
        self.ensure_working()?;
        let _ = self.try_connect();

        let apdu = APDU {
            cla: 0xb0,
            ins: 0x01,
            ..APDU::default()
        };
        match sendrecv_timeout(self, &apdu, 1000) {
            Err(e) => match e {
                HWKeyError::EmptyResponse => Ok(AppDetails::default()),
                _ => Err(e),
            }
            Ok(resp) => AppDetails::try_from(resp)
        }
    }

    pub fn access<T: LedgerApp>(&self) -> Result<T, HWKeyError> {
        Ok(T::new(INSTANCE_LOCKED.get().unwrap().clone()))
    }

    fn run(channel: Receiver<Command>, state: Arc<RwLock<State>>) {
        thread::spawn( move || {
            let ledger = LedgerKey::new();
            if let Err(e) = ledger {
                {
                    let mut w = state.write().unwrap();
                    *w = State::Stopped;
                }
                log::error!("Error creating a Ledger instance: {:?}", e);
                return
            }
            let mut ledger = ledger.unwrap();
            log::debug!("Ledger is working");
            let mut device: Option<HidDevice> = None;
            loop {
                match channel.recv() {
                    Ok(command) => {
                        match command {
                            Command::Stop => break,
                            Command::Connect(resp) => {
                                if let Err(e) = ledger.connect() {
                                    {
                                        let mut w = state.write().unwrap();
                                        *w = State::Disconnected;
                                    }
                                    log::error!("Error connecting to Ledger: {:?}", e);
                                    let _ = resp.send(Err(e));
                                } else {
                                    device = Some(ledger.device().unwrap());
                                    let mut w = state.write().unwrap();
                                    *w = State::Working;
                                    let _ = resp.send(Ok(()));
                                }
                            }
                            Command::HaveDevice(resp) => {
                                let _ = resp.send(device.is_some());
                            }
                            Command::Write(data, resp) => {
                                match &device {
                                    None => {
                                        let _ = resp.send(Err(HWKeyError::Unavailable));
                                    }
                                    Some(hid) => {
                                        log::trace!("Writing: {}", hex::encode(&data));
                                        let result = {
                                            HidDevice::write(hid, data.as_slice())
                                                .map_err(|e| HWKeyError::CommError(format!("{}", e)))
                                        };
                                        if result.is_err() {
                                            {
                                                let mut w = state.write().unwrap();
                                                *w = State::Disconnected;
                                            }
                                        }
                                        let _ = resp.send(result.map_err(|e| e.into()));

                                    }
                                }
                            }
                            Command::Read(timeout, resp) => {
                                match &device {
                                    None => {
                                        let _ = resp.send(Err(HWKeyError::Unavailable));
                                    }
                                    Some(hid) => {
                                        let mut data = [0u8; comm::HID_RPT_SIZE];
                                        let len = {
                                            // hid.read_timeout(&mut data, timeout)
                                            HidDevice::read_timeout(&hid, &mut data, timeout)
                                                .map_err(|e| HWKeyError::CommError(format!("{}", e)))
                                        };
                                        match len {
                                            Err(e) => {
                                                {
                                                    let mut w = state.write().unwrap();
                                                    *w = State::Disconnected;
                                                }
                                                let _ = resp.send(Err(e.into()));
                                            }
                                            Ok(len) => {
                                                let mut result = Vec::with_capacity(len);
                                                result.extend_from_slice(&data[..len]);
                                                log::trace!("Read data: {}", hex::encode(&result));
                                                let _ = resp.send(Ok(result));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Stopping the manager: {:?}", e);
                        break
                    }
                }
            }
            log::info!("Ledger is stopped");
            {
                let mut w = state.write().unwrap();
                *w = State::Stopped;
            }
        });
    }
}

impl LedgerConnection for LedgerKeyShared {
    fn write(&self, data: &[u8]) -> Result<usize, HWKeyError> {
        self.try_connect()?;
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::Write(data.to_vec(), tx)) {
            log::warn!("Error sending command: {:?}", e);
            return Err(HWKeyError::Unavailable)
        }
        let result = rx.recv().unwrap_or_else(|e| {
            log::warn!("Error write receiving response: {:?}", e);
            Err(HWKeyError::Unavailable)
        });
        result
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        self.read_timeout(buf, -1)
    }
    fn read_timeout(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HWKeyError> {
        self.try_connect()?;
        if buf.len() < comm::HID_RPT_SIZE {
            log::error!("Buffer is too small");
            return Err(HWKeyError::CommError("Buffer is too small".to_string()))
        }
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::Read(timeout_ms, tx)) {
            log::warn!("Error sending command: {:?}", e);
            return Err(HWKeyError::Unavailable)
        }
        let data = rx.recv().unwrap_or_else(|e| {
            log::warn!("Error read receiving response: {:?}", e);
            Err(HWKeyError::Unavailable)
        })?;
        let len = data.len();
        buf[..len].copy_from_slice(&data);
        Ok(len)
    }
}