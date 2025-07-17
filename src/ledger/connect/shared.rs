use std::thread;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use hidapi::HidDevice;
use crate::errors::HWKeyError;
use crate::ledger::apdu::APDU;
use crate::ledger::comm;
use crate::ledger::comm::{sendrecv_timeout, LedgerTransport};
use crate::ledger::connect::direct::{AppDetails, LedgerHidKey};
use std::convert::TryFrom;
use std::marker::PhantomData;
use log;
use crate::ledger::connect::LedgerKey;
#[cfg(feature = "speculos")]
use crate::ledger::connect::speculos::LedgerSpeculosKey;

static INSTANCE: OnceLock<LedgerKeyShared<LedgerHidKey>> = OnceLock::new();

#[cfg(feature = "speculos")]
static INSTANCE_SPECULOS: OnceLock<LedgerKeyShared<LedgerSpeculosKey>> = OnceLock::new();

pub struct LedgerKeyShared<LK: LedgerKey> {
    t: PhantomData<LK>,
    channel: Sender<Command>,
    state: Arc<RwLock<State>>,
}

impl<LK: LedgerKey> Clone for LedgerKeyShared<LK> {
    fn clone(&self) -> Self {
        Self { t: self.t, channel: self.channel.clone(), state: self.state.clone() }
    }
}

enum Command {
    Connect(Sender<Result<(), HWKeyError>>),
    HaveDevice(Sender<bool>),
    Write(Vec<u8>, Sender<Result<usize, HWKeyError>>),
    Read(i32, Sender<Result<Vec<u8>, HWKeyError>>),
    SetDisconnected,
}

#[derive(Clone, Eq, PartialEq)]
enum State {
    Init,
    Working,
    Disconnected,
    Stopped,
}

impl LedgerKeyShared<LedgerHidKey> {
    ///
    /// Get (or create on the first call) a shared instance to access LedgerKey
    pub fn instance() -> Result<LedgerKeyShared<LedgerHidKey>, HWKeyError> {
        let instance = INSTANCE.get_or_init(|| {
            let mut value = Self::new();
            let connected = value.connect();
            if connected.is_ok() {
                let ping = comm::ping(&value);
                if ping.is_err() {
                    log::warn!("No immediate response from Ledger: {:?}. Will try to reconnect", ping);
                    value.set_disconnected();
                }
            }
            value
        });

        Ok(instance.clone())
    }
}

#[cfg(feature = "speculos")]
impl LedgerKeyShared<LedgerSpeculosKey> {
    ///
    /// Get (or create on the first call) a shared instance to access LedgerKey
    pub fn instance() -> Result<LedgerKeyShared<LedgerSpeculosKey>, HWKeyError> {
        let instance = INSTANCE_SPECULOS.get_or_init(|| {
            let mut value = Self::new();
            let connected = value.connect();
            if connected.is_ok() {
                let _ = comm::ping(&value);
            }
            value
        });

        Ok(instance.clone())
    }
}

///
/// An instance of LedgerKey that can be safely used between different threads because it opens the device and executes all commands in its own thread.
/// This is important on macOS where the HID device is not thread safe (and sometimes it even needs to "sleep" between uses from different threads,
/// so a Mutex doesn't always help), and when a HID device is used improperly it could panic with SIGILL.
///
impl<LK: LedgerKey> LedgerKeyShared<LK> {

    fn new() -> Self {
        let (tx, rx) = channel();
        let state = Arc::new(RwLock::new(State::Init));
        Self::run(rx, state.clone());
        Self { t: PhantomData, channel: tx, state }
    }

    fn is_working(&self) -> bool {
        let r = self.state.read().unwrap();
        *r != State::Init
    }

    fn ensure_working(&self) -> Result<(), HWKeyError> {
        if !self.is_working() {
            return Err(HWKeyError::Unavailable)
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        if self.ensure_working().is_err() {
            return false
        }
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::HaveDevice(tx)) {
            log::error!("Error sending command: {:?}", e);
            return false
        }
        rx.recv().unwrap_or_default()
    }

    fn set_disconnected(&self) {
        let _ = self.channel.send(Command::SetDisconnected);
    }

    fn run(channel: Receiver<Command>, state: Arc<RwLock<State>>) {
        thread::spawn( move || {
            let ledger = LedgerHidKey::new();
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
                            Command::Connect(resp) => {
                                log::info!("Connecting to Ledger...");
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
                            Command::SetDisconnected => {
                                log::info!("Setting Ledger as disconnected");
                                let mut w = state.write().unwrap();
                                *w = State::Disconnected;
                            }
                            Command::HaveDevice(resp) => {
                                log::trace!("Check if device is connected");
                                let is_connected = {
                                    let state = state.read().unwrap().clone();
                                    matches!(state, State::Working)
                                };
                                let _ = resp.send(device.is_some() && is_connected);
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
                                        let _ = resp.send(result);

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
                                            HidDevice::read_timeout(hid, &mut data, timeout)
                                                .map_err(|e| HWKeyError::CommError(format!("{}", e)))
                                        };
                                        match len {
                                            Err(e) => {
                                                {
                                                    let mut w = state.write().unwrap();
                                                    *w = State::Disconnected;
                                                }
                                                log::trace!("Disconnected due to error: {:?}", e);
                                                let _ = resp.send(Err(e));
                                            }
                                            Ok(len) => {
                                                let mut result = Vec::with_capacity(len);
                                                result.extend_from_slice(&data[..len]);
                                                log::trace!("Received data: {}", hex::encode(&result));
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

impl<LK: LedgerKey> LedgerKey for LedgerKeyShared<LK> {
    type Transport = Self;

    fn create() -> Result<Self, HWKeyError> {
        panic!("Not implemented. use LedgerKeyShared::instance() instead")
    }

    fn connect(&mut self) -> Result<(), HWKeyError> {
        if self.is_connected() {
            return Ok(())
        }
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

    fn get_app_details(&self) -> Result<AppDetails, HWKeyError> {
        self.ensure_working()?;

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

    fn open_exclusive(&self) -> Result<Arc<Mutex<Self::Transport>>, HWKeyError> {
        //TODO have a single instance as a field
        Ok(Arc::new(Mutex::new(self.clone())))
    }
}

impl<LK: LedgerKey> LedgerTransport for LedgerKeyShared<LK> {
    fn write(&self, data: &[u8]) -> Result<usize, HWKeyError> {
        self.ensure_working()?;
        let (tx, rx) = channel();
        if let Err(e) = self.channel.send(Command::Write(data.to_vec(), tx)) {
            log::warn!("Error sending command: {:?}", e);
            return Err(HWKeyError::Unavailable)
        }
        rx.recv().unwrap_or_else(|e| {
            log::warn!("Error write receiving response: {:?}", e);
            Err(HWKeyError::Unavailable)
        })
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, HWKeyError> {
        self.read_timeout(buf, -1)
    }
    fn read_timeout(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, HWKeyError> {
        self.ensure_working()?;
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