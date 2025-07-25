use std::thread;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
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
            let ledger = LK::create();
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
            let mut device: Option<Arc<Mutex<LK::Transport>>> = None;
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
                                    match ledger.open_exclusive() {
                                        Ok(transport) => {
                                            device = Some(transport);
                                            let mut w = state.write().unwrap();
                                            *w = State::Working;
                                            let _ = resp.send(Ok(()));
                                        }
                                        Err(e) => {
                                            {
                                                let mut w = state.write().unwrap();
                                                *w = State::Disconnected;
                                            }
                                            log::error!("Error opening transport: {:?}", e);
                                            let _ = resp.send(Err(e));
                                        }
                                    }
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
                                        log::debug!("Ledger device not connected");
                                        {
                                            let mut w = state.write().unwrap();
                                            *w = State::Disconnected;
                                        }
                                        let _ = resp.send(Err(HWKeyError::Unavailable));
                                    }
                                    Some(transport) => {
                                        log::trace!("Writing: {}", hex::encode(&data));
                                        let result = {
                                            let transport_guard = transport.lock().unwrap();
                                            transport_guard.write(data.as_slice())
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
                                        log::debug!("Ledger device not connected");
                                        {
                                            let mut w = state.write().unwrap();
                                            *w = State::Disconnected;
                                        }
                                        let _ = resp.send(Err(HWKeyError::Unavailable));
                                    }
                                    Some(transport) => {
                                        let mut data = [0u8; comm::HID_RPT_SIZE];
                                        let len = {
                                            let transport_guard = transport.lock().unwrap();
                                            transport_guard.read_timeout(&mut data, timeout)
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
        match sendrecv_timeout(self, &apdu, 5000) {
            Err(e) => {
                debug!("Error sending APDU: {:?}", e);
                match e {
                    HWKeyError::EmptyResponse => Ok(AppDetails::default()),
                    _ => Err(e),
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::connect::direct::LedgerHidKey;
    use crate::ledger::comm;

    /// Give the background thread a moment to initialize
    fn wait_for_thread_init() {
        thread::sleep(std::time::Duration::from_millis(10));
    }

    fn set_state<T: LedgerKey>(key: &LedgerKeyShared<T>, new_state: State) {
        let mut w = key.state.write().unwrap();
        *w = new_state;
    }

    #[test]
    fn test_write_when_device_not_connected() {
        let shared = LedgerKeyShared::<LedgerHidKey>::new();
        set_state(&shared, State::Working);
        wait_for_thread_init();

        // Test write operation - should fail because device is None
        let test_data = vec![0x01, 0x02, 0x03];
        let result = shared.write(&test_data);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HWKeyError::Unavailable));
    }

    #[test]
    fn test_read_when_device_not_connected() {
        let shared = LedgerKeyShared::<LedgerHidKey>::new();
        set_state(&shared, State::Working);
        wait_for_thread_init();

        // Test read operation - should fail because device is None
        let mut buffer = [0u8; comm::HID_RPT_SIZE];
        let result = shared.read_timeout(&mut buffer, 1000);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HWKeyError::Unavailable));
    }

    #[test]
    fn test_is_connected_returns_false_when_not_connected() {
        let shared = LedgerKeyShared::<LedgerHidKey>::new();
        set_state(&shared, State::Working);
        wait_for_thread_init();

        // Test is_connected - should return false because device is None
        let result = shared.is_connected();
        assert_eq!(result, false);
    }

    #[test]
    fn test_send_receive_data() {
        use crate::ledger::connect::mock::MockLedgerKey;
        let shared = LedgerKeyShared::<MockLedgerKey>::new();
        wait_for_thread_init();
        
        let mut shared_for_connect = shared.clone();
        let connect_result = shared_for_connect.connect();
        assert!(connect_result.is_ok());
        
        assert!(shared.is_connected());
        
        // Test write operation
        let test_data = vec![0x01, 0x02, 0x03];
        let write_result = shared.write(&test_data);
        assert!(write_result.is_ok());
        assert_eq!(write_result.unwrap(), 3);
        
        // Test read operation
        let mut buffer = [0u8; comm::HID_RPT_SIZE];
        let read_result = shared.read_timeout(&mut buffer, 1000);
        assert!(read_result.is_ok());
        let bytes_read = read_result.unwrap();
        assert_eq!(bytes_read, 2); // Mock returns success response [0x90, 0x00]
        assert_eq!(&buffer[..bytes_read], &[0x90, 0x00]);
    }
}