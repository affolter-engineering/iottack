use super::{SerialPlugin, UartConfig, UartSession};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Returns true for IO errors that indicate the device was reset or unplugged.
fn is_device_reset(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind::*;
    e.downcast_ref::<std::io::Error>()
        .map(|io| matches!(io.kind(), BrokenPipe | ConnectionReset | ConnectionAborted | UnexpectedEof | NotConnected))
        .unwrap_or(false)
}

pub struct UartTerminal {
    config:  UartConfig,
    session: Option<UartSession>,
}

impl UartTerminal {
    pub fn new() -> Self {
        Self {
            config:  UartConfig::default(),
            session: None,
        }
    }
}

impl Default for UartTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for UartTerminal {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Interactive terminal session over UART",
            description: "Open an interactive terminal with a UART device. Input is forwarded \
                          to the serial port and responses are printed to stdout. Press Ctrl+D \
                          (EOF) to exit.",
            needs_root: false,
            args: &[
                CliArg { name: "port", short: Some('p'), help: "Serial port (e.g., /dev/ttyUSB0)", value_name: "PATH", default: None, is_flag: false },
                CliArg { name: "baud_rate", short: Some('b'), help: "Baud rate", value_name: "BAUD", default: Some("115200"), is_flag: false },
                CliArg { name: "timeout_ms", short: None, help: "Read timeout in milliseconds", value_name: "MS", default: Some("50"), is_flag: false },
            ],
        )
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = UartConfig::from_plugin_config(config)?;
        self.connect()
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        result.set_silent();

        // Capture before the mutable borrow of session below.
        let port = self.config.port.clone();
        let baud = self.config.baud_rate;

        let session = match self.session_mut() {
            Some(s) => s,
            None => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No session",
                    "Serial port was not opened.",
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        // Spawn a thread that reads stdin byte-by-byte and sends chunks over a channel.
        // The thread exits when stdin reaches EOF (Ctrl+D).
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut buf = [0u8; 256];
            let stdin = io::stdin();
            let mut stdin = stdin.lock();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        eprintln!("[iottack] connected to {port} at {baud} baud - Ctrl+D to exit");

        let poll_interval = Duration::from_millis(10);

        loop {
            // Forward any pending stdin input to the serial port.
            match rx.try_recv() {
                Ok(data) => {
                    if let Err(e) = session.write_bytes(&data).and_then(|_| session.flush()) {
                        if is_device_reset(&e) {
                            eprintln!("\n[iottack] device reset or disconnected");
                            break;
                        }
                        return Err(e);
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => break, // stdin closed (Ctrl+D)
                Err(mpsc::TryRecvError::Empty) => {}
            }

            // Read any available serial data and print it.
            match session.read_bytes(256) {
                Ok(received) if !received.is_empty() => {
                    io::stdout().write_all(&received)?;
                    io::stdout().flush()?;
                }
                Ok(_) => thread::sleep(poll_interval),
                Err(e) if is_device_reset(&e) => {
                    eprintln!("\n[iottack] device reset or disconnected");
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        eprintln!("\n[iottack] session ended");
        result.finish(PluginStatus::Pass);
        Ok(result)
    }

    fn teardown(&mut self) -> Result<()> {
        self.disconnect();
        Ok(())
    }
}

impl SerialPlugin for UartTerminal {
    fn serial_config(&self) -> &UartConfig { &self.config }
    fn session(&self) -> Option<&UartSession> { self.session.as_ref() }
    fn session_mut(&mut self) -> Option<&mut UartSession> { self.session.as_mut() }
    fn set_session(&mut self, s: Option<UartSession>) { self.session = s; }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(UartTerminal::new()) as Box<dyn crate::Plugin>)
}
