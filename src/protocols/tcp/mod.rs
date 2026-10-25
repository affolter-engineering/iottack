pub mod banner;
pub mod fuzz;
pub mod shell_detect;

pub use config::{DEFAULT_TIMEOUT_MS, TcpConfig};
pub use session::TcpSession;

use crate::core::{Plugin, PluginConfig};
use anyhow::Result;

mod config {
    pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

    #[derive(Clone)]
    pub struct TcpConfig {
        pub host: String,
        pub port: u16,
        pub timeout_ms: u64,
    }

    impl Default for TcpConfig {
        fn default() -> Self {
            Self {
                host: String::new(),
                port: 0,
                timeout_ms: DEFAULT_TIMEOUT_MS,
            }
        }
    }

    impl TcpConfig {
        pub fn from_plugin_config(config: &crate::core::PluginConfig) -> anyhow::Result<Self> {
            Ok(Self {
                host: config.require("host")?.to_string(),
                port: config.parse_or("port", 0u16),
                timeout_ms: config.parse_or("timeout_ms", DEFAULT_TIMEOUT_MS),
            })
        }

        pub fn addr(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }
    }
}

mod session {
    use super::TcpConfig;
    use anyhow::Result;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    pub struct TcpSession {
        pub(crate) stream: TcpStream,
    }

    impl TcpSession {
        pub fn open(config: &TcpConfig) -> Result<Self> {
            let timeout = Duration::from_millis(config.timeout_ms);
            let sock = config
                .addr()
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("no address resolved for {}", config.addr()))?;
            let stream = TcpStream::connect_timeout(&sock, timeout)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            Ok(Self { stream })
        }

        pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
            self.stream.write_all(data)?;
            Ok(())
        }

        pub fn flush(&mut self) -> Result<()> {
            self.stream.flush()?;
            Ok(())
        }

        pub fn read_bytes(&mut self, limit: usize) -> Result<Vec<u8>> {
            let mut buf = vec![0u8; limit];
            match self.stream.read(&mut buf) {
                Ok(n) => Ok(buf[..n].to_vec()),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    Ok(Vec::new())
                }
                Err(e) => Err(e.into()),
            }
        }

        /// Read all available data up to 8 KiB (returns empty on timeout — not an error).
        pub fn drain(&mut self) -> Result<Vec<u8>> {
            self.read_bytes(8192)
        }
    }
}

/// Extension of `Plugin` for TCP-connected targets.
pub trait TcpPlugin: Plugin {
    fn tcp_config(&self) -> &TcpConfig;
    fn session(&self) -> Option<&TcpSession>;
    fn session_mut(&mut self) -> Option<&mut TcpSession>;
    fn set_session(&mut self, s: Option<TcpSession>);

    fn connect(&mut self) -> Result<()> {
        let config = self.tcp_config().clone();
        let s = TcpSession::open(&config)?;
        self.set_session(Some(s));
        Ok(())
    }

    fn disconnect(&mut self) {
        self.set_session(None);
    }

    fn tcp_pre(&mut self, _config: &PluginConfig) -> Result<()> {
        self.connect()
    }
}
