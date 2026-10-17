pub mod baud_scan;
pub mod config;
pub mod port_scan;
pub mod session;
pub mod shell_detect;

pub use config::UartConfig;
pub use session::UartSession;

use crate::core::{Plugin, PluginConfig};
use anyhow::Result;

/// Extension of `Plugin` for serial/UART-attached devices.
///
/// Implementors store a `UartConfig` and an `Option<UartSession>`.
/// The default `initialize` implementation opens the port; `teardown` drops it.
/// `connect` / `disconnect` can be called explicitly for finer control.
pub trait SerialPlugin: Plugin {
    fn serial_config(&self) -> &UartConfig;
    fn session(&self) -> Option<&UartSession>;
    fn session_mut(&mut self) -> Option<&mut UartSession>;

    /// Replace (or clear) the session. Implementors must provide this.
    fn set_session(&mut self, session: Option<UartSession>);

    fn connect(&mut self) -> Result<()> {
        // Clone config to avoid holding &self while calling set_session(&mut self).
        let config = self.serial_config().clone();
        let session = UartSession::open(&config)?;
        self.set_session(Some(session));
        Ok(())
    }

    fn disconnect(&mut self) {
        self.set_session(None);
    }

    /// Default `initialize`: opens the serial port.
    fn serial_pre(&mut self, config: &PluginConfig) -> Result<()> {
        let _ = config;
        self.connect()
    }

    /// Default `teardown`: closes the serial port.
    fn serial_post(&mut self) -> Result<()> {
        self.disconnect();
        Ok(())
    }
}
