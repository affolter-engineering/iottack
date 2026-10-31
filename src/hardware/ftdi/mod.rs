pub mod config;
pub mod device;

pub use config::FtdiConfig;

use crate::core::Plugin;

/// Extension of `Plugin` for FTDI MPSSE-attached targets.
///
/// Channels A and B carry MPSSE engines and support I2C, SPI, JTAG and SWD.
/// Channels C and D are UART/bit-bang only and cannot run synchronous protocols.
pub trait FtdiPlugin: Plugin {
    fn ftdi_config(&self) -> &FtdiConfig;
}
