use crate::core::PluginConfig;
use anyhow::{anyhow, Result};
use ftdi_nusb::{types::Interface, FtdiDevice};

/// PIDs to probe when no `--pid` is given, in preference order.
const AUTO_PIDS: &[u16] = &[
    0x6014, // FT232H
    0x6011, // FT4232H
    0x6010, // FT2232H / FT2232C
    0x6015, // FT230X / FT231X / FT234XD
    0x6001, // FT232R / FT8U232AM
];

/// SPI clock polarity and phase (standard mode numbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpiConfig {
    /// SPI mode 0-3 (0 = CPOL0/CPHA0, 1 = CPOL0/CPHA1, 2 = CPOL1/CPHA0, 3 = CPOL1/CPHA1).
    pub mode: u8,
    /// Transmit and receive LSB first (default: MSB first).
    pub lsb_first: bool,
}

/// MPSSE protocol mode. Determines which bus type the plugin will instantiate
/// and which channel constraints apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MpsseMode {
    #[default]
    I2c,
    Spi(SpiConfig),
    Jtag,
    Swd,
}

impl std::fmt::Display for MpsseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpsseMode::I2c => write!(f, "I2C"),
            MpsseMode::Spi(c) => write!(f, "SPI mode {} ({})", c.mode, if c.lsb_first { "LSB" } else { "MSB" }),
            MpsseMode::Jtag => write!(f, "JTAG"),
            MpsseMode::Swd => write!(f, "SWD"),
        }
    }
}

/// Shared configuration for FTDI MPSSE-based plugins (I2C, SPI, JTAG, SWD).
#[derive(Debug, Clone)]
pub struct FtdiConfig {
    pub vid: u16,
    /// `None` = auto-detect the first connected FTDI adapter.
    pub pid: Option<u16>,
    pub interface: Interface,
    pub clock_hz: u32,
    pub mpsse_mode: MpsseMode,
}

impl Default for FtdiConfig {
    fn default() -> Self {
        Self {
            vid: 0x0403,
            pid: None,
            interface: Interface::A,
            clock_hz: 100_000,
            mpsse_mode: MpsseMode::default(),
        }
    }
}

impl FtdiConfig {
    /// Build an `FtdiConfig` from CLI key/value pairs.
    ///
    /// `mode` is supplied by the calling plugin (not a CLI arg) because each
    /// plugin type has a fixed protocol. The channel constraint (A or B only)
    /// is validated here so the error surfaces at `initialize()` time.
    pub fn from_plugin_config(config: &PluginConfig, mode: MpsseMode) -> Result<Self> {
        let vid_str = config.get_or("vid", "0403");
        let vid = u16::from_str_radix(
            vid_str.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        )
        .map_err(|_| anyhow!("invalid VID '{vid_str}'. Expected hex like 0403 or 0x0403"))?;

        let pid = match config.get("pid") {
            None => None,
            Some(s) => Some(
                u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .map_err(|_| anyhow!("invalid PID '{s}'. Expected hex like 6011 or 0x6011"))?,
            ),
        };

        let channel_str = config.get_or("channel", "A").to_uppercase();
        let interface = match channel_str.as_str() {
            "A" => Interface::A,
            "B" => Interface::B,
            "C" => Interface::C,
            "D" => Interface::D,
            other => return Err(anyhow!("unknown channel '{other}'; use A, B, C or D")),
        };

        if matches!(interface, Interface::C | Interface::D) {
            return Err(anyhow!(
                "channel {channel_str} does not support MPSSE ({mode}); use A or B"
            ));
        }

        let clock_hz = config.parse_or("clock_hz", 100_000u32);

        Ok(Self { vid, pid, interface, clock_hz, mpsse_mode: mode })
    }

    /// Open an FTDI device on `self.interface`.
    ///
    /// When `self.pid` is `None`, probes all known PIDs and uses the first
    /// adapter that responds. Returns the device and the PID that was used.
    pub async fn open_device(&self) -> Result<(FtdiDevice, u16)> {
        match self.pid {
            Some(pid) => {
                let dev = FtdiDevice::open_with_interface(self.vid, pid, self.interface)
                    .await
                    .map_err(|e| anyhow!("{e}"))?;
                Ok((dev, pid))
            }
            None => {
                for &pid in AUTO_PIDS {
                    if let Ok(dev) =
                        FtdiDevice::open_with_interface(self.vid, pid, self.interface).await
                    {
                        return Ok((dev, pid));
                    }
                }
                Err(anyhow!(
                    "no FTDI adapter found on VID {:04x} (tried: {}). \
                     Connect an adapter or pass --pid to select one explicitly.",
                    self.vid,
                    AUTO_PIDS
                        .iter()
                        .map(|p| format!("{p:04x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }
}
