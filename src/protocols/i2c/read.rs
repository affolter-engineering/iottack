use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::hardware::ftdi::{FtdiConfig, FtdiPlugin};
use crate::hardware::ftdi::config::MpsseMode;
use anyhow::{anyhow, Result};
use ftdi_nusb::{
    mpsse::{i2c::I2cBus, MpsseContext},
    types::Interface,
};

/// I2C read plugin for FTDI MPSSE adapters.
pub struct I2cReadPlugin {
    ftdi: FtdiConfig,
    address: u8,
    register: Option<u8>,
    length: usize,
}

/// I2C read plugin for FTDI MPSSE adapters.
impl I2cReadPlugin {
    pub fn new() -> Self {
        Self {
            ftdi: FtdiConfig::default(),
            address: 0,
            register: None,
            length: 1,
        }
    }
}

/// Default implementation for the I2C read plugin.
impl Default for I2cReadPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement the `FtdiPlugin` trait for the I2C read plugin.
impl Plugin for I2cReadPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Read bytes from an I2C device via an FTDI MPSSE adapter",
            description: "Reads one or more bytes from a target I2C device. When --register is \
                          given, a write-then-read (repeated-START) is performed: the register \
                          byte is written first and the device response is read back. Without \
                          --register a plain read is issued. Raw bytes are reported as hex, \
                          decimal and ASCII. Requires an FTDI FT232H/FT2232H/FT4232H adapter \
                          with channels A or B (MPSSE). Wiring: SCL -> AD0, SDA -> AD1+AD2 \
                          shorted (4.7 kOhm pull-ups to VCC).",
            needs_root: false,
            args: &[
                CliArg {
                    name: "address",
                    short: Some('a'),
                    help: "7-bit I2C target address in HEX, e.g., 68 or 0x68",
                    value_name: "HEX",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "register",
                    short: Some('r'),
                    help: "Register/command byte to write before reading (HEX, e.g., 00 or 0x00). Omit for a plain read",
                    value_name: "HEX",
                    default: Some(""),
                    is_flag: false,
                },
                CliArg {
                    name: "length",
                    short: Some('n'),
                    help: "Number of bytes to read",
                    value_name: "N",
                    default: Some("1"),
                    is_flag: false,
                },
                CliArg {
                    name: "channel",
                    short: Some('c'),
                    help: "FTDI channel to use: A or B (MPSSE-capable channels only)",
                    value_name: "CHANNEL",
                    default: Some("A"),
                    is_flag: false,
                },
                CliArg {
                    name: "vid",
                    short: None,
                    help: "USB vendor ID in hex (default: 0403)",
                    value_name: "HEX",
                    default: Some("0403"),
                    is_flag: false,
                },
                CliArg {
                    name: "pid",
                    short: None,
                    help: "USB product ID in hex (6001=FT232R, 6010=FT2232H, 6011=FT4232H, 6014=FT232H). Omit to auto-detect",
                    value_name: "HEX",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "clock_hz",
                    short: None,
                    help: "I2C clock frequency in Hz (default: 100000)",
                    value_name: "HZ",
                    default: Some("100000"),
                    is_flag: false,
                },
            ],
        )
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.ftdi = FtdiConfig::from_plugin_config(config, MpsseMode::I2c)?;

        let addr_str = config.require("address")?;
        self.address = parse_hex_byte(addr_str)
            .map_err(|_| anyhow!("invalid address '{addr_str}'; expected HEX like 68 or 0x68"))?;

        if self.address < 0x08 || self.address > 0x77 {
            return Err(anyhow!(
                "address 0x{:02x} is reserved; valid 7-bit range is 0x08-0x77",
                self.address
            ));
        }

        let reg_str = config.get_or("register", "");
        self.register = if reg_str.is_empty() {
            None
        } else {
            Some(
                parse_hex_byte(&reg_str).map_err(|_| {
                    anyhow!("invalid register '{reg_str}'; expected hex like 00 or 0x00")
                })?,
            )
        };

        self.length = config.parse_or("length", 1usize);
        if self.length == 0 {
            return Err(anyhow!("--length must be at least 1"));
        }

        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.read())
    }
}

/// Implementation of the I2C read plugin.
impl I2cReadPlugin {
    async fn read(&self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let channel = match self.ftdi.interface {
            Interface::A => "A",
            Interface::B => "B",
            _ => "?",
        };

        let (mut dev, _actual_pid) = match self.ftdi.open_device().await {
            Ok(pair) => pair,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "FTDI device not found",
                    format!(
                        "{e}\n\n\
                         Check the adapter is connected and udev allows access:\n\
                         echo 'SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0403\", MODE=\"0666\"' \
                         | sudo tee /etc/udev/rules.d/99-ftdi.rules && sudo udevadm control --reload",
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut ctx = match MpsseContext::init(&mut dev, self.ftdi.clock_hz).await {
            Ok(c) => c,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "MPSSE initialisation failed",
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut session = ctx.session(&mut dev)?;
        let i2c = I2cBus::new(&mut session).await?;

        let bytes = match self.register {
            Some(reg) => {
                i2c.write_read(&mut session, self.address, &[reg], self.length)
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "write-read failed for 0x{:02x} register 0x{:02x}: {e}",
                            self.address, reg
                        )
                    })?
            }
            None => {
                i2c.read(&mut session, self.address, self.length)
                    .await
                    .map_err(|e| anyhow!("read failed for 0x{:02x}: {e}", self.address))?
            }
        };

        let hex_str: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dec_str: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        let ascii_str: String = bytes
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        let reg_label = match self.register {
            Some(r) => format!(" reg 0x{r:02x}"),
            None => String::new(),
        };

        let description = format!(
            "Device 0x{:02x}{reg_label} on channel {channel} at {} Hz\n  \
             HEX:     {}\n  \
             Decimal: {}\n  \
             ASCII:   {ascii_str}",
            self.address,
            self.ftdi.clock_hz,
            hex_str.join(" "),
            dec_str.join(" "),
        );

        let evidence = format!(
            "addr=0x{:02x}{} bytes=[{}]",
            self.address,
            reg_label,
            hex_str.join(" "),
        );

        result.add(
            PluginFinding::new(
                Severity::Info,
                format!(
                    "{} byte(s) from I2C 0x{:02x}{reg_label}",
                    bytes.len(),
                    self.address
                ),
                description,
            )
            .with_evidence(evidence),
        );

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

/// Parses a hexadecimal byte string into a `u8`.
fn parse_hex_byte(s: &str) -> Result<u8> {
    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u8::from_str_radix(clean, 16).map_err(|e| anyhow!("{e}"))
}

/// Implementation of the `FtdiPlugin` trait for the I2C read plugin.
impl FtdiPlugin for I2cReadPlugin {
    fn ftdi_config(&self) -> &FtdiConfig {
        &self.ftdi
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(I2cReadPlugin::new()) as Box<dyn crate::Plugin>)
}
