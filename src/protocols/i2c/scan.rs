use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::hardware::ftdi::{FtdiConfig, FtdiPlugin};
use crate::hardware::ftdi::config::MpsseMode;
use anyhow::Result;
use ftdi_nusb::{
    mpsse::{i2c::I2cBus, MpsseContext},
    types::Interface,
};

/// Probes all valid 7-bit I2C addresses via an FTDI MPSSE adapter.
pub struct I2cScanPlugin {
    config: FtdiConfig,
}

/// I2C scan plugin using an FTDI MPSSE adapter.
impl I2cScanPlugin {
    pub fn new() -> Self {
        Self {
            config: FtdiConfig::default(),
        }
    }
}

/// Default implementation for `I2cScanPlugin`.
impl Default for I2cScanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for `I2cScanPlugin`.
impl Plugin for I2cScanPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Scan for I2C devices via an FTDI MPSSE adapter",
            description: "Probes all 112 valid 7-bit I2C addresses (0x08-0x77) by sending a \
                          zero-byte write and checking for ACK. Requires an FTDI FT232H, \
                          FT2232H or FT4232H adapter. Only channels A and B support MPSSE \
                          (I2C/SPI/JTAG); channels C and D are UART-only. Wiring: \
                          SCL -> AD0, SDA -> AD1 and AD2 shorted together (add 4.7 kΩ pull-ups \
                          to VCC). On Linux, add a udev rule: \
                          SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0403\", MODE=\"0666\"",
            needs_root: false,
            args: &[
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
                    help: "I2C clock frequency in Hz (100000 = 100 kHz, 400000 = 400 kHz)",
                    value_name: "HZ",
                    default: Some("100000"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = FtdiConfig::from_plugin_config(config, MpsseMode::I2c)?;
        Ok(())
    }

    /// Execute the plugin's main logic.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.scan())
    }
}

/// I2C scan logic for the plugin. Probes all valid 7-bit I2C addresses on the bus.
impl I2cScanPlugin {
    async fn scan(&self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let channel = match self.config.interface {
            Interface::A => "A",
            Interface::B => "B",
            Interface::C => "C",
            Interface::D => "D",
            _ => "?",
        };

        let (mut dev, actual_pid) = match self.config.open_device().await {
            Ok(pair) => pair,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "FTDI device not found",
                    format!(
                        "{e}\n\n\
                         Check that the adapter is connected and that udev allows access:\n\
                         echo 'SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0403\", MODE=\"0666\"' \
                         | sudo tee /etc/udev/rules.d/99-ftdi.rules && sudo udevadm control --reload",
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut ctx = match MpsseContext::init(&mut dev, self.config.clock_hz).await {
            Ok(c) => c,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "MPSSE initialisation failed",
                    format!(
                        "Failed to initialise MPSSE on channel {channel} at {} Hz: {e}",
                        self.config.clock_hz
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut session = ctx.session(&mut dev)?;
        let i2c = I2cBus::new(&mut session).await?;

        // 7-bit I2C address space: 0x00-0x07 and 0x78-0x7F are reserved.
        let mut found: Vec<u8> = Vec::new();
        for addr in 0x08u8..=0x77 {
            match i2c.write(&mut session, addr, &[]).await {
                Ok(_) => {
                    tracing::debug!(addr = format!("0x{addr:02x}"), "I2C ACK");
                    found.push(addr);
                }
                Err(e) => {
                    tracing::trace!(addr = format!("0x{addr:02x}"), "I2C probe: {e}");
                }
            }
        }

        if found.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No I2C devices found",
                format!(
                    "No devices responded on channel {channel} (scanned 0x08-0x77 at {} Hz). \
                     Check wiring, pull-up resistors (4.7 kΩ to VCC) and target power.",
                    self.config.clock_hz
                ),
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("{} I2C device(s) found on channel {channel}", found.len()),
                format!(
                    "Scanned addresses 0x08-0x77 at {} Hz on FTDI {:04x}:{:04x} channel {channel}.",
                    self.config.clock_hz, self.config.vid, actual_pid,
                ),
            ));
            for addr in &found {
                let hint = i2c_device_hint(*addr);
                result.add(
                    PluginFinding::new(
                        Severity::Medium,
                        format!("I2C device at 0x{addr:02x}"),
                        format!(
                            "Address 0x{addr:02x} (decimal {addr}) responded with ACK.\n  Likely: {hint}"
                        ),
                    )
                    .with_evidence(format!("addr=0x{addr:02x} hint=\"{hint}\"")),
                );
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

/// Provide a human-readable hint for the likely type of I2C device at the given address.
fn i2c_device_hint(addr: u8) -> &'static str {
    match addr {
        0x18 | 0x19 => "LIS3DH/LIS2DH accelerometer",
        0x1C | 0x1D => "MMA8452/FXOS8700 accelerometer",
        0x1E | 0x1F => "HMC5883L/MAG3110 magnetometer",
        0x20..=0x27 => "PCF8574/MCP23017 GPIO expander",
        0x28 | 0x29 => "BNO055 IMU/BMP085 pressure",
        0x2A..=0x2F => "CAP1xxx capacitive sensor",
        0x38..=0x3B => "PCF8574A GPIO expander/AHT10 humidity",
        0x3C | 0x3D => "SSD1306/SH1106 OLED display",
        0x3E | 0x3F => "PCF8574A GPIO expander",
        0x40 | 0x41 => "INA219 power monitor/PCA9685 PWM",
        0x44 | 0x45 => "SHT30/SHT31/SHT35 humidity & temperature",
        0x48..=0x4B => "ADS1115 ADC/TMP102 temperature",
        0x4C..=0x4F => "LM75/TMP75/PCT2075 temperature",
        0x50..=0x57 => "24Cxx I2C EEPROM",
        0x5C | 0x5D => "BH1750 ambient light sensor/AM2320",
        0x60..=0x67 => "PCA9685 PWM driver/MPL3115 barometer",
        0x68 | 0x69 => "MPU-6050/9250 IMU/DS3231/DS1307 RTC",
        0x70..=0x75 => "TCA9548A/PCA9548 I2C mux",
        0x76 | 0x77 => "BMP280/BME280/BMP388 pressure sensor",
        _ => "Unknown",
    }
}

/// Implement the `FtdiPlugin` trait for the I2C scan plugin.
impl FtdiPlugin for I2cScanPlugin {
    fn ftdi_config(&self) -> &FtdiConfig {
        &self.config
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(I2cScanPlugin::new()) as Box<dyn crate::Plugin>)
}
