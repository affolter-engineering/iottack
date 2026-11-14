use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::{anyhow, Result};
use ftdi_nusb::{
    blocking,
    types::{DataBits, FlowControl, Interface, Parity, StopBits},
};
use std::thread;
use std::time::Duration;

const AUTO_PIDS: &[u16] = &[0x6001, 0x6010, 0x6011, 0x6014, 0x6015];

/// Auto-detectable FTDI product IDs for 1-Wire scanning
pub struct OneWireScanPlugin {
    vid: u16,
    pid: Option<u16>,
    interface: Interface,
    read_temp: bool,
}

/// OneWireScanPlugin is responsible for scanning 1-Wire devices connected via an FTDI UART interface.
impl OneWireScanPlugin {
    pub fn new() -> Self {
        Self {
            vid: 0x0403,
            pid: None,
            interface: Interface::A,
            read_temp: false,
        }
    }
}

/// Default implementation for OneWireScanPlugin
impl Default for OneWireScanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for OneWireScanPlugin
impl Plugin for OneWireScanPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate 1-Wire devices via FTDI UART (TX/RX loopback method)",
            description: "Uses the FTDI UART TX/RX lines connected to the 1-Wire DQ line via a \
                          4.7 kOhm pull-up resistor. Reports each device's ROM code, family type, \
                          and security relevance. Optionally reads temperature from DS18B20 \
                          sensors. Wiring: connect TX and RX together to DQ, add 4.7 kOhm \
                          pull-up to VCC (3.3 V or 5 V)",
            needs_root: false,
            args: &[
                CliArg {
                    name: "vid",
                    short: None,
                    help: "USB vendor ID in HEX (default: 0403)",
                    value_name: "HEX",
                    default: Some("0403"),
                    is_flag: false,
                },
                CliArg {
                    name: "pid",
                    short: None,
                    help: "USB product ID in HEX (6001=FT232R, 6010=FT2232H, 6011=FT4232H, 6014=FT232H). Omit to auto-detect",
                    value_name: "HEX",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "channel",
                    short: Some('c'),
                    help: "FTDI channel to use: A, B, C or D",
                    value_name: "CHANNEL",
                    default: Some("A"),
                    is_flag: false,
                },
                CliArg {
                    name: "temp",
                    short: Some('t'),
                    help: "Read temperature from DS18B20 sensors (adds ca. 750 ms per sensor)",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
            ],
        )
    }

    /// Initialize the OneWireScanPlugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        let vid_str = config.get_or("vid", "0403");
        self.vid = u16::from_str_radix(
            vid_str.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        )
        .map_err(|_| anyhow!("invalid VID '{vid_str}'. Expected HEX like 0403 or 0x0403"))?;

        self.pid = match config.get("pid") {
            None => None,
            Some(s) => Some(
                u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .map_err(|_| anyhow!("invalid PID '{s}'. Expected HEX like 6011 or 0x6011"))?,
            ),
        };

        let channel_str = config.get_or("channel", "A").to_uppercase();
        self.interface = match channel_str.as_str() {
            "A" => Interface::A,
            "B" => Interface::B,
            "C" => Interface::C,
            "D" => Interface::D,
            other => return Err(anyhow!("unknown channel '{other}'; use A, B, C or D")),
        };

        self.read_temp = config.get("temp").is_some();

        Ok(())
    }

    /// Execute the 1-Wire scan and return the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let channel_desc = match self.interface {
            Interface::A | Interface::Any => "channel A",
            Interface::B => "channel B",
            Interface::C => "channel C",
            Interface::D => "channel D",
        };

        let dev = match open_ftdi(self.vid, self.pid, self.interface) {
            Ok(d) => d,
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

        let mut ow = match OneWireBus::new(dev) {
            Ok(b) => b,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "1-Wire bus initialisation failed",
                    format!("Failed to configure FTDI UART for 1-Wire: {e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        // Probe first to give a targeted diagnostic before the full ROM search.
        match ow.reset()? {
            ResetResult::NoEcho => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "1-Wire bus not detected - TX/RX loopback missing",
                    format!(
                        "No echo received on {channel_desc}. \
                         The FTDI TX pin is not reaching the RX pin.\n\n\
                         Wiring: short TX and RX together on the DQ line, then add a \
                         4.7 kOhm pull-up from DQ to VCC (3.3 V or 5 V).\n\
                         FT232H pins: TXD = ADBUS0, RXD = ADBUS1."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
            ResetResult::NoPresence => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No 1-Wire devices found",
                    format!(
                        "TX/RX loopback is working on {channel_desc} but no device \
                         pulled the line low (no presence pulse).\n\n\
                         Check: device is powered (VCC and GND connected), DQ is \
                         connected to the same node as TX and RX, \
                         4.7 kOhm pull-up to VCC is in place."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
            ResetResult::Presence => {}
        }

        let roms = match search_rom(&mut ow) {
            Ok(r) => r,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "1-Wire ROM search failed",
                    format!("Error during ROM search: {e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        if roms.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No 1-Wire devices found after presence pulse",
                "Presence pulse detected but ROM search returned no valid devices. \
                 Check for CRC errors (noise/timing) or try without --temp."
                    .to_string(),
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} 1-Wire device(s) found on {channel_desc}", roms.len()),
            format!(
                "Completed ROM search on {channel_desc}. Found {} device(s).",
                roms.len()
            ),
        ));

        for rom in &roms {
            let family = rom[0];
            let serial_bytes = &rom[1..7];
            let crc_byte = rom[7];
            let rom_hex = rom
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            let serial_hex = serial_bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            let name = family_name(family);

            let severity = match family {
                0x10 | 0x28 | 0x26 | 0x42 => Severity::Info,
                0x01 => Severity::Low,
                0x14 | 0x23 | 0x2D | 0x1D => Severity::Medium,
                _ => Severity::Info,
            };

            let security_note = match family {
                0x01 => "\n  Security note: DS2401 provides identity without challenge-response; \
                          the serial number is cloneable.",
                0x14 | 0x23 | 0x2D | 0x1D => "\n  Security note: memory device - may contain \
                          credentials, keys, or configuration data.",
                _ => "",
            };

            let mut temp_line = String::new();
            if self.read_temp && family == 0x28 {
                match read_ds18b20_temp(&mut ow, rom) {
                    Ok(t) => temp_line = format!("\n  Temperature: {t:.2} °C"),
                    Err(e) => temp_line = format!("\n  Temperature read failed: {e}"),
                }
            }

            let description = format!(
                "Family: {:02X}h ({})\n  Serial: {}\n  CRC: {:02X}h{}{}",
                family, name, serial_hex, crc_byte, temp_line, security_note
            );

            let evidence = format!(
                "family={:02X}h serial={} crc={:02X}h",
                family, serial_hex, crc_byte
            );

            result.add(
                PluginFinding::new(
                    severity,
                    format!("1-Wire device: {name} [ROM: {rom_hex}]"),
                    description,
                )
                .with_evidence(evidence),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

enum ResetResult {
    /// No echo received — TX is not reaching RX (wiring issue).
    NoEcho,
    /// Echo received but line stayed high — loopback works, no device present.
    NoPresence,
    /// Presence pulse detected — at least one device is on the bus.
    Presence,
}

/// Represents a 1-Wire bus connected via an FTDI UART interface. Provides low-level operations
struct OneWireBus {
    dev: blocking::FtdiDevice,
}

/// Initialize a new OneWireBus instance with the given FTDI device. Sets up the device for 1-Wire communication.
impl OneWireBus {
    fn new(mut dev: blocking::FtdiDevice) -> Result<Self> {
        dev.set_latency_timer(1)
            .map_err(|e| anyhow!("set_latency_timer: {e}"))?;
        dev.set_line_property(DataBits::Eight, StopBits::One, Parity::None)
            .map_err(|e| anyhow!("set_line_property: {e}"))?;
        // Disable hardware flow control — CTS/RTS may be enabled in EEPROM,
        // which would block TX unless CTS is asserted.
        dev.set_flow_control(FlowControl::Disabled)
            .map_err(|e| anyhow!("set_flow_control: {e}"))?;
        dev.set_baudrate(115200)
            .map_err(|e| anyhow!("set_baudrate 115200: {e}"))?;
        dev.flush_all()
            .map_err(|e| anyhow!("flush_all: {e}"))?;
        Ok(Self { dev })
    }

    fn reset(&mut self) -> Result<ResetResult> {
        self.dev
            .set_baudrate(9600)
            .map_err(|e| anyhow!("set_baudrate 9600: {e}"))?;
        self.dev
            .flush_rx()
            .map_err(|e| anyhow!("flush_rx before reset: {e}"))?;
        self.dev
            .write_all(&[0xF0])
            .map_err(|e| anyhow!("write reset pulse: {e}"))?;

        let mut buf = [0u8; 1];
        let mut received = 0usize;
        for _ in 0..15 {
            match self.dev.read_data(&mut buf) {
                Ok(n) if n > 0 => {
                    received += n;
                    break;
                }
                _ => thread::sleep(Duration::from_millis(2)),
            }
        }

        self.dev
            .set_baudrate(115200)
            .map_err(|e| anyhow!("set_baudrate 115200 after reset: {e}"))?;

        if received == 0 {
            return Ok(ResetResult::NoEcho);
        }
        let echo = buf[0];
        if echo == 0xF0 || echo == 0x00 {
            Ok(ResetResult::NoPresence)
        } else {
            Ok(ResetResult::Presence)
        }
    }

    fn write_bit(&mut self, bit: bool) -> Result<()> {
        let byte = if bit { 0xFFu8 } else { 0x00u8 };
        self.dev
            .write_all(&[byte])
            .map_err(|e| anyhow!("write_bit write: {e}"))?;
        let mut buf = [0u8; 1];
        for _ in 0..15 {
            match self.dev.read_data(&mut buf) {
                Ok(n) if n > 0 => return Ok(()),
                _ => thread::sleep(Duration::from_millis(2)),
            }
        }
        Ok(())
    }

    fn read_bit(&mut self) -> Result<bool> {
        self.dev
            .write_all(&[0xFF])
            .map_err(|e| anyhow!("read_bit write: {e}"))?;
        let mut buf = [0u8; 1];
        for _ in 0..15 {
            match self.dev.read_data(&mut buf) {
                Ok(n) if n > 0 => return Ok(buf[0] == 0xFF),
                _ => thread::sleep(Duration::from_millis(2)),
            }
        }
        Ok(false)
    }

    fn write_byte(&mut self, byte: u8) -> Result<()> {
        let mut tx = [0u8; 8];
        for i in 0..8 {
            tx[i] = if (byte >> i) & 1 == 1 { 0xFF } else { 0x00 };
        }
        self.dev
            .write_all(&tx)
            .map_err(|e| anyhow!("write_byte write: {e}"))?;

        let mut echo = [0u8; 8];
        let mut collected = 0usize;
        for _ in 0..20 {
            match self.dev.read_data(&mut echo[collected..]) {
                Ok(n) => {
                    collected += n;
                    if collected >= 8 {
                        return Ok(());
                    }
                }
                Err(_) => {}
            }
            if collected < 8 {
                thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        let tx = [0xFFu8; 8];
        self.dev
            .write_all(&tx)
            .map_err(|e| anyhow!("read_byte write: {e}"))?;

        let mut echo = [0u8; 8];
        let mut collected = 0usize;
        for _ in 0..20 {
            match self.dev.read_data(&mut echo[collected..]) {
                Ok(n) => {
                    collected += n;
                    if collected >= 8 {
                        break;
                    }
                }
                Err(_) => {}
            }
            if collected < 8 {
                thread::sleep(Duration::from_millis(2));
            }
        }

        let mut result = 0u8;
        for (i, &b) in echo.iter().enumerate().take(8) {
            if b == 0xFF {
                result |= 1 << i;
            }
        }
        Ok(result)
    }
}

/// Search for all 1-Wire devices on the bus and return their ROM codes.
fn search_rom(ow: &mut OneWireBus) -> Result<Vec<[u8; 8]>> {
    let mut roms: Vec<[u8; 8]> = Vec::new();
    let mut last_discrepancy: u8 = 0;
    let mut rom = [0u8; 8];

    loop {
        if !matches!(ow.reset()?, ResetResult::Presence) {
            break;
        }

        ow.write_byte(0xF0)?;

        let mut last_zero: u8 = 0;

        for i in 0..64u8 {
            let id_bit = ow.read_bit()?;
            let cmp_id_bit = ow.read_bit()?;

            if id_bit && cmp_id_bit {
                break;
            }

            let direction = if !id_bit && !cmp_id_bit {
                let dir = if i < last_discrepancy {
                    (rom[(i / 8) as usize] >> (i % 8)) & 1 == 1
                } else if i == last_discrepancy {
                    true
                } else {
                    false
                };
                // Track the last bit where we chose 0; that's where the next
                // search pass must branch right to enumerate the next device.
                if !dir {
                    last_zero = i;
                }
                dir
            } else {
                id_bit
            };

            if direction {
                rom[(i / 8) as usize] |= 1 << (i % 8);
            } else {
                rom[(i / 8) as usize] &= !(1 << (i % 8));
            }

            ow.write_bit(direction)?;
        }

        if crc8(&rom) == 0 {
            roms.push(rom);
        }

        last_discrepancy = last_zero;

        if last_discrepancy == 0 || roms.len() >= 20 {
            break;
        }
    }

    Ok(roms)
}

/// Compute the CRC8 of the given data slice using the Dallas/Maxim 1-Wire polynomial.
fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &b in data {
        let mut byte = b;
        for _ in 0..8 {
            let mix = (crc ^ byte) & 0x01;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0x8C;
            }
            byte >>= 1;
        }
    }
    crc
}

/// Read the temperature from a DS18B20 sensor with the given ROM code.
fn read_ds18b20_temp(ow: &mut OneWireBus, rom: &[u8; 8]) -> Result<f32> {
    if !matches!(ow.reset()?, ResetResult::Presence) {
        return Err(anyhow!("no presence pulse before CONVERT T"));
    }
    ow.write_byte(0x55)?;
    for &b in rom {
        ow.write_byte(b)?;
    }
    ow.write_byte(0x44)?;

    thread::sleep(Duration::from_millis(750));

    if !matches!(ow.reset()?, ResetResult::Presence) {
        return Err(anyhow!("no presence pulse before READ SCRATCHPAD"));
    }
    ow.write_byte(0x55)?;
    for &b in rom {
        ow.write_byte(b)?;
    }
    ow.write_byte(0xBE)?;

    let mut scratch = [0u8; 9];
    for b in scratch.iter_mut() {
        *b = ow.read_byte()?;
    }

    let raw = i16::from_le_bytes([scratch[0], scratch[1]]);
    Ok(raw as f32 / 16.0)
}

/// Return the human-readable family name for a given 1-Wire device family code.
fn family_name(code: u8) -> &'static str {
    match code {
        0x01 => "DS2401 (Silicon Serial Number)",
        0x10 => "DS18S20 (Temperature Sensor)",
        0x14 => "DS2430A (256-bit 1-Wire EEPROM)",
        0x1D => "DS2423 (4 kbit RAM & Counter)",
        0x23 => "DS2433 (4 kbit EEPROM)",
        0x26 => "DS2438 (Smart Battery Monitor)",
        0x28 => "DS18B20 (Temperature Sensor)",
        0x2D => "DS2431 (1kbit EEPROM)",
        0x36 => "DS2740 (High-Precision Coulomb Counter)",
        0x3A => "DS2413 (2-channel Addressable Switch)",
        0x41 => "DS2422/DS2423 (Thermochron/Counter)",
        0x42 => "DS28EA00 (Programmable Resolution Temperature Sensor)",
        _ => "Unknown",
    }
}

/// Open an FTDI device with the given vendor ID, optional product ID, and interface. Returns a blocking FTDI device instance.
fn open_ftdi(vid: u16, pid: Option<u16>, iface: Interface) -> Result<blocking::FtdiDevice> {
    match pid {
        Some(p) => blocking::FtdiDevice::open_with_interface(vid, p, iface)
            .map_err(|e| {
                anyhow!(
                    "failed to open FTDI {:04x}:{:04x}: {e}. \
                     Check udev rules: \
                     echo 'SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"{:04x}\", MODE=\"0666\"' \
                     | sudo tee /etc/udev/rules.d/99-ftdi.rules && sudo udevadm control --reload",
                    vid, p, vid
                )
            }),
        None => {
            let mut wrong_iface_pid: Option<u16> = None;
            for &p in AUTO_PIDS {
                match blocking::FtdiDevice::open_with_interface(vid, p, iface) {
                    Ok(dev) => return Ok(dev),
                    Err(ftdi_nusb::Error::DeviceNotFound) => {}
                    Err(_) => {
                        // Device is present but the requested channel doesn't exist
                        // (e.g. --channel B on a single-channel FT232H).
                        wrong_iface_pid = Some(p);
                    }
                }
            }
            if let Some(p) = wrong_iface_pid {
                Err(anyhow!(
                    "FTDI {:04x}:{:04x} found but channel {:?} does not exist on this device. \
                     FT232H is single-channel; use --channel A or omit --channel.",
                    vid, p, iface
                ))
            } else {
                Err(anyhow!(
                    "no FTDI adapter found on VID {:04x} (tried: {}). \
                     Connect an adapter or pass --pid to select one explicitly.",
                    vid,
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

inventory::submit! {
    crate::PluginFactory(|| Box::new(OneWireScanPlugin::new()) as Box<dyn crate::Plugin>)
}
