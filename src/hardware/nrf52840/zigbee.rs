//! nRF52840-based IEEE 802.15.4/Zigbee passive sniffer plugin.
//!
//! Uses a Nordic Semiconductor nRF52840 USB dongle running the nRF Sniffer for
//! 802.15.4 firmware to passively capture IEEE 802.15.4 / Zigbee frames on one
//! or all Zigbee channels (11–26).  Analyses captured MAC frames for security
//! weaknesses: unencrypted data frames, device association events, and default
//! PAN IDs.  Auto-detects dongles by Nordic USB VID/PID via Linux sysfs.
//!
//! Compatible firmware: Nordic Semiconductor nRF Sniffer for 802.15.4
//!   https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4
//!
//! Known USB identifiers (VID 1915, Nordic Semiconductor ASA):
//!   1915:520F  nRF52840 Dongle (application mode)
//!   1915:CA37  nRF52840 Dongle (bootloader mode)
//!   1915:154A  nRF52 USB Product (e.g. Bus 001 Device 061)
//!   1915:154B  nRF Sniffer for 802.15.4 (official firmware PID)

use anyhow::Result;
use std::time::{Duration, Instant};

pub const NORDIC_VID: &str = "1915";
pub const NRF52840_PID: &str = "520f";
pub const NRF52840_BL_PID: &str = "ca37";
pub const NRF52_GENERIC_PID: &str = "154a";
pub const NRF52_SNIFFER_PID: &str = "154b";

/// Returns the value of a USB attribute for a given TTY device from sysfs or `None` if it cannot be read.
pub fn sysfs_usb_attr(tty_name: &str, attr: &str) -> Option<String> {
    let link = format!("/sys/class/tty/{tty_name}/device");
    let dev = std::fs::canonicalize(&link).ok()?;
    for candidate in [dev.join(attr), dev.parent()?.join(attr)] {
        if let Ok(v) = std::fs::read_to_string(&candidate) {
            return Some(v.trim().to_lowercase().to_string());
        }
    }
    None
}

/// Finds all connected nRF52840 ports by checking USB vendor and product IDs via sysfs.
pub fn find_nrf52840_ports() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/dev") else {
        return Vec::new();
    };
    let mut found: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("ttyACM") && !name.starts_with("ttyUSB") {
                return None;
            }
            let vid = sysfs_usb_attr(&name, "idVendor").unwrap_or_default();
            let pid = sysfs_usb_attr(&name, "idProduct").unwrap_or_default();
            if vid == NORDIC_VID
                && (pid == NRF52840_PID
                    || pid == NRF52840_BL_PID
                    || pid == NRF52_GENERIC_PID
                    || pid == NRF52_SNIFFER_PID)
            {
                Some(format!("/dev/{name}"))
            } else {
                None
            }
        })
        .collect();
    found.sort();
    found
}

/// Writes a command to the serial port, appending CRLF.
pub fn write_cmd(port: &mut dyn serialport::SerialPort, cmd: &str) -> Result<()> {
    let mut line = cmd.as_bytes().to_vec();
    line.extend_from_slice(b"\r\n");
    port.write_all(&line)?;
    port.flush()?;
    Ok(())
}

/// Reads a line from the serial port, stripping the trailing CR if present.
pub fn read_line(port: &mut dyn serialport::SerialPort) -> Option<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match port.read_exact(&mut b) {
            Ok(()) => {
                if b[0] == b'\n' {
                    return Some(
                        String::from_utf8_lossy(&buf)
                            .trim_end_matches('\r')
                            .to_string(),
                    );
                }
                buf.push(b[0]);
            }
            Err(_) => {
                return if buf.is_empty() {
                    None
                } else {
                    Some(
                        String::from_utf8_lossy(&buf)
                            .trim_end_matches('\r')
                            .to_string(),
                    )
                };
            }
        }
    }
}

/// Drains the serial port for the specified duration in milliseconds, discarding any incoming lines.
pub fn drain(port: &mut dyn serialport::SerialPort, drain_ms: u64) {
    let deadline = Instant::now() + Duration::from_millis(drain_ms);
    while Instant::now() < deadline {
        if read_line(port).is_none() {
            break;
        }
    }
}

// "received: <HEX> power: <RSSI> lqi: <LQI> time: <TS>"
//
// The firmware includes the 2-byte FCS at the end of the hex string. Strip it
// (last 4 hex chars) before delivering to callers, matching nrf802154_sniffer.py.
// The timestamp is microseconds since device boot (signed, may wrap at ~71 min).

pub struct SniffLine {
    pub frame: Vec<u8>,
    pub rssi: i32,
    pub lqi: u8,
    pub sniffer_us: i64,
}

fn word_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = line[start..].trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace())
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Parses a sniffer output line into a `SniffLine`. Returns `None` if the line is not a valid sniffer frame.
pub fn parse_sniffer_line(line: &str) -> Option<SniffLine> {
    if !line.contains("received:") {
        return None;
    }
    let hex = word_after(line, "received:")?;
    let rssi: i32 = word_after(line, "power:")?.parse().ok()?;
    let lqi: u8 = word_after(line, "lqi:")?.parse().ok()?;
    let sniffer_us: i64 = word_after(line, "time:")?.parse().ok()?;
    let hex_no_fcs = hex.get(..hex.len().saturating_sub(4))?;
    let frame = decode_hex(hex_no_fcs)?;
    Some(SniffLine {
        frame,
        rssi,
        lqi,
        sniffer_us,
    })
}
