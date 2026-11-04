use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::hardware::nrf52840::zigbee::{
    drain, find_nrf52840_ports, parse_sniffer_line, read_line, write_cmd,
};
use crate::plugin_meta;
use anyhow::Result;
use std::collections::HashSet;
use std::time::{Duration, Instant};

// Zigbee 2.4 GHz channel range.
const ZIGBEE_CHANNEL_MIN: u8 = 11;
const ZIGBEE_CHANNEL_MAX: u8 = 26;

// IEEE 802.15.4 MAC Frame Control Word
//
// Bits 2:0  - Frame Type
// Bit  3    - Security Enabled
// Bit  4    - Frame Pending
// Bit  5    - Acknowledge Request
// Bit  6    - PAN ID Compression
// Bits 11:10 - Destination Addressing Mode (0=none, 2=short/16-bit, 3=ext/64-bit)
// Bits 13:12 - Frame Version
// Bits 15:14 - Source Addressing Mode

const FC_FRAME_TYPE: u16 = 0x0007;
const FC_SECURITY_ENABLED: u16 = 0x0008;
const FC_PAN_COMPRESSION: u16 = 0x0040;
const FC_DAM: u16 = 0x0C00;
const FC_SAM: u16 = 0xC000;

const FRAME_TYPE_BEACON: u16 = 0;
const FRAME_TYPE_DATA: u16 = 1;
const FRAME_TYPE_MAC_CMD: u16 = 3;

const ADDR_MODE_NONE: u16 = 0;
const ADDR_MODE_SHORT: u16 = 2;
const ADDR_MODE_EXT: u16 = 3;

// MAC Command identifiers (IEEE 802.15.4-2015, table 7-1).
const MAC_CMD_ASSOC_REQUEST: u8 = 0x01;
const MAC_CMD_ASSOC_RESPONSE: u8 = 0x02;

/// Represents a parsed IEEE 802.15.4 MAC frame.
struct MacFrame {
    frame_type: u16,
    security_enabled: bool,
    dst_pan: Option<u16>,
    src_pan: Option<u16>,
    mac_cmd: Option<u8>,
}

/// Return the number of address bytes for a given addressing mode. Returns 0 for `ADDR_MODE_NONE`.
fn addr_bytes(mode: u16) -> usize {
    match mode {
        ADDR_MODE_SHORT => 2,
        ADDR_MODE_EXT => 8,
        _ => 0,
    }
}

/// Parse a raw 802.15.4 MAC frame into a `MacFrame` struct. Returns `None` if the frame is too short or malformed.
fn parse_mac_frame(data: &[u8]) -> Option<MacFrame> {
    if data.len() < 3 {
        return None;
    }
    let fc = u16::from_le_bytes([data[0], data[1]]);
    let frame_type = fc & FC_FRAME_TYPE;
    let security_enabled = (fc & FC_SECURITY_ENABLED) != 0;
    let pan_compression = (fc & FC_PAN_COMPRESSION) != 0;
    let dam = (fc & FC_DAM) >> 10;
    let sam = (fc & FC_SAM) >> 14;

    // Byte 2: sequence number.
    let mut offset = 3usize;

    let dst_pan = if dam != ADDR_MODE_NONE && data.len() >= offset + 2 {
        let pan = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2 + addr_bytes(dam);
        Some(pan)
    } else {
        if dam != ADDR_MODE_NONE {
            offset += addr_bytes(dam);
        }
        None
    };

    let src_pan = if sam != ADDR_MODE_NONE {
        if !pan_compression && data.len() >= offset + 2 {
            let pan = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2 + addr_bytes(sam);
            Some(pan)
        } else {
            offset += addr_bytes(sam);
            dst_pan
        }
    } else {
        None
    };

    let mac_cmd = if frame_type == FRAME_TYPE_MAC_CMD && data.len() > offset {
        Some(data[offset])
    } else {
        None
    };

    Some(MacFrame {
        frame_type,
        security_enabled,
        dst_pan,
        src_pan,
        mac_cmd,
    })
}

/// Per-channel capture statistics.
#[derive(Default)]
struct ChannelStats {
    total: u32,
    beacons: u32,
    data_plain: u32,
    data_secure: u32,
    assoc_requests: u32,
    assoc_responses: u32,
    pan_ids: HashSet<u16>,
}

/// Capture frames on a specific channel for a given duration and return per-channel statistics.
fn capture_channel(
    port: &mut dyn serialport::SerialPort,
    channel: u8,
    duration: Duration,
) -> Result<ChannelStats> {
    write_cmd(port, &format!("channel {channel}"))?;
    write_cmd(port, "receive")?;

    let mut stats = ChannelStats::default();
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        let line = match read_line(port) {
            Some(l) => l,
            None => continue,
        };
        let pkt = match parse_sniffer_line(&line) {
            Some(p) => p,
            None => continue,
        };

        stats.total += 1;

        if let Some(mac) = parse_mac_frame(&pkt.frame) {
            let pan = mac.dst_pan.or(mac.src_pan);
            if let Some(p) = pan {
                stats.pan_ids.insert(p);
            }
            match mac.frame_type {
                FRAME_TYPE_BEACON => {
                    stats.beacons += 1;
                }
                FRAME_TYPE_DATA => {
                    if mac.security_enabled {
                        stats.data_secure += 1;
                    } else {
                        stats.data_plain += 1;
                    }
                }
                FRAME_TYPE_MAC_CMD => match mac.mac_cmd {
                    Some(MAC_CMD_ASSOC_REQUEST) => {
                        stats.assoc_requests += 1;
                    }
                    Some(MAC_CMD_ASSOC_RESPONSE) => {
                        stats.assoc_responses += 1;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    write_cmd(port, "sleep")?;
    Ok(stats)
}

/// Add findings for a specific channel based on the captured statistics.
fn add_channel_findings(
    result: &mut PluginResult,
    port: &str,
    channel: u8,
    stats: &ChannelStats,
) {
    if stats.total == 0 {
        return;
    }

    result.add(PluginFinding::new(
        Severity::Info,
        format!("Channel {channel}: {} frame(s) captured", stats.total),
        format!(
            "Port:                 {port}\n  \
             Beacons:              {}  \n  \
             Data (encrypted):     {}\n  \
             Data (plaintext):     {}\n  \
             Association requests: {}\n  \
             PAN IDs:              {}",
            stats.beacons,
            stats.data_secure,
            stats.data_plain,
            stats.assoc_requests,
            stats.pan_ids.len(),
        ),
    ));

    if stats.data_plain > 0 {
        result.add(
            PluginFinding::new(
                Severity::High,
                format!(
                    "Unencrypted data frame(s) on channel {channel}: {}",
                    stats.data_plain
                ),
                "IEEE 802.15.4 data frames without the MAC Security Enabled bit were captured. \
                 Zigbee Pro networks encrypt at the NWK layer (AES-128 CCM*). The absence of \
                 MAC-layer security may indicate a legacy device, a misconfigured network \
                 segment or a network operating without link-layer encryption.",
            )
            .with_evidence(format!(
                "plaintext: {} / total data: {}",
                stats.data_plain,
                stats.data_plain + stats.data_secure,
            )),
        );
    }

    if stats.assoc_requests > 0 {
        result.add(
            PluginFinding::new(
                Severity::Medium,
                format!(
                    "Device join observed on channel {channel}: {} association request(s)",
                    stats.assoc_requests
                ),
                "MAC-layer association requests were captured, indicating devices are actively \
                 joining the network. In Zigbee networks without a per-device Trust Centre \
                 link key, the network key is transported in cleartext during the join \
                 procedure and can be extracted from the captured traffic. Disable \
                 permit-join outside of provisioning windows.",
            )
            .with_evidence(format!(
                "association requests: {}, responses: {}",
                stats.assoc_requests, stats.assoc_responses,
            )),
        );
    }

    for &pan in &stats.pan_ids {
        if pan == 0x1234 {
            result.add(PluginFinding::new(
                Severity::High,
                format!("Default PAN ID 0x1234 on channel {channel}"),
                "PAN ID 0x1234 is the factory default for many Zigbee stacks. An unchanged \
                 PAN ID makes the network trivially targetable. Replace it with a randomly \
                 generated value.",
            ));
        } else if pan == 0xFFFF {
            result.add(PluginFinding::new(
                Severity::Medium,
                format!("Broadcast PAN ID 0xFFFF on channel {channel}"),
                "PAN ID 0xFFFF is the IEEE 802.15.4 broadcast address and must not be used \
                 as a network PAN ID.",
            ));
        }
    }
}

/// nRF52840 Zigbee sniffer plugin.
pub struct Nrf52840SnifferPlugin {
    port: String,
    channel: u8,
    scan_all: bool,
    duration_ms: u64,
    timeout_ms: u64,
}

/// nRF52840 Zigbee sniffer plugin implementation.
impl Nrf52840SnifferPlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            channel: 15,
            scan_all: false,
            duration_ms: 5_000,
            timeout_ms: 200,
        }
    }
}

/// Default implementation for the nRF52840 Zigbee sniffer plugin.
impl Default for Nrf52840SnifferPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for the nRF52840 Zigbee sniffer.
impl Plugin for Nrf52840SnifferPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Passively capture IEEE 802.15.4/Zigbee frames via an nRF52840 sniffer dongle",
            description: "Uses a Nordic Semiconductor nRF52840 USB dongle running the nRF Sniffer \
                          for 802.15.4 firmware to passively capture IEEE 802.15.4/Zigbee frames. \
                          The firmware exposes a text shell over USB CDC-ACM. This plugin sends \
                          'channel N' and 'receive' commands and parses the 'received: \
                          HEX power: RSSI lqi: LQI time: TS' output lines. \
                          Auto-detects the dongle by Nordic USB VID/PID (1915) via Linux sysfs. \
                          Recognized PIDs: 520F (application), CA37 (bootloader), 154A (nRF52 USB \
                          Product), 154B (nRF Sniffer firmware). Use --port to override auto-detection. \
                          Captures on a single channel (default 15) or all 16 Zigbee channels (11-26) \
                          when --scan-all is set. Reports unencrypted data frames (MAC security bit \
                          absent), device association events (network join windows) and default PAN IDs.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "Serial port of the nRF52840 sniffer dongle (e.g., /dev/ttyACM0). \
                           Omit to auto-detect by USB VID/PID via sysfs.",
                    value_name: "PORT",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "channel",
                    short: Some('c'),
                    help: "IEEE 802.15.4 channel to sniff (11-26). Ignored when --scan-all is set.",
                    value_name: "CH",
                    default: Some("15"),
                    is_flag: false,
                },
                CliArg {
                    name: "scan_all",
                    short: Some('a'),
                    help: "Scan all 16 Zigbee channels (11-26) sequentially, \
                           spending duration_ms/16 on each.",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
                CliArg {
                    name: "duration_ms",
                    short: Some('d'),
                    help: "Total capture duration in milliseconds. \
                           When --scan-all is set this is split evenly across all 16 channels.",
                    value_name: "MS",
                    default: Some("5000"),
                    is_flag: false,
                },
                CliArg {
                    name: "timeout_ms",
                    short: Some('t'),
                    help: "Per-read serial timeout (ms). Controls how quickly the capture \
                           loop reacts to the deadline between received frames.",
                    value_name: "MS",
                    default: Some("200"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration. Parses command-line arguments and validates them.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.get_or("port", "");
        self.channel = config.parse_or("channel", 15u8);
        self.scan_all = config.get("scan_all") == Some("true");
        self.duration_ms = config.parse_or("duration_ms", 5_000u64);
        self.timeout_ms = config.parse_or("timeout_ms", 200u64);

        if self.channel < ZIGBEE_CHANNEL_MIN || self.channel > ZIGBEE_CHANNEL_MAX {
            anyhow::bail!(
                "channel {} is out of range. Zigbee channels are 11-26",
                self.channel
            );
        }
        Ok(())
    }

    /// Execute the plugin logic. Opens the sniffer dongle, configures it and starts capturing frames.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let port_name = if self.port.is_empty() {
            let mut candidates = find_nrf52840_ports();
            if candidates.is_empty() {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No nRF52840 sniffer dongle detected",
                    "No device with Nordic Semiconductor USB VID 0x1915 and a recognized PID \
                     (520F, CA37, 154A, 154B) was found in /dev/. Flash the dongle with the \
                     nRF Sniffer for 802.15.4 firmware and reconnect or use --port to \
                     specify the port directly.",
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
            candidates.remove(0)
        } else {
            self.port.clone()
        };

        result.add(PluginFinding::new(
            Severity::Info,
            format!("nRF52840 sniffer dongle opened: {port_name}"),
            format!(
                "Capture duration: {} ms\n  \
                 Mode: {}",
                self.duration_ms,
                if self.scan_all {
                    "all channels 11-26".to_string()
                } else {
                    format!("channel {}", self.channel)
                }
            ),
        ));

        // Baud rate is a virtual setting for USB CDC-ACM. Any value opens the port.
        let per_read_timeout = Duration::from_millis(self.timeout_ms);
        let mut port = match serialport::new(&port_name, 115_200)
            .timeout(per_read_timeout)
            .open()
        {
            Ok(p) => p,
            Err(e) => {
                let hint = if e.to_string().contains("No such file") {
                    " The dongle uses CDC-ACM and appears as /dev/ttyACM*. \
                     Run `iottack uart port-scan` to list available serial ports."
                } else {
                    " Check read/write permission on the port \
                     (add your user to the `dialout` group or run with sudo)."
                };
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open {port_name}"),
                    format!("{e}.{hint}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        // Wake the firmware, stop any previous capture, suppress echo, drain output.
        let _ = write_cmd(port.as_mut(), "");
        let _ = write_cmd(port.as_mut(), "sleep");
        let _ = write_cmd(port.as_mut(), "shell echo off");
        drain(port.as_mut(), 150);

        let channels: Vec<u8> = if self.scan_all {
            (ZIGBEE_CHANNEL_MIN..=ZIGBEE_CHANNEL_MAX).collect()
        } else {
            vec![self.channel]
        };

        let per_channel_ms = self.duration_ms / channels.len() as u64;
        let per_channel_duration = Duration::from_millis(per_channel_ms.max(100));

        let mut total_frames = 0u32;
        let mut all_pans: HashSet<u16> = HashSet::new();
        let mut channels_with_traffic: Vec<u8> = Vec::new();

        for &ch in &channels {
            match capture_channel(port.as_mut(), ch, per_channel_duration) {
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Capture error on channel {ch}"),
                        e.to_string(),
                    ));
                }
                Ok(ref stats) => {
                    total_frames += stats.total;
                    all_pans.extend(&stats.pan_ids);
                    if stats.total > 0 {
                        channels_with_traffic.push(ch);
                    }
                    add_channel_findings(&mut result, &port_name, ch, stats);
                }
            }
        }

        if total_frames == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                "No IEEE 802.15.4 frames captured",
                "No traffic was observed on the configured channel(s). Check that Zigbee \
                 devices are active nearby or use --scan-all to search all 16 channels.",
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!(
                    "Capture complete: {total_frames} frame(s) across {} channel(s)",
                    channels_with_traffic.len()
                ),
                format!(
                    "Active channels: {}    \n  \
                     Unique PAN IDs: {}",
                    if channels_with_traffic.is_empty() {
                        "none".to_string()
                    } else {
                        channels_with_traffic
                            .iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    all_pans.len(),
                ),
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(Nrf52840SnifferPlugin::new()) as Box<dyn crate::Plugin>)
}
