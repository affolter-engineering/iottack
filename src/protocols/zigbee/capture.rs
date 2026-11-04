use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::hardware::nrf52840::zigbee::{
    drain, find_nrf52840_ports, parse_sniffer_line, read_line, SniffLine, write_cmd,
};
use crate::plugin_meta;
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Global header (24 bytes):
//   magic       u32 LE  0xa1b2c3d4  (microsecond timestamps)
//   ver_major   u16 LE  2
//   ver_minor   u16 LE  4
//   thiszone    i32 LE  0           (UTC)
//   sigfigs     u32 LE  0
//   snaplen     u32 LE  65535
//   network     u32 LE  230         (DLT_IEEE802_15_4_NOFCS)
//
// Per-packet record (16-byte header + frame bytes):
//   ts_sec      u32 LE
//   ts_usec     u32 LE
//   incl_len    u32 LE  (= orig_len; no truncation)
//   orig_len    u32 LE
//   frame data

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_DLT_IEEE802_15_4_NOFCS: u32 = 230;

const ZIGBEE_CHANNEL_MIN: u8 = 11;
const ZIGBEE_CHANNEL_MAX: u8 = 26;

/// Represents a row in the MAC frame display table.
struct FrameRow {
    num: u32,
    type_str: &'static str,
    channel: u8,
    src: Option<String>,
    dst: Option<String>,
    pan: Option<u16>,
    bytes: usize,
    rssi: i32,
    lqi: u8,
    encrypted: bool,
    hex: String,
}

/// Provides methods for formatting and summarizing a `FrameRow`.
impl FrameRow {
    fn summary(&self) -> String {
        let addr_part = match (&self.src, &self.dst) {
            (Some(s), Some(d)) => format!("  {s} -> {d}"),
            (Some(s), None) => format!("  {s} -> ?"),
            (None, Some(d)) => format!("  ? -> {d}"),
            (None, None) => String::new(),
        };
        let pan_str = self
            .pan
            .map(|p| format!("  PAN:0x{p:04x}"))
            .unwrap_or_default();
        let enc_str = if self.encrypted { "  [enc]" } else { "" };
        format!(
            "#{n}  {t}  ch:{ch}{ap}{ps}  {b} B  {r} dBm  LQI:{l}{enc}",
            n = self.num,
            t = self.type_str,
            ch = self.channel,
            ap = addr_part,
            ps = pan_str,
            b = self.bytes,
            r = self.rssi,
            l = self.lqi,
            enc = enc_str,
        )
    }
}

/// Formats an extended address (8 bytes) as a colon-separated hex string.
fn format_ext_addr(bytes_le: &[u8]) -> String {
    bytes_le
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Computes the column width for a table column based on the maximum value length and the header length.
fn col_w(vals: impl Iterator<Item = usize>, header: &str) -> usize {
    vals.max().unwrap_or(0).max(header.len())
}

/// Formats a list of `FrameRow` entries into a table string.
fn format_table(rows: &[FrameRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let wn = col_w(rows.iter().map(|r| r.num.to_string().len()), "#");
    let wt = col_w(rows.iter().map(|r| r.type_str.len()), "Type");
    let ws = col_w(
        rows.iter()
            .map(|r| r.src.as_deref().unwrap_or("-").len()),
        "Src",
    );
    let wd = col_w(
        rows.iter()
            .map(|r| r.dst.as_deref().unwrap_or("-").len()),
        "Dst",
    );
    let wp = col_w(
        rows.iter().map(|r| if r.pan.is_some() { 6 } else { 1 }),
        "PAN",
    );

    let hdr = format!(
        " {hnum:>wn$}  {htype:<wt$}  {hch:<2}  {hsrc:<ws$}  {hdst:<wd$}  {hpan:<wp$}  {hb:<3}  {hrssi:>4}  {hlqi:<3}  Enc",
        hnum = "#", htype = "Type", hch = "Ch", hsrc = "Src",
        hdst = "Dst", hpan = "PAN", hb = "B", hrssi = "RSSI", hlqi = "LQI",
        wn = wn, wt = wt, ws = ws, wd = wd, wp = wp,
    );
    let sep = "-".repeat(hdr.len());
    let mut out = format!("{hdr}\n{sep}");

    for r in rows {
        let src = r.src.as_deref().unwrap_or("-");
        let dst = r.dst.as_deref().unwrap_or("-");
        let pan = r
            .pan
            .map(|p| format!("0x{p:04x}"))
            .unwrap_or_else(|| "-".to_string());
        let enc = if r.encrypted { "*" } else { " " };
        out.push_str(&format!(
            "\n {num:>wn$}  {type_:<wt$}  {ch:2}  {src:<ws$}  {dst:<wd$}  {pan:<wp$}  {b:3}  {rssi:>4}  {lqi:3}  {enc}",
            num = r.num, type_ = r.type_str, ch = r.channel,
            src = src, dst = dst, pan = pan,
            b = r.bytes, rssi = r.rssi, lqi = r.lqi, enc = enc,
            wn = wn, wt = wt, ws = ws, wd = wd, wp = wp,
        ));
    }
    out
}

/// Parses a captured frame from a `SniffLine` into a `FrameRow` structure, extracting relevant fields.
fn parse_frame(pkt: &SniffLine, channel: u8, frame_num: u32) -> FrameRow {
    let frame = &pkt.frame;
    let hex = frame
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    if frame.len() < 3 {
        return FrameRow {
            num: frame_num,
            type_str: "short",
            channel,
            src: None,
            dst: None,
            pan: None,
            bytes: frame.len(),
            rssi: pkt.rssi,
            lqi: pkt.lqi,
            encrypted: false,
            hex,
        };
    }

    let fcw = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = fcw & 0x07;
    let security = (fcw >> 3) & 1 != 0;
    let pan_compress = (fcw >> 6) & 1 != 0;
    let dst_mode = ((fcw >> 10) & 0x03) as usize;
    let src_mode = ((fcw >> 14) & 0x03) as usize;

    let type_str: &'static str = match frame_type {
        0 => "Beacon",
        1 => "Data",
        2 => "Ack",
        3 => "MACCmd",
        _ => "Unknown",
    };

    let mut offset = 3usize; // FCW (2) + seq num (1)

    let (dst_pan, dst_addr) = if dst_mode == 2 || dst_mode == 3 {
        if frame.len() < offset + 2 {
            (None, None)
        } else {
            let pan = u16::from_le_bytes([frame[offset], frame[offset + 1]]);
            offset += 2;
            let addr = if dst_mode == 2 {
                if frame.len() >= offset + 2 {
                    let a = u16::from_le_bytes([frame[offset], frame[offset + 1]]);
                    offset += 2;
                    Some(format!("0x{a:04x}"))
                } else {
                    None
                }
            } else if frame.len() >= offset + 8 {
                let s = format_ext_addr(&frame[offset..offset + 8]);
                offset += 8;
                Some(s)
            } else {
                None
            };
            (Some(pan), addr)
        }
    } else {
        (None, None)
    };

    let (src_pan, src_addr) = if src_mode == 2 || src_mode == 3 {
        let pan = if pan_compress {
            dst_pan
        } else if frame.len() >= offset + 2 {
            let p = u16::from_le_bytes([frame[offset], frame[offset + 1]]);
            offset += 2;
            Some(p)
        } else {
            None
        };
        let addr = if src_mode == 2 {
            if frame.len() >= offset + 2 {
                let a = u16::from_le_bytes([frame[offset], frame[offset + 1]]);
                offset += 2;
                Some(format!("0x{a:04x}"))
            } else {
                None
            }
        } else if frame.len() >= offset + 8 {
            let s = format_ext_addr(&frame[offset..offset + 8]);
            offset += 8;
            Some(s)
        } else {
            None
        };
        (pan, addr)
    } else {
        (None, None)
    };

    drop(offset);

    FrameRow {
        num: frame_num,
        type_str,
        channel,
        src: src_addr,
        dst: dst_addr,
        pan: dst_pan.or(src_pan),
        bytes: frame.len(),
        rssi: pkt.rssi,
        lqi: pkt.lqi,
        encrypted: security,
        hex,
    }
}

/// Writes the global header for a PCAP file.
fn write_global_header(file: &mut File) -> Result<()> {
    file.write_all(&PCAP_MAGIC.to_le_bytes())?;
    file.write_all(&2u16.to_le_bytes())?; // version major
    file.write_all(&4u16.to_le_bytes())?; // version minor
    file.write_all(&0i32.to_le_bytes())?; // UTC offset
    file.write_all(&0u32.to_le_bytes())?; // timestamp accuracy
    file.write_all(&65535u32.to_le_bytes())?; // snaplen
    file.write_all(&PCAP_DLT_IEEE802_15_4_NOFCS.to_le_bytes())?;
    file.flush()?;
    Ok(())
}

/// Writes a single packet to the PCAP file with the specified timestamp and data.
fn write_packet(file: &mut File, ts_sec: u32, ts_usec: u32, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    file.write_all(&ts_sec.to_le_bytes())?;
    file.write_all(&ts_usec.to_le_bytes())?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

// The sniffer's `time:` field is microseconds since device boot. We anchor the
// first packet to the wall clock and derive subsequent timestamps from the
// sniffer's own clock (which is more accurate for inter-frame spacing than the
// host's scheduling jitter).

/// Maintains an anchor for converting sniffer timestamps to wall clock time.
struct TimestampAnchor {
    first_wall_us: u64,
    first_sniffer_us: i64,
}

/// Maintains an anchor for converting sniffer timestamps to wall clock time.
impl TimestampAnchor {
    fn new(sniffer_us: i64) -> Self {
        let wall_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        Self {
            first_wall_us: wall_us,
            first_sniffer_us: sniffer_us,
        }
    }

    fn wall_us(&self, sniffer_us: i64) -> u64 {
        let delta = sniffer_us.wrapping_sub(self.first_sniffer_us);
        (self.first_wall_us as i64).saturating_add(delta).max(0) as u64
    }
}

/// Represents the result of capturing on a single channel, including the number of frames and errors.
struct ChannelResult {
    frames: u32,
    errors: u32,
}

/// Captures packets on a single channel for the specified duration, writing them to the PCAP file and returning the capture results and frame rows.
fn capture_channel(
    port: &mut dyn serialport::SerialPort,
    channel: u8,
    duration: Duration,
    file: &mut File,
    anchor: &mut Option<TimestampAnchor>,
    frame_counter: &mut u32,
) -> Result<(ChannelResult, Vec<FrameRow>)> {
    write_cmd(port, &format!("channel {channel}"))?;
    write_cmd(port, "receive")?;

    let mut result = ChannelResult {
        frames: 0,
        errors: 0,
    };
    let mut rows: Vec<FrameRow> = Vec::new();
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

        // Anchor timestamp on first packet.
        if anchor.is_none() {
            *anchor = Some(TimestampAnchor::new(pkt.sniffer_us));
        }
        let wall_us = anchor.as_ref().unwrap().wall_us(pkt.sniffer_us);
        let ts_sec = (wall_us / 1_000_000) as u32;
        let ts_usec = (wall_us % 1_000_000) as u32;

        match write_packet(file, ts_sec, ts_usec, &pkt.frame) {
            Ok(()) => {
                *frame_counter += 1;
                rows.push(parse_frame(&pkt, channel, *frame_counter));
                result.frames += 1;
            }
            Err(_) => result.errors += 1,
        }
    }

    write_cmd(port, "sleep")?;
    Ok((result, rows))
}

/// Zigbee live-capture plugin (PCAP output).
pub struct CapturePlugin {
    port: String,
    channel: u8,
    scan_all: bool,
    duration_ms: u64,
    timeout_ms: u64,
    pcap_path: String,
    table: bool,
}

/// Implementation of the Zigbee capture plugin.
impl CapturePlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            channel: 15,
            scan_all: false,
            duration_ms: 30_000,
            timeout_ms: 200,
            pcap_path: String::from("zigbee_capture.pcap"),
            table: false,
        }
    }
}

/// Provides a default implementation for the Zigbee capture plugin.
impl Default for CapturePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the `Plugin` trait for the Zigbee capture plugin.
impl Plugin for CapturePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Capture IEEE 802.15.4/Zigbee frames via an nRF52840 dongle",
            description: "Captures raw IEEE 802.15.4 frames from a Nordic Semiconductor nRF52840 \
                          sniffer dongle and writes them to a PCAP file (DLT 230, \
                          IEEE 802.15.4 without FCS). The file can be opened in Wireshark, \
                          including live reload while capture is running, with full 802.15.4 \
                          /Zigbee dissection and optional decryption key entry. Timestamps use \
                          the sniffer's own microsecond clock anchored to the host wall clock. \
                          Recognized PIDs: 1915:520F, 1915:CA37, 1915:154A, 1915:154B.",
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
                    help: "IEEE 802.15.4 channel to capture (11-26). \
                           Ignored when --scan-all is set.",
                    value_name: "CH",
                    default: Some("15"),
                    is_flag: false,
                },
                CliArg {
                    name: "scan_all",
                    short: Some('a'),
                    help: "Capture on all 16 Zigbee channels (11-26) sequentially, \
                           spending duration_ms/16 on each.",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
                CliArg {
                    name: "duration_ms",
                    short: Some('d'),
                    help: "Total capture duration in milliseconds.",
                    value_name: "MS",
                    default: Some("30000"),
                    is_flag: false,
                },
                CliArg {
                    name: "timeout_ms",
                    short: Some('t'),
                    help: "Per-read serial timeout (ms).",
                    value_name: "MS",
                    default: Some("200"),
                    is_flag: false,
                },
                CliArg {
                    name: "pcap",
                    short: Some('P'),
                    help: "Output PCAP file path. Open in Wireshark during or after capture.",
                    value_name: "FILE",
                    default: Some("zigbee_capture.pcap"),
                    is_flag: false,
                },
                CliArg {
                    name: "table",
                    short: Some('T'),
                    help: "Show all captured frames as an ASCII table in the results instead \
                           of one finding per frame.",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
            ],
        )
    }

    /// Initializes the plugin with the provided configuration, setting up the port, channel and other parameters.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.get_or("port", "");
        self.channel = config.parse_or("channel", 15u8);
        self.scan_all = config.get("scan_all") == Some("true");
        self.duration_ms = config.parse_or("duration_ms", 30_000u64);
        self.timeout_ms = config.parse_or("timeout_ms", 200u64);
        self.pcap_path = config.get_or("pcap", "zigbee_capture.pcap");
        self.table = config.get("table") == Some("true");

        if self.channel < ZIGBEE_CHANNEL_MIN || self.channel > ZIGBEE_CHANNEL_MAX {
            anyhow::bail!(
                "channel {} is out of range. Zigbee channels are 11-26",
                self.channel
            );
        }
        Ok(())
    }

    /// Executes the capture process, handling port selection, PCAP file creation, and channel scanning.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let port_name = if self.port.is_empty() {
            let mut candidates = find_nrf52840_ports();
            if candidates.is_empty() {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No nRF52840 sniffer dongle detected",
                    "No device with Nordic USB VID 0x1915 and a recognized PID \
                     (520F, CA37, 154A, 154B) was found in /dev/. Flash the dongle \
                     with the nRF Sniffer for 802.15.4 firmware and reconnect or \
                     use --port to specify the port directly.",
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
            candidates.remove(0)
        } else {
            self.port.clone()
        };

        let mut file = match File::create(&self.pcap_path) {
            Ok(f) => f,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot create pcap file: {}", self.pcap_path),
                    e.to_string(),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        write_global_header(&mut file)?;

        let channels: Vec<u8> = if self.scan_all {
            (ZIGBEE_CHANNEL_MIN..=ZIGBEE_CHANNEL_MAX).collect()
        } else {
            vec![self.channel]
        };

        let mode_str = if self.scan_all {
            "all channels 11-26".to_string()
        } else {
            format!("channel {}", self.channel)
        };

        result.add(PluginFinding::new(
            Severity::Info,
            format!("Capture started: {port_name} -> {}", self.pcap_path),
            format!(
                "Mode: {mode_str}  |  Duration: {} ms  |  \
                 Open {} in Wireshark now to follow live.",
                self.duration_ms, self.pcap_path,
            ),
        ));

        let per_read_timeout = Duration::from_millis(self.timeout_ms);
        let mut port = match serialport::new(&port_name, 115_200)
            .timeout(per_read_timeout)
            .open()
        {
            Ok(p) => p,
            Err(e) => {
                let hint = if e.to_string().contains("No such file") {
                    " The dongle uses CDC-ACM and appears as /dev/ttyACM*."
                } else {
                    " Check read/write permission (add your user to the `dialout` group)."
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

        let _ = write_cmd(port.as_mut(), "");
        let _ = write_cmd(port.as_mut(), "sleep");
        let _ = write_cmd(port.as_mut(), "shell echo off");
        drain(port.as_mut(), 150);

        let per_channel_ms = self.duration_ms / channels.len() as u64;
        let per_channel_duration = Duration::from_millis(per_channel_ms.max(100));

        let mut total_frames = 0u32;
        let mut total_errors = 0u32;
        let mut active_channels: Vec<u8> = Vec::new();
        let mut anchor: Option<TimestampAnchor> = None;
        let mut frame_counter = 0u32;
        let mut all_rows: Vec<FrameRow> = Vec::new();

        for &ch in &channels {
            match capture_channel(
                port.as_mut(),
                ch,
                per_channel_duration,
                &mut file,
                &mut anchor,
                &mut frame_counter,
            ) {
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Capture error on channel {ch}"),
                        e.to_string(),
                    ));
                }
                Ok((r, rows)) => {
                    total_frames += r.frames;
                    total_errors += r.errors;
                    if r.frames > 0 {
                        active_channels.push(ch);
                    }
                    if self.table {
                        all_rows.extend(rows);
                    } else {
                        for row in &rows {
                            result.add(PluginFinding::new(
                                Severity::Info,
                                row.summary(),
                                row.hex.clone(),
                            ));
                        }
                    }
                }
            }
        }

        if total_frames == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                "No frames captured",
                "No IEEE 802.15.4 traffic was observed. Check that Zigbee devices \
                 are active nearby, verify the channel or use --scan-all.",
            ));
        } else if self.table {
            let active = active_channels
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let errors_note = if total_errors > 0 {
                format!("  |  Write errors: {total_errors}")
            } else {
                String::new()
            };
            result.add(PluginFinding::new(
                Severity::Info,
                format!(
                    "{total_frames} frame(s) captured - active ch: {active}{errors_note}"
                ),
                format_table(&all_rows),
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("{total_frames} frame(s) written to {}", self.pcap_path),
                format!(
                    "Active channels: {}{}",
                    active_channels
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    if total_errors > 0 {
                        format!("  |  Write errors: {total_errors}")
                    } else {
                        String::new()
                    },
                ),
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CapturePlugin::new()) as Box<dyn crate::Plugin>)
}
