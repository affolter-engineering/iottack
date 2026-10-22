//! BlueFi (CVE-2025-27840) vulnerability plugin.
//!
//! CVE-2025-27840: ESP32 Bluetooth firmware exposes undocumented vendor-specific
//! HCI commands (OGF 0x3F, OCF 0x000–0x3FF) over the USB-serial HCI interface
//! with no authentication.  Certain commands provide arbitrary memory read and
//! write access, enabling extraction of cryptographic keys, NVS credentials,
//! and runtime memory modification by anyone with USB access.
//!
//! The plugin connects to an ESP32 in HCI mode over its USB serial port,
//! confirms HCI connectivity via HCI_Reset, probes the known dangerous vendor
//! commands (OCF 0x001/0x002), then optionally sweeps the full OCF range.
//!
//! Inspired by: https://github.com/em0gi/CVE-2025-27840/blob/main/Enumerate.py

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::protocols::uart::{UartConfig, UartSession};
use anyhow::Result;
use std::time::{Duration, Instant};

// ── HCI constants ─────────────────────────────────────────────────────────────
//
// HCI packet types
const HCI_CMD: u8 = 0x01;
const HCI_EVT: u8 = 0x04;

// HCI event codes
const HCI_EV_CMD_COMPLETE: u8 = 0x0E;
const HCI_EV_CMD_STATUS: u8 = 0x0F;

// HCI status codes
const HCI_STATUS_SUCCESS: u8 = 0x00;
const HCI_STATUS_UNKNOWN_CMD: u8 = 0x01;

// HCI_Reset: OGF=0x03 (controller), OCF=0x003 → OpCode=0x0C03
// Bytes: [CMD, 0x03, 0x0C, param_len=0x00]
const HCI_RESET: &[u8] = &[HCI_CMD, 0x03, 0x0C, 0x00];

// ── Vendor-specific HCI commands ──────────────────────────────────────────────
//
// OGF 0x3F (vendor) → OpCode = 0xFC00 | OCF
// Command bytes: [0x01, OCF & 0xFF, 0xFC | (OCF >> 8), 0x00]

/// Known dangerous ESP32 vendor OCFs documented in CVE-2025-27840.
const KNOWN_DANGEROUS: &[(u16, &str)] = &[
    (0x001, "read register / arbitrary memory read"),
    (0x002, "write register / arbitrary memory write"),
];

fn hci_vendor_cmd(ocf: u16) -> [u8; 4] {
    [HCI_CMD, (ocf & 0xFF) as u8, 0xFC | (ocf >> 8) as u8, 0x00]
}

// ── HCI frame reader ──────────────────────────────────────────────────────────

struct HciEvent {
    event_code: u8,
    params: Vec<u8>,
}

/// Read one complete HCI event packet within `timeout`, discarding non-HCI bytes.
fn read_hci_event(session: &mut UartSession, timeout: Duration) -> Option<HciEvent> {
    let deadline = Instant::now() + timeout;

    // Scan for HCI event indicator (0x04).
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match session.read_bytes(1) {
            Ok(b) if b.first() == Some(&HCI_EVT) => break,
            _ => {}
        }
    }

    // Read event_code + param_len.
    let mut header = Vec::with_capacity(2);
    while header.len() < 2 {
        if Instant::now() >= deadline {
            return None;
        }
        if let Ok(b) = session.read_bytes(2 - header.len()) {
            header.extend_from_slice(&b);
        }
    }
    let event_code = header[0];
    let param_len = header[1] as usize;

    // Read parameter bytes.
    let mut params = Vec::with_capacity(param_len);
    while params.len() < param_len {
        if Instant::now() >= deadline {
            return None;
        }
        if let Ok(b) = session.read_bytes(param_len - params.len()) {
            params.extend_from_slice(&b);
        }
    }

    Some(HciEvent { event_code, params })
}

/// Extract the status byte from a Command Complete or Command Status event.
///
/// Command Complete params: [num_cmds(1)][opcode_lo(1)][opcode_hi(1)][status(1)][...]
/// Command Status  params: [status(1)][num_cmds(1)][opcode_lo(1)][opcode_hi(1)]
fn event_status(ev: &HciEvent) -> Option<u8> {
    match ev.event_code {
        HCI_EV_CMD_COMPLETE if ev.params.len() >= 4 => Some(ev.params[3]),
        HCI_EV_CMD_STATUS if !ev.params.is_empty() => Some(ev.params[0]),
        _ => None,
    }
}

/// Send an HCI command and return the response status, or `None` on timeout.
fn hci_transact(session: &mut UartSession, cmd: &[u8], timeout: Duration) -> Option<u8> {
    session.write_bytes(cmd).ok()?;
    session.flush().ok()?;
    let ev = read_hci_event(session, timeout)?;
    event_status(&ev)
}

// ── Plugin ────────────────────────────────────────────────────────────────────

pub struct BlueFiPlugin {
    port: String,
    baud_rate: u32,
    timeout_ms: u64,
    /// Last OCF to probe in the full vendor sweep (inclusive).
    ocf_end: u16,
}

impl BlueFiPlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            baud_rate: 115_200,
            timeout_ms: 200,
            ocf_end: 15, // 0x00F — covers all known dangerous OCFs; set to 1023 for full sweep
        }
    }
}

impl Default for BlueFiPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for BlueFiPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "CVE-2025-27840 — ESP32 HCI vendor backdoor (BlueFi)",
            description: "Connects to an ESP32 in HCI mode over USB serial and probes for \
                          CVE-2025-27840: undocumented Espressif vendor-specific HCI commands \
                          (OGF 0x3F) that expose arbitrary memory read/write with no \
                          authentication. Always probes the known dangerous OCFs (0x001, 0x002) \
                          then sweeps OCF 0x000 to --ocf-end (default 15). Set --ocf-end 1023 \
                          for a complete enumeration of all 1024 vendor commands.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "Serial port of the ESP32 in HCI mode (e.g. /dev/ttyUSB1).",
                    value_name: "PORT",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "baud_rate",
                    short: Some('b'),
                    help: "Serial baud rate (default 115200).",
                    value_name: "BAUD",
                    default: Some("115200"),
                    is_flag: false,
                },
                CliArg {
                    name: "timeout_ms",
                    short: Some('t'),
                    help: "Per-command response timeout in ms (default 200).",
                    value_name: "MS",
                    default: Some("200"),
                    is_flag: false,
                },
                CliArg {
                    name: "ocf_end",
                    short: Some('e'),
                    help: "Last OCF to probe in the vendor command sweep (0–1023). \
                           15 (default) covers the first 16 OCFs in ~3 s. \
                           1023 scans the full vendor space in ~200 s.",
                    value_name: "N",
                    default: Some("15"),
                    is_flag: false,
                },
            ],
        )
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.require("port")?.to_string();
        self.baud_rate = config.parse_or("baud_rate", 115_200u32);
        self.timeout_ms = config.parse_or("timeout_ms", 200u64);
        self.ocf_end = config.parse_or("ocf_end", 15u16).min(1023);
        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let timeout = Duration::from_millis(self.timeout_ms);

        // ── Open serial port ──────────────────────────────────────────────────
        let uart_cfg = UartConfig {
            port: self.port.clone(),
            baud_rate: self.baud_rate,
            timeout_ms: self.timeout_ms,
            ..UartConfig::default()
        };
        let mut session = match UartSession::open(&uart_cfg) {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                let hint = if msg.contains("No such file") {
                    " Run `iottack uart port-scan` to list available ports."
                } else {
                    " Check that your user is in the `dialout` group."
                };
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open {}", self.port),
                    format!("{msg}.{hint}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        // Discard any pending startup output from the device.
        let _ = session.drain();

        // ── Step 1: HCI Reset — confirm the device is in HCI mode ─────────────
        match hci_transact(&mut session, HCI_RESET, timeout) {
            None => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No HCI response to HCI_Reset",
                    format!(
                        "The device at {} did not respond within {} ms. The ESP32 may not \
                         be in HCI mode — ensure it is built with CONFIG_BT_HCI_UART_H4=y \
                         and connected at the correct baud rate.",
                        self.port, self.timeout_ms
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
            Some(s) if s != HCI_STATUS_SUCCESS => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("HCI_Reset returned non-zero status {s:#04x}"),
                    "The device responded to HCI_Reset with an error. \
                     HCI may be partially initialised.",
                ));
            }
            _ => {
                result.add(PluginFinding::new(
                    Severity::Medium,
                    format!("HCI interface reachable on {}", self.port),
                    "The ESP32 responded to HCI_Reset. Raw HCI access is available \
                     over USB with no authentication — the full HCI command set, \
                     including vendor extensions, is exposed.",
                ));
            }
        }

        // ── Step 2: Probe known dangerous OCFs ────────────────────────────────
        let mut vuln_count = 0u32;
        for &(ocf, desc) in KNOWN_DANGEROUS {
            match hci_transact(&mut session, &hci_vendor_cmd(ocf), timeout) {
                Some(HCI_STATUS_UNKNOWN_CMD) | None => {}
                Some(status) => {
                    vuln_count += 1;
                    result.add(PluginFinding::new(
                        Severity::Critical,
                        format!("CVE-2025-27840: OCF {ocf:#05x} responsive ({desc})"),
                        format!(
                            "Espressif vendor command 0xFC{ocf:02X} returned status \
                             {status:#04x} — not 'unknown command'. This command exposes \
                             {desc} with no authentication required. An attacker with USB \
                             access can use this to read NVS keys and credentials, extract \
                             Bluetooth link keys, or corrupt runtime state.",
                        ),
                    ));
                }
            }
        }

        if vuln_count > 0 {
            result.add(PluginFinding::new(
                Severity::Critical,
                "Device is vulnerable to CVE-2025-27840",
                "Mitigation: disable the HCI UART interface in production \
                 (CONFIG_BT_HCI_UART=n), or apply the Espressif patch that \
                 gates vendor command access behind an authenticated channel. \
                 Reference: https://nvd.nist.gov/vuln/detail/CVE-2025-27840",
            ));
        }

        // ── Step 3: Sweep vendor OCF space ────────────────────────────────────
        let known_ocfs: Vec<u16> = KNOWN_DANGEROUS.iter().map(|&(o, _)| o).collect();
        let mut extra: Vec<(u16, u8)> = Vec::new();

        for ocf in 0u16..=self.ocf_end {
            if known_ocfs.contains(&ocf) {
                continue; // already probed in step 2
            }
            if let Some(s) = hci_transact(&mut session, &hci_vendor_cmd(ocf), timeout) {
                if s != HCI_STATUS_UNKNOWN_CMD {
                    extra.push((ocf, s));
                }
            }
        }

        if !extra.is_empty() {
            let list = extra
                .iter()
                .map(|(ocf, s)| format!("0xFC{ocf:02X}={s:#04x}"))
                .collect::<Vec<_>>()
                .join(", ");
            result.add(PluginFinding::new(
                Severity::High,
                format!(
                    "{} additional responsive vendor command(s) in OCF 0x000–{:#05x}",
                    extra.len(),
                    self.ocf_end,
                ),
                format!(
                    "Commands returning non-'unknown' status: {list}. \
                     Each represents unauthenticated attack surface over USB. \
                     Use --ocf-end 1023 for a complete sweep of all 1024 vendor OCFs.",
                ),
            ));
        }

        if vuln_count == 0 && extra.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!(
                    "No responsive vendor commands found in OCF 0x000–{:#05x}",
                    self.ocf_end
                ),
                "All probed vendor commands returned 'unknown command'. \
                 The firmware may have patched CVE-2025-27840, or this device \
                 is not an ESP32 in HCI mode.",
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BlueFiPlugin::new()) as Box<dyn crate::Plugin>)
}
