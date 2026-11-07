use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::fuzzing::{FuzzEngine, FuzzTransport, OwnedFuzzPayload};
use crate::plugin_meta;
use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

//  BACnet/IP packet helpers (minimal, only for fuzzing) 

/// Wrap raw APDU bytes in a valid BVLC + NPDU unicast frame.
fn wrap_apdu_unicast(apdu: &[u8]) -> Vec<u8> {
    let npdu = [0x01u8, 0x04]; // version=1, expecting-reply
    let total = 4 + npdu.len() + apdu.len();
    let mut pkt = vec![0x81, 0x0a, (total >> 8) as u8, total as u8];
    pkt.extend_from_slice(&npdu);
    pkt.extend_from_slice(apdu);
    pkt
}

/// Confirmed-Request APDU for ReadProperty.
fn read_property_apdu(obj_type: u16, instance: u32, prop: u32, invoke_id: u8) -> Vec<u8> {
    let mut a = vec![0x00, 0x04, invoke_id, 0x0c];
    let oid: u32 = ((obj_type as u32) << 22) | (instance & 0x3F_FFFF);
    a.push(0x0c);
    a.extend_from_slice(&oid.to_be_bytes());
    if prop < 256 {
        a.extend_from_slice(&[0x19, prop as u8]);
    } else {
        a.push(0x1a);
        a.extend_from_slice(&(prop as u16).to_be_bytes());
    }
    a
}

/// Find the byte offset of the APDU inside a raw BACnet/IP datagram.
fn apdu_start(data: &[u8]) -> Option<usize> {
    if data.len() < 6 || data[0] != 0x81 { return None; }
    let ctrl = data[5];
    if ctrl & 0x01 != 0 { return None; }
    let mut pos = 6usize;
    if ctrl & 0x20 != 0 {
        if data.len() < pos + 3 { return None; }
        pos += 3 + data[pos + 2] as usize;
    }
    if ctrl & 0x08 != 0 {
        if data.len() < pos + 3 { return None; }
        pos += 3 + data[pos + 2] as usize;
    }
    if ctrl & 0x20 != 0 { pos += 1; }
    Some(pos)
}

/// Translate a raw BACnet/IP response into a human-readable description string
/// that the FuzzEngine's pattern-matcher can work against.
fn describe_response(data: &[u8]) -> String {
    if data.is_empty() { return String::new(); }
    if data.len() < 6 || data[0] != 0x81 {
        return "invalid-bvlc-response".to_string();
    }
    let Some(start) = apdu_start(data) else {
        return "no-apdu-in-response".to_string();
    };
    let apdu = &data[start..];
    if apdu.is_empty() { return "empty-apdu-response".to_string(); }

    match apdu[0] >> 4 {
        2 => "bacnet-simple-ack".to_string(),
        3 => "bacnet-complex-ack".to_string(),
        4 => "bacnet-segment-ack".to_string(),
        5 => {
            // Error PDU: flags | invoke_id | service | error_class | error_code
            let class = apdu.get(3).copied().unwrap_or(0);
            let code  = apdu.get(4).copied().unwrap_or(0);
            format!("bacnet-error class={class} code={code}")
        }
        6 => {
            let reason = apdu.get(2).copied().unwrap_or(0);
            let label = match reason {
                1 => "buffer-overflow overflow",
                2 => "inconsistent-parameters",
                3 => "invalid-parameter-data-type",
                4 => "invalid-tag",
                5 => "missing-required-parameter",
                6 => "parameter-out-of-range",
                7 => "too-many-arguments",
                8 => "undefined-enumeration",
                9 => "unrecognized-service",
                _ => "other",
            };
            format!("bacnet-reject reason={reason} ({label})")
        }
        7 => {
            let reason = apdu.get(2).copied().unwrap_or(0);
            let label = match reason {
                1 => "buffer-overflow overflow",
                2 => "invalid-apdu-in-this-state",
                3 => "preempted-by-higher-priority-task",
                4 => "segmentation-not-supported",
                5 => "security-error",
                6 => "insufficient-security",
                7 => "window-size-out-of-range",
                8 => "application-exceeded-reply-time",
                9 => "out-of-resources",
                10 => "tsm-timeout",
                11 => "apdu-too-long",
                _ => "other",
            };
            format!("bacnet-abort reason={reason} ({label})")
        }
        n => format!("bacnet-unknown-pdu-type={n}"),
    }
}

//  BACnet-specific fuzz payloads 

fn bacnet_payloads() -> Vec<OwnedFuzzPayload> {
    // Helper: complete BVLC packet (transport sends raw when first byte == 0x81)
    let pkt = |label: &str, apdu: Vec<u8>| OwnedFuzzPayload {
        label: label.to_string(),
        data: wrap_apdu_unicast(&apdu),
    };
    let raw = |label: &str, bytes: Vec<u8>| OwnedFuzzPayload {
        label: label.to_string(),
        data: bytes,
    };

    // Device:0, VendorName(121) as baseline
    let baseline_apdu = read_property_apdu(8, 0, 121, 0x01);

    vec![
        //  Truncated / empty 
        pkt("apdu-empty",                  vec![]),
        pkt("apdu-one-byte",               vec![0x00]),
        pkt("apdu-confirmed-no-invoke",    vec![0x00, 0x04]),

        //  ReadProperty mutations 
        pkt("read-prop-device-zero",
            read_property_apdu(8, 0, 77, 0x01)),          // Device:0, ObjectName
        pkt("read-prop-max-instance",
            read_property_apdu(8, 0x3F_FFFF, 121, 0x02)), // Device:MAX_INST
        pkt("read-prop-invalid-obj-type",
            read_property_apdu(0x3FF, 0, 77, 0x03)),      // Type=1023 (invalid)
        pkt("read-prop-prop-0xFFFF",
            read_property_apdu(8, 0, 0xFFFF, 0x04)),      // Property=65535
        pkt("read-prop-prop-zero",
            read_property_apdu(8, 0, 0, 0x05)),           // Property=0
        pkt("read-prop-obj-type-zero",
            read_property_apdu(0, 0, 85, 0x06)),          // Type=0 (AnalogInput:0)
        pkt("read-prop-max-invoke",
            read_property_apdu(8, 0, 121, 0xFF)),         // invoke-id=0xFF

        //  Segmented / flag mutations 
        pkt("seg-flag-set", {
            let mut a = baseline_apdu.clone();
            a[0] = 0x08; // set SEG bit without segmentation headers
            a
        }),
        pkt("mor-flag-set", {
            let mut a = baseline_apdu.clone();
            a[0] = 0x04; // set MOR bit
            a
        }),
        pkt("max-segs-ff", {
            let mut a = baseline_apdu.clone();
            a[1] = 0xFF; // max-segs=7, max-apdu=0xF (invalid)
            a
        }),

        //  WriteProperty (may be rejected but tests parser) 
        pkt("write-prop-device-name", {
            // ConfReq WriteProperty Device:0, ObjectName = "FUZZ"
            let mut a = vec![0x00, 0x04, 0x10, 0x0f]; // WriteProperty
            a.extend_from_slice(&[0x0c, 0x02, 0x00, 0x00, 0x00]); // Device:0
            a.extend_from_slice(&[0x19, 0x4d]);       // ObjectName (77)
            a.extend_from_slice(&[0x3e, 0x75, 0x04, b'F', b'U', b'Z', b'Z', 0x3f]); // value
            a
        }),
        pkt("write-prop-max-priority", {
            let mut a = vec![0x00, 0x04, 0x11, 0x0f];
            a.extend_from_slice(&[0x0c, 0x00, 0x00, 0x00, 0x00]); // AnalogInput:0
            a.extend_from_slice(&[0x19, 0x55]); // PresentValue (85)
            a.extend_from_slice(&[0x3e, 0x44, 0x43, 0x80, 0x00, 0x00, 0x3f]); // value=256.0
            a.extend_from_slice(&[0x49, 0x10]); // priority=16
            a
        }),

        //  DeviceCommunicationControl (DoS attempt)
        pkt("device-comm-control-disable", {
            vec![0x00, 0x04, 0x20, 0x11,  // ConfReq DeviceCommunicationControl
                 0x09, 0x00,              // time-duration=0 (permanent)
                 0x91, 0x01]             // enable-disable=disable
        }),
        pkt("device-comm-control-initiate", {
            vec![0x00, 0x04, 0x21, 0x11,
                 0x09, 0x01,             // time-duration=1
                 0x91, 0x02]             // enable-disable=disableInitiation
        }),

        //  ReinitializeDevice (restart attempt)
        pkt("reinitialize-coldstart", {
            vec![0x00, 0x04, 0x30, 0x14,  // ConfReq ReinitializeDevice
                 0x0e, 0x91, 0x00, 0x0f]  // reinitialized-state-of-device=coldstart
        }),
        pkt("reinitialize-warmstart", {
            vec![0x00, 0x04, 0x31, 0x14,
                 0x0e, 0x91, 0x01, 0x0f]  // warmstart
        }),

        //  ReadPropertyMultiple with ALL
        pkt("read-prop-multiple-all", {
            // ConfReq ReadPropertyMultiple Device:0, property=ALL (0xFF)
            vec![0x00, 0x04, 0x40, 0x0e,  // ReadPropertyMultiple
                 0x0c, 0x02, 0x00, 0x00, 0x00,  // Device:0
                 0x1e, 0x09, 0xff, 0x1f]         // ALL properties
        }),

        //  Who-Is with extreme ranges
        pkt("who-is-all",
            vec![0x10, 0x08]),                          // unconfirmed, no range
        pkt("who-is-max-range", {
            vec![0x10, 0x08,
                 0x09, 0x00,                            // low-limit=0
                 0x19, 0xFF]                            // high-limit=255
        }),

        //  BVLC-level anomalies (send raw, not wrapped) 
        // BVLC with wrong function code
        raw("bvlc-wrong-function",
            vec![0x81, 0x05, 0x00, 0x04]),              // Fn=5 (Register-Foreign-Device, truncated)
        // BVLC length mismatch: header says 100 bytes, only 6 bytes follow
        raw("bvlc-length-mismatch", {
            vec![0x81, 0x0a, 0x00, 0x64,                // length=100 (wrong)
                 0x01, 0x04,                            // NPDU
                 0x00, 0x04, 0x50, 0x0c]                // short APDU
        }),
        // BVLC with broadcast function (0x0B) to unicast target
        raw("bvlc-broadcast-to-unicast", {
            let apdu = read_property_apdu(8, 0, 121, 0x60);
            let npdu = [0x01u8, 0x20, 0xFF, 0xFF, 0x00, 0xFF];
            let total = 4 + npdu.len() + apdu.len();
            let mut pkt = vec![0x81, 0x0b, (total >> 8) as u8, total as u8];
            pkt.extend_from_slice(&npdu);
            pkt.extend_from_slice(&apdu);
            pkt
        }),
        // Garbage prefix before valid BVLC
        raw("garbage-prefix", {
            let mut p = vec![0xDE, 0xAD, 0xBE, 0xEF];
            p.extend_from_slice(&wrap_apdu_unicast(&read_property_apdu(8, 0, 121, 0x70)));
            p
        }),

        //  Boundary values in APDU 
        pkt("all-zeros-apdu-64",  vec![0x00; 64]),
        pkt("all-ones-apdu-64",   vec![0xFF; 64]),
        pkt("apdu-256-zeros",     vec![0x00; 256]),
        pkt("apdu-1024-zeros",    vec![0x00; 1024]),
        pkt("apdu-1025-zeros",    vec![0x00; 1025]), // > max-APDU 1024
    ]
}

//  Transport 
/// BACnet transport layer for sending and receiving packets over UDP.
struct BacnetTransport {
    socket:  UdpSocket,
    target:  SocketAddr,
    timeout: Duration,
    /// Count consecutive timeouts to detect DoS / crash
    consecutive_timeouts: usize,
}

/// Create a new BACnet transport instance with the given socket, target, and timeout.
impl BacnetTransport {
    fn new(socket: UdpSocket, target: SocketAddr, timeout: Duration) -> Self {
        Self { socket, target, timeout, consecutive_timeouts: 0 }
    }
}

/// Implementation of the FuzzTransport trait for BACnet transport.
impl FuzzTransport for BacnetTransport {
    fn send_recv(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        // If first byte is 0x81 treat as a pre-built BACnet/IP packet; otherwise wrap as APDU.
        let wire = if payload.first() == Some(&0x81) {
            payload.to_vec()
        } else {
            wrap_apdu_unicast(payload)
        };

        self.socket.send_to(&wire, self.target)?;

        let mut buf = [0u8; 1500];
        let _ = self.socket.set_read_timeout(Some(self.timeout));
        match self.socket.recv_from(&mut buf) {
            Ok((n, src)) if src.ip() == self.target.ip() => {
                self.consecutive_timeouts = 0;
                Ok(describe_response(&buf[..n]).into_bytes())
            }
            _ => {
                self.consecutive_timeouts += 1;
                // Return empty → engine skips this payload
                Ok(Vec::new())
            }
        }
    }
}

//  Plugin 
/// BACnet fuzzing plugin for sending malformed packets to a target device.
pub struct BacnetFuzzer {
    host:        String,
    port:        u16,
    timeout_ms:  u64,
    iterations:  u32,
    wordlist:    Option<String>,
    delay_ms:    u64,
    patterns:    Vec<String>,
}

/// Constructor for the BacnetFuzzer plugin.
impl BacnetFuzzer {
    pub fn new() -> Self {
        Self {
            host:       String::new(),
            port:       BACNET_DEFAULT_PORT,
            timeout_ms: 1_000,
            iterations: 1,
            wordlist:   None,
            delay_ms:   50,
            patterns:   Vec::new(),
        }
    }
}

/// Default implementation for the BacnetFuzzer plugin.
impl Default for BacnetFuzzer {
    fn default() -> Self { Self::new() }
}

/// Implementation of the Plugin trait for the BacnetFuzzer plugin.
impl Plugin for BacnetFuzzer {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Send malformed BACnet/IP payloads to a device and report anomalous responses",
            description: "Sends a suite of malformed BACnet/IP packets to the target device: \
                          truncated APDUs, boundary values (all-zeros, all-ones, oversized), \
                          ReadProperty with invalid object types and property IDs, WriteProperty \
                          and DeviceCommunicationControl attempts, BVLC-level anomalies \
                          (wrong function code, length mismatches) and ReinitializeDevice \
                          requests. Each response is classified as Error, Reject or Abort PDU. \
                          Buffer-overflow mentions and unknown PDU types are flagged.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target BACnet/IP device",
                    value_name: "HOST",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "BACnet/IP UDP port",
                    value_name: "PORT",
                    default: Some("47808"),
                    is_flag: false
                },
                CliArg {
                    name: "timeout_ms",
                    short: None,
                    help: "Per-packet response timeout (ms)",
                    value_name: "MS",
                    default: Some("1000"),
                    is_flag: false
                },
                CliArg {
                    name: "iterations",
                    short: None,
                    help: "Times to repeat the payload set",
                    value_name: "N",
                    default: Some("1"),
                    is_flag: false
                },
                CliArg {
                    name: "delay_ms",
                    short: Some('d'),
                    help: "Delay between packets (ms)",
                    value_name: "MS",
                    default: Some("50"),
                    is_flag: false
                },
                CliArg {
                    name: "wordlist",
                    short: Some('w'),
                    help: "Wordlist of APDU hex lines to add",
                    value_name: "PATH",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "pattern",
                    short: None,
                    help: "Extra response pattern to flag",
                    value_name: "STR",
                    default: None,
                    is_flag: false
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host       = config.require("host")?.to_string();
        self.port       = config.parse_or("port", BACNET_DEFAULT_PORT);
        self.timeout_ms = config.parse_or("timeout_ms", 1_000u64);
        self.iterations = config.parse_or("iterations", 1u32);
        self.delay_ms   = config.parse_or("delay_ms", 50u64);
        self.wordlist   = config.get("wordlist").map(|s| s.to_string());
        if let Some(p) = config.get("pattern") {
            self.patterns.push(p.to_string());
        }
        Ok(())
    }

    /// Execute the fuzzing routine and return the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| anyhow::anyhow!("failed to bind UDP socket: {e}"))?;
        socket.set_broadcast(true)?;

        let timeout = Duration::from_millis(self.timeout_ms);

        //  Liveness check 
        let liveness_pkt = wrap_apdu_unicast(&read_property_apdu(8, 0, 121, 0x00));
        socket.send_to(&liveness_pkt, addr)?;
        let _ = socket.set_read_timeout(Some(timeout * 3));
        let mut liveness_buf = [0u8; 1500];
        let device_alive_before = socket.recv_from(&mut liveness_buf).is_ok();

        if !device_alive_before {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No BACnet response from {addr} before fuzzing"),
                "Device did not respond to an initial ReadProperty probe. \
                 Fuzzing may not be meaningful; verify the target is reachable.",
            ));
        }

        //  Fuzzing 
        let extra_patterns: Vec<&str> = self.patterns.iter().map(String::as_str).collect();
        let mut engine = FuzzEngine::new(self.iterations)
            .with_delay_ms(self.delay_ms)
            // Replace the generic text payloads with our binary BACnet set
            .with_payloads(&[])
            .with_extra_patterns(&["bacnet-reject", "bacnet-abort", "overflow",
                                   "invalid-bvlc", "no-apdu", "bacnet-unknown"])
            .with_extra_patterns(&extra_patterns);

        // Add all BACnet-specific payloads
        for payload in bacnet_payloads() {
            engine = engine.with_payload(payload);
        }

        if let Some(ref path) = self.wordlist {
            engine = engine.with_wordlist(path)?;
        }

        let mut transport = BacnetTransport::new(socket, addr, timeout);
        let matches = engine.run(&mut transport)?;
        let consecutive_timeouts = transport.consecutive_timeouts;

        //  Post-fuzz liveness check 
        let socket2 = UdpSocket::bind("0.0.0.0:0")?;
        socket2.send_to(&liveness_pkt, addr)?;
        let _ = socket2.set_read_timeout(Some(timeout * 3));
        let device_alive_after = socket2.recv_from(&mut liveness_buf).is_ok();

        //  Build findings 
        if matches.is_empty() && device_alive_after {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No anomalous responses from {addr}"),
                format!(
                    "All {} BACnet payload{} produced only normal error/reject PDUs \
                     or no response. Device remained responsive throughout.",
                    bacnet_payloads().len(),
                    if bacnet_payloads().len() == 1 { "" } else { "s" }
                ),
            ));
        } else {
            for finding in FuzzEngine::to_findings(&matches, &addr.to_string()) {
                result.add(finding);
            }
        }

        if !device_alive_after && device_alive_before {
            result.add(
                PluginFinding::new(
                    Severity::Critical,
                    format!("BACnet device at {addr} stopped responding after fuzzing"),
                    format!(
                        "Device was responsive before fuzzing but did not reply to a \
                         post-fuzz liveness probe. The last {} packet{} received no response. \
                         This may indicate a crash, hang, or triggered DoS condition.",
                        consecutive_timeouts,
                        if consecutive_timeouts == 1 { "" } else { "s" }
                    ),
                ),
            );
            result.finish(PluginStatus::Fail);
        } else if matches.iter().any(|m| matches!(m.severity, Severity::Critical | Severity::High)) {
            result.finish(PluginStatus::Fail);
        } else {
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BacnetFuzzer::new()) as Box<dyn crate::Plugin>)
}
