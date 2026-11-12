use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use socketcan::{
    CanDataFrame, CanFrame, CanRemoteFrame, CanSocket, EmbeddedFrame, Socket, StandardId,
};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::{Duration, Instant};

use super::common::{format_id, hex_bytes, IFACE_HELP};

pub struct CanEnumerate {
    iface: String,
    passive_ms: u64,
    probe_ms: u64,
    no_canopen: bool,
    no_obdii: bool,
}

impl CanEnumerate {
    pub fn new() -> Self {
        Self {
            iface: "can0".into(),
            passive_ms: 1000,
            probe_ms: 500,
            no_canopen: false,
            no_obdii: false,
        }
    }
}

impl Default for CanEnumerate {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CanEnumerate {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate devices on the CAN bus",
            description: "Active and passive device discovery across three strategies:\n\
                          1. Passive: listens for spontaneous CANopen heartbeat frames \
                          (0x700+N) and any other periodic traffic.\n\
                          2. OBD-II: sends a Service 01 PID 00 functional broadcast to \
                          0x7DF and collects responses from ECUs at 0x7E8-0x7EF.\n\
                          3. CANopen node guarding: sends an RTR frame to each address \
                          0x700+N (N=1-127) and waits for a data-frame reply, confirming \
                          the node is alive. For each responding node an SDO upload of \
                          object 0x1000 (Device Type) is attempted to identify the \
                          device profile.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "iface",
                    short: Some('i'),
                    help: "SocketCAN interface name (e.g., can0, vcan0)",
                    value_name: "IFACE",
                    default: Some("can0"),
                    is_flag: false,
                },
                CliArg {
                    name: "passive_ms",
                    short: None,
                    help: "Duration of the passive listening phase in milliseconds",
                    value_name: "MS",
                    default: Some("1000"),
                    is_flag: false,
                },
                CliArg {
                    name: "probe_ms",
                    short: None,
                    help: "Response collection window after active probes in milliseconds",
                    value_name: "MS",
                    default: Some("500"),
                    is_flag: false,
                },
                CliArg {
                    name: "no_canopen",
                    short: None,
                    help: "Skip the CANopen node guarding and SDO probe phase",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
                CliArg {
                    name: "no_obdii",
                    short: None,
                    help: "Skip the OBD-II ECU discovery phase",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
            ],
        )
    }

    /// Initialize the plugin with configuration values.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.iface = config.get_or("iface", "can0");
        self.passive_ms = config.parse_or("passive_ms", 1000u64);
        self.probe_ms = config.parse_or("probe_ms", 500u64);
        self.no_canopen = config.get("no_canopen") == Some("true");
        self.no_obdii = config.get("no_obdii") == Some("true");
        Ok(())
    }

    /// Execute the plugin: enumerate CANopen nodes and OBD-II ECUs.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let socket = match CanSocket::open(&self.iface) {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open CAN interface {}", self.iface),
                    format!("{e}\n\n{IFACE_HELP}"),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        socket
            .set_read_timeout(Duration::from_millis(10))
            .map_err(|e| anyhow::anyhow!("set_read_timeout: {e}"))?;

        // Phase 1: passive listen
        let passive_frames = collect_frames(&socket, Duration::from_millis(self.passive_ms));

        // Heartbeats arrive spontaneously on 0x700+N
        let mut canopen_from_heartbeat: BTreeMap<u8, u8> = BTreeMap::new();
        for (&id, data) in &passive_frames {
            if (0x701..=0x77F).contains(&id) {
                let node = (id - 0x700) as u8;
                let state = data.first().copied().unwrap_or(0xFF);
                canopen_from_heartbeat.insert(node, state);
            }
        }

        if !canopen_from_heartbeat.is_empty() {
            let lines: Vec<String> = canopen_from_heartbeat
                .iter()
                .map(|(n, s)| {
                    format!(
                        "  Node {:3}  ID={:03X}h  state={}",
                        n,
                        0x700 + *n as u32,
                        canopen_state_name(*s)
                    )
                })
                .collect();
            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    format!(
                        "{} CANopen node(s) discovered via passive heartbeat on {}",
                        canopen_from_heartbeat.len(),
                        self.iface
                    ),
                    lines.join("\n"),
                )
                .with_evidence(lines.join("\n")),
            );
        }

        // Phase 2: OBD-II functional broadcast
        let mut obd_ecus: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

        if !self.no_obdii {
            // Service 01, PID 00 — "which PIDs are supported"
            if let Some(req) = make_data_frame(0x7DF, &[0x02, 0x01, 0x00]) {
                let _ = socket.write_frame(&CanFrame::Data(req));
            }

            let after_obd = collect_frames(&socket, Duration::from_millis(self.probe_ms));
            for (&id, data) in &after_obd {
                if (0x7E8..=0x7EF).contains(&id) {
                    let ecu_idx = (id - 0x7E8) as u8;
                    obd_ecus.insert(ecu_idx, data.clone());
                }
            }

            if obd_ecus.is_empty() {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("No OBD-II ECUs responded on {}", self.iface),
                    "Sent Service 01 PID 00 to 0x7DF. No reply on 0x7E8-0x7EF. \
                     The bus may not carry ISO 15765-4 traffic.",
                ));
            } else {
                for (&ecu, data) in &obd_ecus {
                    let resp_id = 0x7E8 + ecu as u32;
                    let supported = decode_obd_supported_pids(data);
                    result.add(
                        PluginFinding::new(
                            Severity::High,
                            format!(
                                "OBD-II ECU {} at 0x{resp_id:03X}h: {} supported PID(s)",
                                ecu,
                                supported.len()
                            ),
                            format!(
                                "ECU index {} (request 0x{:03X}h -> response 0x{resp_id:03X}h)\n\
                                 Supported PIDs (01-20): {}\n\
                                 Raw response: [{}]",
                                ecu,
                                0x7E0 + ecu as u32,
                                if supported.is_empty() {
                                    "none decoded".into()
                                } else {
                                    supported
                                        .iter()
                                        .map(|p| format!("0x{p:02X}"))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                },
                                hex_bytes(data),
                            ),
                        )
                        .with_evidence(format!(
                            "ecu={ecu} resp_id=0x{resp_id:03X} data=[{}]",
                            hex_bytes(data)
                        )),
                    );
                }
            }
        }

        // Phase 3: CANopen node guarding (RTR)
        if !self.no_canopen {
            // Send all RTR probes first, then collect in bulk
            for node in 1u16..=127 {
                let id = 0x700 + node;
                if let Some(sid) = StandardId::new(id) {
                    if let Some(rtr) = CanRemoteFrame::new_remote(sid, 0) {
                        let _ = socket.write_frame(&CanFrame::Remote(rtr));
                    }
                }
            }

            let after_ng = collect_frames(&socket, Duration::from_millis(self.probe_ms));

            // Collect node guard responses AND SDO responses after SDO probes below
            let mut ng_found: BTreeMap<u8, u8> = BTreeMap::new(); // node -> state
            for (&id, data) in &after_ng {
                if (0x701..=0x77F).contains(&id) {
                    let node = (id - 0x700) as u8;
                    if !canopen_from_heartbeat.contains_key(&node) {
                        let state = data.first().copied().unwrap_or(0xFF);
                        ng_found.insert(node, state);
                    }
                }
            }

            // All CANopen nodes found (heartbeat + node guard)
            let mut all_canopen: BTreeMap<u8, u8> = canopen_from_heartbeat.clone();
            for (n, s) in &ng_found {
                all_canopen.insert(*n, *s);
            }

            if !ng_found.is_empty() {
                let lines: Vec<String> = ng_found
                    .iter()
                    .map(|(n, s)| {
                        format!(
                            "  Node {:3}  ID={:03X}h  state={}",
                            n,
                            0x700 + *n as u32,
                            canopen_state_name(*s)
                        )
                    })
                    .collect();
                result.add(
                    PluginFinding::new(
                        Severity::Medium,
                        format!(
                            "{} CANopen node(s) discovered via node guarding on {}",
                            ng_found.len(),
                            self.iface
                        ),
                        lines.join("\n"),
                    )
                    .with_evidence(lines.join("\n")),
                );
            }

            // SDO device-type read for every found CANopen node
            if !all_canopen.is_empty() {
                // Send SDO upload initiate (read 0x1000:00 = Device Type)
                for &node in all_canopen.keys() {
                    let sdo_id = 0x600 + node as u32;
                    if let Some(req) = make_data_frame(
                        sdo_id,
                        &[0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00],
                    ) {
                        let _ = socket.write_frame(&CanFrame::Data(req));
                    }
                }

                let after_sdo = collect_frames(&socket, Duration::from_millis(self.probe_ms));

                let mut sdo_responses: HashMap<u8, u32> = HashMap::new();
                for (&id, data) in &after_sdo {
                    if (0x581..=0x5FF).contains(&id) && data.len() >= 8 {
                        let node = (id - 0x580) as u8;
                        // Expedited upload response: cs byte 0x4F/0x4B/0x47/0x43
                        // object 0x1000 sub 0: bytes 1-2 = 0x00 0x10, byte 3 = 0x00
                        if matches!(data[0], 0x43 | 0x47 | 0x4B | 0x4F)
                            && data[1] == 0x00
                            && data[2] == 0x10
                            && data[3] == 0x00
                        {
                            let device_type =
                                u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                            sdo_responses.insert(node, device_type);
                        }
                    }
                }

                for (&node, &state) in &all_canopen {
                    let nid = format_id(0x700 + node as u32, false);
                    let (device_str, sev) = if let Some(&dt) = sdo_responses.get(&node) {
                        let profile = dt & 0xFFFF;
                        let desc = canopen_device_profile(profile as u16);
                        (
                            format!("profile=0x{profile:04X} ({desc})  raw=0x{dt:08X}"),
                            Severity::High,
                        )
                    } else {
                        ("device type unknown (SDO timeout or not supported)".into(), Severity::Medium)
                    };

                    result.add(
                        PluginFinding::new(
                            sev,
                            format!(
                                "CANopen node {} at {nid}: {}", node, canopen_state_name(state)
                            ),
                            format!(
                                "Node ID  : {node}\n\
                                 Heartbeat: {nid}\n\
                                 State    : {} (0x{state:02X})\n\
                                 Device   : {device_str}",
                                canopen_state_name(state),
                            ),
                        )
                        .with_evidence(format!(
                            "node={node} id={nid} state=0x{state:02X} {device_str}"
                        )),
                    );
                }
            } else if !self.no_canopen {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("No CANopen nodes found on {}", self.iface),
                    "Neither passive heartbeats nor node-guarding RTR produced any response \
                     on 0x701-0x77F. The bus may not carry CANopen traffic.",
                ));
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

/// Collect all data frames into a map of id -> last_payload for the given duration.
fn collect_frames(socket: &CanSocket, window: Duration) -> BTreeMap<u32, Vec<u8>> {
    let deadline = Instant::now() + window;
    let mut map: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

    while Instant::now() < deadline {
        match socket.read_frame() {
            Ok(CanFrame::Data(f)) => {
                let id = match f.id() {
                    socketcan::Id::Standard(s) => s.as_raw() as u32,
                    socketcan::Id::Extended(e) => e.as_raw(),
                };
                map.insert(id, f.data().to_vec());
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    map
}

/// Create a CAN data frame with the given standard ID and payload.
fn make_data_frame(id: u32, data: &[u8]) -> Option<CanDataFrame> {
    let sid = StandardId::new(id as u16)?;
    CanDataFrame::new(sid, data)
}

/// Return a human-readable name for the given CANopen node state.
fn canopen_state_name(state: u8) -> &'static str {
    match state & 0x7F {
        0x00 => "Boot-up/Initializing",
        0x04 => "Stopped",
        0x05 => "Operational",
        0x7F => "Pre-Operational",
        _ => "Unknown",
    }
}

/// Return a human-readable name for the given CANopen device profile.
fn canopen_device_profile(profile: u16) -> &'static str {
    match profile {
        0x0191 => "Encoder",
        0x0192 => "Stepper motor",
        0x0401 => "AC drive (IEC 61800-7-201)",
        0x0402 => "Stepper motor drive",
        0x0403 => "AC servo drive",
        0x0404 => "Digital I/O module",
        0x0405 => "Analog I/O module",
        0x0406 => "Encoder interface",
        0x0407 => "Safety controller",
        0x0408 => "Hydraulic/pneumatic drive",
        0x0409 => "Proportional valve",
        0xFFFF => "Generic CANopen device",
        _ => "Unknown profile",
    }
}

/// Decode the OBD-II supported PID bitmask from a Service 01 PID 00 response.
fn decode_obd_supported_pids(data: &[u8]) -> Vec<u8> {
    // Response format: [len, 0x41, 0x00, byte_a, byte_b, byte_c, byte_d]
    if data.len() < 6 || data.get(1) != Some(&0x41) || data.get(2) != Some(&0x00) {
        return Vec::new();
    }
    let mask = u32::from_be_bytes([
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
        data.get(6).copied().unwrap_or(0),
    ]);
    (1u8..=32).filter(|&pid| mask & (1 << (32 - pid)) != 0).collect()
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CanEnumerate::new()) as Box<dyn crate::Plugin>)
}
