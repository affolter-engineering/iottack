//! Virtual CAN bus simulator for IoTtack testing.
//!
//! Simulates a mixed industrial/automotive CAN network with CANopen nodes,
//! OBD-II diagnostics and a J1939 engine controller. Exercises all
//! security-relevant IDs that the iottack `can scan`, `can dump` and
//! `can enumerate` plugins flag.
//!
//! # Quick start
//!
//!   # Set up virtual CAN interface
//!   modprobe vcan
//!   ip link add dev vcan0 type vcan
//!   ip link set vcan0 up
//!
//!   # Run the simulator
//!   cargo run -- --iface vcan0
//!
//!   # In another terminal, test with iottack
//!   iottack can scan  --iface vcan0
//!   iottack can dump  --iface vcan0 --duration 5
//!
//! # Node layout
//!
//!   CANopen master
//!     0x080  SYNC               100 ms
//!     0x081  EMCY from node 1   5 s
//!
//!   CANopen node 1 - temperature/pressure sensor
//!     0x181  TPDO1              100 ms
//!     0x281  TPDO2              200 ms
//!     0x581  SDO response         2 s
//!     0x601  SDO request (write)  2 s   <- unauthenticated register access
//!     0x701  NMT heartbeat        1 s
//!
//!   CANopen node 2 - motor controller
//!     0x182  TPDO1              200 ms
//!     0x702  NMT heartbeat        1 s
//!
//!   CANopen node 3 - valve controller
//!     0x183  TPDO1              500 ms
//!     0x703  NMT heartbeat        1 s
//!
//!   OBD-II/ISO 15765-4
//!     0x7DF  diagnostic broadcast  1 s  <- HIGH severity
//!     0x7E8  ECU 1 response        1 s  <- HIGH severity
//!
//!   J1939 (extended 29-bit)
//!     0x0CFEEF00  EEC1 engine data  100 ms

use anyhow::{Context, Result};
use clap::Parser;
use socketcan::{CanDataFrame, CanFrame, CanSocket, EmbeddedFrame, ExtendedId, Id, Socket, StandardId};
use std::io;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "can-simulator",
    about = "Virtual CAN bus simulator for IoTtack testing"
)]
struct Cli {
    /// SocketCAN interface to send on
    #[arg(short, long, default_value = "vcan0")]
    iface: String,

    /// Stop after this many seconds (0 = run until Ctrl-C)
    #[arg(short, long, default_value = "0")]
    duration: u64,

    /// Print statistics every N seconds
    #[arg(long, default_value = "5")]
    stats_interval: u64,
}

/// Representation of a CAN node, including its transmit schedule and payload generation function.
struct Node {
    name: &'static str,
    id: u32,
    extended: bool,
    period_ms: u64,
    next_tx: Instant,
    tick: u64,
    total_sent: u64,
    payload_fn: fn(u64) -> Vec<u8>,
}

/// Representation of a CAN node, including its transmit schedule and payload generation function.
impl Node {
    fn new(
        name: &'static str,
        id: u32,
        extended: bool,
        period_ms: u64,
        payload_fn: fn(u64) -> Vec<u8>,
    ) -> Self {
        Self {
            name,
            id,
            extended,
            period_ms,
            next_tx: Instant::now(),
            tick: 0,
            total_sent: 0,
            payload_fn,
        }
    }

    fn is_due(&self) -> bool {
        Instant::now() >= self.next_tx
    }

    /// Build a CAN data frame for the current tick, using the node's payload function.
    fn build_frame(&self) -> Result<CanDataFrame> {
        let payload = (self.payload_fn)(self.tick);
        if self.extended {
            let eid = ExtendedId::new(self.id)
                .ok_or_else(|| anyhow::anyhow!("invalid EFF ID 0x{:08X}", self.id))?;
            CanDataFrame::new(eid, &payload)
                .ok_or_else(|| anyhow::anyhow!("frame build failed for {}", self.name))
        } else {
            let sid = StandardId::new(self.id as u16)
                .ok_or_else(|| anyhow::anyhow!("invalid SFF ID 0x{:03X}", self.id))?;
            CanDataFrame::new(sid, &payload)
                .ok_or_else(|| anyhow::anyhow!("frame build failed for {}", self.name))
        }
    }

    /// Advance the node's internal state, updating the next transmit time and tick counter.
    fn advance(&mut self) {
        self.tick += 1;
        self.total_sent += 1;
        self.next_tx += Duration::from_millis(self.period_ms);
        // Clamp: drop missed slots instead of sending a burst after a stall
        let now = Instant::now();
        if self.next_tx < now {
            self.next_tx = now + Duration::from_millis(self.period_ms);
        }
    }
}

/// Entry point for the CAN traffic generator. Initializes the CAN socket, sets up nodes, and runs the main transmit loop.
fn main() -> Result<()> {
    let cli = Cli::parse();

    let socket = CanSocket::open(&cli.iface).with_context(|| {
        format!(
            "Cannot open '{}'. Set up a virtual CAN interface with:\n  \
             modprobe vcan\n  \
             ip link add dev vcan0 type vcan\n  \
             ip link set vcan0 up",
            cli.iface
        )
    })?;
    // Short timeout so read_frame() acts non-blocking in the drain loop.
    // SO_RECV_OWN_MSGS is off by default, so we only see frames from other
    // sockets (iottack can send, etc.) Never our own TX.
    socket
        .set_read_timeout(Duration::from_millis(1))
        .context("set_read_timeout")?;

    let mut nodes = build_nodes();

    // Spread initial transmit times so all nodes don't fire simultaneously
    let stagger = Duration::from_millis(5);
    for (i, node) in nodes.iter_mut().enumerate() {
        node.next_tx += stagger * (i as u32);
    }

    print_header(&cli.iface, cli.duration, &nodes);

    let deadline = (cli.duration > 0)
        .then(|| Instant::now() + Duration::from_secs(cli.duration));
    let stats_interval = Duration::from_secs(cli.stats_interval.max(1));

    let mut total_sent: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut total_recv: u64 = 0;
    let mut interval_sent: u64 = 0;
    let mut last_stats = Instant::now();

    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }

        for node in nodes.iter_mut() {
            if !node.is_due() {
                continue;
            }
            match node.build_frame() {
                Ok(frame) => match socket.write_frame(&frame) {
                    Ok(()) => {
                        total_sent += 1;
                        interval_sent += 1;
                    }
                    Err(e) => {
                        total_errors += 1;
                        eprintln!("[error] write {} (id={:03X}h): {e}", node.name, node.id);
                    }
                },
                Err(e) => eprintln!("[error] build {}: {e}", node.name),
            }
            node.advance();
        }

        // Drain any frames written by external tools (iottack can send, etc.).
        // The socket does not echo its own TX frames, so everything here came
        // from another process.
        drain_rx(&socket, &mut total_recv);

        // Sleep until the next node is due (but no longer than 10 ms)
        if let Some(next) = nodes.iter().map(|n| n.next_tx).min() {
            let now = Instant::now();
            if next > now {
                std::thread::sleep((next - now).min(Duration::from_millis(10)));
            }
        }

        // Periodic stats
        let elapsed = last_stats.elapsed();
        if elapsed >= stats_interval {
            let rate = interval_sent as f64 / elapsed.as_secs_f64();
            println!(
                "  sent={total_sent:<8}  recv={total_recv:<6}  errors={total_errors}  rate={rate:.1} frames/s"
            );
            interval_sent = 0;
            last_stats = Instant::now();
        }
    }

    println!("\nSimulator stopped.  total_sent={total_sent}  errors={total_errors}");
    Ok(())
}

fn build_nodes() -> Vec<Node> {
    vec![
        // --- CANopen master
        // SYNC (0x080): 10 Hz - triggers "CANopen: SYNC/timestamp"
        Node::new("canopen-sync", 0x080, false, 100, |tick| {
            vec![(tick & 0xFF) as u8]
        }),
        // EMCY from node 1 (0x081): 0.2 Hz - triggers "CANopen: EMCY"
        Node::new("canopen-emcy-node1", 0x081, false, 5000, |tick| {
            if tick % 3 == 0 {
                // Generic error 0x1000
                vec![0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
            } else {
                // Fault cleared
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            }
        }),
        // --- CANopen node 1: temperature/pressure sensor
        // TPDO1 (0x181): 10 Hz - triggers "CANopen: PDO"
        Node::new("canopen-node1-tpdo1", 0x181, false, 100, |tick| {
            // Temperature 65–75 °C ×10 (int16 big-endian)
            let temp = 650u16 + ((tick * 7 % 100) as u16);
            // Pressure 20–35 (×10 bar, i.e. 2.0–3.5 bar)
            let pres = 20u16 + ((tick * 3 % 15) as u16);
            vec![
                (temp >> 8) as u8, (temp & 0xFF) as u8,
                (pres >> 8) as u8, (pres & 0xFF) as u8,
                0x00, 0x00, 0x00, 0x00,
            ]
        }),
        // TPDO2 (0x281): 5 Hz - digital I/O status
        Node::new("canopen-node1-tpdo2", 0x281, false, 200, |tick| {
            let io = if tick % 10 < 7 { 0x01u8 } else { 0x03u8 };
            vec![io, 0x00]
        }),
        // SDO server response (0x581): 0.5 Hz - triggers "CANopen: SDO server response"
        Node::new("canopen-node1-sdo-resp", 0x581, false, 2000, |tick| {
            match tick % 3 {
                0 => vec![0x43, 0x00, 0x10, 0x00, 0x91, 0x01, 0x02, 0x00], // device type
                1 => vec![0x4B, 0x18, 0x10, 0x01, 0x34, 0x12, 0x00, 0x00], // vendor ID
                _ => vec![0x4B, 0x18, 0x10, 0x02, 0x01, 0x00, 0x00, 0x00], // product code
            }
        }),
        // SDO client request (0x601): 0.5 Hz - triggers "CANopen: SDO client request
        //   (unauthenticated register access)"
        Node::new("canopen-node1-sdo-req", 0x601, false, 2000, |tick| {
            match tick % 4 {
                0 => vec![0x40, 0x18, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00], // read vendor ID
                1 => vec![0x40, 0x18, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00], // read product code
                2 => vec![0x40, 0x00, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00], // read digital inputs
                // Unauthenticated write to digital outputs - high-value security finding
                _ => vec![0x2F, 0x00, 0x62, 0x01, 0x01, 0x00, 0x00, 0x00],
            }
        }),
        // NMT heartbeat (0x701): 1 Hz - triggers "CANopen: NMT heartbeat/node guarding"
        Node::new("canopen-node1-heartbeat", 0x701, false, 1000, |tick| {
            // Mostly operational (0x05), briefly pre-operational (0x7F)
            let state = if tick % 20 < 18 { 0x05u8 } else { 0x7Fu8 };
            vec![state]
        }),
        // --- CANopen node 2: motor controller
        // TPDO1 (0x182): 5 Hz
        Node::new("canopen-node2-tpdo1", 0x182, false, 200, |tick| {
            let rpm = 1500u16 + ((tick * 13 % 500) as u16);
            vec![
                (rpm >> 8) as u8, (rpm & 0xFF) as u8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        }),
        // NMT heartbeat (0x702): 1 Hz
        Node::new("canopen-node2-heartbeat", 0x702, false, 1000, |_| vec![0x05]),
        // --- CANopen node 3: valve controller
        // TPDO1 (0x183): 2 Hz
        Node::new("canopen-node3-tpdo1", 0x183, false, 500, |tick| {
            let setpoint = (tick % 100) as u8;
            let actual = ((tick + 2) % 100) as u8;
            vec![setpoint, actual, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        }),
        // NMT heartbeat (0x703): 1 Hz
        Node::new("canopen-node3-heartbeat", 0x703, false, 1000, |_| vec![0x05]),
        // --- OBD-II / ISO 15765-4
        // Diagnostic broadcast (0x7DF): 1 Hz - HIGH severity in iottack
        Node::new("obd2-broadcast", 0x7DF, false, 1000, |tick| {
            let pid = [0x0Cu8, 0x0D, 0x05, 0x0F][(tick % 4) as usize];
            vec![0x02, 0x01, pid, 0x00, 0x00, 0x00, 0x00, 0x00]
        }),
        // ECU 1 diagnostic response (0x7E8): 1 Hz - HIGH severity in iottack
        Node::new("obd2-ecu1-response", 0x7E8, false, 1000, |tick| {
            match tick % 4 {
                0 => { // PID 0x0C: RPM = 2500 rpm  (A*256+B)/4
                    let raw = 2500u16 * 4;
                    vec![0x04, 0x41, 0x0C, (raw >> 8) as u8, (raw & 0xFF) as u8, 0x00, 0x00, 0x00]
                }
                1 => { // PID 0x0D: speed = 80 km/h
                    vec![0x03, 0x41, 0x0D, 80, 0x00, 0x00, 0x00, 0x00]
                }
                2 => { // PID 0x05: coolant temp = 92 °C  (A-40)
                    vec![0x03, 0x41, 0x05, 92 + 40, 0x00, 0x00, 0x00, 0x00]
                }
                _ => { // PID 0x0F: intake air = 25 °C  (A-40)
                    vec![0x03, 0x41, 0x0F, 25 + 40, 0x00, 0x00, 0x00, 0x00]
                }
            }
        }),
        // --- J1939 (extended 29-bit EFF)
        // EEC1 (Electronic Engine Controller 1), PGN 0xF004, SA=0x00: 10 Hz
        // 29-bit ID = Priority(3)=0b011 | DP=0 | PF=0xF0 | PS=0x04 | SA=0x00
        //           = 0x0CF00400
        Node::new("j1939-eec1", 0x0CF00400, true, 100, |tick| {
            // Byte 0: torque demand (0–100%)
            // Bytes 2-3: engine speed (0.125 rpm/bit, range 0–8031.875)
            let torque = ((tick * 3) % 100) as u8;
            let rpm_raw = (2500.0_f64 / 0.125) as u16; // 2500 rpm
            vec![
                torque,
                0xFF, // driver torque demand
                (rpm_raw & 0xFF) as u8,
                (rpm_raw >> 8) as u8,
                0xFF, 0xFF, 0xFF, 0xFF,
            ]
        }),
    ]
}

// --- RX support

/// Drain all frames currently queued on the socket and log them.
///
/// Because SO_RECV_OWN_MSGS is off by default, every frame returned here was
/// sent by a different socket.
fn drain_rx(socket: &CanSocket, total_recv: &mut u64) {
    loop {
        match socket.read_frame() {
            Ok(CanFrame::Data(f)) => {
                *total_recv += 1;
                let (id, ext) = raw_id(&f);
                let id_str = fmt_id(id, ext);
                let data = f.data();
                let hex = hex_bytes(data);
                println!("[recv]  id={id_str:<14}  dlc={}  data=[{hex}]", f.dlc());
                if let Some(detail) = decode_frame(id, ext, data) {
                    println!("        {detail}");
                }
            }
            Ok(CanFrame::Remote(f)) => {
                *total_recv += 1;
                let (id, ext) = raw_id(&f);
                println!("[recv]  id={:<14}  RTR  dlc={}", fmt_id(id, ext), f.dlc());
            }
            Ok(CanFrame::Error(_)) => {
                eprintln!("[recv]  error frame");
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                eprintln!("[rx-error]  {e}");
                break;
            }
        }
    }
}

/// Extract the raw CAN ID and whether it is an extended frame from a CAN frame.
fn raw_id(f: &impl EmbeddedFrame) -> (u32, bool) {
    match f.id() {
        Id::Standard(s) => (s.as_raw() as u32, false),
        Id::Extended(e) => (e.as_raw(), true),
    }
}

/// Format a CAN ID as a human-readable string, indicating whether it is standard or extended.
fn fmt_id(id: u32, ext: bool) -> String {
    if ext {
        format!("{id:08X}h(EFF)")
    } else {
        format!("{id:03X}h(SFF)")
    }
}

fn hex_bytes(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode a received frame into a human-readable description of the operation
/// and any state change it implies.  Returns None for unrecognized frames.
fn decode_frame(id: u32, ext: bool, data: &[u8]) -> Option<String> {
    if ext || data.is_empty() {
        return None;
    }
    match id {
        // NMT command (0x000)
        0x000 if data.len() >= 2 => {
            let cmd_name = match data[0] {
                0x01 => "Start node (→ Operational)",
                0x02 => "Stop node",
                0x80 => "Enter Pre-Operational",
                0x81 => "Reset node",
                0x82 => "Reset communication",
                _ => "Unknown NMT command",
            };
            let target = if data[1] == 0 {
                "all nodes".to_string()
            } else {
                format!("node {}", data[1])
            };
            Some(format!("CANopen NMT  cmd={cmd_name}  target={target}"))
        }

        // SDO client request to node N at base address 0x600+N
        0x600..=0x67F if data.len() >= 4 => {
            let node_id = id - 0x600;
            let cmd = data[0];
            let index = u16::from_le_bytes([data[1], data[2]]);
            let subidx = data[3];

            match cmd >> 5 {
                // Upload initiate (read request)
                0b010 => Some(format!(
                    "CANopen SDO read-request  node={node_id}  obj={index:#06X}:{subidx:02X}"
                )),
                // Download initiate (write command) — implies a state change
                0b001 => {
                    let expedited = (cmd >> 1) & 1 == 1;
                    let size_indicated = cmd & 1 == 1;
                    if expedited && size_indicated {
                        let n = ((cmd >> 2) & 0x03) as usize;
                        let byte_count = 4usize.saturating_sub(n);
                        let raw = &data[4..data.len().min(4 + byte_count)];
                        let value = raw
                            .iter()
                            .enumerate()
                            .fold(0u32, |acc, (i, &b)| acc | ((b as u32) << (i * 8)));
                        let obj_hint = sdo_object_hint(index, subidx);
                        Some(format!(
                            "CANopen SDO write  node={node_id}  obj={index:#06X}:{subidx:02X}\
                             {obj_hint}  value={value:#010X}  [{byte_count} byte(s)]  \
                             -> state change"
                        ))
                    } else {
                        Some(format!(
                            "CANopen SDO write (segmented)  node={node_id}  \
                             obj={index:#06X}:{subidx:02X}"
                        ))
                    }
                }
                _ => None,
            }
        }

        // OBD-II diagnostic broadcast / targeted request
        0x7DF | 0x7E0..=0x7E7 if data.len() >= 3 => {
            let svc = data[1];
            let pid = data[2];
            let pid_label = obd2_pid_label(svc, pid);
            let target = if id == 0x7DF {
                "all ECUs (broadcast)".to_string()
            } else {
                format!("ECU {} ({id:#05X}h)", id - 0x7E0)
            };
            let resp_id = if id == 0x7DF { 0x7E8u32 } else { id + 8 };
            Some(format!(
                "OBD-II request  target={target}  svc={svc:#04X}  pid={pid:#04X}  \
                 ({pid_label})  → response expected on {resp_id:#05X}h"
            ))
        }

        _ => None,
    }
}

/// Return a human-readable hint for a given SDO object index and subindex.
fn sdo_object_hint(index: u16, subidx: u8) -> &'static str {
    match (index, subidx) {
        (0x1000, 0) => " (device-type)",
        (0x1001, 0) => " (error-register)",
        (0x1017, 0) => " (heartbeat-period)",
        (0x1018, 1) => " (vendor-ID)",
        (0x1018, 2) => " (product-code)",
        (0x1018, 3) => " (revision-number)",
        (0x6000, _) => " (digital-inputs)",
        (0x6200, _) => " (digital-outputs)",
        (0x6401, _) => " (analog-inputs)",
        (0x6411, _) => " (analog-outputs)",
        _ => "",
    }
}

/// Return a human-readable label for a given OBD-II service and PID.
fn obd2_pid_label(svc: u8, pid: u8) -> &'static str {
    if svc == 0x01 {
        match pid {
            0x00 => "supported PIDs 01-20",
            0x03 => "fuel system status",
            0x04 => "calculated engine load",
            0x05 => "coolant temperature",
            0x0C => "engine RPM",
            0x0D => "vehicle speed",
            0x0F => "intake air temperature",
            0x11 => "throttle position",
            0x1C => "OBD standards",
            0x2F => "fuel tank level",
            0x33 => "barometric pressure",
            _ => "unknown PID",
        }
    } else {
        match svc {
            0x02 => "freeze frame data",
            0x03 => "emission fault codes",
            0x04 => "clear fault codes",
            0x07 => "pending fault codes",
            0x09 => "vehicle information",
            _ => "unknown service",
        }
    }
}

/// Print the header for the CAN bus simulator output
fn print_header(iface: &str, duration: u64, nodes: &[Node]) {
    println!("IoTtack CAN bus simulator");
    println!("Interface : {iface}");
    if duration > 0 {
        println!("Duration  : {duration}s");
    } else {
        println!("Duration  : unlimited  (Ctrl-C to stop)");
    }
    println!();
    println!(
        "  {:<30}  {:<20}  {}",
        "node", "id", "period"
    );
    println!("  {}", "-".repeat(60));
    for node in nodes {
        let id_str = if node.extended {
            format!("{:08X}h (EFF/29-bit)", node.id)
        } else {
            format!("{:03X}h (SFF/11-bit)", node.id)
        };
        println!(
            "  {:<30}  {:<20}  {}ms",
            node.name, id_str, node.period_ms
        );
    }
    println!();
    println!("Sending ...");
}
