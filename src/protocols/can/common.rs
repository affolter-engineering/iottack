use socketcan::{EmbeddedFrame, Id};

/// Extract (numeric_id, is_extended) from any EmbeddedFrame.
pub fn frame_id(f: &impl EmbeddedFrame) -> (u32, bool) {
    match f.id() {
        Id::Standard(s) => (s.as_raw() as u32, false),
        Id::Extended(e) => (e.as_raw(), true),
    }
}

/// Format a CAN ID as a hex string with format suffix.
pub fn format_id(id: u32, extended: bool) -> String {
    if extended {
        format!("{id:08X}h")
    } else {
        format!("{id:03X}h")
    }
}

/// Return a known protocol hint for a standard (11-bit) CAN ID, or None.
pub fn known_id_hint(id: u32) -> Option<&'static str> {
    match id {
        0x000 => Some("CANopen: NMT network management"),
        0x001..=0x07F => Some("CANopen: SYNC/timestamp"),
        0x080..=0x0FF => Some("CANopen: EMCY (emergency) messages"),
        0x100..=0x4FF => Some("CANopen: PDO (process data objects)"),
        0x580..=0x5FF => Some("CANopen: SDO server response"),
        0x600..=0x67F => Some("CANopen: SDO client request (unauthenticated register access)"),
        0x700..=0x77F => Some("CANopen: NMT heartbeat/node guarding"),
        0x7DF => Some("OBD-II: diagnostic broadcast. Exposes vehicle diagnostics (ISO 15765-4)"),
        0x7E0..=0x7E7 => Some("OBD-II: diagnostic request to specific ECU (ISO 15765-4)"),
        0x7E8..=0x7EF => Some("OBD-II: diagnostic response from ECU (ISO 15765-4)"),
        _ => None,
    }
}

/// Severity hint for a known standard ID: High for OBD-II, Medium for CANopen.
pub fn id_severity_high(id: u32) -> bool {
    id == 0x7DF || (0x7E0..=0x7EF).contains(&id)
}

/// Format a byte slice as space-separated hex.
pub fn hex_bytes(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub const IFACE_HELP: &str =
    "Bring up the interface:\n  \
     ip link set <iface> up type can bitrate 500000\n\
     For virtual CAN:\n  \
     modprobe vcan && ip link add dev vcan0 type vcan && ip link set vcan0 up";
