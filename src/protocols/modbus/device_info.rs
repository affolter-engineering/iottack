use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use super::common::ModbusClient;

const MEI_OBJECT_LABELS: &[(u8, &str)] = &[
    (0x00, "VendorName"),
    (0x01, "ProductCode"),
    (0x02, "MajorMinorRevision"),
    (0x03, "VendorUrl"),
    (0x04, "ProductName"),
    (0x05, "ModelName"),
    (0x06, "UserApplicationName"),
];

pub struct DeviceInfo {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
}

impl DeviceInfo {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            tcp_port: 502,
            serial: String::new(),
            baud: 9600,
            unit_id: 1,
            timeout_ms: 3000,
        }
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a Modbus/TCP MBAP frame for FC43 MEI Read Device Identification.
fn build_mei_request(unit_id: u8, category: u8) -> [u8; 11] {
    [
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Protocol ID (Modbus)
        0x00, 0x05, // Length (5 bytes follow: unit + func + mei_type + category + obj_id)
        unit_id, 0x2B, // FC43: Modbus Encapsulated Interface
        0x0E, // MEI Type 14: Read Device Identification
        category, 0x00, // Start from object 0
    ]
}

/// Build an FC43 MEI request for Modbus RTU (with CRC).
fn build_rtu_mei_request(unit_id: u8, category: u8) -> Vec<u8> {
    let mut frame = vec![unit_id, 0x2B, 0x0E, category, 0x00];
    let crc = rtu_crc16(&frame);
    frame.push((crc & 0xFF) as u8);
    frame.push((crc >> 8) as u8);
    frame
}

fn rtu_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Parse FC43 objects from a response body starting at the object list.
/// `body` starts at the first object (after MBAP/RTU header + fc + mei_type +
/// conformity_level + more_follows + next_obj_id + num_objects).
fn parse_mei_objects(body: &[u8], num_objects: usize) -> Vec<(u8, String)> {
    let mut objects = Vec::new();
    let mut pos = 0;
    for _ in 0..num_objects {
        if pos + 2 > body.len() {
            break;
        }
        let obj_id = body[pos];
        let obj_len = body[pos + 1] as usize;
        pos += 2;
        if pos + obj_len > body.len() {
            break;
        }
        let value = String::from_utf8_lossy(&body[pos..pos + obj_len]).into_owned();
        objects.push((obj_id, value));
        pos += obj_len;
    }
    objects
}

/// Read MEI device identification over TCP using raw socket I/O.
/// Returns (objects, raw_response_hex) on success.
fn read_device_info_tcp(
    host: &str,
    tcp_port: u16,
    unit_id: u8,
    timeout: Duration,
) -> Result<Vec<(u8, String)>> {
    let addr: SocketAddr = format!("{host}:{tcp_port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Try basic (0x01), then regular (0x02), then extended (0x03) categories
    for category in [0x01u8, 0x02, 0x03] {
        let req = build_mei_request(unit_id, category);
        stream.write_all(&req)?;

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf)?;

        if n < 9 {
            continue;
        }

        // Check for exception: byte 7 = 0x2B | 0x80 = 0xAB
        if buf[7] == 0xAB {
            return Err(anyhow::anyhow!(
                "FC43 not supported (exception code 0x{:02X})",
                buf[8]
            ));
        }

        // MBAP header = 7 bytes, then FC(1) + MEI_type(1) + conformity(1) +
        // more_follows(1) + next_obj_id(1) + num_objects(1) = 6 bytes fixed
        if n < 13 {
            continue;
        }

        let num_objects = buf[12] as usize;
        let objects = parse_mei_objects(&buf[13..n], num_objects);
        if !objects.is_empty() {
            return Ok(objects);
        }
    }

    Ok(vec![])
}

/// Read MEI device identification over RTU serial.
fn read_device_info_rtu(
    port: &mut Box<dyn serialport::SerialPort>,
    unit_id: u8,
) -> Result<Vec<(u8, String)>> {
    use std::io::Write;

    let req = build_rtu_mei_request(unit_id, 0x01);
    port.write_all(&req)?;

    let mut buf = [0u8; 256];
    let mut n = 0;
    loop {
        match port.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if n >= buf.len() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(e.into()),
        }
    }

    if n < 4 {
        return Err(anyhow::anyhow!("no response"));
    }

    // Exception check
    if buf[1] & 0x80 != 0 {
        return Err(anyhow::anyhow!(
            "FC43 exception 0x{:02X}",
            if n > 2 { buf[2] } else { 0 }
        ));
    }

    // RTU FC43 response: [uid, 0x2B, 0x0E, conformity, more_follows, next_id, num_objects, ...]
    if n < 7 {
        return Ok(vec![]);
    }

    let num_objects = buf[6] as usize;
    let objects = parse_mei_objects(&buf[7..n.saturating_sub(2)], num_objects);
    Ok(objects)
}

fn format_mei_label(id: u8) -> &'static str {
    MEI_OBJECT_LABELS
        .iter()
        .find(|&&(oid, _)| oid == id)
        .map(|(_, label)| *label)
        .unwrap_or("DeviceSpecific")
}

impl Plugin for DeviceInfo {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Read Modbus controller device identification (FC43 MEI)",
            description: "Queries a Modbus device for its identification strings using function \
                          code 43 (Modbus Encapsulated Interface, MEI type 14). Returns vendor \
                          name, product code, firmware revision, URLs and model name where \
                          supported. Also verifies unauthenticated connectivity and probes \
                          the first holding registers to confirm the device is responsive.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target hostname or IP for Modbus/TCP",
                    value_name: "HOST",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "tcp_port",
                    short: None,
                    help: "Modbus/TCP port (default 502)",
                    value_name: "PORT",
                    default: Some("502"),
                    is_flag: false
                },
                CliArg {
                    name: "serial",
                    short: Some('s'),
                    help: "Serial device for Modbus RTU (e.g., /dev/ttyUSB0)",
                    value_name: "DEVICE",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "baud",
                    short: None,
                    help: "Baud rate for RTU serial transport (default 9600)",
                    value_name: "BAUD",
                    default: Some("9600"),
                    is_flag: false
                },
                CliArg {
                    name: "unit",
                    short: Some('u'),
                    help: "Modbus unit/slave ID 1-247 (default 1)",
                    value_name: "ID",
                    default: Some("1"),
                    is_flag: false
                },
                CliArg {
                    name: "timeout_ms",
                    short: Some('t'),
                    help: "Timeout in milliseconds (default 3000)",
                    value_name: "MS",
                    default: Some("3000"),
                    is_flag: false
                },
            ],
        )
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get_or("host", "");
        self.tcp_port = config.parse_or("tcp_port", 502u16);
        self.serial = config.get_or("serial", "");
        self.baud = config.parse_or("baud", 9600u32);
        self.unit_id = config.parse_or("unit", 1u8);
        self.timeout_ms = config.parse_or("timeout_ms", 3000u64);
        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let mut client = match ModbusClient::connect(
            &self.host,
            self.tcp_port,
            &self.serial,
            self.baud,
            self.unit_id,
            self.timeout_ms,
        ) {
            Ok(c) => c,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Connection failed",
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let transport = client.transport_label().to_string();
        let timeout = Duration::from_millis(self.timeout_ms);

        tracing::info!(
            transport = %transport,
            unit = self.unit_id,
            "probing device with FC03 (holding registers 0-3)",
        );

        // Confirm device responds by reading a few holding registers.
        let probe_result = client.read_holding_registers(0, 4);
        let probe_desc = match &probe_result {
            Ok(regs) => {
                let vals: Vec<String> = regs.iter().map(|v| format!("0x{v:04X}")).collect();
                tracing::info!(transport = %transport, values = ?vals, "probe succeeded");
                format!("Holding registers 0-3: [{}]", vals.join(", "))
            }
            Err(e) => {
                tracing::info!(transport = %transport, error = %e, "probe read failed");
                format!("Holding registers 0-3: not readable ({e})")
            }
        };

        result.add(
            PluginFinding::new(
                Severity::High,
                format!("{transport}: unauthenticated connection accepted (unit {})", self.unit_id),
                format!(
                    "Device at {}:{} accepted a Modbus connection without authentication. {probe_desc}",
                    if self.host.is_empty() { &self.serial } else { &self.host },
                    self.tcp_port,
                ),
            )
            .with_evidence(probe_desc.clone()),
        );

        tracing::info!(transport = %transport, unit = self.unit_id, "requesting FC43 MEI device identification");

        // Try FC43 MEI device identification.
        let mei_result = match &client {
            ModbusClient::Tcp(_) => {
                read_device_info_tcp(&self.host, self.tcp_port, self.unit_id, timeout)
            }
            ModbusClient::Rtu(_) => {
                // We need the raw port. Re-open for the MEI query since ModbusClient
                // doesn't expose raw port access. The connectivity probe above already
                // confirmed the device responds.
                match serialport::new(&self.serial, self.baud)
                    .timeout(timeout)
                    .open()
                {
                    Ok(mut port) => read_device_info_rtu(&mut port, self.unit_id),
                    Err(e) => Err(anyhow::anyhow!("cannot re-open serial port: {e}")),
                }
            }
        };

        match mei_result {
            Ok(objects) if !objects.is_empty() => {
                tracing::info!(
                    transport = %transport,
                    objects = objects.len(),
                    "FC43 MEI returned identification objects",
                );
                for (id, val) in &objects {
                    tracing::debug!(object_id = id, value = %val, "MEI object");
                }
                let evidence = objects
                    .iter()
                    .map(|(id, val)| format!("  0x{id:02X} {}: {val}", format_mei_label(*id)))
                    .collect::<Vec<_>>()
                    .join("\n");

                let summary = objects
                    .iter()
                    .map(|(id, val)| format!("{}: {val}", format_mei_label(*id)))
                    .collect::<Vec<_>>()
                    .join("; ");

                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!(
                            "{transport}: device identification retrieved via FC43 MEI (unit {})",
                            self.unit_id
                        ),
                        format!(
                            "Device exposes identification strings without authentication: {summary}"
                        ),
                    )
                    .with_evidence(evidence),
                );
            }
            Ok(_) => {
                tracing::info!(transport = %transport, "FC43 MEI returned no identification objects");
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("{transport}: FC43 MEI returned no identification objects"),
                    "The device accepted FC43 but returned an empty identification response.",
                ));
            }
            Err(e) => {
                tracing::info!(transport = %transport, error = %e, "FC43 MEI not supported or failed");
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("{transport}: FC43 MEI not supported or failed"),
                    format!("{e}"),
                ));
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DeviceInfo::new()) as Box<dyn crate::Plugin>)
}
