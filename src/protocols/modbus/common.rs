use anyhow::{Result, anyhow};
use modbus::Client;
use std::{
    io::{Read, Write},
    time::Duration,
};

use crate::core::CliArg;

pub const TRANSPORT_ARGS: &[CliArg] = &[
    CliArg {
        name: "host",
        short: Some('H'),
        help: "Target hostname or IP for Modbus/TCP",
        value_name: "HOST",
        default: None,
        is_flag: false,
    },
    CliArg {
        name: "tcp_port",
        short: None,
        help: "Modbus/TCP port (default 502)",
        value_name: "PORT",
        default: Some("502"),
        is_flag: false,
    },
    CliArg {
        name: "serial",
        short: Some('s'),
        help: "Serial device for Modbus RTU (e.g. /dev/ttyUSB0)",
        value_name: "DEVICE",
        default: None,
        is_flag: false,
    },
    CliArg {
        name: "baud",
        short: None,
        help: "Baud rate for RTU serial transport (default 9600)",
        value_name: "BAUD",
        default: Some("9600"),
        is_flag: false,
    },
    CliArg {
        name: "unit",
        short: Some('u'),
        help: "Modbus unit / slave ID, 1-247 (default 1)",
        value_name: "ID",
        default: Some("1"),
        is_flag: false,
    },
    CliArg {
        name: "timeout_ms",
        short: Some('t'),
        help: "Operation timeout in milliseconds (default 3000; use 500-1000 for RTU)",
        value_name: "MS",
        default: Some("3000"),
        is_flag: false,
    },
];

pub struct RtuClient {
    port: Box<dyn serialport::SerialPort>,
    unit_id: u8,
}

impl RtuClient {
    pub fn open(device: &str, baud: u32, unit_id: u8, timeout_ms: u64) -> Result<Self> {
        let port = serialport::new(device, baud)
            .timeout(Duration::from_millis(timeout_ms))
            .open()
            .map_err(|e| anyhow!("failed to open {device}: {e}"))?;
        Ok(Self { port, unit_id })
    }

    fn crc16(data: &[u8]) -> u16 {
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

    fn build_frame(&self, func: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![self.unit_id, func];
        frame.extend_from_slice(payload);
        let crc = Self::crc16(&frame);
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);
        frame
    }

    // Reads up to `expected` bytes, stopping on timeout (marks end of RTU frame).
    fn recv(&mut self, expected: usize) -> Result<Vec<u8>> {
        let cap = expected.max(8);
        let mut buf = vec![0u8; cap];
        let mut n = 0;
        loop {
            match self.port.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => {
                    n += k;
                    if n >= expected {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e.into()),
            }
        }
        if n < 4 {
            return Err(anyhow!("no response (received {n} bytes)"));
        }
        // Exception frame: function code has MSB set
        if buf[1] & 0x80 != 0 {
            let code = if n > 2 { buf[2] } else { 0 };
            return Err(anyhow!("Modbus RTU exception 0x{code:02X}"));
        }
        let data_end = n - 2;
        let calc = Self::crc16(&buf[..data_end]);
        let recv_crc = (buf[data_end] as u16) | ((buf[data_end + 1] as u16) << 8);
        if calc != recv_crc {
            return Err(anyhow!(
                "CRC mismatch (calc={calc:#06x} recv={recv_crc:#06x})"
            ));
        }
        Ok(buf[..n].to_vec())
    }

    pub fn read_registers(&mut self, func: u8, addr: u16, count: u16) -> Result<Vec<u16>> {
        let req = self.build_frame(func, &addr_count_payload(addr, count));
        self.port.write_all(&req)?;
        let resp = self.recv(5 + count as usize * 2)?;
        parse_register_response(&resp)
    }

    pub fn read_bits(&mut self, func: u8, addr: u16, count: u16) -> Result<Vec<bool>> {
        let req = self.build_frame(func, &addr_count_payload(addr, count));
        self.port.write_all(&req)?;
        let byte_count = ((count + 7) / 8) as usize;
        let resp = self.recv(5 + byte_count)?;
        parse_bit_response(&resp, count)
    }

    pub fn write_single_register(&mut self, addr: u16, value: u16) -> Result<()> {
        let payload = [
            (addr >> 8) as u8,
            (addr & 0xFF) as u8,
            (value >> 8) as u8,
            (value & 0xFF) as u8,
        ];
        let req = self.build_frame(0x06, &payload);
        self.port.write_all(&req)?;
        self.recv(8)?;
        Ok(())
    }

    pub fn write_multiple_registers(&mut self, addr: u16, values: &[u16]) -> Result<()> {
        let count = values.len() as u16;
        let mut payload = vec![
            (addr >> 8) as u8,
            (addr & 0xFF) as u8,
            (count >> 8) as u8,
            (count & 0xFF) as u8,
            (count * 2) as u8,
        ];
        for &v in values {
            payload.push((v >> 8) as u8);
            payload.push((v & 0xFF) as u8);
        }
        let req = self.build_frame(0x10, &payload);
        self.port.write_all(&req)?;
        self.recv(8)?;
        Ok(())
    }

    pub fn write_single_coil(&mut self, addr: u16, on: bool) -> Result<()> {
        let val: u16 = if on { 0xFF00 } else { 0x0000 };
        let payload = [
            (addr >> 8) as u8,
            (addr & 0xFF) as u8,
            (val >> 8) as u8,
            (val & 0xFF) as u8,
        ];
        let req = self.build_frame(0x05, &payload);
        self.port.write_all(&req)?;
        self.recv(8)?;
        Ok(())
    }
}

fn addr_count_payload(addr: u16, count: u16) -> [u8; 4] {
    [
        (addr >> 8) as u8,
        (addr & 0xFF) as u8,
        (count >> 8) as u8,
        (count & 0xFF) as u8,
    ]
}

fn parse_register_response(resp: &[u8]) -> Result<Vec<u16>> {
    if resp.len() < 3 {
        return Err(anyhow!("response too short"));
    }
    let byte_count = resp[2] as usize;
    let data_end = resp.len().saturating_sub(2);
    let data = &resp[3..data_end.min(3 + byte_count)];
    let mut values = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        values.push(((data[i] as u16) << 8) | (data[i + 1] as u16));
        i += 2;
    }
    Ok(values)
}

fn parse_bit_response(resp: &[u8], count: u16) -> Result<Vec<bool>> {
    if resp.len() < 3 {
        return Err(anyhow!("response too short"));
    }
    let n_bytes = resp[2] as usize;
    let data_end = resp.len().saturating_sub(2);
    let data = &resp[3..data_end.min(3 + n_bytes)];
    let mut bits = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < data.len() {
            bits.push((data[byte_idx] >> bit_idx) & 1 != 0);
        }
    }
    Ok(bits)
}

pub enum ModbusClient {
    Tcp(modbus::tcp::Transport),
    Rtu(RtuClient),
}

impl ModbusClient {
    pub fn connect(
        host: &str,
        tcp_port: u16,
        serial: &str,
        baud: u32,
        unit_id: u8,
        timeout_ms: u64,
    ) -> Result<Self> {
        if !host.is_empty() {
            tracing::info!(
                host,
                port = tcp_port,
                unit_id,
                timeout_ms,
                "connecting via Modbus/TCP"
            );
            let timeout = Duration::from_millis(timeout_ms);
            let cfg = modbus::Config {
                tcp_port,
                tcp_connect_timeout: Some(timeout),
                tcp_read_timeout: Some(timeout),
                tcp_write_timeout: Some(timeout),
                modbus_uid: unit_id,
            };
            let t = modbus::Transport::new_with_cfg(host, cfg)
                .map_err(|e| anyhow!("TCP connect to {host}:{tcp_port} failed: {e}"))?;
            tracing::info!(host, port = tcp_port, "Modbus/TCP connected");
            Ok(Self::Tcp(t))
        } else if !serial.is_empty() {
            tracing::info!(
                device = serial,
                baud,
                unit_id,
                timeout_ms,
                "connecting via Modbus RTU"
            );
            let r = RtuClient::open(serial, baud, unit_id, timeout_ms)?;
            tracing::info!(device = serial, "Modbus RTU port opened");
            Ok(Self::Rtu(r))
        } else {
            Err(anyhow!(
                "specify --host for Modbus/TCP or --serial for Modbus RTU"
            ))
        }
    }

    pub fn transport_label(&self) -> &str {
        match self {
            Self::Tcp(_) => "Modbus/TCP",
            Self::Rtu(_) => "Modbus RTU",
        }
    }

    pub fn read_holding_registers(&mut self, addr: u16, count: u16) -> Result<Vec<u16>> {
        tracing::debug!(fc = "FC03", address = addr, count, "read holding registers");
        let result = match self {
            Self::Tcp(t) => t
                .read_holding_registers(addr, count)
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.read_registers(0x03, addr, count),
        };
        if let Ok(ref regs) = result {
            tracing::debug!(
                fc = "FC03",
                address = addr,
                returned = regs.len(),
                "holding registers ok"
            );
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC03", address = addr, error = %e, "holding registers failed");
        }
        result
    }

    pub fn read_input_registers(&mut self, addr: u16, count: u16) -> Result<Vec<u16>> {
        tracing::debug!(fc = "FC04", address = addr, count, "read input registers");
        let result = match self {
            Self::Tcp(t) => t
                .read_input_registers(addr, count)
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.read_registers(0x04, addr, count),
        };
        if let Ok(ref regs) = result {
            tracing::debug!(
                fc = "FC04",
                address = addr,
                returned = regs.len(),
                "input registers ok"
            );
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC04", address = addr, error = %e, "input registers failed");
        }
        result
    }

    pub fn read_coils(&mut self, addr: u16, count: u16) -> Result<Vec<bool>> {
        tracing::debug!(fc = "FC01", address = addr, count, "read coils");
        let result = match self {
            Self::Tcp(t) => t
                .read_coils(addr, count)
                .map(|v| v.into_iter().map(|c| c == modbus::Coil::On).collect())
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.read_bits(0x01, addr, count),
        };
        if let Ok(ref bits) = result {
            tracing::debug!(
                fc = "FC01",
                address = addr,
                returned = bits.len(),
                "coils ok"
            );
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC01", address = addr, error = %e, "coils failed");
        }
        result
    }

    pub fn read_discrete_inputs(&mut self, addr: u16, count: u16) -> Result<Vec<bool>> {
        tracing::debug!(fc = "FC02", address = addr, count, "read discrete inputs");
        let result = match self {
            Self::Tcp(t) => t
                .read_discrete_inputs(addr, count)
                .map(|v| v.into_iter().map(|c| c == modbus::Coil::On).collect())
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.read_bits(0x02, addr, count),
        };
        if let Ok(ref bits) = result {
            tracing::debug!(
                fc = "FC02",
                address = addr,
                returned = bits.len(),
                "discrete inputs ok"
            );
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC02", address = addr, error = %e, "discrete inputs failed");
        }
        result
    }

    pub fn write_single_register(&mut self, addr: u16, value: u16) -> Result<()> {
        tracing::debug!(fc = "FC06", address = addr, value, "write single register");
        let result = match self {
            Self::Tcp(t) => t
                .write_single_register(addr, value)
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.write_single_register(addr, value),
        };
        if result.is_ok() {
            tracing::debug!(fc = "FC06", address = addr, "write single register ok");
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC06", address = addr, error = %e, "write single register failed");
        }
        result
    }

    pub fn write_multiple_registers(&mut self, addr: u16, values: &[u16]) -> Result<()> {
        tracing::debug!(
            fc = "FC16",
            address = addr,
            count = values.len(),
            "write multiple registers"
        );
        let result = match self {
            Self::Tcp(t) => t
                .write_multiple_registers(addr, values)
                .map_err(|e| anyhow!("{e}")),
            Self::Rtu(r) => r.write_multiple_registers(addr, values),
        };
        if result.is_ok() {
            tracing::debug!(
                fc = "FC16",
                address = addr,
                count = values.len(),
                "write multiple registers ok"
            );
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC16", address = addr, error = %e, "write multiple registers failed");
        }
        result
    }

    pub fn write_single_coil(&mut self, addr: u16, on: bool) -> Result<()> {
        tracing::debug!(
            fc = "FC05",
            address = addr,
            value = if on { "ON" } else { "OFF" },
            "write single coil"
        );
        let result = match self {
            Self::Tcp(t) => {
                let coil = if on {
                    modbus::Coil::On
                } else {
                    modbus::Coil::Off
                };
                t.write_single_coil(addr, coil).map_err(|e| anyhow!("{e}"))
            }
            Self::Rtu(r) => r.write_single_coil(addr, on),
        };
        if result.is_ok() {
            tracing::debug!(fc = "FC05", address = addr, "write single coil ok");
        } else if let Err(ref e) = result {
            tracing::debug!(fc = "FC05", address = addr, error = %e, "write single coil failed");
        }
        result
    }
}
