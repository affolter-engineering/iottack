use super::UartConfig;
use anyhow::Result;
use serialport::SerialPort;
use std::{
    io::{Read, Write},
    time::Duration,
};

/// An open serial connection. Holds the OS port handle and exposes
/// framed I/O helpers used by all serial plugins.
pub struct UartSession {
    port: Box<dyn SerialPort>,
}

impl UartSession {
    pub fn open(config: &UartConfig) -> Result<Self> {
        let port = serialport::new(&config.port, config.baud_rate)
            .data_bits(config.data_bits)
            .stop_bits(config.stop_bits)
            .parity(config.parity)
            .timeout(Duration::from_millis(config.timeout_ms))
            .open()?;
        tracing::debug!(port = %config.port, baud = config.baud_rate, "opened serial port");
        Ok(Self { port })
    }

    /// Write raw bytes; returns number of bytes written.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<usize> {
        Ok(self.port.write(data)?)
    }

    /// Read up to `max_bytes`. Returns empty vec on timeout (not an error).
    pub fn read_bytes(&mut self, max_bytes: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; max_bytes];
        match self.port.read(&mut buf) {
            Ok(0) => Ok(vec![]),
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }

    /// Drain the port until a read times out, returning all collected bytes.
    pub fn drain(&mut self) -> Result<Vec<u8>> {
        let mut all = Vec::new();
        loop {
            let chunk = self.read_bytes(256)?;
            if chunk.is_empty() {
                break;
            }
            all.extend_from_slice(&chunk);
        }
        Ok(all)
    }

    /// Write a line terminated with CR+LF.
    pub fn write_line(&mut self, line: &str) -> Result<()> {
        let mut data = line.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        self.write_bytes(&data)?;
        Ok(())
    }

    /// Read until LF is received or timeout, stripping CR.
    pub fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.port.read(&mut byte) {
                Ok(1) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    if byte[0] != b'\r' {
                        line.push(byte[0]);
                    }
                }
                _ => break,
            }
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }

    /// Flush the transmit buffer.
    pub fn flush(&mut self) -> Result<()> {
        Ok(self.port.flush()?)
    }
}
