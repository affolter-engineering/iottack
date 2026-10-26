use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::{Result, anyhow};

use super::common::ModbusClient;

/// ReadRegisters holds the configuration for reading Modbus registers over TCP or RTU serial.
pub struct ReadRegisters {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
    address: u16,
    count: u16,
    register_type: String,
}

/// ReadRegisters is used to configure the parameters for reading Modbus registers.
impl ReadRegisters {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            tcp_port: 502,
            serial: String::new(),
            baud: 9600,
            unit_id: 1,
            timeout_ms: 3000,
            address: 0,
            count: 10,
            register_type: "holding".to_string(),
        }
    }
}

/// ReadRegisters represents a plugin for reading Modbus holding or input registers.
impl Default for ReadRegisters {
    fn default() -> Self {
        Self::new()
    }
}

/// Read a block of Modbus holding or input registers over TCP or RTU serial.
impl Plugin for ReadRegisters {
    fn meta(&self) -> PluginMeta {
        let mut m = plugin_meta!(
            summary: "Read Modbus holding or input registers",
            description: "Reads a contiguous block of 16-bit registers from a Modbus device \
                          over TCP or RTU serial. Unauthenticated register access can expose \
                          process data, setpoints and device configuration. Use \
                          --register-type input to read input registers (FC04) instead of \
                          holding registers (FC03).",
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
                    help: "Baud rate for RTU serial (default 9600)",
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
                CliArg {
                    name: "address",
                    short: Some('a'),
                    help: "Starting register address 0-65535 (default 0)",
                    value_name: "ADDR",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "count",
                    short: Some('c'),
                    help: "Number of registers to read, max. 125 (default 10)",
                    value_name: "N",
                    default: Some("10"),
                    is_flag: false
                },
                CliArg {
                    name: "register_type",
                    short: Some('T'),
                    help: "holding (FC03) or input (FC04)",
                    value_name: "TYPE",
                    default: Some("holding"),
                    is_flag: false
                },
            ],
        );
        m.name = "modbus/read-registers".to_string();
        m
    }

    /// Initialize the plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get_or("host", "");
        self.tcp_port = config.parse_or("tcp_port", 502u16);
        self.serial = config.get_or("serial", "");
        self.baud = config.parse_or("baud", 9600u32);
        self.unit_id = config.parse_or("unit", 1u8);
        self.timeout_ms = config.parse_or("timeout_ms", 3000u64);
        self.address = config.parse_or("address", 0u16);
        self.count = config.parse_or("count", 10u16).min(125);
        self.register_type = config.get_or("register_type", "holding");
        Ok(())
    }

    /// Execute the plugin logic to read the configured Modbus registers.
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
        let is_holding = self.register_type != "input";
        let type_label = if is_holding { "Holding" } else { "Input" };
        let fc = if is_holding { "FC03" } else { "FC04" };

        tracing::info!(
            transport = %transport,
            fc,
            address = self.address,
            count = self.count,
            unit = self.unit_id,
            "reading {} registers",
            type_label.to_lowercase(),
        );

        let read_result = if is_holding {
            client.read_holding_registers(self.address, self.count)
        } else {
            client.read_input_registers(self.address, self.count)
        };

        match read_result {
            Ok(regs) => {
                let non_zero = regs.iter().filter(|&&v| v != 0).count();
                tracing::info!(
                    transport = %transport,
                    fc,
                    address = self.address,
                    returned = regs.len(),
                    non_zero,
                    "registers read successfully",
                );
                let evidence = regs
                    .iter()
                    .enumerate()
                    .map(|(i, v)| format!("  [{:5}] 0x{v:04X} = {v:6}", self.address as usize + i))
                    .collect::<Vec<_>>()
                    .join("\n");

                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!(
                            "{transport}: unauthenticated read of {type_label} registers {}-{}",
                            self.address,
                            self.address as usize + regs.len().saturating_sub(1),
                        ),
                        format!(
                            "{fc}: unit {}, {} {type_label} registers at address {}. \
                             {non_zero}/{} registers hold non-zero values.",
                            self.unit_id,
                            regs.len(),
                            self.address,
                            regs.len(),
                        ),
                    )
                    .with_evidence(evidence),
                );
                result.finish(PluginStatus::Pass);
            }
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!(
                        "Failed to read {type_label} registers at address {}",
                        self.address
                    ),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
            }
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(ReadRegisters::new()) as Box<dyn crate::Plugin>)
}

/// Write a value to one or more Modbus holding registers
pub struct WriteRegister {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
    address: u16,
    value: String,
    values: String,
}

/// WriteRegister is used to configure the parameters for writing Modbus holding registers.
impl WriteRegister {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            tcp_port: 502,
            serial: String::new(),
            baud: 9600,
            unit_id: 1,
            timeout_ms: 3000,
            address: 0,
            value: String::new(),
            values: String::new(),
        }
    }
}

/// WriteRegister represents a plugin for writing Modbus holding registers.
impl Default for WriteRegister {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a string as a 16-bit unsigned integer, supporting decimal and 0x-prefixed hex formats.
fn parse_u16_value(s: &str) -> Result<u16> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|_| anyhow!("invalid hex value '{s}'"))
    } else {
        s.parse::<u16>()
            .map_err(|_| anyhow!("invalid decimal value '{s}'"))
    }
}

/// Plugin implementation for writing Modbus holding registers.
impl Plugin for WriteRegister {
    fn meta(&self) -> PluginMeta {
        let mut m = plugin_meta!(
            summary: "Write a value to one or more Modbus holding registers",
            description: "Writes a 16-bit value to a single holding register (FC06) or multiple \
                          values to consecutive registers (FC16). Values may be decimal or \
                          0x-prefixed HEX. Writing registers without authentication can modify \
                          setpoints, configuration or device state.",
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
                    help: "Baud rate for RTU serial (default 9600)",
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
                CliArg {
                    name: "address",
                    short: Some('a'),
                    help: "Target register address 0-65535 (default 0)",
                    value_name: "ADDR",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "value",
                    short: Some('v'),
                    help: "Single 16-bit value (decimal or 0xHEX) for FC06",
                    value_name: "VALUE",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "values",
                    short: Some('V'),
                    help: "Comma-separated values for FC16 multi-register write",
                    value_name: "V1,V2",
                    default: None,
                    is_flag: false
                },
            ],
        );
        m.name = "modbus/write-register".to_string();
        m
    }

    /// Initialize the plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get_or("host", "");
        self.tcp_port = config.parse_or("tcp_port", 502u16);
        self.serial = config.get_or("serial", "");
        self.baud = config.parse_or("baud", 9600u32);
        self.unit_id = config.parse_or("unit", 1u8);
        self.timeout_ms = config.parse_or("timeout_ms", 3000u64);
        self.address = config.parse_or("address", 0u16);
        self.value = config.get_or("value", "");
        self.values = config.get_or("values", "");
        Ok(())
    }

    /// Execute the plugin logic to write the configured Modbus registers.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        if self.value.is_empty() && self.values.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No value specified",
                "Provide --value VALUE for a single register or --values V1,V2,... for multiple.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

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

        if !self.values.is_empty() {
            tracing::info!(
                transport = %transport,
                fc = "FC16",
                address = self.address,
                unit = self.unit_id,
                "writing multiple registers",
            );
            let parsed: Result<Vec<u16>> = self
                .values
                .split(',')
                .map(|s| parse_u16_value(s.trim()))
                .collect();

            match parsed {
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "Invalid values",
                        format!("{e}"),
                    ));
                    result.finish(PluginStatus::Fail);
                }
                Ok(vals) => match client.write_multiple_registers(self.address, &vals) {
                    Ok(()) => {
                        let evidence = vals
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                format!("  [{:5}] 0x{v:04X} = {v}", self.address as usize + i)
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        result.add(
                            PluginFinding::new(
                                Severity::Critical,
                                format!(
                                    "{transport}: wrote {} registers at address {} without authentication (FC16)",
                                    vals.len(),
                                    self.address,
                                ),
                                format!(
                                    "Unit {}: {} consecutive registers written starting at {}.",
                                    self.unit_id,
                                    vals.len(),
                                    self.address,
                                ),
                            )
                            .with_evidence(evidence),
                        );
                        result.finish(PluginStatus::Pass);
                    }
                    Err(e) => {
                        result.add(PluginFinding::new(
                            Severity::Info,
                            "Write failed",
                            format!("{e}"),
                        ));
                        result.finish(PluginStatus::Fail);
                    }
                },
            }
        } else {
            tracing::info!(
                transport = %transport,
                fc = "FC06",
                address = self.address,
                unit = self.unit_id,
                "writing single register",
            );
            match parse_u16_value(&self.value) {
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "Invalid value",
                        format!("{e}"),
                    ));
                    result.finish(PluginStatus::Fail);
                }
                Ok(val) => match client.write_single_register(self.address, val) {
                    Ok(()) => {
                        result.add(
                            PluginFinding::new(
                                Severity::Critical,
                                format!(
                                    "{transport}: wrote register {} = 0x{val:04X} without authentication (FC06)",
                                    self.address,
                                ),
                                format!(
                                    "Unit {}: register {} written with value {} (0x{val:04X}) \
                                     without authentication.",
                                    self.unit_id, self.address, val,
                                ),
                            )
                            .with_evidence(format!(
                                "address={} value={val} (0x{val:04X})",
                                self.address,
                            )),
                        );
                        result.finish(PluginStatus::Pass);
                    }
                    Err(e) => {
                        result.add(PluginFinding::new(
                            Severity::Info,
                            "Write failed",
                            format!("{e}"),
                        ));
                        result.finish(PluginStatus::Fail);
                    }
                },
            }
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(WriteRegister::new()) as Box<dyn crate::Plugin>)
}
