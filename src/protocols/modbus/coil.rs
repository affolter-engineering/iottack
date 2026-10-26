use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::{Result, anyhow};

use super::common::ModbusClient;

/// ReadCoils holds the configuration for reading Modbus coils or discrete inputs over TCP or RTU serial.
pub struct ReadCoils {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
    address: u16,
    count: u16,
    coil_type: String,
}

/// ReadCoils represents a plugin for reading Modbus coils or discrete inputs.
impl ReadCoils {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            tcp_port: 502,
            serial: String::new(),
            baud: 9600,
            unit_id: 1,
            timeout_ms: 3000,
            address: 0,
            count: 16,
            coil_type: "coil".to_string(),
        }
    }
}

/// Default implementation for ReadCoils.
impl Default for ReadCoils {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for reading Modbus coils or discrete inputs over TCP or RTU serial.
impl Plugin for ReadCoils {
    fn meta(&self) -> PluginMeta {
        let mut m = plugin_meta!(
            summary: "Read Modbus coils or discrete inputs",
            description: "Reads a block of single-bit values from a Modbus device over TCP or \
                          RTU serial. Coils (FC01) are read/write bit. Discrete inputs (FC02) \
                          are read-only bits. Accessing these without authentication can reveal \
                          actuator states, sensor readings and system status.",
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
                    help: "Starting coil address 0-65535 (default 0)",
                    value_name: "ADDR",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "count",
                    short: Some('c'),
                    help: "Number of coils to read, max 2000 (default 16)",
                    value_name: "N",
                    default: Some("16"),
                    is_flag: false
                },
                CliArg {
                    name: "coil_type",
                    short: Some('T'),
                    help: "coil (FC01) or discrete (FC02)",
                    value_name: "TYPE",
                    default: Some("coil"),
                    is_flag: false
                },
            ],
        );
        m.name = "modbus/read-coils".to_string();
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
        self.count = config.parse_or("count", 16u16).min(2000);
        self.coil_type = config.get_or("coil_type", "coil");
        Ok(())
    }

    /// Execute the plugin logic to read the configured Modbus coils or discrete inputs.
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
        let is_coil = self.coil_type != "discrete";
        let type_label = if is_coil { "Coils" } else { "Discrete Inputs" };
        let fc = if is_coil { "FC01" } else { "FC02" };

        tracing::info!(
            transport = %transport,
            fc,
            address = self.address,
            count = self.count,
            unit = self.unit_id,
            "reading {}",
            type_label.to_lowercase(),
        );

        let read_result = if is_coil {
            client.read_coils(self.address, self.count)
        } else {
            client.read_discrete_inputs(self.address, self.count)
        };

        match read_result {
            Ok(bits) => {
                let on_count = bits.iter().filter(|&&b| b).count();
                tracing::info!(
                    transport = %transport,
                    fc,
                    address = self.address,
                    returned = bits.len(),
                    on_count,
                    "bits read successfully",
                );
                let evidence = bits
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| {
                        format!(
                            "  [{:5}] {}",
                            self.address as usize + i,
                            if v { "ON " } else { "OFF" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!(
                            "{transport}: unauthenticated read of {type_label} {}-{}",
                            self.address,
                            self.address as usize + bits.len().saturating_sub(1),
                        ),
                        format!(
                            "{fc}: unit {}, {} {type_label} at address {}. \
                             {on_count}/{} bits are ON.",
                            self.unit_id,
                            bits.len(),
                            self.address,
                            bits.len(),
                        ),
                    )
                    .with_evidence(evidence),
                );
                result.finish(PluginStatus::Pass);
            }
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Failed to read {type_label} at address {}", self.address),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
            }
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(ReadCoils::new()) as Box<dyn crate::Plugin>)
}

/// WriteCoil holds the configuration for writing a single Modbus coil over TCP or RTU serial.
pub struct WriteCoil {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
    address: u16,
    value: String,
}

/// WriteCoil represents a plugin for writing a single Modbus coil.
impl WriteCoil {
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
        }
    }
}

/// Default implementation for WriteCoil.
impl Default for WriteCoil {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a string as a boolean coil value, supporting on/off, 1/0, and true/false formats.
fn parse_coil_value(s: &str) -> Result<bool> {
    match s.trim().to_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Ok(true),
        "off" | "0" | "false" | "no" => Ok(false),
        other => Err(anyhow!(
            "invalid coil value '{other}': use on/off, 1/0 or true/false"
        )),
    }
}

/// Plugin implementation for writing a single Modbus coil.
impl Plugin for WriteCoil {
    fn meta(&self) -> PluginMeta {
        let mut m = plugin_meta!(
            summary: "Write a single Modbus coil (FC05)",
            description: "Writes a boolean value (On or Off) to a Modbus coil using function \
                          code 05. Coils typically control digital outputs such as relays, \
                          valves and actuators. Unauthenticated coil writes can directly \
                          affect physical processes.",
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
                    help: "Coil address 0-65535 (default 0)",
                    value_name: "ADDR",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "value",
                    short: Some('v'),
                    help: "Coil state: on/off, 1/0 or true/false",
                    value_name: "VALUE",
                    default: None,
                    is_flag: false
                },
            ],
        );
        m.name = "modbus/write-coil".to_string();
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
        Ok(())
    }

    /// Execute the plugin logic to write the configured Modbus coil.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        if self.value.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No value specified",
                "Provide --value on or --value off.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        let on = match parse_coil_value(&self.value) {
            Ok(v) => v,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Invalid coil value",
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

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
        let state = if on { "ON" } else { "OFF" };

        tracing::info!(
            transport = %transport,
            fc = "FC05",
            address = self.address,
            value = state,
            unit = self.unit_id,
            "writing coil",
        );

        match client.write_single_coil(self.address, on) {
            Ok(()) => {
                result.add(
                    PluginFinding::new(
                        Severity::Critical,
                        format!(
                            "{transport}: coil {} set to {state} without authentication (FC05)",
                            self.address,
                        ),
                        format!(
                            "Unit {}: coil at address {} written to {state}. \
                             This may directly affect a physical actuator or digital output.",
                            self.unit_id, self.address,
                        ),
                    )
                    .with_evidence(format!("address={} value={state}", self.address)),
                );
                result.finish(PluginStatus::Pass);
            }
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Failed to write coil {}", self.address),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
            }
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(WriteCoil::new()) as Box<dyn crate::Plugin>)
}
