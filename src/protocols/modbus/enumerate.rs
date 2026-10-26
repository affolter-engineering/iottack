use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

use super::common::ModbusClient;

const BLOCK_SIZE: u16 = 125;

pub struct Enumerate {
    host: String,
    tcp_port: u16,
    serial: String,
    baud: u32,
    unit_id: u8,
    timeout_ms: u64,
    start_addr: u16,
    end_addr: u16,
    scan_holding: bool,
    scan_input: bool,
    scan_coils: bool,
    scan_discrete: bool,
}

impl Enumerate {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            tcp_port: 502,
            serial: String::new(),
            baud: 9600,
            unit_id: 1,
            timeout_ms: 3000,
            start_addr: 0,
            end_addr: 999,
            scan_holding: true,
            scan_input: true,
            scan_coils: true,
            scan_discrete: true,
        }
    }
}

impl Default for Enumerate {
    fn default() -> Self {
        Self::new()
    }
}

struct ScanResult {
    accessible_ranges: Vec<(u16, u16)>,
    total_accessible: u32,
}

fn scan_registers(
    client: &mut ModbusClient,
    register_type: &'static str,
    start: u16,
    end: u16,
) -> ScanResult {
    let mut accessible_ranges: Vec<(u16, u16)> = Vec::new();
    let mut total_accessible: u32 = 0;
    let mut range_start: Option<u16> = None;

    let mut addr = start;
    while addr <= end {
        let count = BLOCK_SIZE.min(end.saturating_sub(addr) + 1);
        let ok = match register_type {
            "holding" => client.read_holding_registers(addr, count).is_ok(),
            "input" => client.read_input_registers(addr, count).is_ok(),
            "coil" => client.read_coils(addr, count).is_ok(),
            "discrete" => client.read_discrete_inputs(addr, count).is_ok(),
            _ => false,
        };

        if ok {
            total_accessible += count as u32;
            if range_start.is_none() {
                range_start = Some(addr);
            }
        } else if let Some(rs) = range_start.take() {
            accessible_ranges.push((rs, addr.saturating_sub(1)));
        }

        addr = match addr.checked_add(count) {
            Some(next) => next,
            None => break,
        };
    }

    if let Some(rs) = range_start {
        accessible_ranges.push((rs, end));
    }

    ScanResult {
        accessible_ranges,
        total_accessible,
    }
}

impl Plugin for Enumerate {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate accessible Modbus registers and coils",
            description: "Scans a range of addresses across all Modbus data types (holding \
                          registers FC03, input registers FC04, coils FC01, discrete inputs \
                          FC02) to discover which addresses respond without error. Reports \
                          accessible ranges and total count. This reveals the attack surface \
                          for unauthenticated data access or modification.",
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
                    help: "Serial device for Modbus RTU (e.g. /dev/ttyUSB0)",
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
                    help: "Per-block timeout ms (default 3000; lower for speed)",
                    value_name: "MS",
                    default: Some("3000"),
                    is_flag: false
                },
                CliArg {
                    name: "start_addr",
                    short: Some('S'),
                    help: "First address to scan (default 0)",
                    value_name: "ADDR",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "end_addr",
                    short: Some('E'),
                    help: "Last address to scan inclusive (default 999)",
                    value_name: "ADDR",
                    default: Some("999"),
                    is_flag: false
                },
                CliArg {
                    name: "no_holding",
                    short: None,
                    help: "Skip holding register scan (FC03)",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "no_input",
                    short: None,
                    help: "Skip input register scan (FC04)",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "no_coils",
                    short: None,
                    help: "Skip coil scan (FC01)",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "no_discrete",
                    short: None,
                    help: "Skip discrete input scan (FC02)",
                    value_name: "",
                    default: None,
                    is_flag: true
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
        self.start_addr = config.parse_or("start_addr", 0u16);
        self.end_addr = config.parse_or("end_addr", 999u16);
        self.scan_holding = config.get("no_holding") != Some("true");
        self.scan_input = config.get("no_input") != Some("true");
        self.scan_coils = config.get("no_coils") != Some("true");
        self.scan_discrete = config.get("no_discrete") != Some("true");
        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        if self.start_addr > self.end_addr {
            result.add(PluginFinding::new(
                Severity::Info,
                "Invalid range",
                format!(
                    "--start-addr {} is greater than --end-addr {}",
                    self.start_addr, self.end_addr
                ),
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
        let range_desc = format!("{}-{}", self.start_addr, self.end_addr);
        let mut total_found: u32 = 0;

        let types_to_scan: &[(&str, bool, &str)] = &[
            ("holding", self.scan_holding, "Holding Registers (FC03)"),
            ("input", self.scan_input, "Input Registers    (FC04)"),
            ("coil", self.scan_coils, "Coils              (FC01)"),
            ("discrete", self.scan_discrete, "Discrete Inputs    (FC02)"),
        ];

        let mut summary_lines: Vec<String> = Vec::new();

        for &(reg_type, enabled, label) in types_to_scan {
            if !enabled {
                continue;
            }

            tracing::info!(
                transport = %transport,
                register_type = reg_type,
                range = %range_desc,
                "scanning"
            );

            let scan = scan_registers(&mut client, reg_type, self.start_addr, self.end_addr);

            if scan.accessible_ranges.is_empty() {
                summary_lines.push(format!("  {label}: no accessible addresses"));
                continue;
            }

            total_found += scan.total_accessible;

            let ranges_str = scan
                .accessible_ranges
                .iter()
                .map(|(s, e)| format!("{s}-{e}"))
                .collect::<Vec<_>>()
                .join(", ");

            summary_lines.push(format!(
                "  {label}: {} accessible ({} range(s): {ranges_str})",
                scan.total_accessible,
                scan.accessible_ranges.len()
            ));

            let evidence = format!(
                "Accessible ranges: {ranges_str}\nTotal accessible: {}",
                scan.total_accessible
            );

            let sev = if scan.total_accessible > 100 {
                Severity::High
            } else if scan.total_accessible > 0 {
                Severity::Medium
            } else {
                Severity::Info
            };

            result.add(
                PluginFinding::new(
                    sev,
                    format!(
                        "{transport}: {} accessible {} in range {range_desc}",
                        scan.total_accessible,
                        label.trim()
                    ),
                    format!(
                        "Unit {}: {} addresses in {} contiguous block(s) are readable \
                         without authentication.",
                        self.unit_id,
                        scan.total_accessible,
                        scan.accessible_ranges.len()
                    ),
                )
                .with_evidence(evidence),
            );
        }

        if total_found == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No accessible registers found in range {range_desc}"),
                format!(
                    "{transport}: unit {} did not return data for any scanned address range.",
                    self.unit_id
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            let summary = summary_lines.join("\n");
            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!(
                        "{transport}: {total_found} total accessible data points on unit {}",
                        self.unit_id
                    ),
                    format!(
                        "Enumeration of addresses {range_desc} found {total_found} readable \
                         locations across all scanned data types.\n\n{summary}"
                    ),
                )
                .with_evidence(summary_lines.join("\n")),
            );
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(Enumerate::new()) as Box<dyn crate::Plugin>)
}
