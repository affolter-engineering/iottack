use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::{fs, os::unix::fs::FileTypeExt, path::PathBuf};

/// Device name prefixes that indicate a serial/UART port on Linux.
const SERIAL_PREFIXES: &[&str] = &[
    "ttyUSB", // USB-to-serial (FTDI, CH340, CP210x, etc.)
    "ttyACM", // USB CDC ACM (Arduino, modems)
    "ttyAMA", // ARM PL011 UART (Raspberry Pi, etc.)
    "ttymxc", // NXP i.MX SoC UART
    "ttyO",   // TI OMAP UART
    "ttyMSM", // Qualcomm UART
    "ttySAC", // Samsung SoC UART
    "ttyS",   // Native 16550 UART
];

/// Scan `/dev/` for character devices whose names match known serial port
/// prefixes. Returns a sorted list of absolute paths.
pub fn discover_ports() -> Vec<PathBuf> {
    let mut ports: Vec<PathBuf> = match fs::read_dir("/dev") {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                let ft = match e.file_type() {
                    Ok(ft) => ft,
                    Err(_) => return false,
                };
                if !ft.is_char_device() {
                    return false;
                }
                let name = e.file_name();
                let name = name.to_string_lossy();
                SERIAL_PREFIXES.iter().any(|pfx| name.starts_with(pfx))
            })
            .map(|e| e.path())
            .collect(),
        Err(_) => vec![],
    };
    ports.sort();
    ports
}

/// Plugin that scans the host for accessible serial ports and reports them.
///
/// Optionally verifies each port is openable at 9600 baud when
/// `verify=true` is set in the config.
pub struct PortScanner {
    verify: bool,
}

/// Implementation of the PortScanner plugin.
impl PortScanner {
    pub fn new() -> Self {
        Self { verify: false }
    }

    fn try_open(path: &str) -> bool {
        serialport::new(path, 9_600)
            .timeout(std::time::Duration::from_millis(100))
            .open()
            .is_ok()
    }
}

/// Default implementation for the PortScanner plugin.
impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// SerialPlugin implementation for the PortScanner plugin.
impl Plugin for PortScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Discover serial ports available on this host",
            description: "Scans /dev/ for character devices matching known UART naming patterns \
                          (ttyUSB*, ttyACM*, ttyAMA*, ttyS*, etc.). Pass verify=true to confirm \
                          each port can be opened.",
            needs_root: false,
            args: &[
                CliArg { name: "verify", short: None, help: "Try to open each port to confirm accessibility", value_name: "", default: None, is_flag: true },
            ],
        )
    }

    /// Initialize the port scanner with the given plugin configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.verify = config.get_or("verify", "false") == "true";
        Ok(())
    }

    /// Execute the port scanning process and report findings.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let ports = discover_ports();

        if ports.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No serial ports found",
                "No character devices matching known UART prefixes were found in /dev/.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        for path in &ports {
            let path_str = path.display().to_string();

            if self.verify {
                if Self::try_open(&path_str) {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Serial port available: {path_str}"),
                        format!("{path_str} is present and can be opened."),
                    ));
                } else {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Serial port present (not openable): {path_str}"),
                        format!(
                            "{path_str} exists as a character device but could not be opened \
                             (may require elevated privileges or be in use)."
                        ),
                    ));
                }
            } else {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Serial port found: {path_str}"),
                    format!("{path_str} is a character device matching a known UART pattern."),
                ));
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(PortScanner::new()) as Box<dyn crate::Plugin>)
}
