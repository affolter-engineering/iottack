use std::collections::HashSet;
use std::time::Duration;

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use futures::StreamExt;

/// Plugin for scanning nearby Bluetooth Low Energy devices.
pub struct ScanPlugin {
    timeout_secs: u64,
    adapter_name: String,
}

/// Implementation of the ScanPlugin.
impl ScanPlugin {
    pub fn new() -> Self {
        Self {
            timeout_secs: 10,
            adapter_name: String::new(),
        }
    }
}

/// Provides a default implementation for the ScanPlugin.
impl Default for ScanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the Plugin trait for ScanPlugin.
impl Plugin for ScanPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Scan for nearby Bluetooth Low Energy devices",
            description: "Starts active BLE discovery on the specified adapter (default: first \
                          available) and collects nearby devices for the given duration. Each \
                          discovered device is reported as a finding with its address, name, \
                          RSSI, TX power and advertised service UUIDs. Paired or already- \
                          connected devices are flagged at Medium severity; unrecognized devices \
                          are reported at Info.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "timeout",
                    short: Some('t'),
                    help: "Scan duration in seconds",
                    value_name: "SECS",
                    default: Some("10"),
                    is_flag: false,
                },
                CliArg {
                    name: "adapter",
                    short: Some('a'),
                    help: "Bluetooth adapter name to use (e.g. hci0); defaults to first available",
                    value_name: "NAME",
                    default: None,
                    is_flag: false,
                },
            ],
        )
    }

    /// Initializes the ScanPlugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.timeout_secs = config.parse_or("timeout", 10u64);
        self.adapter_name = config.get_or("adapter", "");
        Ok(())
    }

    /// Executes the scanning process and returns the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.scan())
    }
}

/// Performs the actual BLE scanning using the specified adapter and returns the results.
impl ScanPlugin {
    async fn scan(&self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let session = match bluer::Session::new().await {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Bluetooth not available",
                    format!(
                        "{e}\n\nEnsure the BlueZ daemon (bluetoothd) is running and the \
                         D-Bus system bus is accessible."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let adapter_name = if self.adapter_name.is_empty() {
            let names = session.adapter_names().await.unwrap_or_default();
            match names.into_iter().next() {
                Some(n) => n,
                None => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "No Bluetooth adapters found",
                        "No Bluetooth adapters were detected. Connect a Bluetooth adapter and \
                         ensure bluetoothd is running.",
                    ));
                    result.finish(PluginStatus::Pass);
                    return Ok(result);
                }
            }
        } else {
            self.adapter_name.clone()
        };

        let adapter = match session.adapter(&adapter_name) {
            Ok(a) => a,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot access adapter {adapter_name}"),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut discover = match adapter.discover_devices().await {
            Ok(d) => d,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Cannot start BLE scan",
                    format!(
                        "{e}\n\nThe adapter may be powered off or another process holds it. \
                         Try: bluetoothctl power on"
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let mut seen: HashSet<bluer::Address> = HashSet::new();
        let deadline = tokio::time::sleep(Duration::from_secs(self.timeout_secs));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => break,
                event = discover.next() => {
                    match event {
                        Some(bluer::AdapterEvent::DeviceAdded(addr)) => {
                            if !seen.insert(addr) {
                                continue;
                            }
                            if let Ok(device) = adapter.device(addr) {
                                let name = device
                                    .name()
                                    .await
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();
                                let alias = device.alias().await.unwrap_or_default();
                                let rssi = device.rssi().await.ok().flatten();
                                let tx_power = device.tx_power().await.ok().flatten();
                                let is_connected = device.is_connected().await.unwrap_or(false);
                                let is_paired = device.is_paired().await.unwrap_or(false);
                                let uuids = device
                                    .uuids()
                                    .await
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();

                                let display_name = if !name.is_empty() {
                                    name.clone()
                                } else if !alias.is_empty() && alias != addr.to_string() {
                                    alias.clone()
                                } else {
                                    String::new()
                                };

                                let title = if display_name.is_empty() {
                                    format!("{addr}")
                                } else {
                                    format!("{display_name} ({addr})")
                                };

                                let mut desc = format!(
                                    "Address:   {addr}\n  \
                                     Name:      {}\n  \
                                     Connected: {}\n  \
                                     Paired:    {}",
                                    if display_name.is_empty() { "n/a" } else { &display_name },
                                    if is_connected { "yes" } else { "no" },
                                    if is_paired { "yes" } else { "no" },
                                );
                                if let Some(r) = rssi {
                                    desc.push_str(&format!("\n  RSSI:      {r} dBm"));
                                }
                                if let Some(tx) = tx_power {
                                    desc.push_str(&format!("\n  TX Power:  {tx} dBm"));
                                }
                                if !uuids.is_empty() {
                                    let uuid_list: Vec<String> =
                                        uuids.iter().map(|u| u.to_string()).collect();
                                    desc.push_str(&format!("\n  UUIDs:     {}", uuid_list.join(", ")));
                                }

                                let severity =
                                    if is_connected || is_paired { Severity::Medium } else { Severity::Info };

                                let mut evidence_parts = vec![
                                    format!("address={addr}"),
                                    format!("connected={is_connected}"),
                                    format!("paired={is_paired}"),
                                ];
                                if !display_name.is_empty() {
                                    evidence_parts.push(format!("name={display_name}"));
                                }
                                if let Some(r) = rssi {
                                    evidence_parts.push(format!("rssi={r}"));
                                }
                                if let Some(tx) = tx_power {
                                    evidence_parts.push(format!("tx_power={tx}"));
                                }

                                result.add(
                                    PluginFinding::new(severity, title, desc)
                                        .with_evidence(evidence_parts.join(", ")),
                                );
                            }
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        if seen.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No BLE devices found",
                format!(
                    "No Bluetooth Low Energy devices were discovered within {} second(s). \
                     Ensure devices are advertising and within range.",
                    self.timeout_secs
                ),
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("{} BLE device(s) discovered", seen.len()),
                format!(
                    "Scan completed on adapter {adapter_name} after {} second(s).",
                    self.timeout_secs
                ),
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(ScanPlugin::new()) as Box<dyn crate::Plugin>)
}
