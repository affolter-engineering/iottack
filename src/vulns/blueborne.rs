use std::collections::HashSet;
use std::time::Duration;

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use futures::StreamExt;

// Bluetooth SIG service UUIDs exploited by BlueBorne
// AVDTP (A2DP) - targeted by CVE-2017-0781/CVE-2017-0782
const UUID_A2DP: &str = "0000110d-0000-1000-8000-00805f9b34fb";
const UUID_A2DP_SOURCE: &str = "0000110a-0000-1000-8000-00805f9b34fb";
const UUID_A2DP_SINK: &str = "0000110b-0000-1000-8000-00805f9b34fb";
// BNEP / PAN - targeted by CVE-2017-0783/CVE-2017-8628
const UUID_PANU: &str = "00001115-0000-1000-8000-00805f9b34fb";
const UUID_NAP: &str = "00001116-0000-1000-8000-00805f9b34fb";
const UUID_GN: &str = "00001117-0000-1000-8000-00805f9b34fb";

// Bluetooth major device classes
const BT_MAJOR_COMPUTER: u32 = 0x01;
const BT_MAJOR_PHONE: u32 = 0x02;

/// Bluetooth minor device classes
struct Assessment {
    cves: Vec<&'static str>,
    reasons: Vec<String>,
    severity: Severity,
}

/// Assess the vulnerability of a Bluetooth device to BlueBorne exploits based on its name, icon, class and supported UUIDs.
fn assess(name: &str, icon: &str, class: Option<u32>, uuids: &HashSet<bluer::Uuid>) -> Assessment {
    let name_lc = name.to_lowercase();
    let major = class.map(|c| (c >> 8) & 0x1F).unwrap_or(0);

    let has_avdtp = uuids.iter().any(|u| {
        let s = u.to_string();
        s == UUID_A2DP || s == UUID_A2DP_SOURCE || s == UUID_A2DP_SINK
    });
    let has_bnep = uuids.iter().any(|u| {
        let s = u.to_string();
        s == UUID_PANU || s == UUID_NAP || s == UUID_GN
    });

    let is_android = name_lc.contains("android")
        || name_lc.contains("galaxy")
        || name_lc.contains("pixel")
        || name_lc.contains("huawei")
        || name_lc.contains("xiaomi")
        || name_lc.contains("oneplus")
        || name_lc.contains("moto")
        || name_lc.contains("redmi")
        || name_lc.contains("oppo")
        || (major == BT_MAJOR_PHONE && icon != "audio-card");

    let is_linux = name_lc.contains("ubuntu")
        || name_lc.contains("debian")
        || name_lc.contains("raspberry")
        || name_lc.contains("fedora")
        || name_lc.contains("arch")
        || name_lc.contains("kali")
        || major == BT_MAJOR_COMPUTER;

    let mut cves: Vec<&'static str> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();

    if is_android {
        if has_avdtp {
            cves.extend_from_slice(&["CVE-2017-0781", "CVE-2017-0782"]);
            reasons.push("Android and A2DP/AVDTP profile (heap overflow, RCE)".to_string());
        }
        if has_bnep {
            cves.push("CVE-2017-0783");
            reasons.push("Android and BNEP/PAN profile (information disclosure)".to_string());
        }
        cves.push("CVE-2017-0785");
        reasons.push("Android device (SDP information disclosure)".to_string());
    }

    if is_linux {
        cves.extend_from_slice(&["CVE-2017-1000250", "CVE-2017-1000251"]);
        reasons.push("Linux device (BlueZ SDP info-disclosure and L2CAP stack overflow)".to_string());
    }

    if !is_android && !is_linux && has_bnep {
        cves.push("CVE-2017-8628");
        reasons.push("BNEP/PAN profile present (Windows MitM target)".to_string());
    }

    // Any reachable device with Bluetooth Classic profiles is an exposure surface even
    // without platform identification, because BlueBorne requires no pairing.
    if cves.is_empty() && (has_avdtp || has_bnep) {
        cves.extend_from_slice(&["CVE-2017-0781", "CVE-2017-0782", "CVE-2017-1000251"]);
        reasons.push(
            "Bluetooth Classic profiles present, platform unconfirmed. Manual verification required".to_string(),
        );
    }

    let severity = if cves.is_empty() {
        Severity::Info
    } else if (is_android || is_linux) && (has_avdtp || has_bnep) {
        Severity::High
    } else if is_android || is_linux || has_avdtp || has_bnep {
        Severity::Medium
    } else {
        Severity::Low
    };

    Assessment { cves, reasons, severity }
}

/// Plugin for detecting devices potentially vulnerable to the BlueBorne set of Bluetooth exploits.
pub struct BlueBornePlugin {
    timeout_secs: u64,
    adapter_name: String,
}

/// Constructor and initializer for the BlueBorne plugin.
impl BlueBornePlugin {
    pub fn new() -> Self {
        Self {
            timeout_secs: 15,
            adapter_name: String::new(),
        }
    }
}

/// Default implementation for the BlueBorne plugin, delegating to `new()`.
impl Default for BlueBornePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the `Plugin` trait for the BlueBorne plugin.
impl Plugin for BlueBornePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "BlueBorne - scan for nearby Bluetooth devices potentially vulnerable to CVE-2017-0781-0785/CVE-2017-1000250–1000251 / CVE-2017-8628",
            description: "Discovers reachable Bluetooth devices and assesses each one against the \
                          BlueBorne vulnerability set (September 2017). BlueBorne exploits affect \
                          Linux (BlueZ: CVE-2017-1000250/1000251), Android (CVE-2017-0781/0782/ \
                          0783/0785) and Windows (CVE-2017-8628). Crucially, no pairing or \
                          prior association is required. Any device with Bluetooth enabled is \
                          within the attack surface. The plugin uses device name, Bluetooth \
                          device class, icon type and advertised service UUIDs (A2DP/AVDTP, \
                          BNEP/PAN) to classify each device and map it to applicable CVEs. \
                          Results are advisory. Patch status cannot be confirmed without \
                          direct access to the device.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "timeout",
                    short: Some('t'),
                    help: "Scan duration in seconds",
                    value_name: "SECS",
                    default: Some("15"),
                    is_flag: false,
                },
                CliArg {
                    name: "adapter",
                    short: Some('a'),
                    help: "Bluetooth adapter to use (e.g., hci0). Defaults to first available",
                    value_name: "NAME",
                    default: None,
                    is_flag: false,
                },
            ],
        )
    }

    /// Initializes the BlueBorne plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.timeout_secs = config.parse_or("timeout", 15u64);
        self.adapter_name = config.get_or("adapter", "");
        Ok(())
    }

    /// Executes the BlueBorne scan asynchronously and returns the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.scan())
    }
}

impl BlueBornePlugin {
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
            tracing::debug!(adapters = ?names, "discovered adapters");
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

        tracing::debug!(adapter = adapter_name, timeout = self.timeout_secs, "starting BlueBorne scan");
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
                    "Cannot start scan",
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

                            let device = match adapter.device(addr) {
                                Ok(d) => d,
                                Err(_) => continue,
                            };

                            let name = device.name().await.ok().flatten().unwrap_or_default();
                            let alias = device.alias().await.unwrap_or_default();
                            let icon = device.icon().await.ok().flatten().unwrap_or_default();
                            let class = device.class().await.ok().flatten();
                            let rssi = device.rssi().await.ok().flatten();
                            let is_connected = device.is_connected().await.unwrap_or(false);
                            let is_paired = device.is_paired().await.unwrap_or(false);
                            let uuids = device
                                .uuids()
                                .await
                                .ok()
                                .flatten()
                                .unwrap_or_default();

                            tracing::debug!(
                                address = %addr,
                                name = name,
                                icon = icon,
                                class = ?class,
                                rssi = ?rssi,
                                uuids = uuids.len(),
                                "device discovered"
                            );

                            let display_name = if !name.is_empty() {
                                name.clone()
                            } else if !alias.is_empty() && alias != addr.to_string() {
                                alias.clone()
                            } else {
                                String::new()
                            };

                            let label = if display_name.is_empty() {
                                format!("{addr}")
                            } else {
                                format!("{display_name} ({addr})")
                            };

                            let assessment = assess(&display_name, &icon, class, &uuids);

                            if assessment.cves.is_empty() {
                                tracing::debug!(address = %addr, "no BlueBorne indicators");
                                // Device in range but no BlueBorne indicators - report as Info.
                                let mut desc = format!(
                                    "Address:   {addr}  \n  \
                                     Name:      {}  \n  \
                                     Connected: {}  \n  \
                                     Paired:    {}",
                                    if display_name.is_empty() { "n/a" } else { &display_name },
                                    if is_connected { "yes" } else { "no" },
                                    if is_paired { "yes" } else { "no" },
                                );
                                if let Some(r) = rssi {
                                    desc.push_str(&format!("\n  RSSI:      {r} dBm"));
                                }
                                desc.push_str(
                                    "\n\n  No BlueBorne-related profiles or platform indicators detected. \
                                     The device may still be vulnerable if its OS is unpatched."
                                );
                                result.add(PluginFinding::new(
                                    Severity::Info,
                                    format!("Device in range: {label}"),
                                    desc,
                                ));
                            } else {
                                tracing::info!(
                                    address = %addr,
                                    name = display_name,
                                    cves = assessment.cves.join(", "),
                                    severity = ?assessment.severity,
                                    "BlueBorne exposure"
                                );
                                let cve_list = assessment.cves.join(", ");
                                let reason_list = assessment.reasons.join("\n  - ");
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
                                if !icon.is_empty() {
                                    desc.push_str(&format!("\n  Icon:      {icon}"));
                                }
                                if let Some(c) = class {
                                    desc.push_str(&format!("\n  Class:     {c:#010x}"));
                                }
                                if !uuids.is_empty() {
                                    let uuid_list: Vec<String> =
                                        uuids.iter().map(|u| u.to_string()).collect();
                                    desc.push_str(&format!("\n  UUIDs:     {}", uuid_list.join(", ")));
                                }
                                result.add(PluginFinding::new(
                                    assessment.severity,
                                    format!("Potentially vulnerable to BlueBorne: {label}"),
                                    desc,
                                ));
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
                "No Bluetooth devices found",
                format!(
                    "No devices were discovered within {} second(s). \
                     Ensure devices are within range and Bluetooth is enabled on the target.",
                    self.timeout_secs
                ),
            ));
        } else {
            let vulnerable: usize = seen.len(); // all are reported, count is informational
            result.add(PluginFinding::new(
                Severity::Info,
                format!("{} device(s) discovered in BlueBorne scan", vulnerable),
                format!(
                    "Scan completed on adapter {adapter_name} after {} second(s). \
                     BlueBorne affects all unpatched Bluetooth devices regardless of pairing state. \
                     Devices running Linux (BlueZ < 2017-09-12), Android (< 2017-09 security patch) \
                     or Windows (unpatched) should be updated immediately.",
                    self.timeout_secs
                ),
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BlueBornePlugin::new()) as Box<dyn crate::Plugin>)
}
