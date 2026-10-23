use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

/// 
pub struct DevicePlugin {
    address: String,
    adapter_name: String,
    disconnect: bool,
}

/// Represents the BLE device plugin, which manages connection and enumeration of a single BLE device.
impl DevicePlugin {
    pub fn new() -> Self {
        Self {
            address: String::new(),
            adapter_name: String::new(),
            disconnect: true,
        }
    }
}

/// Default implementation for the device plugin. Provides a convenient way to create a new instance with default settings.
impl Default for DevicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the `Plugin` trait for the device plugin. Handles metadata, initialization, and execution logic.
impl Plugin for DevicePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate GATT services and characteristics of a single BLE device",
            description: "Connects to the specified Bluetooth Low Energy device and walks its \
                          GATT profile. Each primary service is reported as a finding. For every \
                          characteristic the UUID, property flags (read/write/notify/indicate), \
                          and, where the characteristic is readable, the current raw value are \
                          captured. The plugin disconnects after enumeration unless \
                          --no-disconnect is given.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "address",
                    short: Some('d'),
                    help: "Bluetooth address of the target device (e.g., AA:BB:CC:DD:EE:FF)",
                    value_name: "ADDR",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "adapter",
                    short: Some('a'),
                    help: "Bluetooth adapter name to use (e.g., hci0). Defaults to first available",
                    value_name: "NAME",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "no-disconnect",
                    short: None,
                    help: "Leave the device connected after enumeration",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
            ],
        )
    }

    /// Initializes the device plugin with the provided configuration. Extracts the target device address, adapter name and disconnect behavior.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.address = config.require("address")?.to_string();
        self.adapter_name = config.get_or("adapter", "");
        self.disconnect = config.get("no-disconnect") != Some("true");
        Ok(())
    }

    /// Executes the device plugin logic, setting up a Tokio runtime and invoking the probe method.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.probe())
    }
}

/// Implementation of the device plugin's core logic, including probing the target BLE device.
impl DevicePlugin {
    async fn probe(&self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let addr: bluer::Address = match self.address.parse() {
            Ok(a) => a,
            Err(_) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Invalid Bluetooth address",
                    format!(
                        "'{}' is not a valid Bluetooth address. \
                         Expected format: AA:BB:CC:DD:EE:FF",
                        self.address
                    ),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

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

        let device = match adapter.device(addr) {
            Ok(d) => d,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot access device {addr}"),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let was_connected = device.is_connected().await.unwrap_or(false);

        if !was_connected {
            if let Err(e) = device.connect().await {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot connect to {addr}"),
                    format!(
                        "{e}\n\nThe device may be out of range, powered off or require pairing. \
                         Run 'iottack ble scan' first to confirm it is advertising."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        }

        let name = device.name().await.ok().flatten().unwrap_or_default();
        let alias = device.alias().await.unwrap_or_default();
        let is_paired = device.is_paired().await.unwrap_or(false);
        let rssi = device.rssi().await.ok().flatten();

        let display_name = if !name.is_empty() {
            name.clone()
        } else if !alias.is_empty() && alias != addr.to_string() {
            alias.clone()
        } else {
            String::new()
        };

        let mut device_desc = format!(
            "Address: {addr}\n  \
             Name:    {}\n  \
             Paired:  {}",
            if display_name.is_empty() { "n/a" } else { &display_name },
            if is_paired { "yes" } else { "no" },
        );
        if let Some(r) = rssi {
            device_desc.push_str(&format!("\n  RSSI:    {r} dBm"));
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!(
                "Connected to {}",
                if display_name.is_empty() { addr.to_string() } else { display_name.clone() }
            ),
            device_desc,
        ));

        let services = match device.services().await {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Cannot enumerate GATT services",
                    format!("{e}"),
                ));
                self.maybe_disconnect(&device, was_connected).await;
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        if services.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No GATT services found",
                "The device reported no GATT services after connection.",
            ));
        }

        for service in &services {
            let svc_uuid = match service.uuid().await {
                Ok(u) => u,
                Err(_) => continue,
            };
            let is_primary = service.primary().await.unwrap_or(false);

            let characteristics = service.characteristics().await.unwrap_or_default();
            let mut svc_desc = format!(
                "UUID:    {svc_uuid}\n  Primary: {}\n  Characteristics: {}",
                if is_primary { "yes" } else { "no" },
                characteristics.len(),
            );

            let mut char_lines: Vec<String> = Vec::new();
            for ch in &characteristics {
                let ch_uuid = match ch.uuid().await {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let flags = ch.flags().await.unwrap_or_default();

                let mut props: Vec<&str> = Vec::new();
                if flags.read { props.push("read") }
                if flags.write { props.push("write") }
                if flags.write_without_response { props.push("write-no-rsp") }
                if flags.notify { props.push("notify") }
                if flags.indicate { props.push("indicate") }

                let value_str = if flags.read {
                    match ch.read().await {
                        Ok(bytes) if bytes.is_empty() => " value=<empty>".to_string(),
                        Ok(bytes) => {
                            let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                            let printable: String = bytes.iter()
                                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                .collect();
                            format!(" value={hex} ({printable})")
                        }
                        Err(_) => String::new(),
                    }
                } else {
                    String::new()
                };

                char_lines.push(format!(
                    "  {ch_uuid} [{}]{value_str}",
                    if props.is_empty() { "none".to_string() } else { props.join(", ") }
                ));
            }

            if !char_lines.is_empty() {
                svc_desc.push('\n');
                svc_desc.push_str(&char_lines.join("\n"));
            }

            let severity = if is_primary { Severity::Low } else { Severity::Info };

            result.add(PluginFinding::new(
                severity,
                format!("Service {svc_uuid}"),
                svc_desc,
            ));
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} GATT service(s) enumerated", services.len()),
            format!("Device {addr} on adapter {adapter_name}."),
        ));

        self.maybe_disconnect(&device, was_connected).await;

        result.finish(PluginStatus::Pass);
        Ok(result)
    }

    async fn maybe_disconnect(&self, device: &bluer::Device, was_connected: bool) {
        if self.disconnect && !was_connected {
            let _ = device.disconnect().await;
        }
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DevicePlugin::new()) as Box<dyn crate::Plugin>)
}
