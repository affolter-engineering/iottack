use crate::core::{
    Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

pub struct AdapterPlugin;

/// Plugin for listing Bluetooth adapters and their details.
impl AdapterPlugin {
    pub fn new() -> Self {
        Self
    }
}

/// Provides a default implementation for the AdapterPlugin.
impl Default for AdapterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the AdapterPlugin.
impl Plugin for AdapterPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "List Bluetooth adapters and their details",
            description: "Connects to the BlueZ daemon via D-Bus and returns a finding for each \
                          Bluetooth adapter present on the host. Each finding includes the \
                          adapter name, MAC address, alias, power state, discoverability, \
                          pairability and hardware modalias. A powered and discoverable adapter \
                          is flagged as a potential exposure because any nearby device can detect \
                          and probe it.",
            needs_root: false,
            args: &[],
        )
    }

    /// Initializes the AdapterPlugin with the provided configuration.
    fn initialize(&mut self, _config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    /// Executes the adapter probing process and returns the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.probe())
    }
}

/// Implementation of the AdapterPlugin.
impl AdapterPlugin {
    async fn probe(&self) -> Result<PluginResult> {
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

        let names = match session.adapter_names().await {
            Ok(n) => n,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Cannot list Bluetooth adapters",
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        if names.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No Bluetooth adapters found",
                "No Bluetooth adapters were detected. Connect a Bluetooth adapter and ensure \
                 bluetoothd is running.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} Bluetooth adapter(s) found", names.len()),
            "Use 'iottack ble scan' to discover nearby BLE devices.",
        ));

        for name in &names {
            let adapter = match session.adapter(name) {
                Ok(a) => a,
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Cannot access adapter {name}"),
                        format!("{e}"),
                    ));
                    continue;
                }
            };

            let address = adapter
                .address()
                .await
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "n/a".to_string());
            let alias = adapter.alias().await.unwrap_or_default();
            let is_powered = adapter.is_powered().await.unwrap_or(false);
            let is_discoverable = adapter.is_discoverable().await.unwrap_or(false);
            let is_pairable = adapter.is_pairable().await.unwrap_or(false);
            let class = adapter.class().await.ok();
            let modalias = adapter.modalias().await.ok().flatten().map(|m| {
                format!("{}:v{:04X}p{:04X}d{:04X}", m.source, m.vendor, m.product, m.device)
            });

            let mut description = format!(
                "Address:      {address}\n  \
                 Alias:        {}\n  \
                 Powered:      {}\n  \
                 Discoverable: {}\n  \
                 Pairable:     {}",
                if alias.is_empty() { "n/a" } else { &alias },
                if is_powered { "yes" } else { "no" },
                if is_discoverable { "yes" } else { "no" },
                if is_pairable { "yes" } else { "no" },
            );
            if let Some(c) = class {
                description.push_str(&format!("\n  Class:        {c:#010x}"));
            }
            if let Some(ref m) = modalias {
                description.push_str(&format!("\n  Modalias:     {m}"));
            }

            let severity = match (is_powered, is_discoverable) {
                (false, _) => Severity::Info,
                (true, false) => Severity::Low,
                (true, true) => Severity::Medium,
            };

            let evidence = format!(
                "adapter={name}, address={address}, alias={alias}, powered={is_powered}, \
                 discoverable={is_discoverable}, pairable={is_pairable}{}{}",
                class.map(|c| format!(", class={c:#010x}")).unwrap_or_default(),
                modalias.as_deref().map(|m| format!(", modalias={m}")).unwrap_or_default(),
            );

            result.add(
                PluginFinding::new(
                    severity,
                    format!("{name} ({address})"),
                    description,
                )
                .with_evidence(evidence),
            );

            if is_powered && is_discoverable {
                result.add(PluginFinding::new(
                    Severity::Medium,
                    format!("Adapter {name} is powered and discoverable"),
                    "A discoverable Bluetooth adapter can be detected and probed by any \
                     nearby device. Disable discoverability when not actively pairing to \
                     reduce the attack surface.",
                ));
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(AdapterPlugin::new()) as Box<dyn crate::Plugin>)
}
