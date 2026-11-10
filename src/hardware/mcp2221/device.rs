use crate::core::{
    Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use nusb::MaybeFuture;

const MCP2221_VID: u16 = 0x04D8;
const MCP2221_PID: u16 = 0x00DD;

pub struct DevicePlugin;

/// DevicePlugin represents the plugin for MCP2221/MCP2221A adapters.
impl DevicePlugin {
    pub fn new() -> Self {
        Self
    }
}

/// Provides a default implementation for DevicePlugin.
impl Default for DevicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// DevicePlugin is a plugin for enumerating MCP2221/MCP2221A adapters connected to the host.
impl Plugin for DevicePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "List MCP2221/MCP2221A adapters connected to this host",
            description: "Enumerates USB devices with Microchip VID 0x04D8/PID 0x00DD and \
                          reports each MCP2221 or MCP2221A adapter with its USB strings and \
                          capabilities (USB-to-I2C bridge up to 400 kHz, USB-to-UART bridge, \
                          4x GPIO, 3x 10-bit ADC, 1x 5-bit DAC).",
            needs_root: false,
        )
    }

    /// Executes the plugin to enumerate connected MCP2221/MCP2221A adapters.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let device_list = match nusb::list_devices().wait() {
            Ok(iter) => iter
                .filter(|d| d.vendor_id() == MCP2221_VID && d.product_id() == MCP2221_PID)
                .collect::<Vec<_>>(),
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "USB enumeration failed",
                    e.to_string(),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        if device_list.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No MCP2221/MCP2221A adapters found",
                "No Microchip MCP2221 devices were detected (VID 0x04D8/PID 0x00DD). \
                 Check the UDEV rules, re-connect an adapter and retry.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} MCP2221/MCP2221A adapter(s) detected", device_list.len()),
            "The MCP2221A provides a USB-to-I2C bridge (up to 400 kHz), a USB-to-UART bridge, \
             4x GPIO, 3x 10-bit ADC and 1x 5-bit DAC.",
        ));

        for dev in &device_list {
            let manufacturer = dev.manufacturer_string().unwrap_or("n/a");
            let product = dev
                .product_string()
                .filter(|s| !s.is_empty())
                .unwrap_or("MCP2221");
            let serial = dev
                .serial_number()
                .filter(|s| !s.is_empty())
                .unwrap_or("n/a");

            let description = format!(
                "USB:          {:04x}:{:04x}\n  \
                 Manufacturer: {manufacturer}\n  \
                 Product:      {product}\n  \
                 Serial:       {serial}\n  \
                 Interfaces:   USB-I2C (up to 400 kHz), USB-UART, 4x GPIO, 3x ADC, 1x DAC",
                MCP2221_VID, MCP2221_PID,
            );

            let evidence = format!(
                "vid={:04x} pid={:04x} product={product} serial={serial}",
                MCP2221_VID, MCP2221_PID,
            );

            let title = format!("{product} — {serial}");

            result.add(
                PluginFinding::new(Severity::Info, title, description)
                    .with_evidence(evidence),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DevicePlugin::new()) as Box<dyn crate::Plugin>)
}
