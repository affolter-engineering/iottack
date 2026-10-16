use super::sysfs::{effective_uid, kernel_attr, os_release_field};
use crate::{
    core::{Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity},
    plugin_meta,
};
use anyhow::Result;
use chrono::Utc;

/// Collect and report details about the host environment: OS, kernel,
/// architecture, privilege level, and whether the process runs as root.
pub struct PlatformDetails;

impl Plugin for PlatformDetails {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Report host environment",
            description: "Collects OS/kernel/architecture details",
            needs_root: false,
        )
    }

    fn initialize(&mut self, _config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let fw_version = env!("CARGO_PKG_VERSION");
        let os_name = os_release_field("NAME").unwrap_or_else(|| "Unknown".into());
        let os_version = os_release_field("VERSION_ID").unwrap_or_else(|| "Unknown".into());
        let os_codename = os_release_field("VERSION_CODENAME").unwrap_or_default();
        let kernel = kernel_attr("osrelease").unwrap_or_else(|| "Unknown".into());
        let arch = std::env::consts::ARCH;
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let distro = if os_codename.is_empty() {
            format!("{os_name} {os_version}")
        } else {
            format!("{os_name} {os_version} ({os_codename})")
        };

        result.add(PluginFinding::new(
            Severity::Info,
            "Host environment",
            format!(
                "Framework: iottack {fw_version}\n\
                 OS: {distro}\n\
                 Kernel: {kernel}\n\
                 Arch: {arch}\n\
                 Time: {timestamp}"
            ),
        ));

        let euid = effective_uid().unwrap_or(u32::MAX);
        let is_root = euid == 0;

        if is_root {
            result.add(PluginFinding::new(
                Severity::Info,
                "Running as root",
                "The process has root privileges (euid=0). All hardware interfaces are accessible.",
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("Running as unprivileged user (euid={euid})"),
                "Some serial ports or USB devices may require elevated privileges. \
                 Run with sudo if access is denied.",
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(PlatformDetails) as Box<dyn crate::Plugin>)
}
