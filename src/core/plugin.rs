use crate::core::{Category, PluginConfig, PluginResult};
use anyhow::Result;

/// Descriptor for a single CLI argument a plugin accepts.
///
/// The `name` field is the config key (underscores, e.g. `timeout_ms`);
/// `main.rs` converts it to `--timeout-ms` for the CLI flag automatically.
pub struct CliArg {
    /// Config key and clap arg ID (e.g. `timeout_ms`).
    pub name: &'static str,
    /// Optional single-character short flag (e.g. `Some('p')`).
    pub short: Option<char>,
    /// Help text shown in `--help`.
    pub help: &'static str,
    /// Placeholder shown in help for value args (e.g. `"PATH"`). Ignored for flags.
    pub value_name: &'static str,
    /// Default value string. `None` means the arg is required.
    /// Ignored for flag args (implicitly `false` when absent).
    pub default: Option<&'static str>,
    /// If `true`, this is a boolean flag - presence sets the config key to `"true"`.
    pub is_flag: bool,
}

/// Derives the plugin category from the module path.
pub fn category_from_module(module: &str) -> Category {
    let stripped = module
        .strip_prefix("iottack::protocols::")
        .or_else(|| module.strip_prefix("iottack::"))
        .unwrap_or(module);

    match stripped.split("::").next().unwrap_or("") {
        "serial" => Category::Physical,
        "network" => Category::Network,
        "radio" => Category::Radio,
        "firmware" => Category::Firmware,
        "cryptography" => Category::Cryptography,
        "host" => Category::Host,
        _ => Category::Network,
    }
}

/// Derives the plugin name from the module path, converting `::` to `/` and underscores to hyphens.
pub fn plugin_name_from_module(module: &str) -> String {
    module
        .strip_prefix("iottack::protocols::")
        .or_else(|| module.strip_prefix("iottack::"))
        .unwrap_or(module)
        .replace("::", "/")
        .replace('_', "-")
}

/// Construct a [`PluginMeta`] with `name` and `category` derived automatically
/// from the calling module's path. Accepts an optional `args:` field.
#[macro_export]
macro_rules! plugin_meta {
    (
        summary: $summary:expr,
        description: $description:expr,
        needs_root: $needs_root:expr,
        args: $args:expr $(,)?
    ) => {
        $crate::PluginMeta {
            name: $crate::plugin_name_from_module(module_path!()),
            category: $crate::category_from_module(module_path!()),
            summary: $summary,
            description: $description,
            needs_root: $needs_root,
            cli_args: $args,
        }
    };
    (
        summary: $summary:expr,
        description: $description:expr,
        needs_root: $needs_root:expr $(,)?
    ) => {
        $crate::PluginMeta {
            name: $crate::plugin_name_from_module(module_path!()),
            category: $crate::category_from_module(module_path!()),
            summary: $summary,
            description: $description,
            needs_root: $needs_root,
            cli_args: &[],
        }
    };
}

/// Metadata for a plugin. Returned by [`Plugin::meta`].
///
/// Construct with the [`plugin_meta!`] macro - never set `name` or `category`
/// by hand.
pub struct PluginMeta {
    /// Derived from the plugin's module path via [`plugin_name_from_module`].
    pub name: String,
    /// One-line description shown in `iottack list`.
    pub summary: &'static str,
    /// Extended description of what the plugin does and how to use it.
    pub description: &'static str,
    /// Derived from the plugin's module path via [`category_from_module`].
    pub category: Category,
    /// Set to `true` if the plugin requires root / administrator privileges.
    pub needs_root: bool,
    /// CLI arguments this plugin accepts. Used by `main.rs` to build subcommands
    /// dynamically - plugins do not need to touch `main.rs`.
    pub cli_args: &'static [CliArg],
}

/// Every test plugin must implement this trait.
///
/// Lifecycle: `initialize` → `execute` → `teardown`. The default `run` implementation
/// orchestrates this and guarantees `teardown` is always called even when
/// `execute` fails.
pub trait Plugin: Send {
    fn meta(&self) -> PluginMeta;

    /// Initialize state from config. Called once before `execute`.
    fn initialize(&mut self, _config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    /// Core test logic. Must be implemented by every plugin.
    fn execute(&mut self) -> Result<PluginResult>;

    /// Teardown: release resources. Always called, even when `execute` erred.
    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }

    /// Orchestrates the full lifecycle. Override only for unusual control flow.
    fn run(&mut self, config: &PluginConfig) -> Result<PluginResult> {
        let name = self.meta().name;
        tracing::info!(plugin = %name, "starting");
        self.initialize(config)?;
        let exec = self.execute();
        let cleanup = self.teardown();
        let result = exec?;
        cleanup?;
        tracing::info!(plugin = %name, status = %result.status, "done");
        Ok(result)
    }
}

/// Tests for the plugin name and category mapping functions.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Category;

    #[test]
    fn plugin_name_strips_protocols_prefix_and_maps_separators() {
        assert_eq!(plugin_name_from_module("iottack::protocols::http::banner"), "http/banner");
        assert_eq!(plugin_name_from_module("iottack::protocols::network::tcp_banner"), "network/tcp-banner");
    }

    #[test]
    fn plugin_name_strips_iottack_prefix_without_protocols() {
        assert_eq!(plugin_name_from_module("iottack::platform::platform"), "platform/platform");
    }

    #[test]
    fn plugin_name_falls_back_for_unknown_prefix() {
        assert_eq!(plugin_name_from_module("other::module"), "other/module");
    }

    #[test]
    fn category_maps_known_protocol_families() {
        assert_eq!(category_from_module("iottack::protocols::network::mdns_scan"), Category::Network);
        assert_eq!(category_from_module("iottack::protocols::serial::uart"), Category::Physical);
    }

    #[test]
    fn category_defaults_to_network_for_unknown_family() {
        assert_eq!(category_from_module("iottack::protocols::http::banner"), Category::Network);
        assert_eq!(category_from_module("iottack::protocols::amqp::scan"), Category::Network);
    }
}
