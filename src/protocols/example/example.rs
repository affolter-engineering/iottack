//! Example plugin, a minimal, fully-commented reference for writing new plugins.
//!
//! Copy this file into `src/protocols/<protocol>/` and adapt it.
//! The only required steps are:
//!   1. Implement the `Plugin` trait on your struct.
//!   2. Add `inventory::submit!` at the bottom.
//!   3. Declare the module in `src/protocols/<protocol>/mod.rs`.
//!   4. Add `pub mod <protocol>;` to `src/protocols/mod.rs`.

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

// Plugin struct
//
// Store every parameter the plugin needs between `initialize` and `execute`.
// Fields should mirror the CLI arguments declared in `meta()`.

/// Example plugin that demonstrates the full plugin authoring API.
pub struct ExamplePlugin {
    /// The message to include in the findings.
    message: String,
    /// When true, the plugin reports a High finding and finishes with Fail.
    fail: bool,
}

/// Implementation of the `ExamplePlugin` struct. Provides a constructor with safe defaults.
impl ExamplePlugin {
    /// Construct the plugin with safe defaults.
    ///
    /// `PluginRegistry` calls this via the factory function at the bottom of
    /// the file, so the struct must always be constructable without arguments.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            fail: false,
        }
    }
}

/// Default implementation for the plugin, delegates to `new()`.
impl Default for ExamplePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// Plugin trait implementation

impl Plugin for ExamplePlugin {
    // meta
    //
    // `plugin_meta!` derives `name` and `category` from the module path
    // automatically. No need to hard-code them.
    //
    // Name derivation:  iottack::protocols::example::example -> "example/example"
    // Category:         falls back to Network for unrecognized families.
    //
    // `cli_args` describes every flag this plugin accepts.  `main.rs` reads
    // this slice to build the clap subcommand dynamically. You never touch
    // `main.rs` when adding a new plugin.

    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Example plugin, shows the full plugin authoring pattern",
            description: "A reference plugin that exercises every part of the Plugin \
                          API: initialize, execute, teardown, CLI arguments, findings \
                          at multiple severity levels and the inventory registration \
                          macro. Copy and adapt it to write a new plugin.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "message",
                    short: Some('m'),
                    help: "Text to include in the Info finding",
                    value_name: "TEXT",
                    default: Some("hello from example plugin"),
                    is_flag: false,
                },
                CliArg {
                    name: "fail",
                    short: Some('x'),
                    help: "Emit a High finding and exit with status Fail",
                    value_name: "",
                    default: None,
                    is_flag: true,   // boolean flag: presence -> "true", absence -> "false"
                },
            ],
        )
    }

    // initialize
    //
    // Called once before `execute`.  Read every CLI argument from `config` and
    // store the values on `self`.  Use `parse_or` for typed values with a safe
    // default, `get_or` for strings, and `require` when a missing value is a
    // hard error.

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.message = config.get_or("message", "hello from example plugin");
        self.fail = config.get("fail") == Some("true");
        Ok(())
    }

    // execute
    //
    // Core test logic.  Create a `PluginResult`, add findings with
    // `PluginFinding::new`, and call `result.finish(status)` before returning.
    //
    // Early-return on hard errors (connection refused, missing required arg)
    // using `PluginStatus::Fail`; reserve `?` / `Err` for truly unexpected
    // failures that warrant an `Error` status.

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        // Info finding - always emitted
        //
        // Use Severity::Info for neutral observations.  The description should
        // explain *what was found*; the title is the headline shown in the
        // formatted output.
        result.add(PluginFinding::new(
            Severity::Info,
            format!("Example plugin executed: {}", self.message),
            "This is an informational finding created by the example plugin. \
             In a real plugin this would describe an observed property of the target.",
        ));

        // Conditional High finding - emitted when --fail is passed
        //
        // Use `with_evidence` to attach the raw data that triggered the finding
        // (a banner, a header value, a captured packet, etc.).  Evidence is
        // printed beneath the description in the text output and preserved in
        // JSON results.
        if self.fail {
            result.add(
                PluginFinding::new(
                    Severity::High,
                    "Simulated failure",
                    "The --fail flag was set, so the plugin is reporting a High \
                     finding. In a real plugin this would represent a confirmed \
                     vulnerability or misconfiguration.",
                )
                .with_evidence("flag: --fail was present"),
            );
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        // Additional example findings at other severity levels
        result.add(PluginFinding::new(
            Severity::Low,
            "Low-severity observation",
            "A low-impact issue that is worth noting but does not require \
             immediate remediation.",
        ));

        result.add(PluginFinding::new(
            Severity::Medium,
            "Medium-severity observation",
            "A moderate issue that should be addressed in the next maintenance \
             window.",
        ));

        result.finish(PluginStatus::Pass);
        Ok(result)
    }

    // teardown
    //
    // Always called after `execute`, even when `execute` returned an error.
    // Release sockets, file handles, or any other resources acquired in
    // `initialize` or `execute`.  The default implementation is a no-op, so
    // you can omit this method if there is nothing to clean up.

    fn teardown(&mut self) -> Result<()> {
        // Nothing to release in this example.
        Ok(())
    }
}

// Auto-registration
//
// This single line registers the plugin with the global inventory at startup.
// `PluginRegistry::new()` collects all submitted factories automatically.
// No changes to `main.rs` or any registry file are needed.

inventory::submit! {
    crate::PluginFactory(|| Box::new(ExamplePlugin::new()) as Box<dyn crate::Plugin>)
}
