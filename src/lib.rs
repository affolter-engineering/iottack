pub mod core;
pub mod platform;
pub mod protocols;

pub use core::{
    Category, CliArg, FrameworkError, Plugin, PluginConfig, PluginFactory, PluginFinding,
    PluginMeta, PluginRegistry, PluginResult, PluginStatus, Severity, category_from_module,
    plugin_name_from_module,
};
