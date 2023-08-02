mod category;
mod config;
mod error;
mod plugin;
mod registry;
mod result;

pub use category::Category;
pub use config::PluginConfig;
pub use error::FrameworkError;
pub use plugin::{CliArg, Plugin, PluginMeta, category_from_module, plugin_name_from_module};
pub use registry::{PluginFactory, PluginRegistry};
pub use result::{PluginFinding, PluginResult, PluginStatus, Severity};
