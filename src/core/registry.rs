use crate::core::{Plugin, PluginConfig, PluginResult};
use anyhow::Result;
use std::collections::HashMap;

type Factory = Box<dyn Fn() -> Box<dyn Plugin> + Send + Sync>;

/// A zero-argument factory function for a plugin.
///
/// Submit one of these per plugin with `inventory::submit!` and `PluginRegistry::new()`
/// will pick them all up automatically — no changes to `main.rs` required.
pub struct PluginFactory(pub fn() -> Box<dyn Plugin>);
inventory::collect!(PluginFactory);

/// Global registry of plugin factories.
///
/// Plugins register themselves by name; callers instantiate on demand so that
/// each run gets a fresh, zeroed-state plugin instance.
#[derive(Default)]
pub struct PluginRegistry {
    factories: HashMap<String, Factory>,
}

/// Implementation of the plugin registry. Handles registration, lookup, and instantiation of plugins.
impl PluginRegistry {
    /// Build a registry pre-populated with every plugin submitted via
    /// `inventory::submit! { PluginFactory(...) }`.
    pub fn new() -> Self {
        let mut reg = Self::default();
        for factory in inventory::iter::<PluginFactory> {
            reg.register(factory.0);
        }
        reg
    }

    /// Register a plugin factory. The plugin name is derived from the plugin
    /// itself by calling `factory().meta().name`.
    pub fn register<F>(&mut self, factory: F)
    where
        F: Fn() -> Box<dyn Plugin> + Send + Sync + 'static,
    {
        let name = factory().meta().name;
        self.factories.insert(name, Box::new(factory));
    }

    /// Instantiate a plugin by name, returning `None` if unknown.
    pub fn get(&self, name: &str) -> Option<Box<dyn Plugin>> {
        self.factories.get(name).map(|f| f())
    }

    /// Sorted list of all registered plugin names.
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.factories.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Instantiate `name` and immediately run it with `config`.
    pub fn run(&self, name: &str, config: &PluginConfig) -> Result<PluginResult> {
        let mut plugin = self
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("plugin '{}' not found", name))?;
        plugin.run(config)
    }
}
