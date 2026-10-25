use crate::core::{Plugin, PluginConfig, PluginResult};
use anyhow::Result;
use std::collections::HashMap;

type Factory = Box<dyn Fn() -> Box<dyn Plugin> + Send + Sync>;

/// A zero-argument factory function for a plugin.
///
/// Submit one of these per plugin with `inventory::submit!` and `PluginRegistry::new()`
/// will pick them all up automatically - no changes to `main.rs` required.
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
    ///
    /// ```
    /// use iottack::{Category, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, PluginRegistry, Severity};
    ///
    /// struct PingPlugin;
    /// impl iottack::Plugin for PingPlugin {
    ///     fn meta(&self) -> PluginMeta {
    ///         PluginMeta {
    ///             name: "test/ping".to_string(),
    ///             summary: "always passes",
    ///             description: "minimal example plugin",
    ///             category: Category::Network,
    ///             needs_root: false,
    ///             cli_args: &[],
    ///         }
    ///     }
    ///     fn execute(&mut self) -> anyhow::Result<PluginResult> {
    ///         let mut r = PluginResult::new("test/ping");
    ///         r.finish(PluginStatus::Pass);
    ///         Ok(r)
    ///     }
    /// }
    ///
    /// let mut reg = PluginRegistry::default();
    /// reg.register(|| Box::new(PingPlugin) as Box<dyn iottack::Plugin>);
    /// assert!(reg.get("test/ping").is_some());
    /// assert!(reg.list().contains(&"test/ping"));
    /// ```
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

/// Tests for the plugin registry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Category, PluginFinding, PluginMeta, PluginStatus, Severity};

    struct NoopPlugin;

    impl Plugin for NoopPlugin {
        fn meta(&self) -> PluginMeta {
            PluginMeta {
                name: "test/noop".to_string(),
                summary: "no-op",
                description: "no-op plugin for tests",
                category: Category::Network,
                needs_root: false,
                cli_args: &[],
            }
        }
        fn execute(&mut self) -> anyhow::Result<PluginResult> {
            let mut r = PluginResult::new("test/noop");
            r.finish(PluginStatus::Pass);
            Ok(r)
        }
    }

    struct FailPlugin;

    impl Plugin for FailPlugin {
        fn meta(&self) -> PluginMeta {
            PluginMeta {
                name: "test/fail".to_string(),
                summary: "always fails",
                description: "plugin that always returns Fail",
                category: Category::Network,
                needs_root: false,
                cli_args: &[],
            }
        }
        fn execute(&mut self) -> anyhow::Result<PluginResult> {
            let mut r = PluginResult::new("test/fail");
            r.add(PluginFinding::new(
                Severity::High,
                "always fails",
                "intentional",
            ));
            r.finish(PluginStatus::Fail);
            Ok(r)
        }
    }

    fn make_registry() -> PluginRegistry {
        let mut reg = PluginRegistry::default();
        reg.register(|| Box::new(NoopPlugin) as Box<dyn Plugin>);
        reg.register(|| Box::new(FailPlugin) as Box<dyn Plugin>);
        reg
    }

    #[test]
    fn get_registered_plugin() {
        let reg = make_registry();
        assert!(reg.get("test/noop").is_some());
        assert!(reg.get("test/fail").is_some());
    }

    #[test]
    fn get_unknown_plugin_returns_none() {
        let reg = make_registry();
        assert!(reg.get("does/not/exist").is_none());
    }

    #[test]
    fn list_returns_all_names_sorted() {
        let reg = make_registry();
        let names = reg.list();
        assert!(names.contains(&"test/noop"));
        assert!(names.contains(&"test/fail"));
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn run_pass_plugin() {
        let reg = make_registry();
        let result = reg.run("test/noop", &PluginConfig::new()).unwrap();
        assert!(matches!(result.status, PluginStatus::Pass));
        assert_eq!(result.plugin, "test/noop");
    }

    #[test]
    fn run_fail_plugin_has_findings() {
        let reg = make_registry();
        let result = reg.run("test/fail", &PluginConfig::new()).unwrap();
        assert!(matches!(result.status, PluginStatus::Fail));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::High);
    }

    #[test]
    fn run_unknown_plugin_returns_error() {
        let reg = make_registry();
        assert!(reg.run("does/not/exist", &PluginConfig::new()).is_err());
    }

    #[test]
    fn each_get_call_invokes_factory_again() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);

        let mut reg = PluginRegistry::default();
        reg.register(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            Box::new(NoopPlugin) as Box<dyn Plugin>
        });

        // register() calls the factory once to derive the plugin name.
        let baseline = calls.load(Ordering::SeqCst);

        reg.get("test/noop");
        reg.get("test/noop");

        assert_eq!(calls.load(Ordering::SeqCst) - baseline, 2);
    }
}
