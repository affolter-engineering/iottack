use std::collections::HashMap;

/// Key-value configuration bag passed to a plugin at runtime.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    args: HashMap<String, String>,
}

/// Implement methods for managing plugin configuration.
impl PluginConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.args.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.args.get(key).map(String::as_str)
    }

    pub fn require(&self, key: &str) -> anyhow::Result<&str> {
        self.get(key)
            .ok_or_else(|| anyhow::anyhow!("required config key '{}' missing", key))
    }

    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_string()
    }

    pub fn parse<T: std::str::FromStr>(&self, key: &str) -> anyhow::Result<T>
    where
        T::Err: std::fmt::Display,
    {
        self.require(key)?
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("config key '{}': {}", key, e))
    }

    pub fn parse_or<T: std::str::FromStr>(&self, key: &str, default: T) -> T
    where
        T::Err: std::fmt::Display,
    {
        self.get(key)
            .and_then(|v| v.parse::<T>().ok())
            .unwrap_or(default)
    }
}
