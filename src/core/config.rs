use std::collections::HashMap;

/// Key-value configuration bag passed to a plugin at runtime.
///
/// ```
/// use iottack::PluginConfig;
/// let mut cfg = PluginConfig::new();
/// cfg.set("host", "192.168.1.1").set("port", "8080");
/// assert_eq!(cfg.get("host"), Some("192.168.1.1"));
/// assert_eq!(cfg.get("missing"), None);
/// ```
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

    /// Returns the value for `key`, or `default` if absent.
    ///
    /// ```
    /// use iottack::PluginConfig;
    /// let mut cfg = PluginConfig::new();
    /// assert_eq!(cfg.get_or("path", "/"), "/");
    /// cfg.set("path", "/api");
    /// assert_eq!(cfg.get_or("path", "/"), "/api");
    /// ```
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

    /// Parses the value for `key` into `T`, returning `default` if absent or unparseable.
    ///
    /// ```
    /// use iottack::PluginConfig;
    /// let mut cfg = PluginConfig::new();
    /// assert_eq!(cfg.parse_or("port", 80u16), 80);
    /// cfg.set("port", "9200");
    /// assert_eq!(cfg.parse_or("port", 80u16), 9200);
    /// cfg.set("port", "bad");
    /// assert_eq!(cfg.parse_or("port", 80u16), 80);
    /// ```
    pub fn parse_or<T: std::str::FromStr>(&self, key: &str, default: T) -> T
    where
        T::Err: std::fmt::Display,
    {
        self.get(key)
            .and_then(|v| v.parse::<T>().ok())
            .unwrap_or(default)
    }
}

/// Tests for the plugin configuration management.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_missing_key_returns_none() {
        assert!(PluginConfig::new().get("x").is_none());
    }

    #[test]
    fn get_returns_set_value() {
        let mut c = PluginConfig::new();
        c.set("host", "192.168.1.1");
        assert_eq!(c.get("host"), Some("192.168.1.1"));
    }

    #[test]
    fn set_is_chainable() {
        let mut c = PluginConfig::new();
        c.set("a", "1").set("b", "2");
        assert_eq!(c.get("a"), Some("1"));
        assert_eq!(c.get("b"), Some("2"));
    }

    #[test]
    fn get_or_returns_value_when_present() {
        let mut c = PluginConfig::new();
        c.set("path", "/api");
        assert_eq!(c.get_or("path", "/"), "/api");
    }

    #[test]
    fn get_or_returns_default_when_absent() {
        assert_eq!(PluginConfig::new().get_or("path", "/"), "/");
    }

    #[test]
    fn require_returns_error_for_missing_key() {
        assert!(PluginConfig::new().require("missing").is_err());
    }

    #[test]
    fn require_returns_value_when_present() {
        let mut c = PluginConfig::new();
        c.set("key", "val");
        assert_eq!(c.require("key").unwrap(), "val");
    }

    #[test]
    fn parse_or_parses_valid_value() {
        let mut c = PluginConfig::new();
        c.set("port", "8080");
        assert_eq!(c.parse_or("port", 80u16), 8080);
    }

    #[test]
    fn parse_or_returns_default_for_missing_key() {
        assert_eq!(PluginConfig::new().parse_or("port", 80u16), 80);
    }

    #[test]
    fn parse_or_returns_default_for_invalid_value() {
        let mut c = PluginConfig::new();
        c.set("port", "not-a-number");
        assert_eq!(c.parse_or("port", 80u16), 80);
    }
}
