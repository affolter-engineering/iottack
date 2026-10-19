use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the severity level of a finding.
///
/// Variants are ordered from least to most severe, so they can be compared and sorted.
///
/// ```
/// use iottack::Severity;
/// assert!(Severity::Info < Severity::Critical);
/// assert_eq!(Severity::High.to_string(), "high");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Implement `Display` for `Severity` to provide a lowercase string representation.
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

/// Represents a security or informational finding discovered during a test.
///
/// ```
/// use iottack::{PluginFinding, Severity};
/// let f = PluginFinding::new(Severity::High, "Open Telnet", "Port 23 accepts connections")
///     .with_evidence("220 Welcome");
/// assert_eq!(f.severity, Severity::High);
/// assert!(f.evidence.is_some());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Option<String>,
}

/// Implement `Display` for `PluginFinding` to provide a human-readable representation.
impl PluginFinding {
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            severity,
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

/// Represents the status of a test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginStatus {
    Pass,
    Fail,
    Error(String),
    Skipped,
}

/// Implement `Display` for `PluginStatus` to provide a lowercase string representation.
impl fmt::Display for PluginStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Error(e) => write!(f, "error({e})"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// Represents the result of a test executed by a plugin.
///
/// ```
/// use iottack::{PluginFinding, PluginResult, PluginStatus, Severity};
/// let mut result = PluginResult::new("http/banner");
/// result.add(PluginFinding::new(Severity::Medium, "No HSTS", "Missing Strict-Transport-Security"));
/// result.add(PluginFinding::new(Severity::High, "Cleartext HTTP", "Port 80 unencrypted"));
/// result.finish(PluginStatus::Fail);
/// assert_eq!(result.highest_severity(), Some(&Severity::High));
/// assert_eq!(result.findings.len(), 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub plugin: String,
    pub status: PluginStatus,
    pub findings: Vec<PluginFinding>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub silent: bool,
}

/// Implement methods for `PluginResult` to manage findings and test status.
impl PluginResult {
    pub fn new(plugin: impl Into<String>) -> Self {
        Self {
            plugin: plugin.into(),
            status: PluginStatus::Pass,
            findings: Vec::new(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            silent: false,
        }
    }

    /// Suppress console output while still allowing the result to be saved to a file.
    ///
    /// ```
    /// use iottack::{PluginResult, PluginStatus};
    /// let mut result = PluginResult::new("http/sse");
    /// result.finish(PluginStatus::Pass);
    /// result.set_silent();
    /// assert!(result.silent);
    /// ```
    pub fn set_silent(&mut self) {
        self.silent = true;
    }

    pub fn add(&mut self, finding: PluginFinding) {
        self.findings.push(finding);
    }

    pub fn finish(&mut self, status: PluginStatus) {
        self.status = status;
        self.finished_at = Utc::now();
    }

    pub fn highest_severity(&self) -> Option<&Severity> {
        self.findings.iter().map(|f| &f.severity).max()
    }
}

/// Tests for the result handling and severity ordering.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Low.to_string(), "low");
    }

    #[test]
    fn finding_new_has_no_evidence() {
        let f = PluginFinding::new(Severity::High, "title", "description");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "title");
        assert_eq!(f.description, "description");
        assert!(f.evidence.is_none());
    }

    #[test]
    fn finding_with_evidence() {
        let f = PluginFinding::new(Severity::Low, "t", "d").with_evidence("proof");
        assert_eq!(f.evidence, Some("proof".to_string()));
    }

    #[test]
    fn plugin_status_display() {
        assert_eq!(PluginStatus::Pass.to_string(), "pass");
        assert_eq!(PluginStatus::Fail.to_string(), "fail");
        assert_eq!(PluginStatus::Skipped.to_string(), "skipped");
        assert_eq!(PluginStatus::Error("oops".into()).to_string(), "error(oops)");
    }

    #[test]
    fn result_accumulates_findings() {
        let mut r = PluginResult::new("test/plugin");
        assert!(r.findings.is_empty());
        r.add(PluginFinding::new(Severity::Info, "a", "b"));
        r.add(PluginFinding::new(Severity::High, "c", "d"));
        assert_eq!(r.findings.len(), 2);
    }

    #[test]
    fn result_highest_severity_empty() {
        let r = PluginResult::new("test/plugin");
        assert!(r.highest_severity().is_none());
    }

    #[test]
    fn result_highest_severity_picks_max() {
        let mut r = PluginResult::new("test/plugin");
        r.add(PluginFinding::new(Severity::Low, "a", "b"));
        r.add(PluginFinding::new(Severity::Critical, "c", "d"));
        r.add(PluginFinding::new(Severity::Medium, "e", "f"));
        assert_eq!(r.highest_severity(), Some(&Severity::Critical));
    }

    #[test]
    fn result_silent_flag() {
        let mut r = PluginResult::new("test/plugin");
        assert!(!r.silent);
        r.set_silent();
        assert!(r.silent);
    }

    #[test]
    fn result_finish_sets_status_and_name() {
        let mut r = PluginResult::new("test/plugin");
        assert_eq!(r.plugin, "test/plugin");
        r.finish(PluginStatus::Fail);
        assert!(matches!(r.status, PluginStatus::Fail));
    }
}
