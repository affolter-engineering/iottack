use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the severity level of a finding.
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
