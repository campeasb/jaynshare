//! The deploy-verb `result`: `{ operation, version, commit, paths,
//! project, rolled_back, checks: [{ name, passed, message }] }`. The
//! same facts go to standard error as the verb works, and the first failed
//! check names the artifact and the check.

use serde_json::{Value, json};

/// One named check and its outcome. `message` never carries a secret, a code
/// or a configuration value.
///
/// A failed check's name selects the verb's exit row by its first
/// dot-separated word (`cli/deploy.rs::exit_row`): `release` 17, `preflight`
/// 18, `manager` 19, `confirmation` 21, `conflict` 8, `configuration` 3; any
/// other name takes the verb's default row. A result with `rolled_back` set
/// exits 20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

impl Check {
    pub fn pass(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: message.into(),
        }
    }

    pub fn fail(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: message.into(),
        }
    }
}

/// What a deploy verb did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeployResult {
    /// The verb's command path (`release verify`, `server install`, …).
    pub operation: String,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub paths: Vec<String>,
    pub project: Option<String>,
    pub rolled_back: bool,
    pub checks: Vec<Check>,
}

impl DeployResult {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            ..Self::default()
        }
    }

    /// The first check that failed, in the order the checks ran.
    pub fn failed(&self) -> Option<&Check> {
        self.checks.iter().find(|check| !check.passed)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "operation": self.operation,
            "version": self.version,
            "commit": self.commit,
            "paths": self.paths,
            "project": self.project,
            "rolled_back": self.rolled_back,
            "checks": self
                .checks
                .iter()
                .map(|c| json!({ "name": c.name, "passed": c.passed, "message": c.message }))
                .collect::<Vec<_>>(),
        })
    }

    /// The human form: one line per check, `ok` or `FAILED`, then the name
    /// and message.
    pub fn to_text(&self) -> String {
        let mut lines = Vec::new();
        if let Some(version) = &self.version {
            let commit = self.commit.as_deref().unwrap_or("unknown commit");
            lines.push(format!("{} {version} ({commit})", self.operation));
        }
        for check in &self.checks {
            let mark = if check.passed { "ok    " } else { "FAILED" };
            lines.push(format!("{mark} {}: {}", check.name, check.message));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_json_carries_the_keys_of_08_section_11() {
        let mut result = DeployResult::new("release verify");
        result.checks.push(Check::pass("signature", "valid"));
        result
            .checks
            .push(Check::fail("digest", "jaynshare.zip: mismatch"));
        let value = result.to_json();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "operation",
                "version",
                "commit",
                "paths",
                "project",
                "rolled_back",
                "checks"
            ]
        );
        assert_eq!(result.failed().unwrap().name, "digest");
    }
}
