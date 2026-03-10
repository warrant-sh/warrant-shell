use std::path::{Path, PathBuf};

use crate::cli::DraftScopeArg;

const CONFIG_SCHEMA_V1: &str = "warrant.config.v1";
const CONFIG_FILE_NAME: &str = "wsh.toml";

#[derive(Debug, Clone)]
pub struct WshConfig {
    pub command_default: PolicyDefaultMode,
    pub manifests: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PolicyDefaultMode {
    Deny,
    Allow,
}

impl PolicyDefaultMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

impl std::fmt::Display for PolicyDefaultMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "{err}"),
            ConfigError::Parse(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Search for an existing `wsh.toml` in all known locations.
/// Returns the path and the inferred scope.
/// Search order: `./wsh.toml` → `.warrant/wsh.toml` → `~/.config/wsh/wsh.toml`
pub fn find_config() -> Option<(PathBuf, DraftScopeArg)> {
    let project_root = Path::new(CONFIG_FILE_NAME);
    if project_root.exists() {
        return Some((project_root.to_path_buf(), DraftScopeArg::Project));
    }

    let warrant_dir = Path::new(".warrant").join(CONFIG_FILE_NAME);
    if warrant_dir.exists() {
        return Some((warrant_dir, DraftScopeArg::Project));
    }

    if let Some(system_path) = system_config_path()
        && system_path.exists()
    {
        return Some((system_path, DraftScopeArg::System));
    }

    None
}

/// Find config matching a specific scope.
pub fn find_config_for_scope(scope: DraftScopeArg) -> Option<PathBuf> {
    match scope {
        DraftScopeArg::Project => {
            let project_root = Path::new(CONFIG_FILE_NAME);
            if project_root.exists() {
                return Some(project_root.to_path_buf());
            }
            let warrant_dir = Path::new(".warrant").join(CONFIG_FILE_NAME);
            if warrant_dir.exists() {
                return Some(warrant_dir);
            }
            None
        }
        DraftScopeArg::System => {
            let path = system_config_path()?;
            if path.exists() { Some(path) } else { None }
        }
    }
}

/// Parse a `wsh.toml` file.
pub fn read_config(path: &Path) -> Result<WshConfig, ConfigError> {
    let text = std::fs::read_to_string(path)?;
    parse_config(&text)
}

/// Parse config from a TOML string.
pub fn parse_config(text: &str) -> Result<WshConfig, ConfigError> {
    let root: toml::Value = toml::from_str(text)
        .map_err(|err| ConfigError::Parse(format!("invalid wsh.toml: {err}")))?;

    let config = root
        .as_table()
        .and_then(|t| t.get("config"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| ConfigError::Parse("[config] section required in wsh.toml".to_string()))?;

    let schema = config
        .get("schema")
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    if schema != CONFIG_SCHEMA_V1 {
        return Err(ConfigError::Parse(format!(
            "unsupported config schema: {schema:?} (expected {CONFIG_SCHEMA_V1:?})"
        )));
    }

    let command_default = config
        .get("command_default")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| ConfigError::Parse("missing required config.command_default".to_string()))
        .and_then(|value| match value {
            "deny" => Ok(PolicyDefaultMode::Deny),
            "allow" => Ok(PolicyDefaultMode::Allow),
            other => Err(ConfigError::Parse(format!(
                "invalid config.command_default: {other:?} (expected \"deny\" or \"allow\")"
            ))),
        })?;

    let manifests = config
        .get("manifests")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(WshConfig {
        command_default,
        manifests,
    })
}

/// Write a config to disk.
pub fn write_config(path: &Path, config: &WshConfig) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serialize_config(config);
    std::fs::write(path, text)?;
    Ok(())
}

/// Append a manifest ID to an existing config file (idempotent).
pub fn append_manifest(path: &Path, manifest_id: &str) -> Result<(), ConfigError> {
    let mut config = read_config(path)?;
    if config.manifests.iter().any(|id| id == manifest_id) {
        return Ok(());
    }
    config.manifests.push(manifest_id.to_string());
    write_config(path, &config)
}

fn serialize_config(config: &WshConfig) -> String {
    let mut out = String::new();
    out.push_str("[config]\n");
    out.push_str("schema = \"warrant.config.v1\"\n");
    out.push_str(&format!(
        "command_default = \"{}\"\n",
        config.command_default.as_str()
    ));
    out.push('\n');
    out.push_str("manifests = [\n");
    for id in &config.manifests {
        out.push_str(&format!("  \"{id}\",\n"));
    }
    out.push_str("]\n");
    out
}

fn system_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.trim().is_empty()
    {
        return Some(Path::new(&xdg).join("wsh").join(CONFIG_FILE_NAME));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(
            Path::new(&home)
                .join(".config")
                .join("wsh")
                .join(CONFIG_FILE_NAME),
        );
    }
    None
}

/// Returns the default system config path for writing (creates parent dirs).
pub fn system_config_path_for_write() -> Option<PathBuf> {
    system_config_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let text = r#"
[config]
schema = "warrant.config.v1"
command_default = "deny"

manifests = [
  "official/git",
  "official/cargo",
  "official/sanitize-env",
]
"#;
        let config = parse_config(text).expect("parse");
        assert_eq!(config.command_default, PolicyDefaultMode::Deny);
        assert_eq!(
            config.manifests,
            vec!["official/git", "official/cargo", "official/sanitize-env"]
        );
    }

    #[test]
    fn rejects_missing_config_section() {
        let text = r#"
[other]
key = "value"
"#;
        let err = parse_config(text).expect_err("must reject missing config section");
        assert!(err.to_string().contains("[config] section required"));
    }

    #[test]
    fn rejects_wrong_schema() {
        let text = r#"
[config]
schema = "warrant.config.v99"
command_default = "deny"
manifests = []
"#;
        let err = parse_config(text).expect_err("must reject wrong schema");
        assert!(err.to_string().contains("unsupported config schema"));
    }

    #[test]
    fn parses_empty_manifests() {
        let text = r#"
[config]
schema = "warrant.config.v1"
command_default = "deny"
manifests = []
"#;
        let config = parse_config(text).expect("parse");
        assert!(config.manifests.is_empty());
    }

    #[test]
    fn rejects_missing_command_default() {
        let text = r#"
[config]
schema = "warrant.config.v1"
manifests = []
"#;
        let err = parse_config(text).expect_err("must reject missing command_default");
        assert!(
            err.to_string()
                .contains("missing required config.command_default")
        );
    }

    #[test]
    fn rejects_invalid_command_default() {
        let text = r#"
[config]
schema = "warrant.config.v1"
command_default = "maybe"
manifests = []
"#;
        let err = parse_config(text).expect_err("must reject invalid command_default");
        assert!(err.to_string().contains("invalid config.command_default"));
    }

    #[test]
    fn serialize_roundtrips() {
        let config = WshConfig {
            command_default: PolicyDefaultMode::Allow,
            manifests: vec![
                "official/git".to_string(),
                "official/sanitize-env".to_string(),
            ],
        };
        let text = serialize_config(&config);
        let parsed = parse_config(&text).expect("roundtrip parse");
        assert_eq!(parsed.command_default, config.command_default);
        assert_eq!(parsed.manifests, config.manifests);
    }

    #[test]
    fn append_manifest_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wsh.toml");
        let config = WshConfig {
            command_default: PolicyDefaultMode::Deny,
            manifests: vec!["official/git".to_string()],
        };
        write_config(&path, &config).expect("write");

        append_manifest(&path, "official/cargo").expect("append");
        let updated = read_config(&path).expect("read");
        assert_eq!(updated.manifests, vec!["official/git", "official/cargo"]);

        // Second append should be idempotent
        append_manifest(&path, "official/cargo").expect("append again");
        let updated2 = read_config(&path).expect("read again");
        assert_eq!(updated2.manifests, vec!["official/git", "official/cargo"]);
    }
}
