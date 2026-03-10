use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest;

const MANIFEST_SCHEMA_V1: &str = "warrant.manifest.v1";
const CACHE_MANIFEST_DIR: &str = "/etc/warrant-shell/manifests";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub manifest: ManifestMeta,
    #[serde(default)]
    pub transforms: Option<ManifestTransforms>,
    #[serde(default)]
    pub tool_policy: ManifestToolPolicy,
    pub commands: Vec<ManifestCommand>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestMeta {
    pub schema: String,
    pub id: String,
    pub tool: String,
    pub tool_version: String,
    pub manifest_version: String,
    pub summary: Option<String>,
    pub license: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestTransforms {
    #[serde(default)]
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ManifestToolPolicy {
    #[serde(default)]
    pub allow_inline_execution: bool,
    #[serde(default)]
    pub strip_env: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub deny_flags: Vec<String>,
    #[serde(default)]
    pub deny_flags_description: Option<String>,
    #[serde(default)]
    pub package_policy: ManifestPackagePolicy,
    /// Declares which package ecosystem's denylist to check against.
    /// Required when package_policy = "denylist". E.g. "pypi", "npm", "cargo".
    #[serde(default)]
    pub package_ecosystem: Option<String>,
    /// Which scope key contains package names to check against the denylist.
    /// Required when package_policy = "denylist". E.g. "packages".
    #[serde(default)]
    pub package_scope: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ManifestPackagePolicy {
    #[default]
    Open,
    Denylist,
    Allowlist,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestCommand {
    #[serde(rename = "match", default)]
    pub match_tokens: Vec<String>,
    #[serde(default)]
    pub when_any_flags: Vec<String>,
    #[serde(default)]
    pub when_all_flags: Vec<String>,
    #[serde(default)]
    pub when_no_flags: Vec<String>,
    #[serde(default = "default_true")]
    pub respect_option_terminator: bool,
    pub capability: String,
    #[serde(default)]
    pub default: Option<ManifestDefaultDecision>,
    #[serde(default)]
    pub args: std::collections::BTreeMap<String, usize>,
    #[serde(default)]
    pub flags: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub options: std::collections::BTreeMap<String, ManifestOptionSpec>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub scope: Option<ManifestScope>,
    #[serde(default)]
    pub scopes: Vec<ManifestScope>,
    #[serde(default)]
    pub scope_examples: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub scope_defaults: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub scope_descriptions: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ManifestDefaultDecision {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestScope {
    pub key: String,
    pub from: String,
    pub index: Option<usize>,
    pub transform: String,
    #[serde(default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestOptionSpec {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default = "default_option_value_forms")]
    pub forms: Vec<String>,
    #[serde(default)]
    pub allow_hyphen_values: bool,
}

#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
    Invalid(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(err) => write!(f, "{err}"),
            ManifestError::ParseToml(err) => write!(f, "{err}"),
            ManifestError::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for ManifestError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ManifestError {
    fn from(value: toml::de::Error) -> Self {
        Self::ParseToml(value)
    }
}

pub fn load_cached_manifest(tool: &str) -> Option<Manifest> {
    let normalized = normalize_tool_name(tool);
    let cache_dirs = manifest_cache_dirs();

    let mut candidates = Vec::<PathBuf>::new();
    for dir in &cache_dirs {
        candidates.push(dir.join(format!("{normalized}.toml")));
    }

    if tool.contains('/') {
        let name = tool.split('@').next().unwrap_or(tool);
        for dir in &cache_dirs {
            candidates.push(dir.join(format!("{name}.toml")));
        }
    }

    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&candidate)
            && let Ok(manifest) = parse_manifest(&text)
        {
            return Some(manifest);
        }
    }

    for dir in &cache_dirs {
        let pattern = format!("{}/**/{normalized}*.toml", dir.display());
        let entries = glob::glob(&pattern).ok()?;
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(&entry)
                && let Ok(manifest) = parse_manifest(&text)
            {
                return Some(manifest);
            }
        }
    }

    None
}

pub fn manifest_cache_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::<PathBuf>::new();
    dirs.push(PathBuf::from(CACHE_MANIFEST_DIR));
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.trim().is_empty()
    {
        dirs.push(Path::new(&xdg).join("wsh").join("manifests"));
    } else if let Ok(home) = std::env::var("HOME") {
        dirs.push(
            Path::new(&home)
                .join(".config")
                .join("wsh")
                .join("manifests"),
        );
    }
    dirs
}

pub fn resolve_manifest(tool: &str) -> Option<Manifest> {
    load_cached_manifest(tool)
}

pub fn parse_manifest(toml_text: &str) -> Result<Manifest, ManifestError> {
    let manifest = toml::from_str::<Manifest>(toml_text)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn manifest_hash(manifest: &Manifest) -> Result<String, ManifestError> {
    let canonical = serde_json::to_vec(manifest)
        .map_err(|err| ManifestError::Invalid(format!("failed to canonicalize manifest: {err}")))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn validate_manifest(manifest: &Manifest) -> Result<(), ManifestError> {
    if manifest.manifest.schema != MANIFEST_SCHEMA_V1 {
        return Err(ManifestError::Invalid(format!(
            "unsupported manifest schema: {}",
            manifest.manifest.schema
        )));
    }
    if manifest.manifest.id.trim().is_empty() {
        return Err(ManifestError::Invalid(
            "manifest.id is required".to_string(),
        ));
    }
    if manifest.manifest.tool.trim().is_empty() {
        return Err(ManifestError::Invalid(
            "manifest.tool is required".to_string(),
        ));
    }
    if manifest.manifest.tool_version.trim().is_empty() {
        return Err(ManifestError::Invalid(
            "manifest.tool_version is required".to_string(),
        ));
    }
    if manifest.manifest.manifest_version.trim().is_empty() {
        return Err(ManifestError::Invalid(
            "manifest.manifest_version is required".to_string(),
        ));
    }
    if manifest.commands.is_empty() {
        return Err(ManifestError::Invalid(
            "manifest must declare at least one command".to_string(),
        ));
    }

    for (idx, command) in manifest.commands.iter().enumerate() {
        if command.capability.trim().is_empty() {
            return Err(ManifestError::Invalid(format!(
                "commands[{idx}].capability is required"
            )));
        }
        for flag in command
            .when_any_flags
            .iter()
            .chain(command.when_all_flags.iter())
            .chain(command.when_no_flags.iter())
        {
            if !flag.starts_with('-') {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}] flag selector '{flag}' must start with '-'"
                )));
            }
        }
        for (arg_key, arg_index) in &command.args {
            if arg_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].args contains an empty key"
                )));
            }
            if *arg_index == 0 {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].args.{arg_key} must be >= 1"
                )));
            }
        }
        for (scope_key, flag_name) in &command.flags {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].flags contains an empty key"
                )));
            }
            if !flag_name.starts_with('-') {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].flags.{scope_key} must start with '-'"
                )));
            }
        }
        for (scope_key, option) in &command.options {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].options contains an empty key"
                )));
            }
            if option.names.is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].options.{scope_key}.names must include at least one option name"
                )));
            }
            for name in &option.names {
                if !name.starts_with('-') {
                    return Err(ManifestError::Invalid(format!(
                        "commands[{idx}].options.{scope_key}.names contains '{name}' which must start with '-'"
                    )));
                }
            }
            if option.forms.is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].options.{scope_key}.forms must include at least one form"
                )));
            }
            for form in &option.forms {
                if !matches!(form.as_str(), "separate" | "equals" | "attached") {
                    return Err(ManifestError::Invalid(format!(
                        "commands[{idx}].options.{scope_key}.forms contains unsupported form '{form}'"
                    )));
                }
            }
        }
        for (scope_key, env_name) in &command.env {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].env contains an empty key"
                )));
            }
            if env_name.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].env.{scope_key} must be a non-empty env var name"
                )));
            }
        }
        for (scope_key, examples) in &command.scope_examples {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_examples contains an empty key"
                )));
            }
            if examples.iter().any(|value| value.trim().is_empty()) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_examples.{scope_key} contains an empty example"
                )));
            }
        }
        for (scope_key, defaults) in &command.scope_defaults {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_defaults contains an empty key"
                )));
            }
            if defaults.iter().any(|value| value.trim().is_empty()) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_defaults.{scope_key} contains an empty value"
                )));
            }
        }
        let mut all_scopes = command.scopes.clone();
        if let Some(scope) = &command.scope {
            all_scopes.push(scope.clone());
        }
        let mut allowed_scope_keys = BTreeSet::<String>::new();
        for scope_key in command.args.keys() {
            allowed_scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.flags.keys() {
            allowed_scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.options.keys() {
            allowed_scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.env.keys() {
            allowed_scope_keys.insert(scope_key.clone());
        }
        for (scope_idx, scope) in all_scopes.iter().enumerate() {
            if scope.key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scopes[{scope_idx}].key is required"
                )));
            }
            if scope.from.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scopes[{scope_idx}].from is required"
                )));
            }
            if scope.transform.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scopes[{scope_idx}].transform is required"
                )));
            }
            if scope.examples.iter().any(|value| value.trim().is_empty()) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scopes[{scope_idx}].examples contains an empty example"
                )));
            }
            allowed_scope_keys.insert(scope.key.clone());
        }
        for scope_key in command.scope_examples.keys() {
            if !allowed_scope_keys.contains(scope_key) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_examples.{scope_key} does not match any known scope key"
                )));
            }
        }
        for scope_key in command.scope_defaults.keys() {
            if !allowed_scope_keys.contains(scope_key) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_defaults.{scope_key} does not match any known scope key"
                )));
            }
        }
        for (scope_key, desc) in &command.scope_descriptions {
            if scope_key.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_descriptions contains an empty key"
                )));
            }
            if desc.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_descriptions.{scope_key} is empty"
                )));
            }
            if !allowed_scope_keys.contains(scope_key) {
                return Err(ManifestError::Invalid(format!(
                    "commands[{idx}].scope_descriptions.{scope_key} does not match any known scope key"
                )));
            }
        }
    }

    if manifest
        .tool_policy
        .strip_env
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(ManifestError::Invalid(
            "tool_policy.strip_env contains an empty env name/pattern".to_string(),
        ));
    }
    if manifest
        .tool_policy
        .paths
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(ManifestError::Invalid(
            "tool_policy.paths contains an empty path glob".to_string(),
        ));
    }
    if manifest
        .tool_policy
        .deny_flags
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(ManifestError::Invalid(
            "tool_policy.deny_flags contains an empty flag".to_string(),
        ));
    }

    if manifest.tool_policy.package_policy == ManifestPackagePolicy::Denylist {
        if manifest.tool_policy.package_ecosystem.is_none() {
            return Err(ManifestError::Invalid(
                "tool_policy.package_ecosystem is required when package_policy = \"denylist\""
                    .to_string(),
            ));
        }
        if manifest.tool_policy.package_scope.is_none() {
            return Err(ManifestError::Invalid(
                "tool_policy.package_scope is required when package_policy = \"denylist\""
                    .to_string(),
            ));
        }
    }

    if let Some(ref eco) = manifest.tool_policy.package_ecosystem
        && crate::package_denylist::normalize_ecosystem(eco).is_none()
    {
        return Err(ManifestError::Invalid(format!(
            "tool_policy.package_ecosystem '{}' is not a recognised ecosystem \
             (expected: npm, pypi, cargo, go, or a known alias like uv, pnpm, yarn, poetry, etc.)",
            eco
        )));
    }

    let mut seen_claims =
        BTreeSet::<(String, Vec<String>, Vec<String>, Vec<String>, Vec<String>)>::new();
    for command in &manifest.commands {
        let mut any_flags = command.when_any_flags.clone();
        any_flags.sort();
        let mut all_flags = command.when_all_flags.clone();
        all_flags.sort();
        let mut no_flags = command.when_no_flags.clone();
        no_flags.sort();
        let claim = (
            manifest.manifest.tool.clone(),
            command.match_tokens.clone(),
            any_flags,
            all_flags,
            no_flags,
        );
        if !seen_claims.insert(claim) {
            return Err(ManifestError::Invalid(format!(
                "duplicate command claim in manifest '{}': match={:?}, when_any_flags={:?}, when_all_flags={:?}, when_no_flags={:?}",
                manifest.manifest.id,
                command.match_tokens,
                command.when_any_flags,
                command.when_all_flags,
                command.when_no_flags
            )));
        }
    }

    Ok(())
}

fn default_true() -> bool {
    true
}

fn default_option_value_forms() -> Vec<String> {
    vec![
        "separate".to_string(),
        "equals".to_string(),
        "attached".to_string(),
    ]
}

pub(crate) fn normalize_tool_name(tool: &str) -> String {
    let no_version = tool.split('@').next().unwrap_or(tool);
    let base = no_version
        .rsplit('/')
        .next()
        .unwrap_or(no_version)
        .to_ascii_lowercase();

    match base.as_str() {
        "scp" | "sftp" => "ssh".to_string(),
        "pip3" => "pip".to_string(),
        "python3" => "python".to_string(),
        "nodejs" => "node".to_string(),
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{ManifestPackagePolicy, parse_manifest, resolve_manifest};

    fn test_manifest(tool: &str, capability: &str) -> String {
        format!(
            r#"[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/{tool}"
tool = "{tool}"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = []
capability = "{capability}"
"#
        )
    }

    fn with_test_cache<F: FnOnce()>(f: F) {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let xdg = TempDir::new().expect("temp xdg dir");
        let manifest_dir = xdg.path().join("wsh").join("manifests");
        std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");
        std::fs::write(
            manifest_dir.join("git.toml"),
            test_manifest("git", "git.any"),
        )
        .expect("write git");
        std::fs::write(
            manifest_dir.join("ssh.toml"),
            test_manifest("ssh", "ssh.any"),
        )
        .expect("write ssh");
        std::fs::write(
            manifest_dir.join("pip.toml"),
            test_manifest("pip", "pip.any"),
        )
        .expect("write pip");
        std::fs::write(
            manifest_dir.join("no-interpreters.toml"),
            test_manifest("no-interpreters", "no-interpreters.any"),
        )
        .expect("write no-interpreters");
        std::fs::write(
            manifest_dir.join("python.toml"),
            test_manifest("python", "python.any"),
        )
        .expect("write python");
        std::fs::write(
            manifest_dir.join("node.toml"),
            test_manifest("node", "node.any"),
        )
        .expect("write node");

        let original = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", xdg.path()) };
        f();
        if let Some(value) = original {
            unsafe { std::env::set_var("XDG_CONFIG_HOME", value) };
        } else {
            unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        }
    }

    #[test]
    fn resolves_namespaced_name() {
        with_test_cache(|| {
            let manifest = resolve_manifest("warrant-sh/git").expect("must resolve manifest");
            assert_eq!(manifest.manifest.tool, "git");
        });
    }

    #[test]
    fn resolves_tool_aliases() {
        with_test_cache(|| {
            assert_eq!(
                resolve_manifest("scp")
                    .expect("must resolve scp alias")
                    .manifest
                    .tool,
                "ssh"
            );
            assert_eq!(
                resolve_manifest("sftp")
                    .expect("must resolve sftp alias")
                    .manifest
                    .tool,
                "ssh"
            );
            assert_eq!(
                resolve_manifest("pip3")
                    .expect("must resolve pip3 alias")
                    .manifest
                    .tool,
                "pip"
            );
            assert_eq!(
                resolve_manifest("python")
                    .expect("must resolve python manifest")
                    .manifest
                    .tool,
                "python"
            );
            assert_eq!(
                resolve_manifest("python3")
                    .expect("must resolve python3 alias")
                    .manifest
                    .tool,
                "python"
            );
            assert_eq!(
                resolve_manifest("node")
                    .expect("must resolve node manifest")
                    .manifest
                    .tool,
                "node"
            );
            assert_eq!(
                resolve_manifest("nodejs")
                    .expect("must resolve nodejs alias")
                    .manifest
                    .tool,
                "node"
            );
        });
    }

    #[test]
    fn parses_inline_single_scope_field() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["run"]
capability = "test.run"
scope = { key = "target", from = "arg", index = 1, transform = "literal" }
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(manifest.commands.len(), 1);
        assert!(manifest.commands[0].scope.is_some());
    }

    #[test]
    fn parses_args_shorthand() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "test.push"
args = { remote = 1, branch = 2 }
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.commands[0].args.get("remote"), Some(&1));
        assert_eq!(manifest.commands[0].args.get("branch"), Some(&2));
    }

    #[test]
    fn parses_flags_shorthand() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["messages", "list"]
capability = "test.messages.list"
flags = { account = "--account", folder = "--folder" }
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(
            manifest.commands[0].flags.get("account"),
            Some(&"--account".to_string())
        );
    }

    #[test]
    fn parses_options_with_aliases_and_forms() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["build"]
capability = "test.build"
options = { output = { names = ["-o", "--output"], forms = ["separate", "equals"] } }
"#;

        let manifest = parse_manifest(text).expect("parse");
        let option = manifest.commands[0].options.get("output").expect("output");
        assert_eq!(option.names, vec!["-o".to_string(), "--output".to_string()]);
        assert_eq!(
            option.forms,
            vec!["separate".to_string(), "equals".to_string()]
        );
    }

    #[test]
    fn parses_scope_examples() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "test.push"
args = { remote = 1, branch = 2 }
scope_examples = { remote = ["origin"], branch = ["main", "release/*"] }
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(
            manifest.commands[0].scope_examples.get("remote"),
            Some(&vec!["origin".to_string()])
        );
        assert_eq!(
            manifest.commands[0].scope_examples.get("branch"),
            Some(&vec!["main".to_string(), "release/*".to_string()])
        );
    }

    #[test]
    fn rejects_scope_examples_for_unknown_scope_key() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "test.push"
args = { remote = 1 }
scope_examples = { branch = ["main"] }
"#;

        let err = parse_manifest(text).expect_err("must reject unknown scope example key");
        assert!(
            err.to_string()
                .contains("scope_examples.branch does not match any known scope key")
        );
    }

    #[test]
    fn parses_extended_flag_and_env_controls() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
strip_env = ["RUSTC_WRAPPER"]
deny_flags = ["--dangerously-skip-permissions"]
deny_flags_description = "Block unsafe bypass flags"

[[commands]]
match = ["push"]
when_any_flags = ["--force"]
when_all_flags = ["--atomic", "--force"]
when_no_flags = ["--dry-run"]
respect_option_terminator = false
capability = "test.push"
env = { profile = "AWS_PROFILE" }
args = { remote = 1 }
"#;

        let manifest = parse_manifest(text).expect("parse");
        let command = &manifest.commands[0];
        assert_eq!(command.when_any_flags, vec!["--force".to_string()]);
        assert_eq!(
            command.when_all_flags,
            vec!["--atomic".to_string(), "--force".to_string()]
        );
        assert_eq!(command.when_no_flags, vec!["--dry-run".to_string()]);
        assert!(!command.respect_option_terminator);
        assert_eq!(command.env.get("profile"), Some(&"AWS_PROFILE".to_string()));
        assert_eq!(
            manifest.tool_policy.strip_env,
            vec!["RUSTC_WRAPPER".to_string()]
        );
        assert!(!manifest.tool_policy.allow_inline_execution);
        assert_eq!(
            manifest.tool_policy.deny_flags,
            vec!["--dangerously-skip-permissions".to_string()]
        );
        assert_eq!(
            manifest.tool_policy.deny_flags_description.as_deref(),
            Some("Block unsafe bypass flags")
        );
        assert_eq!(
            manifest.tool_policy.package_policy,
            ManifestPackagePolicy::Open
        );
    }

    #[test]
    fn parses_package_policy_modes() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "npm"
package_scope = "packages"

[[commands]]
match = []
capability = "test.exec"
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(
            manifest.tool_policy.package_policy,
            ManifestPackagePolicy::Denylist
        );
        assert!(!manifest.tool_policy.allow_inline_execution);
        assert!(manifest.tool_policy.deny_flags.is_empty());
        assert!(manifest.tool_policy.deny_flags_description.is_none());
    }

    #[test]
    fn parses_allow_inline_execution_flag() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "python"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
allow_inline_execution = true

[[commands]]
match = []
capability = "python.exec"
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert!(manifest.tool_policy.allow_inline_execution);
    }

    #[test]
    fn parses_package_ecosystem() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/bloop"
tool = "bloop"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "pypi"
package_scope = "deps"

[[commands]]
match = ["fire"]
capability = "bloop.fire"
"#;

        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(
            manifest.tool_policy.package_policy,
            ManifestPackagePolicy::Denylist
        );
        assert_eq!(
            manifest.tool_policy.package_ecosystem.as_deref(),
            Some("pypi")
        );
        assert_eq!(manifest.tool_policy.package_scope.as_deref(), Some("deps"));
    }

    #[test]
    fn rejects_denylist_without_package_scope() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "npm"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "npm"

[[commands]]
match = ["install"]
capability = "npm.install"
"#;

        let err = parse_manifest(text).unwrap_err();
        assert!(err.to_string().contains("package_scope is required"));
    }

    #[test]
    fn rejects_denylist_without_package_ecosystem() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "npm"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_scope = "packages"

[[commands]]
match = ["install"]
capability = "npm.install"
"#;

        let err = parse_manifest(text).unwrap_err();
        assert!(err.to_string().contains("package_ecosystem is required"));
    }

    #[test]
    fn rejects_unknown_package_ecosystem() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/bloop"
tool = "bloop"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "bloopgems"
package_scope = "packages"

[[commands]]
match = ["fire"]
capability = "bloop.fire"
"#;

        let err = parse_manifest(text).unwrap_err();
        assert!(
            err.to_string().contains("not a recognised ecosystem"),
            "expected ecosystem validation error, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_tool_policy_deny_flag() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["--yolo", ""]

[[commands]]
match = []
capability = "test.exec"
"#;

        let err = parse_manifest(text).expect_err("must reject empty deny flag");
        assert!(
            err.to_string()
                .contains("tool_policy.deny_flags contains an empty flag")
        );
    }

    #[test]
    fn rejects_invalid_flag_selector_syntax() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
when_all_flags = ["force"]
capability = "test.push"
"#;

        let err = parse_manifest(text).expect_err("must reject invalid flag selector");
        assert!(err.to_string().contains("must start with '-'"));
    }

    #[test]
    fn rejects_invalid_option_form() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["build"]
capability = "test.build"
options = { output = { names = ["--output"], forms = ["weird"] } }
"#;

        let err = parse_manifest(text).expect_err("must reject invalid option form");
        assert!(err.to_string().contains("unsupported form"));
    }

    #[test]
    fn parses_scope_defaults() {
        let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool = "test"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = []
capability = "policy.test"
scope = { key = "paths", from = "arg_rest", transform = "glob" }
scope_defaults = { paths = ["/usr/bin/**", "/bin/**"] }
"#;
        let manifest = parse_manifest(text).expect("parse");
        assert_eq!(
            manifest.commands[0].scope_defaults.get("paths"),
            Some(&vec!["/usr/bin/**".to_string(), "/bin/**".to_string()])
        );
    }

    #[test]
    fn registry_manifests_include_r8_network_deny_flags() {
        let parse = |text: &str| -> super::Manifest {
            parse_manifest(text).unwrap_or_else(|err| panic!("failed to parse manifest fixture: {err}"))
        };

        let curl = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/curl"
tool = "curl"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["-K", "--config", "--connect-to", "--resolve", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--preproxy", "--proxy", "--unix-socket", "--abstract-unix-socket", "--dns-servers", "--doh-url", "--dns-interface", "--netrc", "--netrc-optional", "--netrc-file"]

[[commands]]
match = ["curl"]
capability = "network.fetch"
"#,
        );
        for flag in [
            "-K",
            "--config",
            "--connect-to",
            "--resolve",
            "--socks4",
            "--socks4a",
            "--socks5",
            "--socks5-hostname",
            "--preproxy",
            "--proxy",
            "--unix-socket",
            "--abstract-unix-socket",
            "--dns-servers",
            "--doh-url",
            "--dns-interface",
            "--netrc",
            "--netrc-optional",
            "--netrc-file",
        ] {
            assert!(
                curl.tool_policy.deny_flags.iter().any(|v| v == flag),
                "curl deny_flags missing {flag}"
            );
        }

        let ssh = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/ssh"
tool = "ssh"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["-o", "-F", "-J", "-W", "-S"]

[[commands]]
match = ["ssh"]
capability = "network.remote"
"#,
        );
        for flag in ["-o", "-F", "-J", "-W", "-S"] {
            assert!(
                ssh.tool_policy.deny_flags.iter().any(|v| v == flag),
                "ssh deny_flags missing {flag}"
            );
        }

        let git = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/git"
tool = "git"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["-c", "-f", "--file"]

[[commands]]
match = ["git", "clone"]
capability = "repo.clone"
"#,
        );
        for flag in ["-c", "-f", "--file"] {
            assert!(
                git.tool_policy.deny_flags.iter().any(|v| v == flag),
                "git deny_flags missing {flag}"
            );
        }

        let wget = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/wget"
tool = "wget"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["-e", "--execute", "--config", "--post-file", "--post-data", "--body-file", "--body-data", "--header", "--load-cookies"]
strip_env = ["WGETRC", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ftp_proxy", "FTP_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY"]

[[commands]]
match = ["wget"]
capability = "network.upload"
when_any_flags = ["--post-data", "--post-file", "--body-data", "--body-file"]
"#,
        );
        for flag in [
            "-e",
            "--execute",
            "--config",
            "--post-file",
            "--post-data",
            "--body-file",
            "--body-data",
            "--header",
            "--load-cookies",
        ] {
            assert!(
                wget.tool_policy.deny_flags.iter().any(|v| v == flag),
                "wget deny_flags missing {flag}"
            );
        }
        for env_name in [
            "WGETRC",
            "http_proxy",
            "HTTP_PROXY",
            "https_proxy",
            "HTTPS_PROXY",
            "ftp_proxy",
            "FTP_PROXY",
            "no_proxy",
            "NO_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            assert!(
                wget.tool_policy.strip_env.iter().any(|v| v == env_name),
                "wget strip_env missing {env_name}"
            );
        }
        assert!(
            wget.commands.iter().any(|command| {
                command.capability == "network.upload"
                    && command
                        .when_any_flags
                        .iter()
                        .any(|flag| flag == "--post-data")
                    && command
                        .when_any_flags
                        .iter()
                        .any(|flag| flag == "--post-file")
                    && command
                        .when_any_flags
                        .iter()
                        .any(|flag| flag == "--body-data")
                    && command
                        .when_any_flags
                        .iter()
                        .any(|flag| flag == "--body-file")
            }),
            "wget manifest missing network.upload rule for post/body flags"
        );
    }

    #[test]
    fn registry_manifests_include_r16_policy_updates() {
        let parse = |text: &str| -> super::Manifest {
            parse_manifest(text).unwrap_or_else(|err| panic!("failed to parse manifest fixture: {err}"))
        };

        let python = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/python"
tool = "python"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "pypi"
package_scope = "packages"
strip_env = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "PIP_CONFIG_FILE"]

[[commands]]
match = ["python3", "-m", "pip", "install"]
capability = "package.install"
scope = { key = "packages", from = "arg_rest", transform = "literal" }
"#,
        );
        assert_eq!(
            python.tool_policy.package_policy,
            super::ManifestPackagePolicy::Denylist
        );
        assert_eq!(
            python.tool_policy.package_ecosystem.as_deref(),
            Some("pypi")
        );
        assert_eq!(
            python.tool_policy.package_scope.as_deref(),
            Some("packages")
        );
        for env_name in [
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "PIP_TRUSTED_HOST",
            "PIP_CONFIG_FILE",
        ] {
            assert!(
                python.tool_policy.strip_env.iter().any(|v| v == env_name),
                "python strip_env missing {env_name}"
            );
        }
        assert!(python.commands.iter().any(|command| {
            command.match_tokens == ["python3", "-m", "pip", "install"]
                && command
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.key == "packages")
        }));

        let git = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/git"
tool = "git"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["pull"]
capability = "repo.sync"

[[commands]]
match = ["submodule", "add"]
capability = "repo.write"
scope = { key = "repo", from = "arg", index = 1, transform = "literal" }

[[commands]]
match = ["config"]
capability = "config.write"
when_any_flags = ["--global"]

[[commands]]
match = ["config"]
capability = "config.write"
when_any_flags = ["--system"]
"#,
        );
        assert!(
            git.commands
                .iter()
                .any(|command| command.match_tokens == ["pull"])
        );
        assert!(git.commands.iter().any(|command| {
            command.match_tokens == ["submodule", "add"]
                && command
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.key == "repo")
        }));
        assert!(git.commands.iter().any(|command| {
            command.match_tokens == ["config"]
                && command.when_any_flags.contains(&"--global".into())
        }));
        assert!(git.commands.iter().any(|command| {
            command.match_tokens == ["config"]
                && command.when_any_flags.contains(&"--system".into())
        }));

        let ruby = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/ruby"
tool = "ruby"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "rubygems"
package_scope = "packages"

[[commands]]
match = ["gem", "install"]
capability = "package.install"
scope = { key = "packages", from = "arg_rest", transform = "literal" }
"#,
        );
        assert_eq!(
            ruby.tool_policy.package_policy,
            super::ManifestPackagePolicy::Denylist
        );
        assert_eq!(
            ruby.tool_policy.package_ecosystem.as_deref(),
            Some("rubygems")
        );
        assert_eq!(ruby.tool_policy.package_scope.as_deref(), Some("packages"));
        assert!(ruby.commands.iter().any(|command| {
            command.match_tokens == ["gem", "install"]
                && command
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.key == "packages")
        }));

        let node = parse(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/node"
tool = "node"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "npm"
package_scope = "packages"

[[commands]]
match = ["npm", "install"]
capability = "package.install"
scope = { key = "packages", from = "arg_rest", transform = "literal" }
"#,
        );
        assert_eq!(
            node.tool_policy.package_policy,
            super::ManifestPackagePolicy::Denylist
        );
        assert_eq!(node.tool_policy.package_ecosystem.as_deref(), Some("npm"));
        assert_eq!(node.tool_policy.package_scope.as_deref(), Some("packages"));
    }
}
