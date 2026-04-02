use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, ManifestCommand, ManifestDefaultDecision, manifest_hash};

const DRAFT_SCHEMA_V1: &str = "warrant.draft.v1";

#[derive(Debug, Clone)]
pub struct Draft {
    pub draft: DraftMeta,
    pub capabilities: BTreeMap<String, DraftCapability>,
    pub metadata: DraftMetadata,
    pub capability_meta: BTreeMap<String, CapabilityMeta>,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityMeta {
    pub label: String,
    pub description: Option<String>,
    pub risk: Option<String>,
    pub command_example: Option<String>,
    pub scope_descriptions: BTreeMap<String, String>,
    pub scope_examples: BTreeMap<String, Vec<String>>,
    pub scope_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DraftMeta {
    pub schema: String,
    pub manifest: String,
    pub manifest_hash: String,
    pub tool: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct DraftCapability {
    pub decision: DraftDecision,
    pub scopes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DraftDecision {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DraftMetadata {
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug)]
pub enum DraftError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
    Invalid(String),
}

impl std::fmt::Display for DraftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DraftError::Io(err) => write!(f, "{err}"),
            DraftError::ParseToml(err) => write!(f, "{err}"),
            DraftError::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for DraftError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for DraftError {
    fn from(value: toml::de::Error) -> Self {
        Self::ParseToml(value)
    }
}

pub fn build_capability_meta(manifest: &Manifest) -> BTreeMap<String, CapabilityMeta> {
    let mut out = BTreeMap::<String, CapabilityMeta>::new();

    for command in &manifest.commands {
        let meta = out.entry(command.capability.clone()).or_default();

        if meta.label.is_empty() {
            meta.label = command
                .label
                .clone()
                .unwrap_or_else(|| derive_label(&command.capability));
        }
        if meta.description.is_none() {
            meta.description = command.description.clone();
        }
        if meta.risk.is_none() {
            meta.risk = command.risk.clone();
        }
        if meta.command_example.is_none() {
            meta.command_example = format_command_example(&manifest.manifest.tool, command);
        }

        for (scope_key, desc) in &command.scope_descriptions {
            meta.scope_descriptions
                .entry(scope_key.clone())
                .or_insert_with(|| desc.clone());
        }

        // Collect scope examples
        for (scope_key, examples) in &command.scope_examples {
            let values = meta.scope_examples.entry(scope_key.clone()).or_default();
            for value in examples {
                let trimmed = value.trim();
                if !trimmed.is_empty() && !values.contains(&trimmed.to_string()) {
                    values.push(trimmed.to_string());
                }
            }
        }
        if let Some(scope) = &command.scope
            && !scope.examples.is_empty()
        {
            let values = meta.scope_examples.entry(scope.key.clone()).or_default();
            for value in &scope.examples {
                let trimmed = value.trim();
                if !trimmed.is_empty() && !values.contains(&trimmed.to_string()) {
                    values.push(trimmed.to_string());
                }
            }
        }
        for scope in &command.scopes {
            if !scope.examples.is_empty() {
                let values = meta.scope_examples.entry(scope.key.clone()).or_default();
                for value in &scope.examples {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() && !values.contains(&trimmed.to_string()) {
                        values.push(trimmed.to_string());
                    }
                }
            }
        }

        // Collect scope keys
        let mut keys = BTreeSet::<String>::new();
        for scope_key in command.args.keys() {
            keys.insert(scope_key.clone());
        }
        for scope_key in command.flags.keys() {
            keys.insert(scope_key.clone());
        }
        for scope_key in command.options.keys() {
            keys.insert(scope_key.clone());
        }
        for scope_key in command.env.keys() {
            keys.insert(scope_key.clone());
        }
        if let Some(scope) = &command.scope {
            keys.insert(scope.key.clone());
        }
        for scope in &command.scopes {
            keys.insert(scope.key.clone());
        }
        for key in keys {
            if !meta.scope_keys.contains(&key) {
                meta.scope_keys.push(key);
            }
        }
    }

    out
}

pub fn generate_draft_from_manifest(manifest: &Manifest) -> Draft {
    let mut capabilities = BTreeMap::new();

    for command in &manifest.commands {
        let mut decision = match command.default.unwrap_or(ManifestDefaultDecision::Review) {
            ManifestDefaultDecision::Allow => DraftDecision::Allow,
            ManifestDefaultDecision::Deny => DraftDecision::Deny,
            ManifestDefaultDecision::Review => DraftDecision::Review,
        };
        if command.capability.starts_with("interpreter.") && decision == DraftDecision::Allow {
            decision = DraftDecision::Deny;
        }
        capabilities
            .entry(command.capability.clone())
            .or_insert_with(|| DraftCapability {
                decision,
                scopes: BTreeMap::new(),
            });
        if !command.scope_defaults.is_empty()
            && let Some(capability_entry) = capabilities.get_mut(&command.capability)
        {
            for (scope_key, defaults) in &command.scope_defaults {
                if defaults.is_empty() {
                    continue;
                }
                let values = capability_entry
                    .scopes
                    .entry(scope_key.clone())
                    .or_default();
                for value in defaults {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() && !values.iter().any(|existing| existing == trimmed) {
                        values.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    let capability_meta = build_capability_meta(manifest);

    Draft {
        draft: DraftMeta {
            schema: DRAFT_SCHEMA_V1.to_string(),
            manifest: format!(
                "{}@{}",
                manifest.manifest.id, manifest.manifest.manifest_version
            ),
            manifest_hash: manifest_hash(manifest).unwrap_or_default(),
            tool: manifest.manifest.tool.clone(),
            state: "editable".to_string(),
        },
        capabilities,
        metadata: DraftMetadata {
            created_by: format!("{}@{}", username(), hostname()),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        },
        capability_meta,
    }
}

pub fn validate_draft(draft: &Draft, manifest: &Manifest) -> Result<(), DraftError> {
    if draft.draft.schema != DRAFT_SCHEMA_V1 {
        return Err(DraftError::Invalid(format!(
            "unsupported draft schema: {}",
            draft.draft.schema
        )));
    }

    if draft.draft.tool != manifest.manifest.tool {
        return Err(DraftError::Invalid(format!(
            "draft tool '{}' does not match manifest tool '{}'",
            draft.draft.tool, manifest.manifest.tool
        )));
    }

    let mut capability_scope_keys = BTreeMap::<String, BTreeSet<String>>::new();
    let mut known_capabilities = BTreeSet::<String>::new();

    for command in &manifest.commands {
        known_capabilities.insert(command.capability.clone());
        let scope_keys = capability_scope_keys
            .entry(command.capability.clone())
            .or_default();
        for scope_key in command.args.keys() {
            scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.flags.keys() {
            scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.options.keys() {
            scope_keys.insert(scope_key.clone());
        }
        for scope_key in command.env.keys() {
            scope_keys.insert(scope_key.clone());
        }
        if let Some(scope) = &command.scope {
            scope_keys.insert(scope.key.clone());
        }
        for scope in &command.scopes {
            scope_keys.insert(scope.key.clone());
        }
    }

    for (capability, draft_capability) in &draft.capabilities {
        if !known_capabilities.contains(capability) {
            return Err(DraftError::Invalid(format!(
                "unknown capability '{capability}' for tool '{}'",
                manifest.manifest.tool
            )));
        }

        let allowed_scope_keys = capability_scope_keys
            .get(capability)
            .cloned()
            .unwrap_or_default();

        for scope_key in draft_capability.scopes.keys() {
            if !allowed_scope_keys.contains(scope_key) {
                return Err(DraftError::Invalid(format!(
                    "unknown scope key '{}' for capability '{}'",
                    scope_key, capability
                )));
            }
        }
    }

    Ok(())
}

pub fn parse_draft(toml_text: &str) -> Result<Draft, DraftError> {
    let root = toml::from_str::<toml::Value>(toml_text)?;
    let root_table = root
        .as_table()
        .ok_or_else(|| DraftError::Invalid("draft must be a TOML table".to_string()))?;

    let draft_table = root_table
        .get("draft")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| DraftError::Invalid("draft section is required".to_string()))?;
    let draft = DraftMeta {
        schema: table_str(draft_table, "schema", "draft")?,
        manifest: table_str(draft_table, "manifest", "draft")?,
        manifest_hash: draft_table
            .get("manifest_hash")
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        tool: table_str(draft_table, "tool", "draft")?,
        state: table_str(draft_table, "state", "draft")?,
    };

    let mut capabilities = BTreeMap::<String, DraftCapability>::new();
    let capabilities_table = root_table
        .get("capabilities")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| DraftError::Invalid("capabilities section is required".to_string()))?;
    parse_capabilities_table("", capabilities_table, &mut capabilities)?;

    let metadata =
        if let Some(metadata_table) = root_table.get("metadata").and_then(toml::Value::as_table) {
            DraftMetadata {
                created_by: metadata_table
                    .get("created_by")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                created_at: metadata_table
                    .get("created_at")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }
        } else {
            DraftMetadata::default()
        };

    let draft = Draft {
        draft,
        capabilities,
        metadata,
        capability_meta: BTreeMap::new(),
    };

    if draft.draft.schema.trim().is_empty() {
        return Err(DraftError::Invalid("draft.schema is required".to_string()));
    }
    if draft.draft.manifest.trim().is_empty() {
        return Err(DraftError::Invalid(
            "draft.manifest is required".to_string(),
        ));
    }
    if draft.draft.tool.trim().is_empty() {
        return Err(DraftError::Invalid("draft.tool is required".to_string()));
    }
    Ok(draft)
}

pub fn read_draft(path: &Path) -> Result<Draft, DraftError> {
    let text = std::fs::read_to_string(path)?;
    parse_draft(&text)
}

pub fn write_draft(path: &Path, draft: &Draft, compact: bool) -> Result<(), DraftError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = render_draft(draft, compact);
    std::fs::write(path, format!("{text}\n"))?;
    Ok(())
}

pub fn render_draft(draft: &Draft, compact: bool) -> String {
    let mut out = String::new();
    out.push_str("[draft]\n");
    out.push_str(&format!("schema = {}\n", toml_string(&draft.draft.schema)));
    out.push_str(&format!(
        "manifest = {}\n",
        toml_string(&draft.draft.manifest)
    ));
    if !draft.draft.manifest_hash.trim().is_empty() {
        out.push_str(&format!(
            "manifest_hash = {}\n",
            toml_string(&draft.draft.manifest_hash)
        ));
    }
    out.push_str(&format!("tool = {}\n", toml_string(&draft.draft.tool)));
    out.push_str(&format!("state = {}\n", toml_string(&draft.draft.state)));
    out.push('\n');

    out.push_str("[capabilities]\n");
    for (idx, (capability, entry)) in draft.capabilities.iter().enumerate() {
        if idx > 0 && !compact {
            out.push('\n');
        }

        if !compact && let Some(meta) = draft.capability_meta.get(capability) {
            render_capability_comment(&mut out, meta);
        }

        if entry.scopes.is_empty() {
            out.push_str(&format!(
                "{} = {}\n",
                capability,
                toml_string(decision_text(entry.decision))
            ));
            continue;
        }

        let mut fields = Vec::<String>::new();
        match entry.decision {
            DraftDecision::Allow => fields.push("allow = true".to_string()),
            DraftDecision::Deny => fields.push("allow = false".to_string()),
            DraftDecision::Review => fields.push(format!(
                "decision = {}",
                toml_string(decision_text(entry.decision))
            )),
        }
        let scope_pairs = entry
            .scopes
            .iter()
            .map(|(scope_key, values)| {
                format!(
                    "{} = {}",
                    scope_key,
                    toml_array(values.iter().map(|v| v.as_str()))
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        fields.push(format!("where = {{ {scope_pairs} }}"));
        out.push_str(&format!("{} = {{ {} }}\n", capability, fields.join(", ")));
    }
    out.push('\n');

    out.push_str("[metadata]\n");
    out.push_str(&format!(
        "created_by = {}\n",
        toml_string(&draft.metadata.created_by)
    ));
    out.push_str(&format!(
        "created_at = {}\n",
        toml_string(&draft.metadata.created_at)
    ));
    out
}

fn render_capability_comment(out: &mut String, meta: &CapabilityMeta) {
    // Header: # ── Label (risk risk) ──────────────────
    let risk_part = meta
        .risk
        .as_deref()
        .map(|r| format!(" ({r} risk)"))
        .unwrap_or_default();
    let header = format!("{}{}", meta.label, risk_part);
    let rule_len = 50usize.saturating_sub(header.len() + 5);
    let rule = "\u{2500}".repeat(rule_len);
    out.push_str(&format!("# \u{2500}\u{2500} {header} {rule}\n"));

    if let Some(desc) = &meta.description {
        out.push_str(&format!("# {desc}\n"));
    }

    if let Some(example) = &meta.command_example {
        out.push_str(&format!("# Example: {example}\n"));
    }

    if !meta.scope_keys.is_empty() {
        out.push_str("# Scopes:\n");
        for key in &meta.scope_keys {
            let desc_part = meta
                .scope_descriptions
                .get(key)
                .map(|d| format!(" - {d}"))
                .unwrap_or_default();
            let examples_part = meta
                .scope_examples
                .get(key)
                .filter(|e| !e.is_empty())
                .map(|e| format!(" (e.g. {})", e.join(", ")))
                .unwrap_or_default();
            out.push_str(&format!("#   {key}{desc_part}{examples_part}\n"));
        }
    }
}

fn derive_label(capability: &str) -> String {
    let base = capability.rsplit('.').next().unwrap_or(capability);
    base.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let mut s = c.to_uppercase().to_string();
                    s.extend(chars);
                    s
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_command_example(tool: &str, command: &ManifestCommand) -> Option<String> {
    let mut examples = BTreeMap::<String, String>::new();
    for (scope_key, values) in &command.scope_examples {
        if let Some(first) = values.first()
            && !first.trim().is_empty()
        {
            examples.insert(scope_key.clone(), first.clone());
        }
    }
    if let Some(scope) = &command.scope
        && let Some(first) = scope.examples.first()
        && !first.trim().is_empty()
    {
        examples
            .entry(scope.key.clone())
            .or_insert_with(|| first.clone());
    }
    for scope in &command.scopes {
        if let Some(first) = scope.examples.first()
            && !first.trim().is_empty()
        {
            examples
                .entry(scope.key.clone())
                .or_insert_with(|| first.clone());
        }
    }

    let mut args = command.match_tokens.clone();
    for (scope_key, index) in &command.args {
        while args.len() <= *index {
            args.push(format!("<arg{}>", args.len()));
        }
        let value = examples
            .get(scope_key)
            .cloned()
            .unwrap_or_else(|| format!("<{scope_key}>"));
        args[*index] = value;
    }
    if let Some(scope) = &command.scope
        && scope.from == "arg"
    {
        let index = scope.index.unwrap_or(1);
        while args.len() <= index {
            args.push(format!("<arg{}>", args.len()));
        }
        let value = examples
            .get(&scope.key)
            .cloned()
            .unwrap_or_else(|| format!("<{}>", scope.key));
        args[index] = value;
    }
    for scope in &command.scopes {
        if scope.from == "arg" {
            let index = scope.index.unwrap_or(1);
            while args.len() <= index {
                args.push(format!("<arg{}>", args.len()));
            }
            let value = examples
                .get(&scope.key)
                .cloned()
                .unwrap_or_else(|| format!("<{}>", scope.key));
            args[index] = value;
        }
    }
    for (scope_key, flag_name) in &command.flags {
        let value = examples
            .get(scope_key)
            .cloned()
            .unwrap_or_else(|| format!("<{scope_key}>"));
        args.push(flag_name.clone());
        args.push(value);
    }
    for (scope_key, option) in &command.options {
        let value = examples
            .get(scope_key)
            .cloned()
            .unwrap_or_else(|| format!("<{scope_key}>"));
        if let Some(option_name) = option.names.first() {
            if option.forms.iter().any(|form| form == "equals") {
                args.push(format!("{option_name}={value}"));
            } else if option.forms.iter().any(|form| form == "attached")
                && option_name.starts_with('-')
                && !option_name.starts_with("--")
                && option_name.len() == 2
            {
                args.push(format!("{option_name}{value}"));
            } else {
                args.push(option_name.clone());
                args.push(value);
            }
        }
    }
    if !command.when_any_flags.is_empty() {
        args.push(command.when_any_flags[0].clone());
    }
    if !command.when_all_flags.is_empty() {
        for flag in &command.when_all_flags {
            if !args.iter().any(|existing| existing == flag) {
                args.push(flag.clone());
            }
        }
    }

    let mut out = Vec::with_capacity(1 + args.len());
    out.push(tool.to_string());
    out.extend(args);
    Some(out.join(" "))
}

fn table_str(table: &toml::Table, key: &str, section: &str) -> Result<String, DraftError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| DraftError::Invalid(format!("{section}.{key} is required")))
}

fn parse_decision(raw: &str, capability: &str) -> Result<DraftDecision, DraftError> {
    match raw {
        "allow" => Ok(DraftDecision::Allow),
        "deny" => Ok(DraftDecision::Deny),
        "review" => Ok(DraftDecision::Review),
        _ => Err(DraftError::Invalid(format!(
            "invalid decision '{}' for capability '{}'",
            raw, capability
        ))),
    }
}

fn parse_capabilities_table(
    prefix: &str,
    table: &toml::Table,
    out: &mut BTreeMap<String, DraftCapability>,
) -> Result<(), DraftError> {
    for (key, value) in table {
        let capability = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::String(raw) => {
                out.insert(
                    capability.clone(),
                    DraftCapability {
                        decision: parse_decision(raw, &capability)?,
                        scopes: BTreeMap::new(),
                    },
                );
            }
            toml::Value::Table(inner) => {
                if inner.contains_key("decision") || inner.contains_key("allow") {
                    let decision = if let Some(raw) = inner.get("decision") {
                        raw.as_str()
                            .ok_or_else(|| {
                                DraftError::Invalid(format!(
                                    "capabilities.{capability}.decision must be a string"
                                ))
                            })
                            .and_then(|value| parse_decision(value, &capability))?
                    } else {
                        match inner.get("allow").and_then(toml::Value::as_bool) {
                            Some(true) => DraftDecision::Allow,
                            Some(false) => DraftDecision::Deny,
                            None => {
                                return Err(DraftError::Invalid(format!(
                                    "capabilities.{capability}.allow must be a bool"
                                )));
                            }
                        }
                    };
                    let scope_key = if inner.contains_key("where") {
                        "where"
                    } else {
                        "scope"
                    };
                    let scopes = match inner.get(scope_key) {
                        None => BTreeMap::new(),
                        Some(value) => {
                            let scope_table = value.as_table().ok_or_else(|| {
                                DraftError::Invalid(format!(
                                    "capabilities.{capability}.{scope_key} must be a table"
                                ))
                            })?;
                            let mut scopes = BTreeMap::<String, Vec<String>>::new();
                            for (scope_key, scope_values) in scope_table {
                                scopes.insert(
                                    scope_key.clone(),
                                    parse_scope_values(scope_values, &capability, scope_key)?,
                                );
                            }
                            scopes
                        }
                    };
                    out.insert(capability, DraftCapability { decision, scopes });
                } else {
                    parse_capabilities_table(&capability, inner, out)?;
                }
            }
            _ => {
                return Err(DraftError::Invalid(format!(
                    "capabilities.{capability} must be a decision string or decision object"
                )));
            }
        }
    }
    Ok(())
}

fn parse_scope_values(
    value: &toml::Value,
    capability: &str,
    scope_key: &str,
) -> Result<Vec<String>, DraftError> {
    value
        .as_array()
        .ok_or_else(|| {
            DraftError::Invalid(format!(
                "capabilities.{capability}.scope.{scope_key} must be an array of strings"
            ))
        })?
        .iter()
        .map(|v| {
            v.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                DraftError::Invalid(format!(
                    "capabilities.{capability}.scope.{scope_key} entries must be strings"
                ))
            })
        })
        .collect()
}

fn decision_text(decision: DraftDecision) -> &'static str {
    match decision {
        DraftDecision::Allow => "allow",
        DraftDecision::Deny => "deny",
        DraftDecision::Review => "review",
    }
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn toml_array<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let items = values
        .map(|v| toml::Value::String(v.to_string()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

fn username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        DraftDecision, derive_label, generate_draft_from_manifest, parse_draft, render_draft,
        validate_draft,
    };
    use crate::manifest::{Manifest, parse_manifest};

    fn test_git_manifest() -> Manifest {
        parse_manifest(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "test/git"
tool = "git"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "git.push"
args = { remote = 1, branch = 2 }
default = "allow"

[[commands]]
match = ["reset"]
capability = "git.reset"
"#,
        )
        .expect("test manifest")
    }

    fn test_cargo_manifest() -> Manifest {
        parse_manifest(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "test/cargo"
tool = "cargo"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["build"]
capability = "cargo.build"

[[commands]]
match = ["test"]
capability = "cargo.test"
"#,
        )
        .expect("test manifest")
    }

    fn test_interpreter_manifest() -> Manifest {
        parse_manifest(
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "test/python"
tool = "python"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["python3"]
capability = "interpreter.python3"
default = "allow"
"#,
        )
        .expect("test interpreter manifest")
    }

    #[test]
    fn generates_review_entries() {
        let manifest = test_cargo_manifest();
        let draft = generate_draft_from_manifest(&manifest);

        assert!(
            draft
                .capabilities
                .values()
                .all(|capability| capability.decision == DraftDecision::Review)
        );
    }

    #[test]
    fn interpreter_capabilities_default_to_deny_even_if_manifest_allows() {
        let manifest = test_interpreter_manifest();
        let draft = generate_draft_from_manifest(&manifest);
        assert_eq!(
            draft
                .capabilities
                .get("interpreter.python3")
                .expect("interpreter capability")
                .decision,
            DraftDecision::Deny
        );
    }

    #[test]
    fn rejects_unknown_scope_keys() {
        let manifest = test_git_manifest();
        let mut draft = generate_draft_from_manifest(&manifest);

        let cap = draft
            .capabilities
            .get_mut("git.push")
            .expect("git.push exists");
        cap.scopes
            .insert("not_in_manifest".to_string(), vec!["x".to_string()]);

        let err = validate_draft(&draft, &manifest).expect_err("must reject invalid scope key");
        assert!(
            err.to_string()
                .contains("unknown scope key 'not_in_manifest'")
        );
    }

    #[test]
    fn parses_flat_capabilities_and_scopes_format() {
        let text = r#"[draft]
schema = "warrant.draft.v1"
manifest = "official/git@1.0.0"
tool = "git"
state = "editable"

[capabilities]
git.push = { decision = "allow", scope = { remote = ["origin"], branch = ["main"] } }
git.reset = "deny"
"#;

        let draft = parse_draft(text).expect("parse");
        assert_eq!(
            draft
                .capabilities
                .get("git.push")
                .expect("git.push")
                .decision,
            DraftDecision::Allow
        );
        assert_eq!(
            draft
                .capabilities
                .get("git.reset")
                .expect("git.reset")
                .decision,
            DraftDecision::Deny
        );
        assert_eq!(
            draft
                .capabilities
                .get("git.push")
                .expect("git.push")
                .scopes
                .get("remote")
                .expect("remote"),
            &vec!["origin".to_string()]
        );
    }

    #[test]
    fn parses_allow_where_format() {
        let text = r#"[draft]
schema = "warrant.draft.v1"
manifest = "official/git@1.0.0"
tool = "git"
state = "editable"

[capabilities]
git.push = { allow = true, where = { remote = ["origin"] } }
git.reset = { allow = false }
"#;

        let draft = parse_draft(text).expect("parse");
        assert_eq!(
            draft
                .capabilities
                .get("git.push")
                .expect("git.push")
                .decision,
            DraftDecision::Allow
        );
        assert_eq!(
            draft
                .capabilities
                .get("git.reset")
                .expect("git.reset")
                .decision,
            DraftDecision::Deny
        );
    }

    #[test]
    fn renders_verbose_with_metadata() {
        let manifest = test_git_manifest();
        let draft = generate_draft_from_manifest(&manifest);
        let text = render_draft(&draft, false);
        assert!(text.contains("[capabilities]"));
        assert!(text.contains("# Scopes:"));
        assert!(text.contains("git.push = \"allow\""));
    }

    #[test]
    fn renders_compact_without_comments() {
        let manifest = test_git_manifest();
        let draft = generate_draft_from_manifest(&manifest);
        let text = render_draft(&draft, true);
        assert!(text.contains("[capabilities]"));
        assert!(!text.contains("# "));
        assert!(text.contains("git.push = \"allow\""));
    }

    #[test]
    fn renders_scoped_capability_inline() {
        let mut draft = generate_draft_from_manifest(&test_git_manifest());
        let push = draft
            .capabilities
            .get_mut("git.push")
            .expect("git.push capability");
        push.scopes
            .insert("remote".to_string(), vec!["origin".to_string()]);
        let text = render_draft(&draft, false);
        assert!(text.contains("git.push = { allow = true, where = { remote = [\"origin\"] } }"));
    }

    #[test]
    fn derive_label_from_capability_name() {
        assert_eq!(derive_label("git.push"), "Push");
        assert_eq!(derive_label("git.push_force"), "Push Force");
        assert_eq!(derive_label("cargo.build"), "Build");
        assert_eq!(derive_label("network.request"), "Request");
        assert_eq!(derive_label("policy.commands_paths"), "Commands Paths");
    }

    #[test]
    fn roundtrip_preserves_decisions() {
        let manifest = test_git_manifest();
        let draft = generate_draft_from_manifest(&manifest);
        let text = render_draft(&draft, false);
        let parsed = parse_draft(&text).expect("parse rendered draft");
        for (capability, entry) in &draft.capabilities {
            let parsed_entry = parsed
                .capabilities
                .get(capability)
                .unwrap_or_else(|| panic!("missing {capability}"));
            assert_eq!(
                entry.decision, parsed_entry.decision,
                "decision mismatch for {capability}"
            );
        }
    }

    #[test]
    fn compact_roundtrip_preserves_decisions() {
        let manifest = test_cargo_manifest();
        let draft = generate_draft_from_manifest(&manifest);
        let compact = render_draft(&draft, true);
        let parsed = parse_draft(&compact).expect("parse compact draft");
        for (capability, entry) in &draft.capabilities {
            let parsed_entry = parsed
                .capabilities
                .get(capability)
                .unwrap_or_else(|| panic!("missing {capability}"));
            assert_eq!(
                entry.decision, parsed_entry.decision,
                "decision mismatch for {capability}"
            );
        }
    }
}
