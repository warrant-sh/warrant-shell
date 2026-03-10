use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::draft::{
    Draft, DraftCapability, DraftDecision, read_draft, validate_draft, write_draft,
};
use crate::manifest::{Manifest, manifest_hash, resolve_manifest};

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub capabilities: BTreeMap<String, toml::Value>,
    pub compiled_from: Vec<PathBuf>,
    pub manifests: Vec<String>,
}

#[derive(Debug, Clone)]
struct LoadedDraft {
    path: PathBuf,
    draft: Draft,
    manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestClaim {
    tool: String,
    match_tokens: Vec<String>,
    when_any_flags: BTreeSet<String>,
    when_all_flags: BTreeSet<String>,
    when_no_flags: BTreeSet<String>,
}

#[derive(Debug)]
pub enum CompileError {
    Io(std::io::Error),
    Draft(crate::draft::DraftError),
    Invalid(String),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Io(err) => write!(f, "{err}"),
            CompileError::Draft(err) => write!(f, "{err}"),
            CompileError::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for CompileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<crate::draft::DraftError> for CompileError {
    fn from(value: crate::draft::DraftError) -> Self {
        Self::Draft(value)
    }
}

#[derive(Debug, Clone)]
enum Grant {
    AllowAll,
    AllowScoped(BTreeMap<String, BTreeSet<String>>),
    Deny,
}

#[derive(Default)]
struct PolicyChannels {
    command_allow: BTreeSet<String>,
    command_paths: BTreeSet<String>,
    command_block: BTreeSet<String>,
    environment_strip: BTreeSet<String>,
}

pub fn compile_drafts(
    drafts_dir: &Path,
    selected_tool: Option<&str>,
) -> Result<CompiledPolicy, CompileError> {
    let mut files = std::fs::read_dir(drafts_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    files.sort();

    if files.is_empty() {
        return Err(CompileError::Invalid(format!(
            "no draft files found in {}",
            drafts_dir.display()
        )));
    }

    let selected = selected_tool.map(normalize_tool_name);
    let mut loaded = Vec::<LoadedDraft>::new();

    for path in files {
        let mut draft = read_draft(&path)?;
        if let Some(selected_tool) = selected.as_deref()
            && normalize_tool_name(&draft.draft.tool) != selected_tool
        {
            continue;
        }

        let manifest_lookup = if draft.draft.manifest.trim().is_empty() {
            draft.draft.tool.clone()
        } else {
            draft.draft.manifest.clone()
        };
        let manifest = resolve_manifest(&manifest_lookup)
            .or_else(|| resolve_manifest(&draft.draft.tool))
            .ok_or_else(|| {
                CompileError::Invalid(format!(
                    "manifest not found for draft '{}' (tool '{}')",
                    path.display(),
                    draft.draft.tool
                ))
            })?;
        maybe_migrate_draft_manifest_metadata(&path, &mut draft, &manifest)?;
        validate_draft(&draft, &manifest)?;
        loaded.push(LoadedDraft {
            path,
            draft,
            manifest,
        });
    }

    if loaded.is_empty() {
        return Err(CompileError::Invalid(match selected {
            Some(tool) => format!("no draft file found for tool '{tool}'"),
            None => "no matching draft files found".to_string(),
        }));
    }

    detect_overlapping_manifest_claims(&loaded)?;

    let mut merged = BTreeMap::<String, Grant>::new();
    let mut compiled_from = Vec::<PathBuf>::new();
    let mut manifests = BTreeSet::<String>::new();
    for loaded_draft in loaded {
        merge_draft_into(&mut merged, &loaded_draft.draft, &loaded_draft.path)?;
        manifests.insert(format!(
            "{}@{}",
            loaded_draft.manifest.manifest.id, loaded_draft.manifest.manifest.manifest_version
        ));
        compiled_from.push(loaded_draft.path);
    }

    let channels = extract_policy_channels(&mut merged)?;
    let mut capabilities = merged
        .into_iter()
        .map(|(capability, grant)| (capability, grant_to_toml(grant)))
        .collect::<BTreeMap<_, _>>();
    apply_policy_channels(&mut capabilities, channels);

    Ok(CompiledPolicy {
        capabilities,
        compiled_from,
        manifests: manifests.into_iter().collect(),
    })
}

fn extract_policy_channels(
    merged: &mut BTreeMap<String, Grant>,
) -> Result<PolicyChannels, CompileError> {
    let mut channels = PolicyChannels::default();

    if let Some(grant) = merged.remove("policy.commands_allow") {
        let scopes = expect_policy_scoped_grant("policy.commands_allow", grant)?;
        let values = scopes.get("programs").ok_or_else(|| {
            CompileError::Invalid(
                "policy.commands_allow must define scope key 'programs'".to_string(),
            )
        })?;
        channels.command_allow.extend(values.iter().cloned());
    }

    if let Some(grant) = merged.remove("policy.commands_paths") {
        let scopes = expect_policy_scoped_grant("policy.commands_paths", grant)?;
        let values = scopes.get("paths").ok_or_else(|| {
            CompileError::Invalid("policy.commands_paths must define scope key 'paths'".to_string())
        })?;
        channels.command_paths.extend(values.iter().cloned());
    }

    if let Some(grant) = merged.remove("policy.commands_block") {
        let scopes = expect_policy_scoped_grant("policy.commands_block", grant)?;
        let values = scopes.get("patterns").ok_or_else(|| {
            CompileError::Invalid(
                "policy.commands_block must define scope key 'patterns'".to_string(),
            )
        })?;
        channels.command_block.extend(values.iter().cloned());
    }

    if let Some(grant) = merged.remove("policy.environment_strip") {
        let scopes = expect_policy_scoped_grant("policy.environment_strip", grant)?;
        let values = scopes.get("strip").ok_or_else(|| {
            CompileError::Invalid(
                "policy.environment_strip must define scope key 'strip'".to_string(),
            )
        })?;
        channels.environment_strip.extend(values.iter().cloned());
    }

    Ok(channels)
}

fn expect_policy_scoped_grant(
    capability: &str,
    grant: Grant,
) -> Result<BTreeMap<String, BTreeSet<String>>, CompileError> {
    match grant {
        Grant::AllowScoped(scopes) => Ok(scopes),
        Grant::AllowAll => Err(CompileError::Invalid(format!(
            "{capability} must be scoped (provide values in draft scope)"
        ))),
        Grant::Deny => Ok(BTreeMap::new()),
    }
}

fn apply_policy_channels(
    capabilities: &mut BTreeMap<String, toml::Value>,
    channels: PolicyChannels,
) {
    if !channels.command_allow.is_empty() {
        let mut commands = capabilities
            .remove("commands")
            .and_then(|value| value.as_table().cloned())
            .unwrap_or_default();
        let mut allow = commands
            .remove("allow")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        for program in &channels.command_allow {
            let val = toml::Value::String(program.clone());
            if !allow.contains(&val) {
                allow.push(val);
            }
        }
        commands.insert("allow".to_string(), toml::Value::Array(allow));
        capabilities.insert("commands".to_string(), toml::Value::Table(commands));
    }

    if !channels.command_paths.is_empty() {
        let mut commands = capabilities
            .remove("commands")
            .and_then(|value| value.as_table().cloned())
            .unwrap_or_default();
        commands.insert(
            "paths".to_string(),
            toml::Value::Array(
                channels
                    .command_paths
                    .into_iter()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
        capabilities.insert("commands".to_string(), toml::Value::Table(commands));
    }

    if !channels.command_block.is_empty() {
        let mut commands = capabilities
            .remove("commands")
            .and_then(|value| value.as_table().cloned())
            .unwrap_or_default();
        commands.insert(
            "block".to_string(),
            toml::Value::Array(
                channels
                    .command_block
                    .into_iter()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
        capabilities.insert("commands".to_string(), toml::Value::Table(commands));
    }

    if !channels.environment_strip.is_empty() {
        let mut environment = capabilities
            .remove("environment")
            .and_then(|value| value.as_table().cloned())
            .unwrap_or_default();
        environment.insert(
            "strip".to_string(),
            toml::Value::Array(
                channels
                    .environment_strip
                    .into_iter()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
        capabilities.insert("environment".to_string(), toml::Value::Table(environment));
    }
}

fn maybe_migrate_draft_manifest_metadata(
    path: &Path,
    draft: &mut Draft,
    manifest: &Manifest,
) -> Result<(), CompileError> {
    let expected_manifest_ref = format!(
        "{}@{}",
        manifest.manifest.id, manifest.manifest.manifest_version
    );
    let expected_hash = manifest_hash(manifest)
        .map_err(|err| CompileError::Invalid(format!("failed to hash manifest: {err}")))?;

    let mut changed = false;
    if draft.draft.manifest != expected_manifest_ref {
        draft.draft.manifest = expected_manifest_ref;
        changed = true;
    }
    if draft.draft.manifest_hash != expected_hash {
        draft.draft.manifest_hash = expected_hash;
        changed = true;
    }
    if changed {
        draft.capability_meta = crate::draft::build_capability_meta(manifest);
        write_draft(path, draft, false)?;
        eprintln!("note: migrated draft metadata: {}", path.display());
    }

    Ok(())
}

fn detect_overlapping_manifest_claims(loaded: &[LoadedDraft]) -> Result<(), CompileError> {
    let mut claims = Vec::<(String, String, ManifestClaim)>::new();
    for loaded_draft in loaded {
        let manifest = &loaded_draft.manifest;
        for command in &manifest.commands {
            claims.push((
                manifest.manifest.id.clone(),
                manifest.manifest.manifest_version.clone(),
                ManifestClaim {
                    tool: manifest.manifest.tool.clone(),
                    match_tokens: command.match_tokens.clone(),
                    when_any_flags: command.when_any_flags.iter().cloned().collect(),
                    when_all_flags: command.when_all_flags.iter().cloned().collect(),
                    when_no_flags: command.when_no_flags.iter().cloned().collect(),
                },
            ));
        }
    }

    for i in 0..claims.len() {
        for j in (i + 1)..claims.len() {
            let (left_id, left_ver, left_claim) = &claims[i];
            let (right_id, right_ver, right_claim) = &claims[j];
            if left_id == right_id && left_ver == right_ver {
                continue;
            }
            if claims_overlap(left_claim, right_claim) {
                return Err(CompileError::Invalid(format!(
                    "overlapping manifest claims: {}@{} and {}@{} both control tool='{}' match={:?}",
                    left_id,
                    left_ver,
                    right_id,
                    right_ver,
                    left_claim.tool,
                    left_claim.match_tokens
                )));
            }
        }
    }
    Ok(())
}

fn claims_overlap(left: &ManifestClaim, right: &ManifestClaim) -> bool {
    if left.tool != right.tool || left.match_tokens != right.match_tokens {
        return false;
    }
    if left
        .when_no_flags
        .intersection(&right.when_all_flags)
        .next()
        .is_some()
        || right
            .when_no_flags
            .intersection(&left.when_all_flags)
            .next()
            .is_some()
    {
        return false;
    }
    if left.when_any_flags.is_empty() || right.when_any_flags.is_empty() {
        return true;
    }
    left.when_any_flags
        .intersection(&right.when_any_flags)
        .next()
        .is_some()
}

pub fn merge_existing_capabilities(
    compiled: &mut CompiledPolicy,
    existing_capabilities: &serde_json::Value,
) -> Result<(), CompileError> {
    let existing = existing_capabilities.as_object().ok_or_else(|| {
        CompileError::Invalid("installed warrant has non-object capabilities payload".to_string())
    })?;

    for (capability, value) in existing {
        let existing_grant = json_to_grant(value).ok_or_else(|| {
            CompileError::Invalid(format!(
                "installed warrant has invalid capability grant for '{capability}'"
            ))
        })?;

        let candidate = grant_to_toml(existing_grant.clone());
        if let Some(current) = compiled.capabilities.get(capability) {
            let current_grant = toml_to_grant(current).ok_or_else(|| {
                CompileError::Invalid(format!("invalid compiled grant for '{capability}'"))
            })?;
            let merged = merge_grants(
                capability,
                current_grant,
                existing_grant,
                "selected draft",
                "installed lock",
            )?;
            compiled
                .capabilities
                .insert(capability.clone(), grant_to_toml(merged));
        } else {
            compiled.capabilities.insert(capability.clone(), candidate);
        }
    }

    Ok(())
}

fn merge_draft_into(
    merged: &mut BTreeMap<String, Grant>,
    draft: &Draft,
    path: &Path,
) -> Result<(), CompileError> {
    for (capability, draft_capability) in &draft.capabilities {
        let grant = draft_capability_to_grant(capability, draft_capability, path)?;
        let source = path.display().to_string();

        if let Some(existing) = merged.get(capability).cloned() {
            let resolved = merge_grants(capability, existing, grant, "previous draft", &source)?;
            merged.insert(capability.clone(), resolved);
        } else {
            merged.insert(capability.clone(), grant);
        }
    }

    Ok(())
}

fn draft_capability_to_grant(
    capability: &str,
    draft_capability: &DraftCapability,
    path: &Path,
) -> Result<Grant, CompileError> {
    match draft_capability.decision {
        DraftDecision::Review => Err(CompileError::Invalid(format!(
            "draft {} has unresolved review decision for capability '{}'",
            path.display(),
            capability
        ))),
        DraftDecision::Deny => Ok(Grant::Deny),
        DraftDecision::Allow => {
            if draft_capability.scopes.is_empty() {
                return Ok(Grant::AllowAll);
            }
            let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
            for (scope_key, values) in &draft_capability.scopes {
                scopes.insert(scope_key.clone(), values.iter().cloned().collect());
            }
            Ok(Grant::AllowScoped(scopes))
        }
    }
}

fn merge_grants(
    capability: &str,
    left: Grant,
    right: Grant,
    left_src: &str,
    right_src: &str,
) -> Result<Grant, CompileError> {
    match (left, right) {
        (Grant::Deny, Grant::Deny) => Ok(Grant::Deny),
        (Grant::AllowAll, Grant::AllowAll) => Ok(Grant::AllowAll),
        (Grant::AllowAll, Grant::AllowScoped(_)) | (Grant::AllowScoped(_), Grant::AllowAll) => {
            Ok(Grant::AllowAll)
        }
        (Grant::AllowScoped(mut a), Grant::AllowScoped(b)) => {
            for (scope, values) in b {
                a.entry(scope).or_default().extend(values);
            }
            Ok(Grant::AllowScoped(a))
        }
        (Grant::Deny, Grant::AllowAll)
        | (Grant::Deny, Grant::AllowScoped(_))
        | (Grant::AllowAll, Grant::Deny)
        | (Grant::AllowScoped(_), Grant::Deny) => Err(CompileError::Invalid(format!(
            "conflict for capability '{capability}': contradictory decisions between {left_src} and {right_src}"
        ))),
    }
}

fn grant_to_toml(grant: Grant) -> toml::Value {
    match grant {
        Grant::AllowAll => toml::Value::Boolean(true),
        Grant::Deny => toml::Value::Boolean(false),
        Grant::AllowScoped(scopes) => {
            let mut table = toml::Table::new();
            table.insert("allow".to_string(), toml::Value::Boolean(true));
            for (scope_key, values) in scopes {
                let values = values
                    .into_iter()
                    .map(toml::Value::String)
                    .collect::<Vec<_>>();
                table.insert(scope_key, toml::Value::Array(values));
            }
            toml::Value::Table(table)
        }
    }
}

fn toml_to_grant(value: &toml::Value) -> Option<Grant> {
    match value {
        toml::Value::Boolean(true) => Some(Grant::AllowAll),
        toml::Value::Boolean(false) => Some(Grant::Deny),
        toml::Value::Table(table) => {
            let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
            for (scope_key, value) in table {
                if scope_key == "allow" {
                    continue;
                }
                let values = value
                    .as_array()?
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                scopes.insert(scope_key.clone(), values);
            }
            Some(Grant::AllowScoped(scopes))
        }
        _ => None,
    }
}

fn json_to_grant(value: &serde_json::Value) -> Option<Grant> {
    match value {
        serde_json::Value::Bool(true) => Some(Grant::AllowAll),
        serde_json::Value::Bool(false) => Some(Grant::Deny),
        serde_json::Value::Object(map) => {
            let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
            for (scope_key, value) in map {
                if scope_key == "allow" {
                    continue;
                }
                let values = match value {
                    serde_json::Value::String(single) => {
                        let mut set = BTreeSet::new();
                        set.insert(single.clone());
                        set
                    }
                    serde_json::Value::Array(items) => items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .map(ToOwned::to_owned)
                        .collect::<BTreeSet<_>>(),
                    _ => return None,
                };
                scopes.insert(scope_key.clone(), values);
            }
            Some(Grant::AllowScoped(scopes))
        }
        _ => None,
    }
}

fn normalize_tool_name(tool: &str) -> String {
    tool.split('@')
        .next()
        .unwrap_or(tool)
        .rsplit('/')
        .next()
        .unwrap_or(tool)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{ManifestClaim, claims_overlap};

    #[test]
    fn claims_overlap_when_same_match_and_one_unflagged() {
        let left = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: Default::default(),
            when_all_flags: Default::default(),
            when_no_flags: Default::default(),
        };
        let right = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: ["--force".to_string()].into_iter().collect(),
            when_all_flags: Default::default(),
            when_no_flags: Default::default(),
        };
        assert!(claims_overlap(&left, &right));
    }

    #[test]
    fn claims_do_not_overlap_when_flags_disjoint() {
        let left = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: ["--force".to_string()].into_iter().collect(),
            when_all_flags: Default::default(),
            when_no_flags: Default::default(),
        };
        let right = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: ["--dry-run".to_string()].into_iter().collect(),
            when_all_flags: Default::default(),
            when_no_flags: Default::default(),
        };
        assert!(!claims_overlap(&left, &right));
    }

    #[test]
    fn claims_do_not_overlap_when_all_flags_conflict_with_exclusions() {
        let left = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: Default::default(),
            when_all_flags: ["--force".to_string()].into_iter().collect(),
            when_no_flags: Default::default(),
        };
        let right = ManifestClaim {
            tool: "git".to_string(),
            match_tokens: vec!["push".to_string()],
            when_any_flags: Default::default(),
            when_all_flags: Default::default(),
            when_no_flags: ["--force".to_string()].into_iter().collect(),
        };
        assert!(!claims_overlap(&left, &right));
    }

    #[test]
    fn policy_channels_compile_into_commands_paths_and_environment_strip() {
        let mut merged = BTreeMap::new();
        merged.insert(
            "policy.commands_paths".to_string(),
            super::Grant::AllowScoped(BTreeMap::from([(
                "paths".to_string(),
                BTreeSet::from(["/usr/bin/**".to_string(), "/usr/local/bin/**".to_string()]),
            )])),
        );
        merged.insert(
            "policy.environment_strip".to_string(),
            super::Grant::AllowScoped(BTreeMap::from([(
                "strip".to_string(),
                BTreeSet::from(["RUSTC_WRAPPER".to_string(), "LD_PRELOAD".to_string()]),
            )])),
        );

        let channels = super::extract_policy_channels(&mut merged).expect("extract channels");
        let mut capabilities = merged
            .into_iter()
            .map(|(capability, grant)| (capability, super::grant_to_toml(grant)))
            .collect::<BTreeMap<_, _>>();
        super::apply_policy_channels(&mut capabilities, channels);

        let commands = capabilities
            .get("commands")
            .and_then(toml::Value::as_table)
            .expect("commands table");
        assert!(
            commands
                .get("paths")
                .and_then(toml::Value::as_array)
                .is_some()
        );

        let environment = capabilities
            .get("environment")
            .and_then(toml::Value::as_table)
            .expect("environment table");
        assert!(
            environment
                .get("strip")
                .and_then(toml::Value::as_array)
                .is_some()
        );
    }

    #[test]
    fn policy_channels_compile_commands_block() {
        let mut merged = BTreeMap::new();
        merged.insert(
            "policy.commands_block".to_string(),
            super::Grant::AllowScoped(BTreeMap::from([(
                "patterns".to_string(),
                BTreeSet::from(["rm -rf /".to_string(), "curl * | bash".to_string()]),
            )])),
        );

        let channels = super::extract_policy_channels(&mut merged).expect("extract channels");
        let mut capabilities = merged
            .into_iter()
            .map(|(capability, grant)| (capability, super::grant_to_toml(grant)))
            .collect::<BTreeMap<_, _>>();
        super::apply_policy_channels(&mut capabilities, channels);

        let commands = capabilities
            .get("commands")
            .and_then(toml::Value::as_table)
            .expect("commands table");
        let block = commands
            .get("block")
            .and_then(toml::Value::as_array)
            .expect("block array");
        let patterns: Vec<&str> = block.iter().filter_map(toml::Value::as_str).collect();
        assert!(patterns.contains(&"rm -rf /"));
        assert!(patterns.contains(&"curl * | bash"));
    }
}
