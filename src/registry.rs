use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::Digest;

use crate::manifest::{Manifest, parse_manifest};
use crate::trusted_tools::trusted_curl_path;

pub(crate) const DEFAULT_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/warrant-sh/registry/main";
const DEFAULT_REGISTRY_INDEX_PUBLIC_KEY_B64: &str = "Dm3ihYAV2z7i9xOdD6diY/NjHCEodfQYIaiEx/F2SPs=";

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryIndex {
    pub registry: RegistryMeta,
    #[serde(default)]
    pub manifests: Vec<RegistryManifestEntry>,
    #[serde(default)]
    pub bundles: Vec<RegistryBundleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryMeta {
    pub schema: String,
    pub updated: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryManifestEntry {
    pub id: String,
    pub path: String,
    pub version: String,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryBundleEntry {
    pub id: String,
    pub path: String,
    pub version: String,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleConfig {
    pub bundle: BundleMeta,
    pub setup: BundleSetup,
    #[serde(default)]
    pub agents: Vec<BundleAgent>,
    pub manifests: BundleManifests,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleMeta {
    pub name: String,
    pub description: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleSetup {
    pub guard_all_sessions: bool,
    pub shell_guard: bool,
    pub prompt_lock: bool,
    #[serde(default)]
    pub claude_pretool_hook: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleAgent {
    pub name: String,
    pub alias: String,
    /// If true, this agent needs a shell alias with WSH_GUARD + BASH_ENV wrapping.
    /// Default false — most agents use hooks or don't need wrapping.
    #[serde(default)]
    pub wrap: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleManifests {
    #[serde(default)]
    pub include: Vec<String>,
}

pub fn registry_base_url() -> String {
    #[cfg(test)]
    if let Some(url) = std::env::var("WSH_REGISTRY_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return url;
    }
    DEFAULT_REGISTRY_URL.to_string()
}

pub fn fetch_registry_index() -> Result<RegistryIndex, String> {
    let base_url = registry_base_url();
    let url = format!("{base_url}/registry.toml");
    let text = download_text(&url)?;
    let sig_url = format!("{base_url}/registry.toml.sig");
    let signature_text = download_text(&sig_url)?;
    verify_registry_index_signature(&text, &signature_text)?;
    toml::from_str::<RegistryIndex>(&text)
        .map_err(|err| format!("failed to parse registry index from {url}: {err}"))
}

pub fn fetch_manifest(entry: &RegistryManifestEntry) -> Result<String, String> {
    let base_url = registry_base_url();
    validate_registry_relative_path(&entry.path, "manifest")?;
    let url = format!("{base_url}/{}", entry.path);
    download_text(&url)
}

pub fn fetch_bundle(name: &str) -> Result<BundleConfig, String> {
    let index = fetch_registry_index()?;
    let entry = index
        .bundles
        .iter()
        .find(|entry| entry.id.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("bundle '{name}' not found in registry index"))?;

    let base_url = registry_base_url();
    validate_registry_relative_path(&entry.path, "bundle")?;
    let url = format!("{base_url}/{}", entry.path);
    let text = download_text(&url)?;
    verify_bundle_hash_matches_entry(entry, &text)?;
    toml::from_str::<BundleConfig>(&text)
        .map_err(|err| format!("failed to parse bundle config for '{name}': {err}"))
}

pub fn list_available_bundles() -> Result<Vec<String>, String> {
    let index = fetch_registry_index()?;
    Ok(index.bundles.into_iter().map(|entry| entry.id).collect())
}

pub fn load_all_cached_manifests(cache_dirs: &[PathBuf]) -> Vec<Manifest> {
    let mut manifests = Vec::<Manifest>::new();
    let mut seen_ids = std::collections::BTreeSet::<String>::new();

    for dir in cache_dirs {
        let pattern = format!("{}/**/*.toml", dir.display());
        let Ok(entries) = glob::glob(&pattern) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(text) = fs::read_to_string(&entry) else {
                continue;
            };
            let Ok(manifest) = parse_manifest(&text) else {
                continue;
            };
            let key = manifest.manifest.id.to_ascii_lowercase();
            if seen_ids.insert(key) {
                manifests.push(manifest);
            }
        }
    }

    manifests
}

pub fn pull_manifest_to_cache(id: &str, cache_dir: &Path) -> Result<Manifest, String> {
    let index = fetch_registry_index()?;
    let requested = normalize_manifest_id(id);
    let entry = index
        .manifests
        .iter()
        .find(|entry| {
            entry.id.eq_ignore_ascii_case(id)
                || normalize_manifest_id(&entry.id).eq_ignore_ascii_case(&requested)
        })
        .ok_or_else(|| format!("manifest '{id}' not found in registry index"))?;

    let text = fetch_manifest(entry)?;
    verify_manifest_hash_matches_entry(entry, &text)?;
    let manifest = parse_manifest(&text)
        .map_err(|err| format!("invalid manifest '{}' from registry: {err}", entry.id))?;

    fs::create_dir_all(cache_dir)
        .map_err(|err| format!("failed to create cache dir {}: {err}", cache_dir.display()))?;
    let target = cache_file_path(cache_dir, &manifest);
    fs::write(&target, text)
        .map_err(|err| format!("failed to write {}: {err}", target.display()))?;
    Ok(manifest)
}

pub fn pull_all_manifests(cache_dir: &Path) -> Result<Vec<Manifest>, String> {
    let index = fetch_registry_index()?;
    fs::create_dir_all(cache_dir)
        .map_err(|err| format!("failed to create cache dir {}: {err}", cache_dir.display()))?;

    let mut pulled = Vec::<Manifest>::new();
    for entry in &index.manifests {
        let normalized_name = normalize_manifest_id(&entry.id);
        let target = cache_dir.join(format!("{normalized_name}.toml"));
        if target.exists()
            && let Ok(existing) = fs::read_to_string(&target)
            && text_sha256(&existing) == entry.hash
        {
            continue;
        }

        let text = fetch_manifest(entry)?;
        verify_manifest_hash_matches_entry(entry, &text)?;
        let manifest = parse_manifest(&text)
            .map_err(|err| format!("invalid manifest '{}' from registry: {err}", entry.id))?;
        fs::write(&target, text)
            .map_err(|err| format!("failed to write {}: {err}", target.display()))?;
        pulled.push(manifest);
    }

    Ok(pulled)
}

pub fn download_text(url: &str) -> Result<String, String> {
    let curl_path = trusted_curl_path()
        .map_err(|err| format!("failed to resolve trusted curl path for {url}: {err}"))?;
    let mut cmd = Command::new(curl_path);
    cmd.args([
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "-fsSL",
    ]);
    if is_github_domain(url)
        && let Some(token) = github_token()
    {
        cmd.arg("-H").arg(format!("Authorization: Bearer {token}"));
    }
    let output = cmd
        .arg(url)
        .output()
        .map_err(|err| format!("failed to run curl for {url}: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            return Err(format!(
                "curl returned non-zero status ({}) for {url}",
                output.status
            ));
        }
        return Err(format!(
            "curl returned non-zero status ({}) for {url}: {detail}",
            output.status
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|err| format!("response was not valid UTF-8 for {url}: {err}"))
}

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
        .or_else(|| {
            std::env::var("GH_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty())
        })
}

fn is_github_domain(url: &str) -> bool {
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    let authority = after_scheme.split('/').next().unwrap_or_default();
    let host = authority
        .split('@')
        .next_back()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase();
    matches!(
        host.as_str(),
        "github.com" | "raw.githubusercontent.com" | "api.github.com"
    )
}

fn normalize_manifest_id(id: &str) -> String {
    id.split('@')
        .next()
        .unwrap_or(id)
        .rsplit('/')
        .next()
        .unwrap_or(id)
        .to_ascii_lowercase()
}

fn cache_file_path(cache_dir: &Path, manifest: &Manifest) -> std::path::PathBuf {
    let normalized_name = normalize_manifest_id(&manifest.manifest.id);
    cache_dir.join(format!("{normalized_name}.toml"))
}

fn text_sha256(text: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(text.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn verify_manifest_hash_matches_entry(
    entry: &RegistryManifestEntry,
    text: &str,
) -> Result<(), String> {
    let actual = text_sha256(text);
    if !entry.hash.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "manifest '{}' hash mismatch: expected {}, got {}",
            entry.id, entry.hash, actual
        ));
    }
    Ok(())
}

fn verify_bundle_hash_matches_entry(entry: &RegistryBundleEntry, text: &str) -> Result<(), String> {
    let expected = entry.hash.trim();
    if expected.is_empty() {
        return Err(format!(
            "bundle '{}' is missing required hash in registry index",
            entry.id
        ));
    }

    let actual = text_sha256(text);
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "bundle '{}' hash mismatch: expected {}, got {}",
            entry.id, expected, actual
        ));
    }
    Ok(())
}

fn validate_registry_relative_path(path: &str, kind: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err(format!("{kind} path is empty"));
    }
    if path.contains("://") {
        return Err(format!("{kind} path must be relative, got URL-like value"));
    }
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Err(format!("{kind} path must be relative"));
    }
    if candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{kind} path must not contain parent traversal"));
    }
    Ok(())
}

pub(crate) fn verify_registry_index_signature(
    index_text: &str,
    signature_text: &str,
) -> Result<(), String> {
    let public_key_b64 = DEFAULT_REGISTRY_INDEX_PUBLIC_KEY_B64;
    let signature_b64 = signature_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| "registry signature file is empty".to_string())?;

    let public_key_bytes = BASE64_STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| "invalid registry public key base64".to_string())?;
    let public_key: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid registry public key length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "invalid registry public key".to_string())?;

    let signature_bytes = BASE64_STANDARD
        .decode(signature_b64)
        .map_err(|_| "invalid registry signature base64".to_string())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "invalid registry signature length".to_string())?;
    verifying_key
        .verify_strict(index_text.as_bytes(), &signature)
        .map_err(|_| "registry index signature verification failed".to_string())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    use super::{
        BundleConfig, DEFAULT_REGISTRY_INDEX_PUBLIC_KEY_B64, DEFAULT_REGISTRY_URL, RegistryIndex,
        RegistryManifestEntry, download_text, registry_base_url, validate_registry_relative_path,
        verify_manifest_hash_matches_entry, verify_registry_index_signature,
    };

    #[test]
    fn parses_registry_index_toml() {
        let text = r#"
[registry]
schema = "warrant.registry.v1"
updated = "2026-02-21T08:00:00Z"

[[manifests]]
id = "warrant-sh/git"
path = "warrant-sh/git/manifest.toml"
version = "1.0.0"
hash = "sha256:abc123"

[[bundles]]
id = "python"
path = "bundles/python.toml"
version = "1.0.0"
hash = "sha256:def456"
"#;

        let parsed: RegistryIndex = toml::from_str(text).expect("parse index");
        assert_eq!(parsed.registry.schema, "warrant.registry.v1");
        assert_eq!(parsed.manifests.len(), 1);
        assert_eq!(parsed.manifests[0].id, "warrant-sh/git");
        assert_eq!(parsed.bundles.len(), 1);
        assert_eq!(parsed.bundles[0].id, "python");
    }

    #[test]
    fn parses_bundle_config_toml() {
        let text = r#"
[bundle]
name = "codex"
description = "Coding agents"
version = "1.0.0"

[setup]
guard_all_sessions = false
shell_guard = true
prompt_lock = true
claude_pretool_hook = false

[[agents]]
name = "codex"
alias = "codex"

[manifests]
include = ["warrant-sh/git", "warrant-sh/coreutils"]
"#;

        let parsed: BundleConfig = toml::from_str(text).expect("parse bundle");
        assert_eq!(parsed.bundle.name, "codex");
        assert!(parsed.setup.prompt_lock);
        assert!(!parsed.setup.claude_pretool_hook);
        assert_eq!(parsed.manifests.include.len(), 2);
    }

    #[test]
    fn download_text_invalid_url_returns_error() {
        let err = download_text("://not-a-valid-url").expect_err("must fail");
        assert!(
            err.contains("curl returned non-zero status") || err.contains("failed to run curl")
        );
    }

    #[test]
    fn registry_url_respects_env_override() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe { std::env::set_var("WSH_REGISTRY_URL", "https://example.test/registry") };
        assert_eq!(registry_base_url(), "https://example.test/registry");
        unsafe { std::env::remove_var("WSH_REGISTRY_URL") };
        assert_eq!(registry_base_url(), DEFAULT_REGISTRY_URL);
    }

    #[test]
    fn rejects_manifest_hash_mismatch() {
        let entry = RegistryManifestEntry {
            id: "warrant-sh/git".to_string(),
            path: "warrant-sh/git/manifest.toml".to_string(),
            version: "1.0.0".to_string(),
            hash: "sha256:not-valid".to_string(),
        };
        let err = verify_manifest_hash_matches_entry(&entry, "hello world").expect_err("must fail");
        assert!(err.contains("hash mismatch"));
    }

    #[test]
    fn verifies_signed_registry_index() {
        let mut secret = [0u8; 32];
        secret[0] = 7;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let payload = "[registry]\nschema = \"warrant.registry.v1\"\n";
        let signature = signing_key.sign(payload.as_bytes());
        let sig_b64 = BASE64_STANDARD.encode(signature.to_bytes());
        let pub_b64 = BASE64_STANDARD.encode(verifying_key.as_bytes());

        assert_ne!(pub_b64, DEFAULT_REGISTRY_INDEX_PUBLIC_KEY_B64);
        let err = verify_registry_index_signature(payload, &sig_b64).expect_err("must fail");
        assert!(err.contains("verification failed"));
    }

    #[test]
    fn reject_parent_traversal_paths() {
        let err = validate_registry_relative_path("../bad.toml", "manifest").expect_err("invalid");
        assert!(err.contains("parent traversal"));
    }
}
