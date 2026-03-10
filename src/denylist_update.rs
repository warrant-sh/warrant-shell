use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use crate::trusted_tools::trusted_curl_path;

pub const DEFAULT_DENYLIST_DIR: &str = "/var/lib/warrant-shell/denylists";

const NPM_MANIFEST_URL: &str = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json";
const PYPI_MANIFEST_URL: &str = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json";
const MAX_DENYLIST_MANIFEST_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct DenylistUpdateSummary {
    pub npm_count: usize,
    pub pypi_count: usize,
}

pub fn denylist_files_exist(dir: &Path) -> bool {
    dir.join("npm.txt").exists() && dir.join("pypi.txt").exists() && dir.join("cargo.txt").exists()
}

pub fn download_and_write_denylists(dir: &Path) -> Result<DenylistUpdateSummary, String> {
    fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create denylist dir {}: {err}", dir.display()))?;

    let npm = download_manifest_keys(NPM_MANIFEST_URL)?;
    let pypi = download_manifest_keys(PYPI_MANIFEST_URL)?;

    write_lines(&dir.join("npm.txt"), &npm)?;
    write_lines(&dir.join("pypi.txt"), &pypi)?;

    let cargo_path = dir.join("cargo.txt");
    if !cargo_path.exists() {
        write_lines(&cargo_path, &[])?;
    }
    let go_path = dir.join("go.txt");
    if !go_path.exists() {
        write_lines(&go_path, &[])?;
    }

    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    fs::write(dir.join("last_updated"), format!("{now}\n"))
        .map_err(|err| format!("failed to write last_updated marker: {err}"))?;

    Ok(DenylistUpdateSummary {
        npm_count: npm.len(),
        pypi_count: pypi.len(),
    })
}

fn download_manifest_keys(url: &str) -> Result<Vec<String>, String> {
    let curl_path = trusted_curl_path()
        .map_err(|err| format!("failed to resolve trusted curl path for {url}: {err}"))?;
    let output = Command::new(curl_path)
        .args(["--proto", "=https", "--tlsv1.2", "-fsSL"])
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

    if output.stdout.len() > MAX_DENYLIST_MANIFEST_BYTES {
        return Err(format!(
            "denylist manifest from {url} exceeds size limit ({} bytes > {} bytes)",
            output.stdout.len(),
            MAX_DENYLIST_MANIFEST_BYTES
        ));
    }

    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse manifest JSON from {url}: {err}"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| format!("unexpected manifest format from {url}: expected JSON object"))?;
    // Values are either null (malicious-intent packages) or arrays/objects (compromised packages
    // listing affected versions). Both are valid — we only need the keys.
    if obj
        .values()
        .any(|value| !value.is_null() && !value.is_object() && !value.is_array())
    {
        return Err(format!(
            "unexpected manifest format from {url}: expected object values keyed by package name"
        ));
    }

    let mut keys = obj
        .keys()
        .map(|key| key.trim().to_ascii_lowercase())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

fn write_lines(path: &Path, lines: &[String]) -> Result<(), String> {
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))
}
