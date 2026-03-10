use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};

const DATASET_SOURCE: &str = "Datadog malicious-software-packages-dataset";

static DENYLISTS: OnceLock<Result<DenylistData, String>> = OnceLock::new();
static DENYLIST_DIR: OnceLock<PathBuf> = OnceLock::new();
static WARN_ONCE: Once = Once::new();

#[derive(Debug)]
struct DenylistData {
    npm: Vec<String>,
    pypi: Vec<String>,
    cargo: Vec<String>,
    go: Vec<String>,
    rubygems: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DenylistFreshness {
    pub last_updated: String,
    pub package_count: usize,
}

pub fn source_name() -> &'static str {
    DATASET_SOURCE
}

pub fn init_denylist_dir(dir: PathBuf) {
    let _ = DENYLIST_DIR.set(dir);
}

pub fn normalize_ecosystem(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "npm" | "node" | "nodejs" | "pnpm" | "yarn" | "bun" => Some("npm"),
        "pip" | "pip3" | "pypi" | "python" | "uv" | "poetry" | "pdm" | "pipx" => Some("pypi"),
        "cargo" | "crates" | "crates-io" | "rust" => Some("cargo"),
        "go" | "golang" | "gomod" | "modules" => Some("go"),
        "gem" | "ruby" | "rubygem" | "rubygems" => Some("rubygems"),
        _ => None,
    }
}

pub fn is_malicious(ecosystem_or_tool: &str, package: &str) -> bool {
    let Some(ecosystem) = normalize_ecosystem(ecosystem_or_tool) else {
        return false;
    };
    let package = package.trim().to_ascii_lowercase();
    if package.is_empty() {
        return false;
    }

    let denylist = match load_lists() {
        Ok(data) => match ecosystem {
            "npm" => &data.npm,
            "pypi" => &data.pypi,
            "cargo" => &data.cargo,
            "go" => &data.go,
            "rubygems" => &data.rubygems,
            _ => return false,
        },
        Err(err) => {
            warn_once(err);
            return true;
        }
    };

    denylist
        .binary_search_by(|entry| entry.as_str().cmp(package.as_str()))
        .is_ok()
}

pub fn denylist_freshness(ecosystem_or_tool: &str) -> Option<DenylistFreshness> {
    let ecosystem = normalize_ecosystem(ecosystem_or_tool)?;
    let dir = resolve_denylist_dir();
    let last_updated = fs::read_to_string(dir.join("last_updated"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let package_count = fs::read_to_string(denylist_file_path(&dir, ecosystem))
        .ok()?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .count();

    Some(DenylistFreshness {
        last_updated,
        package_count,
    })
}

fn load_lists() -> Result<&'static DenylistData, &'static str> {
    match DENYLISTS.get_or_init(build_lists) {
        Ok(data) => Ok(data),
        Err(err) => Err(err.as_str()),
    }
}

fn build_lists() -> Result<DenylistData, String> {
    let dir = resolve_denylist_dir();
    let npm_path = denylist_file_path(&dir, "npm");
    let pypi_path = denylist_file_path(&dir, "pypi");
    let cargo_path = denylist_file_path(&dir, "cargo");
    let go_path = denylist_file_path(&dir, "go");
    let rubygems_path = denylist_file_path(&dir, "rubygems");

    let npm = parse_file(&npm_path)?;
    let pypi = parse_file(&pypi_path)?;
    let cargo = parse_optional_file(&cargo_path)?;
    let go = parse_optional_file(&go_path)?;
    let rubygems = parse_optional_file(&rubygems_path)?;

    if npm.is_empty() {
        return Err("npm denylist is empty".to_string());
    }
    if pypi.is_empty() {
        return Err("pypi denylist is empty".to_string());
    }

    Ok(DenylistData {
        npm,
        pypi,
        cargo,
        go,
        rubygems,
    })
}

fn parse_file(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(parse_content(&content))
}

fn parse_optional_file(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    parse_file(path)
}

fn parse_content(content: &str) -> Vec<String> {
    let mut out = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_ascii_lowercase())
        .collect::<Vec<_>>();
    out.sort_unstable();
    out.dedup();
    out
}

fn denylist_file_path(dir: &Path, ecosystem: &str) -> PathBuf {
    dir.join(format!("{ecosystem}.txt"))
}

fn resolve_denylist_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("WSH_DENYLIST_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return dir;
    }

    DENYLIST_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(crate::denylist_update::DEFAULT_DENYLIST_DIR))
}

fn warn_once(reason: &str) {
    WARN_ONCE.call_once(|| {
        eprintln!("warning: package denylist unavailable ({reason}); defaulting to fail-closed");
    });
}

#[cfg(test)]
mod tests {
    use super::normalize_ecosystem;

    #[test]
    fn normalizes_supported_ecosystems() {
        assert_eq!(normalize_ecosystem("npm"), Some("npm"));
        assert_eq!(normalize_ecosystem("pip"), Some("pypi"));
        assert_eq!(normalize_ecosystem("pypi"), Some("pypi"));
        assert_eq!(normalize_ecosystem("cargo"), Some("cargo"));
        assert_eq!(normalize_ecosystem("go"), Some("go"));
        assert_eq!(normalize_ecosystem("rubygems"), Some("rubygems"));
        assert_eq!(normalize_ecosystem("ruby"), Some("rubygems"));
        assert_eq!(normalize_ecosystem("unknown"), None);
    }
}
