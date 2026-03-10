use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use warrant_core::ToolPaths;

use crate::TOOL_NAME;
use crate::app::{AppError, Result};

pub(crate) struct ProfileInfo {
    pub(crate) name: String,
    pub(crate) version: u64,
    pub(crate) issuer: String,
}

pub(crate) fn profile_metadata(
    root: Option<&Path>,
    profile: Option<&str>,
    discover_project: bool,
) -> Result<Option<ProfileInfo>> {
    let paths = resolve_paths_internal(root, profile, discover_project)?.paths;
    if !paths.installed_warrant_path.exists() {
        return Ok(None);
    }

    let warrant = warrant_core::load_installed_warrant_for_tool(&paths, TOOL_NAME)?;
    let name = profile
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "default".to_string());

    Ok(Some(ProfileInfo {
        name,
        version: warrant.meta.version,
        issuer: warrant.meta.issuer,
    }))
}

pub(crate) fn validate_profile_name(profile: &str) -> Result<()> {
    let valid = !profile.is_empty()
        && !profile.starts_with('-')
        && !profile.contains('/')
        && !profile.contains('\\')
        && !profile.contains("..")
        && profile
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));

    if valid {
        Ok(())
    } else {
        Err(AppError::Message(format!(
            "Invalid profile name '{}': must be alphanumeric with dots, underscores, or hyphens only",
            profile
        )))
    }
}

pub(crate) struct ResolvedPaths {
    pub(crate) paths: ToolPaths,
    pub(crate) source: PathSource,
}

pub(crate) enum PathSource {
    ActivatedProject {
        profile: String,
        project_dir: PathBuf,
    },
    Profile(String, PathBuf),
    System(PathBuf),
}

impl PathSource {
    pub(crate) fn display(&self) -> String {
        match self {
            PathSource::ActivatedProject {
                profile,
                project_dir,
            } => {
                format!("project ({profile}: {})", project_dir.display())
            }
            PathSource::Profile(name, path) => format!("profile ({name}: {})", path.display()),
            PathSource::System(path) => format!("system ({})", path.display()),
        }
    }
}

pub fn resolve_paths(root: Option<&Path>, profile: Option<&str>) -> Result<ToolPaths> {
    resolve_paths_internal(root, profile, true).map(|resolved| resolved.paths)
}

pub(crate) fn resolve_paths_with_source(
    root: Option<&Path>,
    profile: Option<&str>,
) -> Result<ResolvedPaths> {
    resolve_paths_internal(root, profile, true)
}

pub(crate) fn resolve_paths_internal(
    root: Option<&Path>,
    profile: Option<&str>,
    discover_project: bool,
) -> Result<ResolvedPaths> {
    if let Some(profile_name) = profile {
        validate_profile_name(profile_name)?;
    }

    if discover_project
        && profile.is_none()
        && let Ok(project_dir) = canonical_cwd()
    {
        let registry = load_projects_registry(root)?;
        if let Some(entry) = registry.get(&project_dir.display().to_string()) {
            let paths = project_profile_paths(root, &entry.profile)?;
            return Ok(ResolvedPaths {
                paths,
                source: PathSource::ActivatedProject {
                    profile: entry.profile.clone(),
                    project_dir,
                },
            });
        }
        if project_dir.join(".warrant").join("drafts").exists() {
            eprintln!("note: found .warrant/drafts but project is not locked. Run: sudo wsh lock");
        }
    }

    let (base_etc, base_run) = system_base_dirs(root)?;
    let host_secret_path = default_host_secret_path(root, &base_etc);

    let (etc, run) = if let Some(name) = profile.filter(|name| !name.is_empty()) {
        (
            base_etc.join("profiles").join(name),
            base_run.join("profiles").join(name),
        )
    } else {
        (base_etc, base_run)
    };

    let source = if let Some(name) = profile.filter(|name| !name.is_empty()) {
        PathSource::Profile(name.to_string(), etc.clone())
    } else {
        PathSource::System(etc.clone())
    };

    let mut paths = ToolPaths {
        tool_id: warrant_core::ToolId::parse(TOOL_NAME).unwrap(),
        installed_warrant_path: etc.join("warrant.toml"),
        version_state_path: etc.join("signing").join("version"),
        signing_private_key_path: etc.join("signing").join("private.key"),
        signing_public_key_path: etc.join("signing").join("public.key"),
        host_secret_path,
        session_dir_path: run,
    };
    if matches!(source, PathSource::System(_)) {
        apply_system_read_fallbacks(&mut paths);
    }

    Ok(ResolvedPaths { paths, source })
}

fn is_readable(path: &Path) -> bool {
    fs::File::open(path).is_ok()
}

fn is_not_found_or_permission_denied(path: &Path) -> bool {
    matches!(
        fs::File::open(path),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            )
    )
}

fn apply_system_read_fallbacks(paths: &mut ToolPaths) {
    if is_not_found_or_permission_denied(&paths.installed_warrant_path) {
        let relay_warrant = PathBuf::from("/tmp/warrant-shell/warrant.toml");
        if is_readable(&relay_warrant) {
            paths.installed_warrant_path = relay_warrant;
        }
    }

    if is_not_found_or_permission_denied(&paths.signing_public_key_path) {
        let relay_public_key = PathBuf::from("/tmp/warrant-shell/signing/public.key");
        if is_readable(&relay_public_key) {
            paths.signing_public_key_path = relay_public_key;
        }
    }
}

pub(crate) fn canonical_cwd() -> Result<PathBuf> {
    Ok(fs::canonicalize(std::env::current_dir()?)?)
}

pub(crate) fn system_base_dirs(root: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    if let Some(root) = root {
        return Ok((
            root.join("etc").join(TOOL_NAME),
            root.join("run").join(TOOL_NAME),
        ));
    }

    let default_paths = ToolPaths::for_tool(TOOL_NAME)?;
    let base_etc = default_paths
        .installed_warrant_path
        .parent()
        .ok_or_else(|| AppError::Message("invalid installed warrant path".to_string()))?
        .to_path_buf();
    Ok((base_etc, default_paths.session_dir_path))
}

fn projects_registry_path(root: Option<&Path>) -> Result<PathBuf> {
    let (base_etc, _) = system_base_dirs(root)?;
    Ok(base_etc.join("projects.json"))
}

pub(crate) fn project_profile_paths(root: Option<&Path>, profile: &str) -> Result<ToolPaths> {
    validate_profile_name(profile)?;
    let (base_etc, base_run) = system_base_dirs(root)?;
    let host_secret_path = default_host_secret_path(root, &base_etc);
    Ok(ToolPaths {
        tool_id: warrant_core::ToolId::parse(TOOL_NAME).unwrap(),
        installed_warrant_path: base_etc.join("profiles").join(profile).join("warrant.toml"),
        version_state_path: base_etc
            .join("profiles")
            .join(profile)
            .join("signing")
            .join("version"),
        signing_private_key_path: base_etc.join("signing").join("private.key"),
        signing_public_key_path: base_etc.join("signing").join("public.key"),
        host_secret_path,
        session_dir_path: base_run.join("profiles").join(profile),
    })
}

fn default_host_secret_path(root: Option<&Path>, base_etc: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        return base_etc.join("host.key");
    }
    if let Some(root) = root {
        return root
            .join("var")
            .join("lib")
            .join(TOOL_NAME)
            .join("hmac.key");
    }
    PathBuf::from("/var/lib/warrant-shell/hmac.key")
}

fn project_hash(project_dir: &Path) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(project_dir.as_os_str().to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

pub(crate) fn project_profile_name(project_dir: &Path) -> String {
    format!("project-{}", project_hash(project_dir))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActivatedProject {
    pub(crate) profile: String,
    pub(crate) activated_at: String,
    pub(crate) draft_path: String,
}

type ProjectsRegistry = std::collections::BTreeMap<String, ActivatedProject>;

pub(crate) fn load_projects_registry(root: Option<&Path>) -> Result<ProjectsRegistry> {
    let path = projects_registry_path(root)?;
    load_projects_registry_from_path(&path)
}

fn load_projects_registry_from_path(path: &Path) -> Result<ProjectsRegistry> {
    if !path.exists() {
        return Ok(ProjectsRegistry::new());
    }
    let text = fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(ProjectsRegistry::new());
    }
    serde_json::from_str(&text)
        .map_err(|err| AppError::Message(format!("invalid projects.json: {err}")))
}

fn write_projects_registry_atomic(path: &Path, registry: &ProjectsRegistry) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(registry)
        .map_err(|err| AppError::Message(format!("failed to serialize projects.json: {err}")))?;
    let parent = path.parent().ok_or_else(|| {
        AppError::Message("projects.json path has no parent directory".to_string())
    })?;
    let tmp_path = parent.join(format!(
        ".projects.{}.{}.tmp",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    {
        let mut tmp = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp.write_all(format!("{text}\n").as_bytes())?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub(crate) fn with_locked_projects_registry<T>(
    root: Option<&Path>,
    op: impl FnOnce(&mut ProjectsRegistry) -> Result<T>,
) -> Result<T> {
    let path = projects_registry_path(root)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = path.with_extension("json.lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock_file.lock_exclusive()?;

    let result = (|| {
        let mut registry = load_projects_registry_from_path(&path)?;
        let value = op(&mut registry)?;
        write_projects_registry_atomic(&path, &registry)?;
        Ok(value)
    })();

    let _ = lock_file.unlock();
    result
}

#[cfg(test)]
mod tests {
    use super::validate_profile_name;

    #[test]
    fn rejects_profile_traversal_input() {
        let err = validate_profile_name("../../../tmp/evil").expect_err("must reject traversal");
        assert_eq!(
            err.to_string(),
            "Invalid profile name '../../../tmp/evil': must be alphanumeric with dots, underscores, or hyphens only"
        );
    }

    #[test]
    fn accepts_valid_profile_name() {
        validate_profile_name("codex.v1_profile-01").expect("valid profile");
    }
}
