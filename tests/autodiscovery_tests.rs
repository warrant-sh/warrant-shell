use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;
use wsh::draft::{DraftDecision, read_draft, write_draft};

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

fn install_git_manifest_cache() -> TempDir {
    let manifests = TempDir::new().expect("temp manifests");
    std::fs::write(
        manifests.path().join("git.toml"),
        r#"
[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/git"
tool = "git"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "git.push"
args = { remote = 1, branch = 2 }

[[commands]]
match = ["push"]
when_any_flags = ["--force"]
capability = "git.push_force"

[[commands]]
match = ["reset"]
capability = "git.reset"
"#,
    )
    .expect("write git manifest");
    manifests
}

fn canonical_project(project: &Path) -> String {
    std::fs::canonicalize(project)
        .expect("canonicalize")
        .to_string_lossy()
        .to_string()
}

fn project_profile(project: &Path) -> String {
    let canonical = std::fs::canonicalize(project).expect("canonicalize");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_os_str().to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("project-{}", &digest[..16])
}

fn mark_draft_all_deny(path: &Path) {
    let mut draft = read_draft(path).expect("read draft");
    for capability in draft.capabilities.values_mut() {
        capability.decision = DraftDecision::Deny;
        capability.scopes.clear();
    }
    write_draft(path, &draft, false).expect("write draft");
}

fn install_default_warrant(paths_root: &TempDir, workdir: &TempDir, allow: &[&str]) {
    let allow_line = allow
        .iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let draft = workdir.path().join("default-draft.toml");
    let draft_text = format!(
        r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-17T04:30:00Z"
issuer = "default@host"

[capabilities.commands]
allow = [{allow_line}]
block = ["rm -rf /"]

[capabilities.files]
read = {{ allow = true, paths = ["/tmp/**"] }}
write = {{ allow = true, paths = ["/tmp/**"] }}
delete = {{ allow = true, paths = ["/tmp/**"] }}

[capabilities.network]
allow = true

[capabilities.git]
push = true
push_force = false

[capabilities.process]
kill = false
background = true

[policy]
command_default = "deny"
"#
    );
    std::fs::write(&draft, draft_text).expect("write default draft");
    let paths = resolve_paths(Some(paths_root.path()), None).expect("resolve paths");
    lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect("lock");
}

#[test]
fn add_defaults_to_system_scope() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();

    assert!(
        xdg.path()
            .join("wsh")
            .join("drafts")
            .join("git.toml")
            .exists()
    );
    assert!(!project.path().join(".warrant").join("drafts").exists());
}

#[test]
fn add_project_scope_creates_project_drafts_dir() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    assert!(
        project
            .path()
            .join(".warrant")
            .join("drafts")
            .join("git.toml")
            .exists()
    );
}

#[test]
fn lock_project_mode_binds_directory_and_lists_in_projects() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();
    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    let system_draft = xdg.path().join("wsh").join("drafts").join("git.toml");
    let project_draft = project
        .path()
        .join(".warrant")
        .join("drafts")
        .join("git.toml");
    mark_draft_all_deny(&system_draft);
    mark_draft_all_deny(&project_draft);

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("lock")
        .assert()
        .success()
        .stdout(predicate::str::contains("bound directory:"));

    let profile = project_profile(project.path());
    assert!(
        paths_root
            .path()
            .join("etc")
            .join("warrant-shell")
            .join("profiles")
            .join(&profile)
            .join("warrant.toml")
            .exists()
    );

    let registry: Value = serde_json::from_str(
        &std::fs::read_to_string(
            paths_root
                .path()
                .join("etc")
                .join("warrant-shell")
                .join("projects.json"),
        )
        .expect("read projects"),
    )
    .expect("json");
    let key = canonical_project(project.path());
    assert_eq!(registry[&key]["profile"], profile);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("projects")
        .assert()
        .success()
        .stdout(predicate::str::contains(&profile))
        .stdout(predicate::str::contains(canonical_project(project.path())));
}

#[test]
fn lock_project_mode_rejects_looser_project_policy() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();
    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    let system_draft = xdg.path().join("wsh").join("drafts").join("git.toml");
    let project_draft = project
        .path()
        .join(".warrant")
        .join("drafts")
        .join("git.toml");
    mark_draft_all_deny(&system_draft);
    let mut project_doc = read_draft(&project_draft).expect("read project draft");
    for capability in project_doc.capabilities.values_mut() {
        capability.decision = DraftDecision::Allow;
        capability.scopes.clear();
    }
    write_draft(&project_draft, &project_doc, false).expect("write project draft");

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("lock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("would loosen"));
}

#[test]
fn check_shows_hint_for_unlocked_project_drafts() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    install_default_warrant(&paths_root, &workdir, &["ls"]);

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "note: found .warrant/drafts but project is not locked. Run: sudo wsh lock",
        ));
}
