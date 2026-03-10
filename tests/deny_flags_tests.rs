use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;
use wsh::manifest::{manifest_hash, parse_manifest};

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

fn install_warrant(
    paths_root: &TempDir,
    workdir: &TempDir,
    locked_manifest_id: &str,
    locked_manifest_hash: &str,
) {
    let draft = workdir.path().join("draft.toml");
    let text = format!(
        r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-22T00:00:00Z"
issuer = "test@host"

[capabilities]
"echo.exec" = true

[capabilities.commands]
allow = ["echo"]

[policy]
manifests = [{{ id = "{locked_manifest_id}", hash = "{locked_manifest_hash}" }}]
command_default = "deny"
"#
    );
    std::fs::write(&draft, text).expect("write draft");
    let paths = resolve_paths(Some(paths_root.path()), None).expect("resolve paths");
    lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect("lock warrant");
}

fn write_echo_manifest_with_deny_flags(dir: &TempDir) -> (String, String) {
    let manifests_dir = dir.path().join("wsh").join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("mkdir manifests");
    let manifest = r#"[manifest]
schema = "warrant.manifest.v1"
id = "official/echo"
tool = "echo"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
deny_flags = ["--yolo"]
deny_flags_description = "Block unsafe bypass flags"

[[commands]]
match = []
capability = "echo.exec"
"#;
    std::fs::write(manifests_dir.join("echo.toml"), manifest).expect("write manifest");
    let parsed = parse_manifest(manifest).expect("parse manifest");
    let hash = manifest_hash(&parsed).expect("manifest hash");
    (parsed.manifest.id, hash)
}

#[test]
fn deny_flags_denies_blocked_flag() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg_config_home = TempDir::new().expect("tempdir");
    let (manifest_id, manifest_hash) = write_echo_manifest_with_deny_flags(&xdg_config_home);
    install_warrant(&paths_root, &workdir, &manifest_id, &manifest_hash);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("--yolo")
        .arg("hello")
        .env("XDG_CONFIG_HOME", xdg_config_home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "flag '--yolo' is blocked by tool_policy.deny_flags",
        ));
}

#[test]
fn deny_flags_allows_command_without_blocked_flag() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg_config_home = TempDir::new().expect("tempdir");
    let (manifest_id, manifest_hash) = write_echo_manifest_with_deny_flags(&xdg_config_home);
    install_warrant(&paths_root, &workdir, &manifest_id, &manifest_hash);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("--safe")
        .arg("hello")
        .env("XDG_CONFIG_HOME", xdg_config_home.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed"));
}

#[test]
fn deny_flags_denies_equals_form() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg_config_home = TempDir::new().expect("tempdir");
    let (manifest_id, manifest_hash) = write_echo_manifest_with_deny_flags(&xdg_config_home);
    install_warrant(&paths_root, &workdir, &manifest_id, &manifest_hash);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("--yolo=true")
        .arg("hello")
        .env("XDG_CONFIG_HOME", xdg_config_home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "flag '--yolo' is blocked by tool_policy.deny_flags",
        ));
}
