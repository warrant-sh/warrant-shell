use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

fn install_profile_warrant(
    paths_root: &TempDir,
    workdir: &TempDir,
    profile: Option<&str>,
    issuer: &str,
    allow: &[&str],
) {
    let draft = workdir
        .path()
        .join(format!("{}-draft.toml", profile.unwrap_or("default")));

    let allow_line = allow
        .iter()
        .map(|cmd| format!("\"{cmd}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let draft_text = format!(
        r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-16T12:00:00Z"
issuer = {issuer:?}

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

    std::fs::write(&draft, draft_text).expect("write draft");
    let paths = resolve_paths(Some(paths_root.path()), profile).expect("resolve paths");
    lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect("lock");
}

fn read_audit_lines(paths_root: &TempDir, profile: Option<&str>) -> Vec<String> {
    let mut log_path = paths_root.path().join("etc").join("warrant-shell");
    if let Some(profile) = profile {
        log_path = log_path.join("profiles").join(profile);
    }
    log_path = log_path.join("audit.log");
    let text = std::fs::read_to_string(log_path).expect("read audit log");
    text.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn profile_uses_separate_warrant_path() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");

    install_profile_warrant(&paths_root, &workdir, Some("codex"), "codex@host", &["ls"]);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("--profile")
        .arg("codex")
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("issuer: codex@host"));

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("no warrant installed"));
}

#[test]
fn default_profile_still_works_without_profile_flag() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");

    install_profile_warrant(&paths_root, &workdir, None, "default@host", &["ls", "echo"]);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("issuer: default@host"));

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("hello")
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed"));
}

#[test]
fn profiles_subcommand_lists_installed_profiles() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");

    install_profile_warrant(&paths_root, &workdir, None, "default@host", &["ls"]);
    install_profile_warrant(&paths_root, &workdir, Some("codex"), "codex@host", &["ls"]);
    install_profile_warrant(
        &paths_root,
        &workdir,
        Some("bertie"),
        "bertie@host",
        &["echo"],
    );

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("profiles")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("default")
                .and(predicate::str::contains("issuer=default@host")),
        )
        .stdout(
            predicate::str::contains("codex").and(predicate::str::contains("issuer=codex@host")),
        )
        .stdout(
            predicate::str::contains("bertie").and(predicate::str::contains("issuer=bertie@host")),
        );
}

#[test]
fn audit_entries_include_profile_name() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");

    install_profile_warrant(&paths_root, &workdir, Some("codex"), "codex@host", &["ls"]);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("--profile")
        .arg("codex")
        .arg("check")
        .arg("ls")
        .arg("/tmp")
        .assert()
        .success();

    let lines = read_audit_lines(&paths_root, Some("codex"));
    assert_eq!(lines.len(), 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("valid json");
    assert_eq!(entry["profile"], "codex");
}

#[test]
fn profiles_can_hold_different_policies_for_same_command() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");

    install_profile_warrant(&paths_root, &workdir, Some("codex"), "codex@host", &["ls"]);
    install_profile_warrant(
        &paths_root,
        &workdir,
        Some("bertie"),
        "bertie@host",
        &["ls", "echo"],
    );

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("--profile")
        .arg("codex")
        .arg("check")
        .arg("echo")
        .arg("hi")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "not in capabilities.commands.allow",
        ));

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("--profile")
        .arg("bertie")
        .arg("check")
        .arg("echo")
        .arg("hi")
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed"));
}
