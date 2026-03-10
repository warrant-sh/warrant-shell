use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

fn install_warrant(
    paths_root: &TempDir,
    workdir: &TempDir,
    capability_toml: &str,
    policy_extra_toml: &str,
) {
    let draft = workdir.path().join("draft.toml");
    let text = format!(
        r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-20T00:00:00Z"
issuer = "test@host"

[capabilities]
{capability_toml}

[capabilities.commands]
allow = ["echo", "printf", "npm", "pip"]

[policy]
command_default = "deny"
{policy_extra_toml}
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

fn locked_manifest_policy_toml(dir: &TempDir) -> String {
    let manifests_dir = dir.path().join("wsh").join("manifests");
    let mut entries = std::fs::read_dir(&manifests_dir)
        .expect("read manifests dir")
        .map(|entry| entry.expect("manifest entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
        .collect::<Vec<_>>();
    entries.sort();

    let refs = entries
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).expect("read manifest");
            let manifest = wsh::manifest::parse_manifest(&text).expect("parse manifest");
            let hash = wsh::manifest::manifest_hash(&manifest).expect("hash manifest");
            format!(
                "{{ id = \"{}\", hash = \"{}\" }}",
                manifest.manifest.id, hash
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("manifests = [{refs}]")
}

fn write_custom_manifest(dir: &TempDir, package_policy: &str) {
    let manifests_dir = dir.path().join("wsh").join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");
    // Only include package_ecosystem/package_scope when policy requires them
    let extra = if package_policy == "denylist" || package_policy == "allowlist" {
        "package_ecosystem = \"npm\"\npackage_scope = \"packages\""
    } else {
        ""
    };
    let manifest = format!(
        r#"[manifest]
schema = "warrant.manifest.v1"
id = "official/npm-custom"
tool = "echo"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "{package_policy}"
{extra}

    [[commands]]
    match = ["install"]
capability = "echo.install"
    scope = {{ key = "packages", from = "arg_rest", transform = "literal" }}
"#
    );
    std::fs::write(manifests_dir.join("echo.toml"), manifest).expect("write manifest");
}

fn write_default_package_manifests(dir: &TempDir) {
    let manifests_dir = dir.path().join("wsh").join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");
    let npm_manifest = r#"[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/npm"
tool = "echo"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "npm"
package_scope = "packages"

[[commands]]
match = ["install"]
capability = "echo.install"
scope = { key = "packages", from = "arg_rest", transform = "literal" }
"#;
    std::fs::write(manifests_dir.join("echo.toml"), npm_manifest).expect("write npm manifest");

    let pip_manifest = r#"[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/pip"
tool = "printf"
tool_version = "*"
manifest_version = "1.0.0"

[tool_policy]
package_policy = "denylist"
package_ecosystem = "pypi"
package_scope = "packages"

[[commands]]
match = ["install"]
capability = "printf.install"
scope = { key = "packages", from = "arg_rest", transform = "literal" }
"#;
    std::fs::write(manifests_dir.join("printf.toml"), pip_manifest).expect("write pip manifest");
}

fn write_test_denylists() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("npm.txt"),
        "000webhost-admin\nmiddle-package\nzzz-last-entry\n",
    )
    .expect("write npm denylist");
    std::fs::write(dir.path().join("pypi.txt"), "0wneg\n").expect("write pypi denylist");
    std::fs::write(dir.path().join("cargo.txt"), "").expect("write cargo denylist");
    std::fs::write(dir.path().join("last_updated"), "2026-02-20T21:34:00Z\n")
        .expect("write last_updated");
    dir
}

fn with_denylist_env(cmd: &mut Command, denylist_dir: &Path) {
    cmd.env("WSH_DENYLIST_DIR", denylist_dir);
}

#[test]
fn known_malicious_npm_package_is_denied() {
    let denylist = write_test_denylists();
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let manifest_dir = TempDir::new().expect("tempdir");
    write_default_package_manifests(&manifest_dir);
    let policy_extra = locked_manifest_policy_toml(&manifest_dir);
    install_warrant(
        &paths_root,
        &workdir,
        "\"echo.install\" = true",
        &policy_extra,
    );

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("install")
        .arg("000webhost-admin")
        .env("XDG_CONFIG_HOME", manifest_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("known malicious package"));
}

#[test]
fn legitimate_npm_package_is_allowed() {
    let denylist = write_test_denylists();
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let manifest_dir = TempDir::new().expect("tempdir");
    write_default_package_manifests(&manifest_dir);
    let policy_extra = locked_manifest_policy_toml(&manifest_dir);
    install_warrant(
        &paths_root,
        &workdir,
        "\"echo.install\" = true",
        &policy_extra,
    );

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("install")
        .arg("express")
        .env("XDG_CONFIG_HOME", manifest_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed"));
}

#[test]
fn denylist_disabled_open_mode_allows_malicious_package() {
    let denylist = write_test_denylists();
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let manifest_dir = TempDir::new().expect("tempdir");
    write_custom_manifest(&manifest_dir, "open");
    let policy_extra = locked_manifest_policy_toml(&manifest_dir);
    install_warrant(
        &paths_root,
        &workdir,
        "\"echo.install\" = true",
        &policy_extra,
    );

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("install")
        .arg("000webhost-admin")
        .env("XDG_CONFIG_HOME", manifest_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed"));
}

#[test]
fn pip_denylist_blocks_known_malicious_package() {
    let denylist = write_test_denylists();
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let manifest_dir = TempDir::new().expect("tempdir");
    write_default_package_manifests(&manifest_dir);
    let policy_extra = locked_manifest_policy_toml(&manifest_dir);
    install_warrant(
        &paths_root,
        &workdir,
        "\"printf.install\" = true",
        &policy_extra,
    );

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("printf")
        .arg("install")
        .arg("0wneg")
        .env("XDG_CONFIG_HOME", manifest_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("known malicious package"));
}

#[test]
fn allowlist_mode_restricts_to_listed_packages() {
    let denylist = write_test_denylists();
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let manifest_dir = TempDir::new().expect("tempdir");
    write_custom_manifest(&manifest_dir, "allowlist");
    let policy_extra = locked_manifest_policy_toml(&manifest_dir);
    install_warrant(
        &paths_root,
        &workdir,
        "\"echo.install\" = { allow = true, packages = [\"express\"] }",
        &policy_extra,
    );

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("install")
        .arg("lodash")
        .env("XDG_CONFIG_HOME", manifest_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("denied"));
}

#[test]
fn package_check_reads_runtime_files() {
    let denylist = write_test_denylists();

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, denylist.path());
    cmd.arg("package-check")
        .arg("npm")
        .arg("middle-package")
        .assert()
        .success()
        .stdout(predicate::str::contains("warning"))
        .stdout(predicate::str::contains(
            "denylist last updated: 2026-02-20T21:34:00Z",
        ))
        .stdout(predicate::str::contains("(3 npm packages)"));
}

#[test]
fn missing_denylist_dir_fails_closed() {
    let missing = TempDir::new().expect("tempdir");
    let missing_path = missing.path().join("does-not-exist");

    let mut cmd = wsh_cmd();
    with_denylist_env(&mut cmd, &missing_path);
    cmd.arg("package-check")
        .arg("npm")
        .arg("000webhost-admin")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "is in the malicious package database",
        ));
}
