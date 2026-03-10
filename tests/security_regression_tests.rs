#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;
use wsh::draft::{DraftDecision, read_draft as read_tool_draft, write_draft as write_tool_draft};

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

fn set_draft_decision(path: &Path, decision: DraftDecision) {
    let mut draft = read_tool_draft(path).expect("read tool draft");
    for capability in draft.capabilities.values_mut() {
        capability.decision = decision;
        capability.scopes.clear();
    }
    write_tool_draft(path, &draft, false).expect("write tool draft");
}

fn write_draft(
    path: &Path,
    version: u64,
    allow: &[&str],
    files_read: &[&str],
    extra_commands: &str,
) {
    let allow_line = allow
        .iter()
        .map(|cmd| format!("\"{cmd}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let read_line = files_read
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let text = format!(
        r#"[warrant]
version = {version}
tool = "warrant-shell"
created = "2026-02-17T00:00:00Z"
issuer = "security@test"

[capabilities.commands]
allow = [{allow_line}]
{extra_commands}

[capabilities.files]
read = {{ allow = true, paths = [{read_line}] }}
write = {{ allow = true, paths = ["/tmp/**", "/home/**", "/var/**", "/private/var/**"] }}
delete = {{ allow = true, paths = ["/tmp/**", "/var/**", "/private/var/**"] }}

[capabilities.network]
allow = true
hosts = ["github.com", "crates.io"]

[capabilities.git]
push = false
push_force = false

[capabilities.process]
kill = false
background = false

[policy]
command_default = "deny"
"#
    );

    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, text).expect("write draft");
}

fn install_warrant(paths_root: &TempDir, workdir: &TempDir, allow: &[&str], extra_commands: &str) {
    let draft = workdir.path().join("draft.toml");
    write_draft(
        &draft,
        1,
        allow,
        &[
            "/tmp/**",
            "/home/**",
            "/etc/**",
            "/usr/**",
            "/var/**",
            "/private/var/**",
        ],
        extra_commands,
    );
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

fn audit_log_default(paths_root: &TempDir) -> PathBuf {
    paths_root
        .path()
        .join("etc")
        .join("warrant-shell")
        .join("audit.log")
}

fn install_warrant_with_environment_strip(
    paths_root: &TempDir,
    workdir: &TempDir,
    allow: &[&str],
    strip: &[&str],
) {
    let allow_line = allow
        .iter()
        .map(|cmd| format!("\"{cmd}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let strip_line = strip
        .iter()
        .map(|pattern| format!("\"{pattern}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let draft = workdir.path().join("draft.toml");
    let text = format!(
        r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-17T00:00:00Z"
issuer = "security@test"

[capabilities.commands]
allow = [{allow_line}]

[capabilities.files]
read = {{ allow = true, paths = ["/tmp/**", "/home/**", "/etc/**", "/usr/**", "/var/**", "/private/var/**"] }}
write = {{ allow = true, paths = ["/tmp/**", "/home/**", "/var/**", "/private/var/**"] }}
delete = {{ allow = true, paths = ["/tmp/**", "/var/**", "/private/var/**"] }}

[capabilities.network]
allow = true
hosts = ["github.com", "crates.io"]

[capabilities.git]
push = false
push_force = false

[capabilities.process]
kill = false
background = false

[capabilities.environment]
strip = [{strip_line}]

[policy]
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
    .expect("lock");
}

fn exec_env_output(paths_root: &TempDir, extra_env: &[(&str, &str)]) -> String {
    let mut cmd = wsh_cmd();
    cmd.arg("--paths-root")
        .arg(paths_root.path())
        .arg("exec")
        .arg("--")
        .arg("printenv");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("run printenv");
    assert!(
        output.status.success(),
        "printenv command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 printenv stdout")
}

// RT-001
#[test]
fn test_rt001_profile_path_traversal_rejected() {
    wsh_cmd()
        .arg("--profile")
        .arg("../../escape")
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid profile name"));
}

// RT-002
#[test]
fn test_rt002_project_mode_uses_system_keys() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let home = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "")
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();

    wsh_cmd()
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "")
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    let system_draft = home
        .path()
        .join(".config")
        .join("wsh")
        .join("drafts")
        .join("git.toml");
    let project_draft = project
        .path()
        .join(".warrant")
        .join("drafts")
        .join("git.toml");
    set_draft_decision(&system_draft, DraftDecision::Deny);
    set_draft_decision(&project_draft, DraftDecision::Deny);

    wsh_cmd()
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "")
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("lock")
        .assert()
        .success();

    assert!(!project.path().join(".warrant").join("private.key").exists());
    assert!(!project.path().join(".warrant").join("public.key").exists());
    assert!(
        paths_root
            .path()
            .join("etc")
            .join("warrant-shell")
            .join("signing")
            .join("private.key")
            .exists()
    );
}

// RT-003
#[test]
fn test_rt003_elevation_token_requires_valid_hmac() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo"], "");

    let host_key = resolve_paths(Some(paths_root.path()), None)
        .expect("resolve paths")
        .host_secret_path;
    std::fs::create_dir_all(host_key.parent().expect("parent")).expect("mkdir");
    std::fs::write(&host_key, "aa".repeat(32)).expect("write host key");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&host_key)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&host_key, perms).expect("chmod");
    }

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("elevate")
        .arg("--duration")
        .arg("1")
        .assert()
        .success();

    let session_path = std::fs::read_dir(paths_root.path().join("run").join("warrant-shell"))
        .expect("session dir")
        .next()
        .expect("session entry")
        .expect("entry")
        .path();
    let mut token: Value =
        serde_json::from_str(&std::fs::read_to_string(&session_path).expect("read token"))
            .expect("json");
    token["expires_at_epoch_secs"] = Value::from(9_999_999_999_u64);
    std::fs::write(
        &session_path,
        serde_json::to_string(&token).expect("serialize"),
    )
    .expect("rewrite");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("is-elevated")
        .assert()
        .success()
        .stdout(predicate::str::contains("false"));
}

// RT-004
#[test]
fn test_rt004_path_hijack_allowed_when_command_is_allowlisted() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["ls"], "");

    let evil = TempDir::new().expect("tempdir");
    let fake_ls = evil.path().join("ls");
    std::fs::write(&fake_ls, "#!/bin/sh\nexit 0\n").expect("write fake ls");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&fake_ls).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ls, perms).expect("chmod");
    }

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .env(
            "PATH",
            format!(
                "{}:{}",
                evil.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .assert()
        .success();
}

// RT-005
#[test]
fn test_rt005_find_exec_denied_as_wrapper_command() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["find"], "");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("find")
        .arg(".")
        .arg("-exec")
        .arg("echo")
        .arg("{}")
        .arg(";")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "not in capabilities.commands.allow",
        ));
}

// RT-005
#[test]
fn test_rt005_xargs_denied_as_wrapper_command() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["xargs"], "");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("xargs")
        .arg("echo")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "not in capabilities.commands.allow",
        ));
}

// RT-005
#[test]
fn test_rt005_make_dash_f_allowed_without_hardcoded_safety_class() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["make"], "");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("make")
        .arg("-f")
        .arg("evil.mk")
        .assert()
        .success();
}

// RT-006
#[test]
#[cfg(unix)]
fn test_rt006_symlink_path_escape_denied() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let allowed_dir = workdir.path().join("allowed");
    std::fs::create_dir_all(&allowed_dir).expect("mkdir allowed");
    symlink("/etc", allowed_dir.join("etc-link")).expect("symlink");

    let draft = workdir.path().join("draft.toml");
    write_draft(
        &draft,
        1,
        &["cat"],
        &[&format!("{}/**", allowed_dir.display())],
        "",
    );
    let paths = resolve_paths(Some(paths_root.path()), None).expect("resolve paths");
    lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect("lock");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("cat")
        .arg(allowed_dir.join("etc-link/passwd"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("outside capabilities.files.read.paths")
                .or(predicate::str::contains("symlink component")),
        );
}

// RT-007
#[test]
#[cfg(unix)]
fn test_rt007_audit_fail_closed_denies_command() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["ls"], "");

    let audit_dir = paths_root.path().join("etc").join("warrant-shell");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");
    let mut perms = std::fs::metadata(&audit_dir)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&audit_dir, perms).expect("chmod");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Audit logging failed"));
}

// RT-008
#[test]
fn test_rt008_version_over_max_rejected() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let draft = workdir.path().join("draft.toml");
    write_draft(&draft, 1_000_001, &["echo"], &["/tmp/**"], "");
    let paths = resolve_paths(Some(paths_root.path()), None).expect("resolve paths");
    let err = lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect_err("must reject oversized version");
    assert!(err.to_string().contains("exceeds maximum allowed"));
}

// RT2-001
#[test]
fn test_rt2_001_semicolon_in_token_not_reinterpreted() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo", "cat"], "");

    let marker = workdir.path().join("semicolon-marker");
    wsh_cmd()
        .current_dir(workdir.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("exec")
        .arg("--")
        .arg("echo")
        .arg(format!("OK;touch {}", marker.display()))
        .arg("|")
        .arg("cat")
        .assert()
        .success();

    assert!(
        !marker.exists(),
        "marker created by semicolon reinterpretation"
    );
}

// RT2-001
#[test]
fn test_rt2_001_backtick_in_token_not_reinterpreted() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo"], "");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("`id`")
        .assert()
        .failure()
        .stderr(predicate::str::contains("command substitution detected"));
}

// RT2-002
#[test]
fn test_rt2_002_bash_env_is_inherited_without_environment_policy() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["bash", "true"], "");

    let script = workdir.path().join("bash_env.sh");
    let marker = workdir.path().join("bash_env_marker");
    std::fs::write(&script, format!("touch {}\n", marker.display())).expect("write script");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("exec")
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg("true")
        .env("BASH_ENV", &script)
        .assert()
        .success();

    assert!(marker.exists(), "BASH_ENV marker was not inherited");
}

// RT2-002
#[test]
fn test_rt2_002_ld_preload_is_inherited_without_environment_policy() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["printenv"], "");

    let out = exec_env_output(&paths_root, &[("LD_PRELOAD", "/tmp/does-not-exist.so")]);
    assert!(out.contains("LD_PRELOAD=/tmp/does-not-exist.so"));
}

// RT2-003
#[test]
fn test_rt2_003_binary_outside_trusted_dirs_is_allowed_when_allowlisted() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["ls"], "");

    let evil = TempDir::new().expect("tempdir");
    let fake_ls = evil.path().join("ls");
    std::fs::write(&fake_ls, "#!/bin/sh\nexit 0\n").expect("write fake ls");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&fake_ls).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ls, perms).expect("chmod");
    }

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .env(
            "PATH",
            format!(
                "{}:{}",
                evil.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .assert()
        .success();
}

// RT2-004
#[test]
fn test_rt2_004_warrant_test_root_ignored_in_production() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let fake_root = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo"], "");

    let marker = "rt2-warrant-test-root";
    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg(marker)
        .env("WARRANT_TEST_ROOT", fake_root.path())
        .assert()
        .success();

    let default_text =
        std::fs::read_to_string(audit_log_default(&paths_root)).expect("default audit");
    assert!(default_text.contains(marker));
    let fake_log = fake_root.path().join("audit.log");
    assert!(
        !fake_log.exists(),
        "WARRANT_TEST_ROOT unexpectedly affected production path"
    );
}

// RT3-001
#[test]
fn test_rt3_001_rustc_wrapper_is_inherited_without_environment_policy() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["printenv"], "");

    let out = exec_env_output(&paths_root, &[("RUSTC_WRAPPER", "/tmp/wrapper")]);
    assert!(out.contains("RUSTC_WRAPPER=/tmp/wrapper"));
}

// RT3-001
#[test]
fn test_rt3_001_git_ssh_command_is_inherited_without_environment_policy() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["printenv"], "");

    let out = exec_env_output(&paths_root, &[("GIT_SSH_COMMAND", "/tmp/ssh-shim")]);
    assert!(out.contains("GIT_SSH_COMMAND=/tmp/ssh-shim"));
}

// RT3-002
#[test]
fn test_rt3_002_xdg_data_home_does_not_redirect_audit() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo"], "");

    let marker = "rt3-xdg-audit";
    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg(marker)
        .env("XDG_DATA_HOME", xdg.path())
        .assert()
        .success();

    let default_text =
        std::fs::read_to_string(audit_log_default(&paths_root)).expect("default audit");
    assert!(default_text.contains(marker));
    let xdg_log = xdg.path().join("warrant-shell").join("audit.log");
    if xdg_log.exists() {
        let xdg_text = std::fs::read_to_string(xdg_log).expect("xdg audit");
        assert!(!xdg_text.contains(marker));
    }
}

// RT3-003
#[test]
#[cfg(unix)]
fn test_rt3_003_fifo_audit_path_rejected() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["echo"], "");

    let audit_path = audit_log_default(&paths_root);
    if audit_path.exists() {
        std::fs::remove_file(&audit_path).expect("remove old audit log");
    }
    let status = std::process::Command::new("mkfifo")
        .arg(&audit_path)
        .status()
        .expect("mkfifo");
    assert!(status.success());

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("echo")
        .arg("hi")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Audit logging failed"));
}

#[test]
fn test_final_env_default_policy_inherits_variables() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["printenv"], "");

    let out = exec_env_output(
        &paths_root,
        &[
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/tmp/final-home"),
            ("USER", "final-user"),
            ("TERM", "xterm-final"),
        ],
    );
    assert!(
        out.contains("PATH=/usr/bin:/bin"),
        "PATH missing from child env"
    );
    assert!(
        out.contains("HOME=/tmp/final-home"),
        "HOME missing from child env"
    );
    assert!(
        out.contains("USER=final-user"),
        "USER missing from child env"
    );
    assert!(
        out.contains("TERM=xterm-final"),
        "TERM missing from child env"
    );
}

#[test]
fn test_final_env_environment_strip_policy_blocks_selected_vars() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant_with_environment_strip(
        &paths_root,
        &workdir,
        &["printenv"],
        &["BASH_ENV", "LD_PRELOAD", "RUSTC_WRAPPER", "GIT_SSH_COMMAND"],
    );

    let out = exec_env_output(
        &paths_root,
        &[
            ("BASH_ENV", "/tmp/bashenv.sh"),
            ("LD_PRELOAD", "/tmp/libevil.so"),
            ("RUSTC_WRAPPER", "/tmp/wrapper.sh"),
            ("GIT_SSH_COMMAND", "/tmp/sshshim.sh"),
        ],
    );
    assert!(!out.contains("BASH_ENV="), "BASH_ENV leaked into child env");
    assert!(
        !out.contains("LD_PRELOAD="),
        "LD_PRELOAD leaked into child env"
    );
    assert!(
        !out.contains("RUSTC_WRAPPER="),
        "RUSTC_WRAPPER leaked into child env"
    );
    assert!(
        !out.contains("GIT_SSH_COMMAND="),
        "GIT_SSH_COMMAND leaked into child env"
    );
}

#[test]
fn test_final_env_strip_policy_does_not_block_custom_var() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant_with_environment_strip(
        &paths_root,
        &workdir,
        &["printenv"],
        &["BASH_ENV", "LD_PRELOAD"],
    );

    let out = exec_env_output(&paths_root, &[("CUSTOM_VAR", "custom-value-123")]);
    assert!(
        out.contains("CUSTOM_VAR=custom-value-123"),
        "CUSTOM_VAR missing despite not being listed in strip policy"
    );
}

#[test]
fn test_final_env_default_policy_keeps_unknown_vars() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_warrant(&paths_root, &workdir, &["printenv"], "");

    let out = exec_env_output(
        &paths_root,
        &[("TEST_UNKNOWN_ENV_12345", "should-not-pass")],
    );
    assert!(
        out.contains("TEST_UNKNOWN_ENV_12345=should-not-pass"),
        "unknown env var should be inherited without strip policy"
    );
}

// RT-005
#[test]
fn test_rt005_find_allowed_without_wrapper_subcommand_when_command_default_allow() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let draft = workdir.path().join("draft.toml");
    write_draft(
        &draft,
        1,
        &["find"],
        &[
            "/tmp/**",
            "/home/**",
            "/etc/**",
            "/usr/**",
            "/var/**",
            "/private/var/**",
        ],
        "",
    );
    let draft_text = std::fs::read_to_string(&draft).expect("read draft");
    std::fs::write(
        &draft,
        draft_text.replace("command_default = \"deny\"", "command_default = \"allow\""),
    )
    .expect("write allow policy draft");
    let paths = resolve_paths(Some(paths_root.path()), None).expect("resolve paths");
    lock_warrant_from_draft_path(
        &draft,
        &paths,
        &LockOptions {
            create_keys_if_missing: true,
        },
    )
    .expect("lock");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("find")
        .arg(".")
        .arg("-maxdepth")
        .arg("1")
        .assert()
        .success();
}

// RT3-004
#[test]
fn test_rt3_004_concurrent_project_lock_preserves_all_entries() {
    let paths_root = TempDir::new().expect("tempdir");
    let setup = TempDir::new().expect("tempdir");
    let home = TempDir::new().expect("tempdir");
    let project_one = TempDir::new().expect("tempdir");
    let project_two = TempDir::new().expect("tempdir");
    let manifests = install_git_manifest_cache();

    wsh_cmd()
        .current_dir(setup.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "")
        .env("WSH_MANIFEST_DIR", manifests.path())
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();
    let system_draft = home
        .path()
        .join(".config")
        .join("wsh")
        .join("drafts")
        .join("git.toml");
    set_draft_decision(&system_draft, DraftDecision::Deny);

    for project in [&project_one, &project_two] {
        wsh_cmd()
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", "")
            .env("WSH_MANIFEST_DIR", manifests.path())
            .arg("--paths-root")
            .arg(paths_root.path())
            .arg("add")
            .arg("git")
            .arg("--scope")
            .arg("project")
            .assert()
            .success();
        let project_draft = project
            .path()
            .join(".warrant")
            .join("drafts")
            .join("git.toml");
        set_draft_decision(&project_draft, DraftDecision::Deny);
    }

    let bin = assert_cmd::cargo::cargo_bin!("wsh").to_path_buf();
    let root_path = paths_root.path().to_path_buf();
    let home_path = home.path().to_path_buf();
    let manifests_path = manifests.path().to_path_buf();
    let p1 = project_one.path().to_path_buf();
    let p2 = project_two.path().to_path_buf();

    let t1 = thread::spawn({
        let bin = bin.clone();
        let root_path = root_path.clone();
        let home_path = home_path.clone();
        let manifests_path = manifests_path.clone();
        move || {
            let status = std::process::Command::new(&bin)
                .current_dir(&p1)
                .env("HOME", &home_path)
                .env("XDG_CONFIG_HOME", "")
                .env("WSH_MANIFEST_DIR", &manifests_path)
                .arg("--paths-root")
                .arg(&root_path)
                .arg("lock")
                .status()
                .expect("lock one");
            assert!(status.success());
        }
    });
    let t2 = thread::spawn({
        let bin = bin.clone();
        let home_path = home_path.clone();
        let manifests_path = manifests_path.clone();
        move || {
            let status = std::process::Command::new(&bin)
                .current_dir(&p2)
                .env("HOME", &home_path)
                .env("XDG_CONFIG_HOME", "")
                .env("WSH_MANIFEST_DIR", &manifests_path)
                .arg("--paths-root")
                .arg(&root_path)
                .arg("lock")
                .status()
                .expect("lock two");
            assert!(status.success());
        }
    });
    t1.join().expect("t1");
    t2.join().expect("t2");

    let registry_path = paths_root
        .path()
        .join("etc")
        .join("warrant-shell")
        .join("projects.json");
    let registry: Value =
        serde_json::from_str(&std::fs::read_to_string(registry_path).expect("registry"))
            .expect("json");
    assert_eq!(registry.as_object().map(|obj| obj.len()), Some(2));
}
