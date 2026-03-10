use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;
use warrant_core::{LockOptions, lock_warrant_from_draft_path};
use wsh::app::resolve_paths;

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

fn install_test_warrant(paths_root: &TempDir, workdir: &TempDir) {
    let draft = workdir.path().join("draft.toml");
    let workdir_glob = format!("{}/**", workdir.path().display());
    let draft_text = r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-16T12:00:00Z"
issuer = "test@host"

[capabilities.commands]
allow = ["ls", "cat", "git", "cargo", "grep", "rm", "curl", "bash", "echo", "chmod", "touch"]
block = [
    "rm -rf /",
    "rm -rf ~",
    "curl * | bash",
    "chmod -R 777 /"
]

[capabilities.files]
read = { allow = true, paths = ["/tmp/**", "__WORKDIR_GLOB__"] }
write = { allow = true, paths = ["/tmp/**", "__WORKDIR_GLOB__"] }
delete = { allow = true, paths = ["/tmp/**", "__WORKDIR_GLOB__"] }

[capabilities.network]
allow = true
hosts = ["github.com", "crates.io"]

[capabilities.git]
push = { allow = true, branches = ["feature/*", "fix/*"] }
push_force = false

[capabilities.process]
kill = false
background = true

[policy]
command_default = "deny"
"#
    .replace("__WORKDIR_GLOB__", &workdir_glob);
    std::fs::write(&draft, draft_text).expect("write draft");
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

fn read_audit_lines(paths_root: &TempDir) -> Vec<String> {
    let log_path = paths_root
        .path()
        .join("etc")
        .join("warrant-shell")
        .join("audit.log");
    let text = std::fs::read_to_string(log_path).expect("read audit log");
    text.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn allowed_commands_produce_audit_entries() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .env("WSH_SESSION_ID", "session-allow")
        .assert()
        .success();

    let lines = read_audit_lines(&paths_root);
    assert_eq!(lines.len(), 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("valid json");
    assert_eq!(entry["decision"], "allow");
    assert_eq!(entry["reason"], "policy_check_passed");
    assert_eq!(entry["program"], "ls");
    assert_eq!(entry["session_id"], "session-allow");
    assert!(entry["policy_hash"].is_string());
    assert_eq!(entry["elevated"], false);
}

#[test]
fn denied_commands_produce_audit_entries() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("rm")
        .arg("-rf")
        .arg("/")
        .env("WSH_SESSION_ID", "session-deny")
        .assert()
        .failure()
        .stderr(predicate::str::contains("denied"));

    let lines = read_audit_lines(&paths_root);
    assert_eq!(lines.len(), 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("valid json");
    assert_eq!(entry["decision"], "deny");
    assert_eq!(entry["program"], "rm");
    assert_eq!(entry["session_id"], "session-deny");
    assert!(
        entry["reason"]
            .as_str()
            .unwrap_or("")
            .contains("blocked pattern")
    );
}

#[test]
fn audit_log_is_valid_json_lines() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .env("WSH_SESSION_ID", "jsonl-1")
        .assert()
        .success();

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("rm")
        .arg("-rf")
        .arg("/")
        .env("WSH_SESSION_ID", "jsonl-2")
        .assert()
        .failure();

    let lines = read_audit_lines(&paths_root);
    assert_eq!(lines.len(), 2);
    for line in lines {
        let parsed: Value = serde_json::from_str(&line).expect("json line parses");
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("command").is_some());
    }
}

#[test]
fn audit_subcommand_outputs_and_clears_log() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .env("WSH_SESSION_ID", "audit-cmd-1")
        .assert()
        .success();

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("rm")
        .arg("-rf")
        .arg("/")
        .env("WSH_SESSION_ID", "audit-cmd-2")
        .assert()
        .failure();

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("audit")
        .arg("--tail")
        .arg("1")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"decision\":\"deny\""));

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("audit")
        .arg("--tail")
        .arg("1")
        .assert()
        .success()
        .stdout(predicate::str::contains("DENY"))
        .stdout(predicate::str::contains("rm -rf /"));

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("audit")
        .arg("--clear")
        .write_stdin("yes\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("cleared"));

    let lines = read_audit_lines(&paths_root);
    assert!(lines.is_empty());
}

#[test]
fn find_exec_is_allowed_when_allowlisted_without_hardcoded_safety_class() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let draft = workdir.path().join("draft-safety.toml");
    let draft_text = r#"[warrant]
version = 1
tool = "warrant-shell"
created = "2026-02-16T12:00:00Z"
issuer = "test@host"

[capabilities.commands]
allow = ["find"]

[capabilities.files]
read = { allow = true, paths = ["/tmp/**"] }
write = { allow = true, paths = ["/tmp/**"] }
delete = { allow = true, paths = ["/tmp/**"] }

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
"#;
    std::fs::write(&draft, draft_text).expect("write draft");
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
        .arg("-name")
        .arg("*.toml")
        .assert()
        .success();

    let lines = read_audit_lines(&paths_root);
    assert_eq!(lines.len(), 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("valid json");
    assert_eq!(entry["decision"], "allow");
    assert_eq!(entry["reason"], "policy_check_passed");
}

#[test]
fn xdg_data_home_does_not_redirect_audit_log() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    let xdg_root = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    let session = "rt3-xdg-ignore";
    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .env("XDG_DATA_HOME", xdg_root.path())
        .env("WSH_SESSION_ID", session)
        .assert()
        .success();

    let system_log = paths_root
        .path()
        .join("etc")
        .join("warrant-shell")
        .join("audit.log");
    let system_text = std::fs::read_to_string(system_log).expect("system audit log");
    assert!(system_text.contains(session));

    let xdg_log = xdg_root.path().join("warrant-shell").join("audit.log");
    if xdg_log.exists() {
        let xdg_text = std::fs::read_to_string(xdg_log).expect("xdg log");
        assert!(
            !xdg_text.contains(session),
            "XDG log unexpectedly captured session"
        );
    }
}

#[test]
#[cfg(unix)]
fn denies_command_when_audit_write_fails_and_audit_required_is_true() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    let audit_dir = paths_root.path().join("etc").join("warrant-shell");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");
    let mut perms = std::fs::metadata(&audit_dir)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&audit_dir, perms).expect("chmod readonly");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Audit logging failed — command denied (audit_required=true)",
        ));
}

#[test]
#[cfg(unix)]
fn denies_command_when_audit_path_is_fifo() {
    let paths_root = TempDir::new().expect("tempdir");
    let workdir = TempDir::new().expect("tempdir");
    install_test_warrant(&paths_root, &workdir);

    let audit_path = paths_root
        .path()
        .join("etc")
        .join("warrant-shell")
        .join("audit.log");
    if audit_path.exists() {
        std::fs::remove_file(&audit_path).expect("remove prior audit log");
    }
    let status = std::process::Command::new("mkfifo")
        .arg(&audit_path)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed");

    wsh_cmd()
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("ls")
        .arg(workdir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Audit logging failed — command denied (audit_required=true)",
        ));
}
