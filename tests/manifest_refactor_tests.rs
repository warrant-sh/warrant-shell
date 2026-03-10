use std::collections::BTreeMap;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wsh::draft::{
    DraftDecision, generate_draft_from_manifest, read_draft, validate_draft, write_draft,
};
use wsh::manifest::{Manifest, parse_manifest};
use wsh::{compiler::compile_drafts, transforms::apply_transform};

fn wsh_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("wsh"))
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let lock = LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("env lock");
        let original = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        Self {
            key,
            original,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe { std::env::set_var(self.key, value) };
        } else {
            unsafe { std::env::remove_var(self.key) };
        }
    }
}

fn manifest_text(tool: &str) -> &'static str {
    match tool {
        "git" => {
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
match = ["reset"]
capability = "git.reset"
"#
        }
        "cargo" => {
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/cargo"
tool = "cargo"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["build"]
capability = "cargo.build"
"#
        }
        "npm" => {
            r#"
[manifest]
schema = "warrant.manifest.v1"
id = "warrant-sh/npm"
tool = "npm"
tool_version = "*"
manifest_version = "1.0.0"

[[commands]]
match = ["install"]
capability = "npm.install"
"#
        }
        _ => panic!("unknown test tool {tool}"),
    }
}

fn test_manifest(tool: &str) -> Manifest {
    parse_manifest(manifest_text(tool)).expect("test manifest")
}

fn write_manifests(dir: &std::path::Path, tools: &[&str]) {
    std::fs::create_dir_all(dir).expect("mkdir manifests");
    for tool in tools {
        std::fs::write(dir.join(format!("{tool}.toml")), manifest_text(tool))
            .expect("write manifest");
    }
}

fn all_deny_except(
    draft_path: &std::path::Path,
    allow_overrides: &[(&str, BTreeMap<String, Vec<String>>)],
) {
    let mut draft = read_draft(draft_path).expect("read draft");

    for capability in draft.capabilities.values_mut() {
        capability.decision = DraftDecision::Deny;
        capability.scopes.clear();
    }

    for (capability, scopes) in allow_overrides {
        let entry = draft
            .capabilities
            .get_mut(*capability)
            .expect("capability exists");
        entry.decision = DraftDecision::Allow;
        entry.scopes = scopes.clone();
    }

    write_draft(draft_path, &draft, false).expect("write draft");
}

fn add_git_draft(paths_root: &TempDir, project: &TempDir) -> std::path::PathBuf {
    let xdg_config_home = paths_root.path().join("xdg");

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .assert()
        .success();
    let system_draft = xdg_config_home.join("wsh").join("drafts").join("git.toml");
    let mut system_draft_doc = read_draft(&system_draft).expect("read system draft");
    for capability in system_draft_doc.capabilities.values_mut() {
        capability.decision = DraftDecision::Allow;
        capability.scopes.clear();
    }
    write_draft(&system_draft, &system_draft_doc, false).expect("write system draft");

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("add")
        .arg("git")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    project
        .path()
        .join(".warrant")
        .join("drafts")
        .join("git.toml")
}

fn lock_git(paths_root: &TempDir, project: &TempDir) {
    let xdg_config_home = paths_root.path().join("xdg");
    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("lock")
        .arg("git")
        .assert()
        .success();
}

#[test]
fn parses_test_manifests() {
    for tool in ["git", "cargo", "npm"] {
        let manifest = test_manifest(tool);
        assert_eq!(manifest.manifest.tool, tool);
        assert!(!manifest.commands.is_empty());
    }
}

#[test]
fn rejects_manifest_with_unknown_schema() {
    let text = r#"
[manifest]
schema = "warrant.manifest.v999"
id = "official/test"
tool = "test"
tool_version = ">=1.0"
manifest_version = "1.0.0"

[[commands]]
match = []
capability = "test.run"
"#;

    let err = parse_manifest(text).expect_err("must reject unsupported schema");
    assert!(err.to_string().contains("unsupported manifest schema"));
}

#[test]
fn rejects_manifest_missing_required_fields() {
    let text = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/test"
tool_version = ">=1.0"
manifest_version = "1.0.0"

[[commands]]
match = []
capability = "test.run"
"#;

    assert!(parse_manifest(text).is_err());
}

#[test]
fn draft_generation_starts_in_review_state() {
    let manifest = test_manifest("cargo");
    let draft = generate_draft_from_manifest(&manifest);
    assert!(
        draft
            .capabilities
            .values()
            .all(|cap| cap.decision == DraftDecision::Review)
    );
}

#[test]
fn validate_draft_accepts_allow_and_deny_only() {
    let manifest = test_manifest("git");
    let mut draft = generate_draft_from_manifest(&manifest);

    for (idx, cap) in draft.capabilities.values_mut().enumerate() {
        cap.decision = if idx % 2 == 0 {
            DraftDecision::Allow
        } else {
            DraftDecision::Deny
        };
    }

    validate_draft(&draft, &manifest).expect("allow/deny draft should validate");
}

#[test]
fn validate_draft_rejects_unknown_scope_keys() {
    let manifest = test_manifest("git");
    let mut draft = generate_draft_from_manifest(&manifest);
    let push = draft
        .capabilities
        .get_mut("git.push")
        .expect("git.push exists");
    push.decision = DraftDecision::Allow;
    push.scopes
        .insert("unknown_scope".to_string(), vec!["x".to_string()]);

    let err = validate_draft(&draft, &manifest).expect_err("must reject unknown scope key");
    assert!(err.to_string().contains("unknown scope key"));
}

#[test]
fn compile_single_draft_to_policy() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git"]);
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    let manifest = test_manifest("git");
    let mut draft = generate_draft_from_manifest(&manifest);
    for cap in draft.capabilities.values_mut() {
        cap.decision = DraftDecision::Deny;
    }
    write_draft(&drafts_dir.join("git.toml"), &draft, false).expect("write draft");

    let compiled = compile_drafts(&drafts_dir, None).expect("compile single draft");
    assert!(!compiled.capabilities.is_empty());
    assert_eq!(compiled.compiled_from.len(), 1);
}

#[test]
fn compile_multiple_drafts_merges_policy() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git", "npm"]);
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    for tool in ["git", "npm"] {
        let manifest = test_manifest(tool);
        let mut draft = generate_draft_from_manifest(&manifest);
        for cap in draft.capabilities.values_mut() {
            cap.decision = DraftDecision::Deny;
        }
        write_draft(&drafts_dir.join(format!("{tool}.toml")), &draft, false).expect("write draft");
    }

    let compiled = compile_drafts(&drafts_dir, None).expect("compile merged drafts");
    assert!(
        compiled
            .capabilities
            .keys()
            .any(|key| key.starts_with("git."))
    );
    assert!(
        compiled
            .capabilities
            .keys()
            .any(|key| key.starts_with("npm."))
    );
    assert_eq!(compiled.compiled_from.len(), 2);
}

#[test]
fn compile_detects_conflicting_decisions() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git"]);
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    let manifest = test_manifest("git");

    let mut allow = generate_draft_from_manifest(&manifest);
    for cap in allow.capabilities.values_mut() {
        cap.decision = DraftDecision::Deny;
    }
    allow
        .capabilities
        .get_mut("git.push")
        .expect("git.push")
        .decision = DraftDecision::Allow;
    write_draft(&drafts_dir.join("git-allow.toml"), &allow, false).expect("write allow");

    let mut deny = generate_draft_from_manifest(&manifest);
    for cap in deny.capabilities.values_mut() {
        cap.decision = DraftDecision::Deny;
    }
    write_draft(&drafts_dir.join("git-deny.toml"), &deny, false).expect("write deny");

    let err = compile_drafts(&drafts_dir, None).expect_err("must reject conflicting drafts");
    assert!(
        err.to_string()
            .contains("conflict for capability 'git.push'")
    );
}

#[test]
fn compile_detects_overlapping_manifest_claims() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("mkdir manifests");
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    let safe_manifest = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/super-safe-git"
tool = "git"
tool_version = ">=2.30"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "git.push"
default = "deny"
"#;
    let unsafe_manifest = r#"
[manifest]
schema = "warrant.manifest.v1"
id = "official/unsafe-git"
tool = "git"
tool_version = ">=2.30"
manifest_version = "1.0.0"

[[commands]]
match = ["push"]
capability = "git.push_anywhere"
default = "allow"
"#;
    std::fs::write(manifests_dir.join("super-safe-git.toml"), safe_manifest).expect("write safe");
    std::fs::write(manifests_dir.join("unsafe-git.toml"), unsafe_manifest).expect("write unsafe");

    std::fs::write(
        drafts_dir.join("super-safe-git.toml"),
        r#"[draft]
schema = "warrant.draft.v1"
manifest = "official/super-safe-git@1.0.0"
tool = "git"
state = "editable"

[capabilities]
git.push = "deny"
"#,
    )
    .expect("write safe draft");

    std::fs::write(
        drafts_dir.join("unsafe-git.toml"),
        r#"[draft]
schema = "warrant.draft.v1"
manifest = "official/unsafe-git@1.0.0"
tool = "git"
state = "editable"

[capabilities]
git.push_anywhere = "allow"
"#,
    )
    .expect("write unsafe draft");

    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let err = compile_drafts(&drafts_dir, None).expect_err("must reject overlapping claims");
    assert!(err.to_string().contains("overlapping manifest claims"));
}

#[test]
fn compile_rejects_review_entries() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git"]);
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    let manifest = test_manifest("git");
    let mut draft = generate_draft_from_manifest(&manifest);
    let capability = draft
        .capabilities
        .get_mut("git.push")
        .expect("git.push capability");
    capability.decision = DraftDecision::Review;
    write_draft(&drafts_dir.join("git.toml"), &draft, false).expect("write draft");

    let err = compile_drafts(&drafts_dir, None).expect_err("review entries should be rejected");
    assert!(err.to_string().contains("unresolved review decision"));
}

#[test]
fn compile_selected_tool_only() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg_config_home = tmp.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git", "npm"]);
    let _guard = EnvVarGuard::set("XDG_CONFIG_HOME", &xdg_config_home);
    let drafts_dir = tmp.path().join("drafts");
    std::fs::create_dir_all(&drafts_dir).expect("mkdir drafts");

    for tool in ["git", "npm"] {
        let manifest = test_manifest(tool);
        let mut draft = generate_draft_from_manifest(&manifest);
        for cap in draft.capabilities.values_mut() {
            cap.decision = DraftDecision::Deny;
        }
        write_draft(&drafts_dir.join(format!("{tool}.toml")), &draft, false).expect("write draft");
    }

    let compiled = compile_drafts(&drafts_dir, Some("git")).expect("compile selected tool");
    assert!(
        compiled
            .capabilities
            .keys()
            .all(|key| key.starts_with("git."))
    );
    assert_eq!(compiled.compiled_from.len(), 1);
}

#[test]
fn transforms_cover_expected_behaviors_and_edges() {
    assert_eq!(apply_transform("literal", "abc"), Some("abc".to_string()));

    let cwd = std::env::current_dir().expect("cwd");
    assert_eq!(
        apply_transform("path", "src").expect("path transform"),
        cwd.join("src").to_string_lossy().to_string()
    );

    assert_eq!(
        apply_transform("hostname", "https://GitHub.com/rust-lang/rust"),
        Some("github.com".to_string())
    );
    assert_eq!(apply_transform("hostname", ""), None);
    assert_eq!(apply_transform("hostname", "https:///missing-host"), None);

    assert_eq!(
        apply_transform("email_domain", "Alice@Example.COM"),
        Some("example.com".to_string())
    );
    assert_eq!(apply_transform("email_domain", ""), None);

    assert_eq!(apply_transform("glob", "*.rs"), Some("*.rs".to_string()));

    assert_eq!(
        apply_transform("git_remote", "origin"),
        Some("origin".to_string())
    );
    assert_eq!(
        apply_transform("git_remote", "git@github.com:owner/repo.git"),
        Some("github.com".to_string())
    );

    assert_eq!(
        apply_transform("hostname", "https://例子.测试/路径"),
        Some("例子.测试".to_string())
    );
}

#[test]
fn wsh_add_edit_search_and_full_manifest_flow() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg_config_home = paths_root.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git"]);

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("search")
        .arg("git")
        .assert()
        .success()
        .stdout(predicate::str::contains("warrant-sh/git"));

    let draft_path = add_git_draft(&paths_root, &project);
    assert!(draft_path.exists());

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("edit")
        .arg("git")
        .arg("--editor")
        .arg("true")
        .arg("--scope")
        .arg("project")
        .assert()
        .success();

    let mut scopes = BTreeMap::new();
    scopes.insert("remote".to_string(), vec!["origin".to_string()]);
    scopes.insert("branch".to_string(), vec!["main".to_string()]);
    all_deny_except(&draft_path, &[("git.push", scopes)]);

    lock_git(&paths_root, &project);

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("git")
        .arg("push")
        .arg("origin")
        .arg("main")
        .assert()
        .success();

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("git")
        .arg("push")
        .arg("upstream")
        .arg("main")
        .assert()
        .failure()
        .stderr(predicate::str::contains("denied"));
}

#[test]
fn manifest_aware_exec_denies_unknown_git_subcommand() {
    let paths_root = TempDir::new().expect("tempdir");
    let project = TempDir::new().expect("tempdir");
    let xdg_config_home = paths_root.path().join("xdg");
    let manifests_dir = xdg_config_home.join("wsh").join("manifests");
    write_manifests(&manifests_dir, &["git"]);
    let draft_path = add_git_draft(&paths_root, &project);

    all_deny_except(&draft_path, &[]);
    lock_git(&paths_root, &project);

    wsh_cmd()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--paths-root")
        .arg(paths_root.path())
        .arg("check")
        .arg("git")
        .arg("frobnicate")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no manifest command mapping matched",
        ));
}
