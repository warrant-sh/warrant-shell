use std::fs;
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use colored::Colorize;
use serde_json::{Value, json};

use crate::app::{
    AppError, Result, create_draft_for_manifest, init_onboarding, onboarding_completed,
    resolve_paths,
};
use crate::audit;
use crate::bundles::{get_bundle, list_bundles};
use crate::cli::DraftScopeArg;
use crate::manifest::{manifest_cache_dirs, resolve_manifest};
use crate::registry;

#[allow(dead_code)]
const WSH_SHELL_WRAPPER: &str = include_str!("../scripts/wsh-shell");
const CLAUDE_WSH_GUARD_SCRIPT: &str = r#"#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import sys

def main():
    if os.getenv("WSH_GUARD") == "0":
        return 0

    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return 0
        return guard_command(command)

    if tool_name in ("Edit", "Write"):
        file_path = tool_input.get("file_path", "")
        if not isinstance(file_path, str) or not file_path.strip():
            return 0
        return guard_command("touch " + shlex.quote(file_path))

    return 0

def guard_command(command):
    result = subprocess.run(
        ["wsh", "guard", command],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "denied by warrant policy").strip()
        if message:
            print(message, file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
"#;

pub(crate) fn setup_bundles(bundle_names: &[String], accept_defaults: bool) -> Result<()> {
    if !onboarding_completed()? {
        init_onboarding()?;
    }

    if !accept_defaults && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err(AppError::Message(
            "`wsh setup` requires an interactive terminal".to_string(),
        ));
    }

    // Resolve all requested bundles upfront.
    let available = list_bundles();
    let available_names: Vec<_> = available.iter().map(|b| b.name.as_str()).collect();
    let mut bundles = Vec::new();
    for name in bundle_names {
        let bundle = get_bundle(name).ok_or_else(|| {
            AppError::Message(format!(
                "unknown bundle '{name}'. Available: {}",
                available_names.join(", ")
            ))
        })?;
        bundles.push(bundle);
    }

    // Collect and deduplicate manifests across all bundles.
    let mut all_manifest_names: Vec<String> = Vec::new();
    for bundle in &bundles {
        for m in &bundle.manifests {
            if !all_manifest_names.contains(m) {
                all_manifest_names.push(m.clone());
            }
        }
    }

    // Pull any missing manifests.
    let missing_manifests: Vec<_> = all_manifest_names
        .iter()
        .filter(|name| resolve_manifest(name).is_none())
        .cloned()
        .collect();
    if !missing_manifests.is_empty() {
        let cache_dir = first_writable_manifest_cache_dir()?;
        for manifest_name in &missing_manifests {
            println!(
                "{} {} from registry...",
                "pulling".cyan().bold(),
                manifest_name
            );
            registry::pull_manifest_to_cache(manifest_name, &cache_dir).map_err(|err| {
                AppError::Message(format!("failed to pull manifest '{manifest_name}': {err}"))
            })?;
        }
    }

    // Resolve all manifests.
    let mut resolved_manifests = Vec::new();
    for manifest_name in &all_manifest_names {
        let Some(manifest) = resolve_manifest(manifest_name) else {
            if resolved_manifests.is_empty() {
                return Err(AppError::Message(
                    "No manifests available. Run `wsh pull` first to fetch manifests from the registry."
                        .to_string(),
                ));
            }
            return Err(AppError::Message(format!(
                "manifest not found for '{manifest_name}'"
            )));
        };
        resolved_manifests.push(manifest);
    }
    if resolved_manifests.is_empty() {
        return Err(AppError::Message(
            "No manifests available. Run `wsh pull` first to fetch manifests from the registry."
                .to_string(),
        ));
    }

    // Display what we're setting up.
    let descriptions: Vec<_> = bundles
        .iter()
        .map(|b| b.description.to_lowercase())
        .collect();
    println!("Setting up warrant for {}...\n", descriptions.join(", "));
    println!("{}", "Manifests:".bold());
    for manifest in &resolved_manifests {
        let manifest_name = &manifest.manifest.id;
        if let Some(summary) = manifest.manifest.summary.as_deref() {
            println!(
                "  {} {} ({summary})",
                "✓".green().bold(),
                manifest_name.bold()
            );
        } else {
            println!("  {} {}", "✓".green().bold(), manifest_name.bold());
        }
    }
    println!();

    for manifest in &resolved_manifests {
        let _ = create_draft_for_manifest(manifest, DraftScopeArg::System, false, true)?;
    }
    println!(
        "{} added {} manifest draft(s)",
        "ok".green().bold(),
        all_manifest_names.len()
    );

    // --- Lock policy (single sudo prompt for all bundles) ---
    let mut lock_failed = false;
    if prompt_yes_no(
        "Lock policy? (requires sudo) [Y/n]: ",
        true,
        accept_defaults,
    )? {
        let status = Command::new("sudo")
            .arg("wsh")
            .arg("lock")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if !status.success() {
            lock_failed = true;
            eprintln!(
                "{} sudo wsh lock failed (status {}). Run `sudo wsh lock` manually.",
                "⚠".yellow(),
                status.code().unwrap_or(1)
            );
        } else {
            println!("{} policy locked", "ok".green().bold());
            if let Ok(paths) = resolve_paths(None, None) {
                match audit::verify_daemon_health(&paths) {
                    Ok(()) => println!("{} audit daemon verified", "✓".green().bold()),
                    Err(_) => eprintln!(
                        "⚠ audit daemon not responding — run: sudo systemctl restart wsh-auditd"
                    ),
                }
            } else {
                eprintln!("⚠ audit daemon not responding — run: sudo systemctl restart wsh-auditd");
            }
        }
    }

    // --- Install Claude PreToolUse hook (separate sudo prompt) ---
    let needs_claude_hook = bundles.iter().any(|b| {
        b.aliases
            .iter()
            .any(|a| a.alias == "claude" || a.name == "claude")
    });
    if needs_claude_hook
        && prompt_yes_no(
            "Install Claude guard hook to system path? (requires sudo) [Y/n]: ",
            true,
            accept_defaults,
        )?
    {
        let home = std::env::var("HOME").unwrap_or_default();
        ensure_claude_prettool_wsh_guard(&PathBuf::from(home))?;
    }

    // --- Shell aliases (for agents that opt in to wrapping) ---
    let wrappable: Vec<&crate::bundles::BundleAlias> = bundles
        .iter()
        .flat_map(|b| b.aliases.iter())
        .filter(|a| a.wrap)
        .collect();

    if !wrappable.is_empty() {
        if wrappable.len() > 1 {
            println!("\nWhich commands should be wrapped with warrant?");
        }
        let mut selected_aliases: Vec<(&str, &str)> = Vec::new();
        for agent in &wrappable {
            let prompt_text = if wrappable.len() == 1 {
                format!("\n  Wrap {} with warrant? [Y/n]: ", agent.alias.bold())
            } else {
                format!("  Wrap {}? [Y/n]: ", agent.alias.bold())
            };
            if prompt_yes_no(&prompt_text, true, accept_defaults)? {
                selected_aliases.push((agent.alias.as_str(), agent.name.as_str()));
            }
        }
        if !selected_aliases.is_empty() {
            let shell_rc = detect_shell_rc_path()?;
            let added = add_selected_aliases_to_shell_rc(&selected_aliases, &shell_rc)?;
            if added == 0 {
                println!(
                    "{} aliases already present in {}",
                    "ok".green().bold(),
                    shell_rc.display()
                );
            } else {
                println!(
                    "{} added {} alias(es) to {}",
                    "ok".green().bold(),
                    added,
                    shell_rc.display()
                );
            }
        } else {
            println!("{} no aliases selected", "ok".green().bold());
        }
    }

    // --- Final summary ---
    let default_cmd = bundles
        .iter()
        .flat_map(|b| b.aliases.first())
        .next()
        .map(|a| a.alias.as_str())
        .unwrap_or("wsh");
    let guard_all = bundles.iter().any(|b| b.guard_all_sessions);
    println!();
    if lock_failed {
        println!(
            "{} Shell guard hooks installed. Run `sudo wsh lock` to activate policy enforcement.",
            "⚠".yellow(),
        );
    } else {
        println!(
            "{} Done! Every command is now policy-enforced and audited.",
            "✓".green().bold(),
        );
    }
    println!("  Run '{}' to get started.", default_cmd.bold());
    if guard_all {
        println!("  Tip: Run `wsh guard --all` to guard all shell sessions on this machine.");
    }
    println!(
        "  Open a new terminal to activate, or run: {}",
        shell_reload_hint().bold()
    );
    Ok(())
}

fn system_hook_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/warrant-shell/claude_hook.py")
    } else {
        PathBuf::from("/usr/local/lib/warrant-shell/claude_hook.py")
    }
}

fn install_system_hook(sys_path: &Path) -> Result<()> {
    let parent = sys_path
        .parent()
        .ok_or_else(|| AppError::Message("no parent directory for system hook path".to_string()))?;

    // Write the hook to a temp file, then sudo install it.
    let tmp = std::env::temp_dir().join("wsh_claude_hook.py");
    fs::write(&tmp, CLAUDE_WSH_GUARD_SCRIPT)?;

    let mkdir_status = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(parent)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| AppError::Message(format!("failed to run sudo mkdir: {err}")))?;
    if !mkdir_status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(AppError::Message(format!(
            "failed to create directory {} (sudo required)",
            parent.display()
        )));
    }

    let install_status = Command::new("sudo")
        .args(["install", "-m", "555"])
        .arg(&tmp)
        .arg(sys_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| AppError::Message(format!("failed to run sudo install: {err}")))?;
    let _ = fs::remove_file(&tmp);
    if !install_status.success() {
        return Err(AppError::Message(format!(
            "failed to install guard hook to {} (sudo required)",
            sys_path.display()
        )));
    }
    Ok(())
}

fn ensure_claude_prettool_wsh_guard(home: &Path) -> Result<()> {
    let sys_path = system_hook_path();
    let needs_install = if sys_path.exists() {
        // Check if the existing hook content matches; update if stale.
        let existing = fs::read_to_string(&sys_path).unwrap_or_default();
        if existing == CLAUDE_WSH_GUARD_SCRIPT {
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&sys_path)?.permissions();
                if perms.mode() & 0o222 != 0 {
                    perms.set_mode(0o555);
                    let _ = fs::set_permissions(&sys_path, perms);
                }
            }
            println!(
                "  {} system hook up to date at {}",
                "✓".green().bold(),
                sys_path.display()
            );
            false
        } else {
            println!(
                "  {} system hook at {} is outdated — updating...",
                "⚠".yellow(),
                sys_path.display()
            );
            true
        }
    } else {
        true
    };

    if needs_install {
        install_system_hook(&sys_path)?;
        println!(
            "  {} guard hook installed to {} (root-owned, read-only)",
            "✓".green().bold(),
            sys_path.display()
        );
    }

    let script_path = sys_path;

    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    fs::create_dir_all(&claude_dir)?;

    let mut settings = if settings_path.exists() {
        let raw = fs::read_to_string(&settings_path)?;
        serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !settings.is_object() {
        settings = json!({});
    }
    let root = settings
        .as_object_mut()
        .ok_or_else(|| AppError::Message("invalid Claude settings root object".to_string()))?;

    let hooks = root.entry("hooks".to_string()).or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| AppError::Message("invalid Claude hooks object".to_string()))?;

    let pre = hooks_obj
        .entry("PreToolUse".to_string())
        .or_insert_with(|| json!([]));
    if !pre.is_array() {
        *pre = json!([]);
    }
    let pre_arr = pre
        .as_array_mut()
        .ok_or_else(|| AppError::Message("invalid Claude PreToolUse hook list".to_string()))?;

    let command = format!("python3 '{}'", script_path.display());

    // Check if any existing entry already references the guard hook (by either path).
    let existing_idx = pre_arr.iter().position(|entry| {
        let matcher_ok = entry
            .get("matcher")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m == "Bash|Edit|Write" || m == "Bash");
        let hook_has_cmd = entry
            .get("hooks")
            .and_then(|v| v.as_array())
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|v| v.as_str())
                        .is_some_and(|c| {
                            c.contains("wsh_guard_pretool.py") || c.contains("claude_hook.py")
                        })
                })
            });
        matcher_ok && hook_has_cmd
    });

    let new_entry = json!({
        "matcher": "Bash|Edit|Write",
        "hooks": [
            {
                "type": "command",
                "command": command,
                "timeout": 10
            }
        ]
    });

    let needs_write = if let Some(idx) = existing_idx {
        // Entry exists — check if the command path matches the current target.
        let current_cmd = pre_arr[idx]
            .get("hooks")
            .and_then(|v| v.as_array())
            .and_then(|h| h.first())
            .and_then(|h| h.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if current_cmd == command {
            false
        } else {
            // Update to point at the (possibly upgraded) path.
            pre_arr[idx] = new_entry;
            true
        }
    } else {
        pre_arr.push(new_entry);
        true
    };

    if needs_write {
        let rendered = serde_json::to_string_pretty(&settings)
            .map_err(|err| AppError::Message(format!("failed to render Claude settings: {err}")))?;
        fs::write(&settings_path, format!("{rendered}\n"))?;
        println!(
            "  {} Claude PreToolUse hook added to {}",
            "✓".green().bold(),
            settings_path.display()
        );
    } else {
        println!(
            "{} Claude PreToolUse hook already configured in {}",
            "ok".green().bold(),
            settings_path.display()
        );
    }

    Ok(())
}

fn first_writable_manifest_cache_dir() -> Result<PathBuf> {
    for dir in manifest_cache_dirs() {
        if fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let probe = dir.join(".wsh-write-test");
        if fs::write(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            return Ok(dir);
        }
    }
    Err(AppError::Message(
        "no writable manifest cache directory found".to_string(),
    ))
}

fn prompt_yes_no(prompt: &str, default_yes: bool, accept_defaults: bool) -> Result<bool> {
    if accept_defaults {
        return Ok(default_yes);
    }

    loop {
        print!("{prompt}");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
            return Ok(true);
        }
        if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
            return Ok(false);
        }
        println!("please answer y or n");
    }
}

#[allow(dead_code)]
fn install_wsh_shell_wrapper() -> Result<()> {
    let target = Path::new("/usr/local/bin/wsh-shell");

    if fs::write(target, WSH_SHELL_WRAPPER).is_ok() {
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(target)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(target, perms)?;
        }
        return Ok(());
    }

    let tmp = std::env::temp_dir().join("wsh-shell");
    fs::write(&tmp, WSH_SHELL_WRAPPER)?;
    let status = std::process::Command::new("sudo")
        .args(["install", "-m", "755"])
        .arg(&tmp)
        .arg(target)
        .status()
        .map_err(|e| AppError::Message(format!("failed to run sudo install: {e}")))?;
    let _ = fs::remove_file(&tmp);
    if !status.success() {
        return Err(AppError::Message(format!(
            "sudo install failed with status {status}"
        )));
    }
    Ok(())
}

fn detect_shell_rc_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| {
        AppError::Message("HOME is not set; cannot resolve shell rc file".to_string())
    })?;
    let home = PathBuf::from(home);
    let shell = std::env::var("SHELL").unwrap_or_default();

    let ordered = if shell.contains("zsh") {
        vec![".zshrc", ".bashrc", ".bash_profile"]
    } else {
        vec![".bashrc", ".bash_profile", ".zshrc"]
    };

    for filename in &ordered {
        let candidate = home.join(filename);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Ok(home.join(ordered[0]))
}

fn shell_reload_hint() -> &'static str {
    let shell = std::env::var("SHELL").unwrap_or_default();
    if shell.contains("bash") {
        "source ~/.bashenv && source ~/.bashrc"
    } else {
        "source ~/.zshenv && source ~/.zshrc"
    }
}

fn add_selected_aliases_to_shell_rc(aliases: &[(&str, &str)], shell_rc: &Path) -> Result<usize> {
    let mut text = if shell_rc.exists() {
        fs::read_to_string(shell_rc)?
    } else {
        String::new()
    };
    let mut added = 0usize;
    let mut pending = String::new();

    for (alias_name, binary_name) in aliases {
        let alias_key = format!("alias {alias_name}=");
        let line = format!(
            "alias {alias_name}='WSH_GUARD=1 BASH_ENV=\"$HOME/.bashenv\" {}'",
            guarded_agent_command(binary_name)
        );
        let existing_line = text
            .lines()
            .find(|line| line.trim_start().starts_with(&alias_key))
            .map(str::to_string);
        if let Some(existing_line) = existing_line {
            if existing_line.trim() == line {
                continue;
            }
            if existing_line.contains("WSH_GUARD=1") {
                text = text.replacen(&existing_line, &line, 1);
                println!("  {} {}", "✓".green().bold(), line);
                added += 1;
            }
            continue;
        }

        println!("  {} {}", "✓".green().bold(), line);
        pending.push_str(&line);
        pending.push('\n');
        added += 1;
    }

    if !aliases.is_empty() {
        let home = std::env::var("HOME").unwrap_or_default();
        let guard_marker = "# warrant-shell guard";

        let zsh_guard_block = format!(
            "\n{guard_marker}\n\
             if [[ -n \"${{ZSH_EXECUTION_STRING:-}}\" && \"${{WSH_GUARD:-}}\" != \"0\" && ( -n \"${{WSH_GUARD:-}}\" || \"${{CODEX_CI:-}}\" = \"1\" ) ]]; then\n\
             \x20 wsh guard \"$ZSH_EXECUTION_STRING\" || exit 1\n\
             fi\n"
        );
        let bash_guard_block = format!(
            "\n{guard_marker}\n\
             if [[ -n \"${{BASH_EXECUTION_STRING:-}}\" && \"${{WSH_GUARD:-}}\" != \"0\" && ( -n \"${{WSH_GUARD:-}}\" || \"${{CODEX_CI:-}}\" = \"1\" ) ]]; then\n\
             \x20 wsh guard \"$BASH_EXECUTION_STRING\" || exit 1\n\
             fi\n"
        );

        let zshenv_path = PathBuf::from(&home).join(".zshenv");
        let zshenv_text = if zshenv_path.exists() {
            fs::read_to_string(&zshenv_path).unwrap_or_default()
        } else {
            String::new()
        };
        if !zshenv_text.contains(guard_marker) {
            let mut full = zshenv_text;
            if !full.is_empty() && !full.ends_with('\n') {
                full.push('\n');
            }
            full.push_str(&zsh_guard_block);
            fs::write(&zshenv_path, full)?;
            println!(
                "  {} warrant guard added to {}",
                "✓".green().bold(),
                zshenv_path.display()
            );
            added += 1;
        }

        if shell_rc
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == ".zshrc")
            && !text.contains(guard_marker)
        {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&zsh_guard_block);
            println!(
                "  {} warrant guard mirrored to {}",
                "✓".green().bold(),
                shell_rc.display()
            );
            added += 1;
        }

        let bashenv_path = PathBuf::from(&home).join(".bashenv");
        let bashenv_text = if bashenv_path.exists() {
            fs::read_to_string(&bashenv_path).unwrap_or_default()
        } else {
            String::new()
        };
        if !bashenv_text.contains(guard_marker) {
            let mut full = bashenv_text;
            if !full.is_empty() && !full.ends_with('\n') {
                full.push('\n');
            }
            full.push_str(&bash_guard_block);
            fs::write(&bashenv_path, full)?;
            println!(
                "  {} warrant guard added to {}",
                "✓".green().bold(),
                bashenv_path.display()
            );
            added += 1;
        }

        // Keep interactive/login bash shells consistent by sourcing ~/.bashenv.
        let bash_loader_marker = "# warrant-shell bashenv loader";
        let bash_loader_block = format!(
            "\n{bash_loader_marker}\n\
             if [[ -f \"$HOME/.bashenv\" ]]; then\n\
             \x20 . \"$HOME/.bashenv\"\n\
             fi\n"
        );
        for bash_rc in [
            PathBuf::from(&home).join(".bashrc"),
            PathBuf::from(&home).join(".bash_profile"),
        ] {
            let bash_rc_text = if bash_rc.exists() {
                fs::read_to_string(&bash_rc).unwrap_or_default()
            } else {
                String::new()
            };
            if !bash_rc_text.contains(bash_loader_marker) {
                let mut full = bash_rc_text;
                if !full.is_empty() && !full.ends_with('\n') {
                    full.push('\n');
                }
                full.push_str(&bash_loader_block);
                fs::write(&bash_rc, full)?;
                println!(
                    "  {} bashenv loader added to {}",
                    "✓".green().bold(),
                    bash_rc.display()
                );
                added += 1;
            }
        }
    }

    if added > 0 {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&pending);
        fs::write(shell_rc, text)?;
    }

    Ok(added)
}

fn guarded_agent_command(binary_name: &str) -> String {
    binary_name.to_string()
}
