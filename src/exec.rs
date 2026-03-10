use std::fs;
use std::process::{ChildStdout, Command, ExitStatus, Stdio};

use colored::Colorize;
use glob::Pattern;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use warrant_core::ToolPaths;

use crate::app::{AppError, AuditLogRequest, Result, evaluate_access, log_decision_with_policy};
use crate::audit::Decision;
use crate::parser::{ParsedCommand, Redirect, RedirectKind, parse_command};
use crate::paths::PathSource;
use crate::policy::resolve_program_path_with_dirs;

pub(crate) fn exec_command(
    paths: &ToolPaths,
    source: &PathSource,
    command: &[String],
    profile: Option<&str>,
) -> Result<()> {
    let (allowed, stripped_env_var_count, environment_strip, trusted_program_dirs) =
        match evaluate_access(paths, source, command)? {
            crate::app::AccessDecision::Allow {
                parsed,
                elevated,
                audit_required,
                resolved_program,
                environment_strip,
                trusted_program_dirs,
            } => {
                let stripped_env_var_count = stripped_env_var_count(&environment_strip);
                log_decision_with_policy(
                    paths,
                    command,
                    AuditLogRequest {
                        decision: Decision::Allow,
                        reason: "policy_check_passed",
                        elevated,
                        profile,
                        resolved_program: resolved_program.as_deref(),
                        audit_required,
                        stripped_env_var_count: Some(stripped_env_var_count),
                    },
                )?;
                (
                    parsed,
                    stripped_env_var_count,
                    environment_strip,
                    trusted_program_dirs,
                )
            }
            crate::app::AccessDecision::Deny {
                reason,
                audit_reason,
                elevated,
                audit_required,
            } => {
                log_decision_with_policy(
                    paths,
                    command,
                    AuditLogRequest {
                        decision: Decision::Deny,
                        reason: audit_reason.as_deref().unwrap_or(&reason),
                        elevated,
                        profile,
                        resolved_program: None,
                        audit_required,
                        stripped_env_var_count: None,
                    },
                )?;
                return Err(AppError::Message(format!(
                    "{}: {}",
                    "denied".red().bold(),
                    reason
                )));
            }
        };

    if allowed.program.is_empty() {
        return Err(AppError::Message("denied: empty command".to_string()));
    }

    let status = execute_checked_command(command, &environment_strip, &trusted_program_dirs)?;
    let _ = stripped_env_var_count;

    if status.success() {
        Ok(())
    } else {
        Err(AppError::Message(format!(
            "command exited with status {}",
            status.code().unwrap_or(1)
        )))
    }
}

#[derive(Clone, Copy)]
enum ChainOperator {
    And,
    Or,
}

fn execute_checked_command(
    tokens: &[String],
    environment_strip: &[String],
    trusted_program_dirs: &[std::path::PathBuf],
) -> Result<ExitStatus> {
    let (units, operators) = split_chain_units(tokens)?;
    let mut last_status: Option<ExitStatus> = None;

    for (idx, unit_tokens) in units.iter().enumerate() {
        let should_run = if idx == 0 {
            true
        } else {
            let prev = last_status.expect("previous status must exist");
            match operators[idx - 1] {
                ChainOperator::And => prev.success(),
                ChainOperator::Or => !prev.success(),
            }
        };

        if should_run {
            last_status = Some(execute_pipeline_unit(
                unit_tokens,
                environment_strip,
                trusted_program_dirs,
            )?);
        }
    }

    last_status.ok_or_else(|| AppError::Message("denied: empty command".to_string()))
}

fn split_chain_units(tokens: &[String]) -> Result<(Vec<Vec<String>>, Vec<ChainOperator>)> {
    let mut units = Vec::new();
    let mut operators = Vec::new();
    let mut current = Vec::new();

    for token in tokens {
        match token.as_str() {
            "&&" => {
                if current.is_empty() {
                    return Err(AppError::Message(
                        "denied: invalid command chain near '&&'".to_string(),
                    ));
                }
                units.push(std::mem::take(&mut current));
                operators.push(ChainOperator::And);
            }
            "||" => {
                if current.is_empty() {
                    return Err(AppError::Message(
                        "denied: invalid command chain near '||'".to_string(),
                    ));
                }
                units.push(std::mem::take(&mut current));
                operators.push(ChainOperator::Or);
            }
            _ => current.push(token.clone()),
        }
    }

    if current.is_empty() {
        return Err(AppError::Message(
            "denied: command chain cannot end with && or ||".to_string(),
        ));
    }
    units.push(current);

    Ok((units, operators))
}

fn split_pipeline_segments(tokens: &[String]) -> Result<Vec<Vec<String>>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();

    for token in tokens {
        if token == "|" {
            if current.is_empty() {
                return Err(AppError::Message(
                    "denied: invalid pipeline near '|'".to_string(),
                ));
            }
            segments.push(std::mem::take(&mut current));
            continue;
        }
        current.push(token.clone());
    }

    if current.is_empty() {
        return Err(AppError::Message(
            "denied: pipeline cannot end with '|'".to_string(),
        ));
    }
    segments.push(current);
    Ok(segments)
}

fn execute_pipeline_unit(
    tokens: &[String],
    environment_strip: &[String],
    trusted_program_dirs: &[std::path::PathBuf],
) -> Result<ExitStatus> {
    let segments = split_pipeline_segments(tokens)?;
    if segments.len() == 1 {
        let parsed = parse_command(&segments[0]).parsed;
        return run_single_segment(&parsed, environment_strip, trusted_program_dirs);
    }

    let mut children = Vec::new();
    let mut previous_stdout: Option<ChildStdout> = None;

    for (idx, segment_tokens) in segments.iter().enumerate() {
        let parsed = parse_command(segment_tokens).parsed;
        if parsed.program.is_empty() {
            return Err(AppError::Message("denied: empty command".to_string()));
        }
        let is_first = idx == 0;
        let is_last = idx + 1 == segments.len();
        if !is_first && has_stdin_redirect(&parsed.redirects) {
            return Err(AppError::Message(
                "denied: input redirection is only supported on the first pipeline segment"
                    .to_string(),
            ));
        }
        if !is_last && has_stdout_redirect(&parsed.redirects) {
            return Err(AppError::Message(
                "denied: output redirection is only supported on the last pipeline segment"
                    .to_string(),
            ));
        }

        let mut cmd = command_for_segment(&parsed, environment_strip, trusted_program_dirs)?;
        configure_stderr(&mut cmd, &parsed.redirects)?;

        if let Some(pipe) = previous_stdout.take() {
            cmd.stdin(Stdio::from(pipe));
        } else {
            configure_stdin(&mut cmd, &parsed.redirects, Stdio::inherit())?;
        }

        if !is_last {
            cmd.stdout(Stdio::piped());
        } else {
            configure_stdout(&mut cmd, &parsed.redirects, Stdio::inherit())?;
        }

        let mut child = cmd.spawn()?;
        if !is_last {
            previous_stdout = child.stdout.take();
        }
        children.push(child);
    }

    let mut last_status = None;
    for mut child in children {
        let status = child.wait()?;
        last_status = Some(status);
    }
    last_status.ok_or_else(|| AppError::Message("denied: empty command".to_string()))
}

fn run_single_segment(
    parsed: &ParsedCommand,
    environment_strip: &[String],
    trusted_program_dirs: &[std::path::PathBuf],
) -> Result<ExitStatus> {
    let mut cmd = command_for_segment(parsed, environment_strip, trusted_program_dirs)?;
    configure_stdin(&mut cmd, &parsed.redirects, Stdio::inherit())?;
    configure_stdout(&mut cmd, &parsed.redirects, Stdio::inherit())?;
    configure_stderr(&mut cmd, &parsed.redirects)?;
    Ok(cmd.status()?)
}

fn command_for_segment(
    parsed: &ParsedCommand,
    environment_strip: &[String],
    trusted_program_dirs: &[std::path::PathBuf],
) -> Result<Command> {
    let resolved = resolve_program_path_with_dirs(&parsed.program, trusted_program_dirs)
        .map_err(|deny| AppError::Message(deny.reason))?
        .to_string_lossy()
        .to_string();
    let mut cmd = Command::new(resolved);
    apply_environment_strip(&mut cmd, environment_strip);
    for (key, value) in &parsed.env_assignments {
        cmd.env(key, value);
    }
    cmd.args(&parsed.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(cmd)
}

fn has_stdin_redirect(redirects: &[Redirect]) -> bool {
    redirects
        .iter()
        .any(|redirect| matches!(redirect.kind, RedirectKind::Stdin))
}

fn has_stdout_redirect(redirects: &[Redirect]) -> bool {
    redirects
        .iter()
        .any(|redirect| matches!(redirect.kind, RedirectKind::Stdout | RedirectKind::Append))
}

fn configure_stdin(cmd: &mut Command, redirects: &[Redirect], default: Stdio) -> Result<()> {
    if let Some(redirect) = redirects
        .iter()
        .rev()
        .find(|redirect| matches!(redirect.kind, RedirectKind::Stdin))
    {
        let file = open_redirect_file_read(&redirect.target)?;
        cmd.stdin(Stdio::from(file));
    } else {
        cmd.stdin(default);
    }
    Ok(())
}

fn open_redirect_file_read(path: &std::path::Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

fn configure_stdout(cmd: &mut Command, redirects: &[Redirect], default: Stdio) -> Result<()> {
    if let Some(redirect) = redirects
        .iter()
        .rev()
        .find(|redirect| matches!(redirect.kind, RedirectKind::Stdout | RedirectKind::Append))
    {
        let file = match redirect.kind {
            RedirectKind::Append => open_redirect_file_append(&redirect.target)?,
            _ => open_redirect_file_truncate(&redirect.target)?,
        };
        cmd.stdout(Stdio::from(file));
    } else {
        cmd.stdout(default);
    }
    Ok(())
}

fn configure_stderr(cmd: &mut Command, redirects: &[Redirect]) -> Result<()> {
    if let Some(redirect) = redirects.iter().rev().find(|redirect| {
        matches!(
            redirect.kind,
            RedirectKind::Stderr | RedirectKind::StderrAppend
        )
    }) {
        let file = match redirect.kind {
            RedirectKind::StderrAppend => open_redirect_file_append(&redirect.target)?,
            _ => open_redirect_file_truncate(&redirect.target)?,
        };
        cmd.stderr(Stdio::from(file));
    } else {
        cmd.stderr(Stdio::inherit());
    }
    Ok(())
}

fn open_redirect_file_truncate(path: &std::path::Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

fn open_redirect_file_append(path: &std::path::Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

pub(crate) fn apply_environment_strip(cmd: &mut Command, environment_strip: &[String]) {
    if environment_strip.is_empty() {
        return;
    }
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().to_string();
        if should_strip_env_key(&key, environment_strip) {
            cmd.env_remove(&key);
        }
    }
}

pub(crate) fn should_strip_env_key(key: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let pat = pattern.trim();
        if pat.is_empty() {
            return false;
        }
        Pattern::new(pat)
            .map(|compiled| compiled.matches(key))
            .unwrap_or_else(|_| pat == key)
    })
}

fn stripped_env_var_count(environment_strip: &[String]) -> usize {
    std::env::vars_os()
        .map(|(key, _)| key.to_string_lossy().to_string())
        .filter(|key| should_strip_env_key(key, environment_strip))
        .count()
}
