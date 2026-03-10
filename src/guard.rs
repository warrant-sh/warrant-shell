use colored::Colorize;
use warrant_core::ToolPaths;

use crate::app::{
    AccessDecision, AuditLogRequest, Result, evaluate_access, log_decision_with_policy,
};
use crate::audit::Decision;
use crate::parser::parse_command;
use crate::paths::PathSource;
use crate::shell_parser::parse_shell_command;

/// Shell builtins that are skipped by the guard (no evaluation, no audit logging).
///
/// These execute inside the shell process and never spawn an external binary,
/// so there is nothing for wsh to intercept at the OS level. Logging them would
/// create enormous noise (hundreds per minute in a typical agent session) with
/// no security value.
///
/// **Deliberately excluded from this list** (i.e. they ARE evaluated and logged):
/// - `eval`   — executes arbitrary strings as code; classic evasion vector
/// - `exec`   — replaces the shell process entirely, bypassing further guards
/// - `source` / `.` — runs arbitrary script files in the current shell
const SHELL_BUILTINS: &[&str] = &[
    "if", "then", "else", "fi", "for", "do", "done", "while", "until", "case", "esac", "function",
    "select", "coproc", "{", "}", "!", "[[", "print", "printf", "echo", "cd", "set", "unset",
    "setopt", "unsetopt", "typeset", "declare", "local", "readonly", "true", "false", ":", "test",
    "[", "return", "exit", "break", "continue", "shift", "wait", "type", "pushd", "popd", "dirs",
    "fg", "bg", "jobs", "let", "getopts", "pwd",
];

pub(crate) fn guard_command(
    paths: &ToolPaths,
    source: &PathSource,
    command_string: &str,
    profile: Option<&str>,
) -> Result<()> {
    let command_has_shell_syntax = has_shell_syntax(command_string);
    let parsed = parse_shell_command(command_string).map_err(|err| {
        crate::app::AppError::Message(format!("denied: shell parse failed: {err}"))
    })?;
    guard_parsed_segments(
        paths,
        source,
        command_string,
        command_has_shell_syntax,
        profile,
        &parsed,
    )?;
    Ok(())
}

fn guard_parsed_segments(
    paths: &ToolPaths,
    source: &PathSource,
    command_string: &str,
    command_has_shell_syntax: bool,
    profile: Option<&str>,
    parsed: &crate::shell_parser::ShellParseResult,
) -> Result<()> {
    for tokens in &parsed.segments {
        if tokens.is_empty() {
            continue;
        }

        let Some(program) = effective_program_name(tokens) else {
            continue;
        };
        if SHELL_BUILTINS.contains(&program.as_str()) && !command_has_shell_syntax {
            continue;
        }

        match evaluate_access(paths, source, tokens)? {
            AccessDecision::Allow {
                elevated,
                audit_required,
                resolved_program,
                ..
            } => {
                log_decision_with_policy(
                    paths,
                    tokens,
                    AuditLogRequest {
                        decision: Decision::Allow,
                        reason: "policy_check_passed",
                        elevated,
                        profile,
                        resolved_program: resolved_program.as_deref(),
                        audit_required,
                        stripped_env_var_count: None,
                    },
                )?;
            }
            AccessDecision::Deny {
                reason,
                audit_reason,
                elevated,
                audit_required,
            } => {
                log_decision_with_policy(
                    paths,
                    tokens,
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
                eprintln!(
                    "{}: {}",
                    "denied by warrant policy".red().bold(),
                    command_string
                );
                return Err(crate::app::AppError::Message(reason));
            }
        }
    }
    for subst in &parsed.substitutions {
        guard_parsed_segments(
            paths,
            source,
            command_string,
            true, // substitutions always have shell syntax
            profile,
            subst,
        )?;
    }
    Ok(())
}

fn has_shell_syntax(cmd: &str) -> bool {
    if cmd.contains('\n') || cmd.contains('\r') {
        return true;
    }

    if cmd.contains("$(") || cmd.contains('`') {
        return true;
    }

    if cmd.contains('$') {
        return true;
    }

    if has_unquoted_redirection(cmd) || cmd.contains("<<") {
        return true;
    }

    if cmd.contains('|') || cmd.contains(';') || cmd.contains("&&") || cmd.contains("||") {
        return true;
    }

    if looks_like_brace_expansion(cmd) {
        return true;
    }

    let mut tokens = cmd.split_whitespace();
    let mut program = tokens.next();
    while let Some(token) = program {
        if !looks_like_env_assignment(token) {
            break;
        }
        program = tokens.next();
    }

    matches!(program, Some("export" | "unset" | "set"))
}

fn has_unquoted_redirection(cmd: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if !in_single && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if !in_single && !in_double && (ch == '>' || ch == '<') {
            return true;
        }
    }
    false
}

fn looks_like_brace_expansion(text: &str) -> bool {
    for token in text.split_whitespace() {
        let Some(open) = token.find('{') else {
            continue;
        };
        let Some(close) = token.rfind('}') else {
            continue;
        };
        if close > open + 1 && token[open + 1..close].contains(',') {
            return true;
        }
    }
    false
}

fn looks_like_env_assignment(token: &str) -> bool {
    if token.starts_with('-') {
        return false;
    }
    let Some(eq_index) = token.find('=') else {
        return false;
    };
    eq_index > 0
}

fn effective_program_name(tokens: &[String]) -> Option<String> {
    let parsed = parse_command(tokens).parsed;
    if parsed.program.is_empty() {
        return None;
    }
    if parsed.program == "builtin" {
        let target = parsed
            .args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .and_then(|arg| arg.rsplit('/').next().map(ToOwned::to_owned));
        if target.is_some() {
            return target;
        }
    }
    Some(
        parsed
            .program
            .rsplit('/')
            .next()
            .unwrap_or(&parsed.program)
            .to_string(),
    )
}

#[cfg(test)]
pub(crate) fn unwrap_shell_dash_c(command: &[String]) -> Option<(String, Vec<String>)> {
    if command.len() < 3 {
        return None;
    }
    let program = command[0].rsplit('/').next().unwrap_or(&command[0]);
    if !matches!(program, "sh" | "bash" | "zsh" | "dash") {
        return None;
    }
    if command[1] != "-c" {
        return None;
    }
    let inner = command[2..].join(" ");
    if inner.is_empty() {
        return None;
    }

    let mut binaries = Vec::new();
    for segment in inner.split(&['&', '|', ';'][..]) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let first_cmd = segment
            .split_whitespace()
            .find(|tok| !tok.contains('=') || tok.starts_with('-') || tok.starts_with('/'));
        if let Some(bin) = first_cmd {
            let bin_name = bin.rsplit('/').next().unwrap_or(bin);
            if !bin_name.is_empty() {
                binaries.push(bin_name.to_string());
            }
        }
    }

    if binaries.is_empty() {
        return None;
    }
    Some((inner, binaries))
}

pub(crate) fn detect_shell_evasion(tokens: &[String]) -> Option<&'static str> {
    for token in tokens {
        if token.contains("$(") || token.contains('`') {
            return Some("command substitution detected ($() or backticks)");
        }
        if token.contains("$'") {
            return Some("ANSI-C quoted string detected ($'...')");
        }
    }
    if has_unquoted_variable_expansion(tokens) {
        return Some("variable expansion detected ($VAR or ${VAR})");
    }
    if tokens
        .iter()
        .any(|token| token.contains('\n') || token.contains('\r'))
    {
        return Some("embedded newline detected");
    }
    if tokens.iter().any(|token| token == "eval") {
        return Some("eval detected");
    }
    let joined = tokens.join(" ");
    if looks_like_brace_expansion(&joined) {
        return Some("brace expansion detected");
    }
    for token in tokens {
        if (token.contains("\"\"") && token.len() > 2) || (token.contains("''") && token.len() > 2)
        {
            return Some("suspected string concatenation evasion (adjacent quotes)");
        }
        let chars: Vec<char> = token.chars().collect();
        for i in 1..chars.len().saturating_sub(1) {
            if (chars[i] == '"' || chars[i] == '\'')
                && !chars[i - 1].is_whitespace()
                && !chars[i + 1].is_whitespace()
            {
                return Some("suspected string concatenation evasion (quotes within token)");
            }
        }
    }
    if joined.to_ascii_lowercase().contains("base64") && looks_like_base64_pipe_to_shell(&joined) {
        return Some("base64 decode piped to shell");
    }
    None
}

fn has_unquoted_variable_expansion(tokens: &[String]) -> bool {
    for token in tokens {
        let chars: Vec<char> = token.chars().collect();
        for (idx, ch) in chars.iter().enumerate() {
            if *ch != '$' {
                continue;
            }
            if let Some(next) = chars.get(idx + 1)
                && (*next == '{' || *next == '_' || next.is_ascii_alphabetic())
            {
                return true;
            }
        }
    }
    false
}

fn looks_like_base64_pipe_to_shell(cmd: &str) -> bool {
    let compact = cmd
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    [
        "|sh",
        "|bash",
        "|zsh",
        "|dash",
        "|ksh",
        "|fish",
        "|/bin/sh",
        "|/bin/bash",
        "|envsh",
        "|envbash",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        SHELL_BUILTINS, detect_shell_evasion, effective_program_name, has_shell_syntax,
        unwrap_shell_dash_c,
    };

    #[test]
    fn unwrap_shell_dash_c_simple() {
        let cmd = vec!["sh".into(), "-c".into(), "curl https://example.com".into()];
        let (inner, bins) = unwrap_shell_dash_c(&cmd).expect("should unwrap");
        assert_eq!(inner, "curl https://example.com");
        assert_eq!(bins, vec!["curl"]);
    }

    #[test]
    fn unwrap_shell_dash_c_chained() {
        let cmd = vec![
            "bash".into(),
            "-c".into(),
            "cd /tmp && curl https://evil.com && rm -rf /".into(),
        ];
        let (_, bins) = unwrap_shell_dash_c(&cmd).expect("should unwrap");
        assert_eq!(bins, vec!["cd", "curl", "rm"]);
    }

    #[test]
    fn unwrap_shell_dash_c_piped() {
        let cmd = vec![
            "sh".into(),
            "-c".into(),
            "cat file.txt | grep foo | wc -l".into(),
        ];
        let (_, bins) = unwrap_shell_dash_c(&cmd).expect("should unwrap");
        assert_eq!(bins, vec!["cat", "grep", "wc"]);
    }

    #[test]
    fn unwrap_shell_dash_c_with_env_prefix() {
        let cmd = vec![
            "sh".into(),
            "-c".into(),
            "FOO=bar curl https://example.com".into(),
        ];
        let (_, bins) = unwrap_shell_dash_c(&cmd).expect("should unwrap");
        assert_eq!(bins, vec!["curl"]);
    }

    #[test]
    fn unwrap_non_shell_returns_none() {
        let cmd = vec!["python3".into(), "-c".into(), "print('hello')".into()];
        assert!(unwrap_shell_dash_c(&cmd).is_none());
    }

    #[test]
    fn unwrap_shell_no_dash_c_returns_none() {
        let cmd = vec!["sh".into(), "script.sh".into()];
        assert!(unwrap_shell_dash_c(&cmd).is_none());
    }

    #[test]
    fn unwrap_shell_dash_c_full_path() {
        let cmd = vec![
            "/bin/bash".into(),
            "-c".into(),
            "curl https://example.com".into(),
        ];
        let (_, bins) = unwrap_shell_dash_c(&cmd).expect("should unwrap");
        assert_eq!(bins, vec!["curl"]);
    }

    #[test]
    fn command_builtin_is_not_skipped_by_guard() {
        assert!(!SHELL_BUILTINS.contains(&"command"));
    }

    #[test]
    fn effective_program_uses_first_non_env_token() {
        let cmd = vec![
            "SNAPSHOT_FILE=/tmp/s.sh".into(),
            "source".into(),
            "~/.zshrc".into(),
        ];
        assert_eq!(effective_program_name(&cmd).as_deref(), Some("source"));
    }

    #[test]
    fn effective_program_is_none_for_env_only_assignments() {
        let cmd = vec!["FOO=bar".into(), "BAR=baz".into()];
        assert_eq!(effective_program_name(&cmd), None);
    }

    #[test]
    fn effective_program_unwraps_builtin_target() {
        let cmd = vec!["builtin".into(), "source".into(), "/tmp/payload.sh".into()];
        assert_eq!(effective_program_name(&cmd).as_deref(), Some("source"));
    }

    #[test]
    fn alias_builtin_is_not_skipped_by_guard() {
        assert!(!SHELL_BUILTINS.contains(&"alias"));
    }

    #[test]
    fn security_relevant_builtins_are_not_skipped_by_guard() {
        assert!(!SHELL_BUILTINS.contains(&"hash"));
        assert!(!SHELL_BUILTINS.contains(&"umask"));
        assert!(!SHELL_BUILTINS.contains(&"ulimit"));
        assert!(!SHELL_BUILTINS.contains(&"time"));
        assert!(!SHELL_BUILTINS.contains(&"noglob"));
    }

    #[test]
    fn evasion_command_substitution_dollar() {
        assert!(
            detect_shell_evasion(&["$(echo curl)".into(), "https://evil.com".into()]).is_some()
        );
    }

    #[test]
    fn evasion_command_substitution_backtick() {
        assert!(detect_shell_evasion(&["`echo curl`".into(), "https://evil.com".into()]).is_some());
    }

    #[test]
    fn evasion_eval() {
        assert!(
            detect_shell_evasion(&["eval".into(), "cu\"r\"l".into(), "https://evil.com".into()])
                .is_some()
        );
    }

    #[test]
    fn evasion_adjacent_quotes() {
        assert!(detect_shell_evasion(&["cu\"\"rl".into(), "https://evil.com".into()]).is_some());
    }

    #[test]
    fn evasion_hex_escape() {
        assert!(
            detect_shell_evasion(&["$'\\x63\\x75\\x72\\x6c'".into(), "https://evil.com".into()])
                .is_some()
        );
    }

    #[test]
    fn evasion_ansi_c_octal_escape() {
        assert!(
            detect_shell_evasion(&["$'\\143\\165\\162\\154'".into(), "https://evil.com".into()])
                .is_some()
        );
    }

    #[test]
    fn evasion_ansi_c_unicode_escape() {
        assert!(
            detect_shell_evasion(&[
                "$'\\u0063\\u0075\\u0072\\u006c'".into(),
                "https://evil.com".into()
            ])
            .is_some()
        );
    }

    #[test]
    fn evasion_ansi_c_mixed_escape() {
        assert!(detect_shell_evasion(&["$'cu\\x72l'".into(), "https://evil.com".into()]).is_some());
    }

    #[test]
    fn evasion_base64_to_shell() {
        assert!(
            detect_shell_evasion(&[
                "echo".into(),
                "Y3VybA==".into(),
                "|".into(),
                "base64".into(),
                "-d".into(),
                "|".into(),
                "bash".into(),
            ])
            .is_some()
        );
    }

    #[test]
    fn no_evasion_normal_command() {
        assert!(detect_shell_evasion(&["git".into(), "status".into()]).is_none());
    }

    #[test]
    fn no_evasion_quoted_args() {
        assert!(detect_shell_evasion(&["echo".into(), "hello world".into()]).is_none());
    }

    #[test]
    fn no_evasion_chained_normal() {
        assert!(
            detect_shell_evasion(&[
                "cd".into(),
                "/tmp".into(),
                "&&".into(),
                "ls".into(),
                "-la".into()
            ])
            .is_none()
        );
    }

    #[test]
    fn shell_syntax_detects_export_with_separator() {
        assert!(has_shell_syntax("export PATH=/evil; ls"));
    }

    #[test]
    fn shell_syntax_detects_newline_separator() {
        assert!(has_shell_syntax("echo ok\nid"));
    }

    #[test]
    fn shell_syntax_detects_redirection() {
        assert!(has_shell_syntax("echo test > /sensitive"));
    }

    #[test]
    fn shell_syntax_detects_descriptor_redirection() {
        assert!(has_shell_syntax("echo test 2>&1"));
        assert!(has_shell_syntax("echo test >&2"));
        assert!(has_shell_syntax("echo test &>/tmp/all.log"));
        assert!(has_shell_syntax("cat <>/tmp/rw"));
    }

    #[test]
    fn shell_syntax_detects_pipe() {
        assert!(has_shell_syntax("printf evil | base64"));
    }

    #[test]
    fn shell_syntax_detects_subshell() {
        assert!(has_shell_syntax("echo $(id)"));
    }

    #[test]
    fn shell_syntax_detects_variable_expansion() {
        assert!(has_shell_syntax("printf %s \"$HOME\""));
    }

    #[test]
    fn shell_syntax_detects_unset_and_set_builtins() {
        assert!(has_shell_syntax("unset PATH"));
        assert!(has_shell_syntax("set -e"));
    }

    #[test]
    fn shell_syntax_detects_brace_expansion() {
        assert!(has_shell_syntax("{rm,-rf,/}"));
    }

    #[test]
    fn shell_syntax_is_false_for_plain_builtin_without_metacharacters() {
        assert!(!has_shell_syntax("echo hello"));
    }
}
