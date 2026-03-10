use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env_assignments: Vec<(String, String)>,
    pub file_paths: Vec<PathBuf>,
    pub flags: Vec<String>,
    pub is_piped: bool,
    pub is_chained: bool,
    pub redirects: Vec<Redirect>,
    pub subcommands: Vec<ParsedCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub target: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    Stdout,
    Stderr,
    StderrAppend,
    Stdin,
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutcome {
    pub parsed: ParsedCommand,
    pub unsupported_shell_features: Vec<String>,
}

type SimpleParts = (String, Vec<String>, Vec<Redirect>, Vec<(String, String)>);

pub fn parse_command(tokens: &[String]) -> ParseOutcome {
    let unsupported_shell_features = find_unsupported(tokens);
    let parsed = parse_segment(tokens);
    ParseOutcome {
        parsed,
        unsupported_shell_features,
    }
}

fn parse_segment(tokens: &[String]) -> ParsedCommand {
    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut current = Vec::new();
    let mut is_piped = false;
    let mut is_chained = false;

    for token in tokens {
        if token == "|" {
            is_piped = true;
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        if token == "&&" || token == "||" {
            is_chained = true;
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(token.clone());
    }
    if !current.is_empty() {
        segments.push(current);
    }

    let primary_tokens = segments.first().cloned().unwrap_or_default();
    let (program, args, redirects, env_assignments) = parse_simple_parts(&primary_tokens);
    let flags = args
        .iter()
        .filter(|arg| arg.starts_with('-'))
        .cloned()
        .collect::<Vec<_>>();
    let file_paths = args
        .iter()
        .filter(|arg| looks_like_path(arg))
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    let subcommands = if segments.len() > 1 {
        segments
            .iter()
            .map(|segment| {
                let (p, a, r, env) = parse_simple_parts(segment);
                let f = a
                    .iter()
                    .filter(|arg| arg.starts_with('-'))
                    .cloned()
                    .collect::<Vec<_>>();
                let paths = a
                    .iter()
                    .filter(|arg| looks_like_path(arg))
                    .map(PathBuf::from)
                    .collect::<Vec<_>>();
                ParsedCommand {
                    program: p,
                    args: a,
                    env_assignments: env,
                    file_paths: paths,
                    flags: f,
                    is_piped: false,
                    is_chained: false,
                    redirects: r,
                    subcommands: Vec::new(),
                }
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    ParsedCommand {
        program,
        args,
        env_assignments,
        file_paths,
        flags,
        is_piped,
        is_chained,
        redirects,
        subcommands,
    }
}

fn parse_simple_parts(tokens: &[String]) -> SimpleParts {
    if tokens.is_empty() {
        return (String::new(), Vec::new(), Vec::new(), Vec::new());
    }

    let mut idx = 0usize;
    let mut env_assignments = Vec::<(String, String)>::new();
    while idx < tokens.len() {
        let token = &tokens[idx];
        let Some((key, value)) = token.split_once('=') else {
            break;
        };
        if !is_env_assignment_key(key) {
            break;
        }
        env_assignments.push((key.to_string(), value.to_string()));
        idx += 1;
    }
    if idx >= tokens.len() {
        return (String::new(), Vec::new(), Vec::new(), env_assignments);
    }

    let program = tokens[idx].clone();
    let mut args = Vec::new();
    let mut redirects = Vec::new();
    let mut active_heredoc_delim: Option<String> = None;

    let mut i = idx + 1;
    while i < tokens.len() {
        let token = &tokens[i];
        if let Some(delim) = active_heredoc_delim.as_deref() {
            if token == delim {
                active_heredoc_delim = None;
            }
            i += 1;
            continue;
        }

        if let Some((delim, consumed)) = heredoc_start(tokens, i) {
            active_heredoc_delim = Some(delim);
            i += consumed;
            continue;
        }

        // Skip fd duplication/close tokens (2>&1, >&2, <&0, 2>&-, etc.)
        // — no file path involved.
        if is_fd_duplication(token) {
            i += 1;
            continue;
        }

        if let Some(kind) = redirect_kind(token)
            && i + 1 < tokens.len()
            && is_supported_redirect_target(&tokens[i + 1])
        {
            redirects.push(Redirect {
                kind,
                target: PathBuf::from(&tokens[i + 1]),
            });
            i += 2;
            continue;
        }

        if let Some((kind, target)) = inline_redirect(token) {
            redirects.push(Redirect {
                kind,
                target: PathBuf::from(target),
            });
            i += 1;
            continue;
        }

        args.push(token.clone());
        i += 1;
    }

    (program, args, redirects, env_assignments)
}

fn redirect_kind(token: &str) -> Option<RedirectKind> {
    match token {
        ">" | "1>" | "&>" | ">|" | "1>|" => Some(RedirectKind::Stdout),
        ">>" | "1>>" | "&>>" => Some(RedirectKind::Append),
        "2>" => Some(RedirectKind::Stderr),
        "2>>" => Some(RedirectKind::StderrAppend),
        "<" => Some(RedirectKind::Stdin),
        _ => None,
    }
}

fn inline_redirect(token: &str) -> Option<(RedirectKind, &str)> {
    for (prefix, kind) in [
        ("&>>", RedirectKind::Append),
        ("&>", RedirectKind::Stdout),
        ("2>>", RedirectKind::StderrAppend),
        ("1>>", RedirectKind::Append),
        (">>", RedirectKind::Append),
        ("2>", RedirectKind::Stderr),
        ("1>|", RedirectKind::Stdout),
        (">|", RedirectKind::Stdout),
        ("1>", RedirectKind::Stdout),
        (">", RedirectKind::Stdout),
        ("<", RedirectKind::Stdin),
    ] {
        if let Some(target) = token.strip_prefix(prefix)
            && is_supported_redirect_target(target)
        {
            return Some((kind, target));
        }
    }
    None
}

fn is_supported_redirect_target(target: &str) -> bool {
    !target.is_empty()
        && !matches!(
            target.chars().next(),
            Some('&' | '>' | '<' | '|' | '(' | ')')
        )
}

fn looks_like_path(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with('~')
        || token.contains('/')
}

fn is_env_assignment_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn find_unsupported(tokens: &[String]) -> Vec<String> {
    let mut unsupported = Vec::new();
    let mut active_heredoc_delim: Option<String> = None;
    let mut i = 0usize;
    while i < tokens.len() {
        let token = &tokens[i];
        if let Some(delim) = active_heredoc_delim.as_deref() {
            if token == delim {
                active_heredoc_delim = None;
            }
            i += 1;
            continue;
        }

        if let Some((delim, consumed)) = heredoc_start(tokens, i) {
            active_heredoc_delim = Some(delim);
            i += consumed;
            continue;
        }

        if redirect_kind(token).is_some() {
            let next = tokens.get(i + 1).map(String::as_str).unwrap_or("");
            if !is_supported_redirect_target(next) {
                let combined = if next.is_empty() {
                    token.clone()
                } else {
                    format!("{token}{next}")
                };
                unsupported.push(combined);
            }
            i += 1;
            continue;
        }

        if token.contains("$(")
            || token.contains("${")
            || token.contains("`")
            || token.contains("<(")
            || token.contains(">(")
            || has_unmodeled_redirection(token)
        {
            unsupported.push(token.clone());
        }
        i += 1;
    }
    unsupported
}

/// Matches fd duplication/close tokens: `2>&1`, `>&2`, `2>&-`, `<&0`, `<&-`, etc.
fn is_fd_duplication(token: &str) -> bool {
    let s = token
        .strip_prefix(|c: char| c.is_ascii_digit())
        .unwrap_or(token);
    let rest = if let Some(rest) = s.strip_prefix(">&") {
        rest
    } else if let Some(rest) = s.strip_prefix("<&") {
        rest
    } else {
        return false;
    };
    rest == "-" || (rest.len() == 1 && rest.as_bytes()[0].is_ascii_digit())
}

fn has_unmodeled_redirection(token: &str) -> bool {
    if !(token.contains('>') || token.contains('<')) {
        return false;
    }
    if redirect_kind(token).is_some()
        || inline_redirect(token).is_some()
        || is_fd_duplication(token)
    {
        return false;
    }
    true
}

fn heredoc_start(tokens: &[String], idx: usize) -> Option<(String, usize)> {
    let token = tokens.get(idx)?;
    if token == "<<" || token == "<<-" {
        let raw = tokens.get(idx + 1)?;
        let delim = normalize_heredoc_delimiter(raw);
        if delim.is_empty() {
            return None;
        }
        return Some((delim, 2));
    }

    let raw = if let Some(rest) = token.strip_prefix("<<-") {
        rest
    } else if let Some(rest) = token.strip_prefix("<<") {
        rest
    } else {
        return None;
    };
    let delim = normalize_heredoc_delimiter(raw);
    if delim.is_empty() {
        return None;
    }
    Some((delim, 1))
}

fn normalize_heredoc_delimiter(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(stripped) = s.strip_prefix('\\') {
        s = stripped.to_string();
    }
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0] as char;
        let last = bytes[s.len() - 1] as char;
        if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
            s = s[1..s.len() - 1].to_string();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{RedirectKind, parse_command};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_simple_command() {
        let parsed = parse_command(&v(&["rm", "-rf", "/tmp/cache"])).parsed;
        assert_eq!(parsed.program, "rm");
        assert_eq!(parsed.flags, vec!["-rf"]);
        assert_eq!(parsed.file_paths.len(), 1);
        assert_eq!(parsed.file_paths[0].to_string_lossy(), "/tmp/cache");
    }

    #[test]
    fn parses_leading_env_assignments() {
        let parsed = parse_command(&v(&["FOO=bar", "BAR=baz", "git", "status"])).parsed;
        assert_eq!(parsed.program, "git");
        assert_eq!(parsed.args, vec!["status"]);
        assert_eq!(
            parsed.env_assignments,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAR".to_string(), "baz".to_string())
            ]
        );
    }

    #[test]
    fn parses_pipe_segments() {
        let parsed = parse_command(&v(&["cat", "file.txt", "|", "grep", "pattern"])).parsed;
        assert!(parsed.is_piped);
        assert_eq!(parsed.subcommands.len(), 2);
        assert_eq!(parsed.subcommands[0].program, "cat");
        assert_eq!(parsed.subcommands[1].program, "grep");
    }

    #[test]
    fn parses_chain_segments() {
        let parsed = parse_command(&v(&["make", "&&", "make", "install"])).parsed;
        assert!(parsed.is_chained);
        assert_eq!(parsed.subcommands.len(), 2);
        assert_eq!(parsed.subcommands[1].args, vec!["install"]);
    }

    #[test]
    fn parses_redirects() {
        let parsed = parse_command(&v(&["echo", "data", ">", "/etc/config"])).parsed;
        assert_eq!(parsed.redirects.len(), 1);
        assert_eq!(parsed.redirects[0].kind, RedirectKind::Stdout);
        assert_eq!(parsed.redirects[0].target.to_string_lossy(), "/etc/config");
    }

    #[test]
    fn parses_stderr_append_redirect() {
        let parsed = parse_command(&v(&["cat", "missing.txt", "2>>", "/tmp/errors.log"])).parsed;
        assert_eq!(parsed.redirects.len(), 1);
        assert_eq!(parsed.redirects[0].kind, RedirectKind::StderrAppend);
        assert_eq!(
            parsed.redirects[0].target.to_string_lossy(),
            "/tmp/errors.log"
        );
    }

    #[test]
    fn flags_unsupported_shell_features() {
        let outcome = parse_command(&v(&["echo", "$(whoami)"]));
        assert_eq!(outcome.unsupported_shell_features, vec!["$(whoami)"]);
    }

    #[test]
    fn ignores_unsupported_tokens_inside_heredoc_body() {
        let outcome = parse_command(&v(&[
            "cat",
            ">",
            "/tmp/out.md",
            "<<'EOF'",
            "`policy.command_default`",
            "$(whoami)",
            "EOF",
        ]));
        assert!(outcome.unsupported_shell_features.is_empty());
        assert_eq!(outcome.parsed.program, "cat");
        assert_eq!(outcome.parsed.redirects.len(), 1);
        assert_eq!(
            outcome.parsed.redirects[0].target.to_string_lossy(),
            "/tmp/out.md"
        );
    }

    #[test]
    fn still_flags_unsupported_tokens_outside_heredoc_body() {
        let outcome = parse_command(&v(&["cat", "<<EOF", "safe", "EOF", "$(whoami)"]));
        assert_eq!(outcome.unsupported_shell_features, vec!["$(whoami)"]);
    }

    #[test]
    fn fd_duplication_is_not_flagged_as_unsupported() {
        let outcome = parse_command(&v(&["echo", "ok", "2>&1"]));
        assert!(
            outcome.unsupported_shell_features.is_empty(),
            "2>&1 should be supported, got: {:?}",
            outcome.unsupported_shell_features
        );
    }

    #[test]
    fn fd_duplication_is_not_added_as_arg() {
        let outcome = parse_command(&v(&["echo", "ok", "2>&1"]));
        assert_eq!(outcome.parsed.args, vec!["ok"]);
    }

    #[test]
    fn combined_redirect_creates_redirect_struct() {
        let outcome = parse_command(&v(&["echo", "ok", "&>", "/tmp/all.log"]));
        assert!(outcome.unsupported_shell_features.is_empty());
        assert_eq!(outcome.parsed.redirects.len(), 1);
        assert_eq!(outcome.parsed.redirects[0].kind, RedirectKind::Stdout);
        assert_eq!(
            outcome.parsed.redirects[0].target.to_string_lossy(),
            "/tmp/all.log"
        );
    }

    #[test]
    fn inline_combined_redirect_creates_redirect_struct() {
        let outcome = parse_command(&v(&["echo", "ok", "&>/tmp/all.log"]));
        assert!(outcome.unsupported_shell_features.is_empty());
        assert_eq!(outcome.parsed.redirects.len(), 1);
        assert_eq!(outcome.parsed.redirects[0].kind, RedirectKind::Stdout);
        assert_eq!(
            outcome.parsed.redirects[0].target.to_string_lossy(),
            "/tmp/all.log"
        );
    }

    #[test]
    fn noclobber_override_creates_redirect() {
        let outcome = parse_command(&v(&["echo", "ok", ">|/tmp/out"]));
        assert!(outcome.unsupported_shell_features.is_empty());
        assert_eq!(outcome.parsed.redirects.len(), 1);
        assert_eq!(outcome.parsed.redirects[0].kind, RedirectKind::Stdout);
        assert_eq!(
            outcome.parsed.redirects[0].target.to_string_lossy(),
            "/tmp/out"
        );
    }
}
