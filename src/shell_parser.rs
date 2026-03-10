use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellParseResult {
    pub segments: Vec<Vec<String>>,
    pub separators: Vec<String>,
    pub substitutions: Vec<ShellParseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellParseError {
    EmptyCommand,
    UnterminatedQuote,
    InvalidSyntax(String),
    UnsupportedFeature(String),
}

impl fmt::Display for ShellParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellParseError::EmptyCommand => write!(f, "empty shell command"),
            ShellParseError::UnterminatedQuote => write!(f, "unterminated shell quote"),
            ShellParseError::InvalidSyntax(msg) => write!(f, "invalid shell command syntax: {msg}"),
            ShellParseError::UnsupportedFeature(feature) => {
                write!(f, "unsupported shell feature in -c mode: {feature}")
            }
        }
    }
}

pub fn extract_programs(command: &str) -> Result<Vec<String>, ShellParseError> {
    let parsed = parse_shell_command(command)?;
    let mut programs = Vec::new();
    collect_programs(&parsed, &mut programs)?;
    Ok(programs)
}

fn collect_programs(
    parsed: &ShellParseResult,
    programs: &mut Vec<String>,
) -> Result<(), ShellParseError> {
    for segment in &parsed.segments {
        let program = first_program_token(segment).ok_or_else(|| {
            ShellParseError::InvalidSyntax("unable to extract program name".to_string())
        })?;
        programs.push(program.to_string());
    }
    for subst in &parsed.substitutions {
        collect_programs(subst, programs)?;
    }
    Ok(())
}

pub fn parse_shell_command(command: &str) -> Result<ShellParseResult, ShellParseError> {
    if command.trim().is_empty() {
        return Err(ShellParseError::EmptyCommand);
    }

    let chars: Vec<char> = command.chars().collect();
    let mut idx = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_ansi_c_single = false;
    let mut escaped = false;

    let mut current_token = String::new();
    let mut current_segment = Vec::<String>::new();
    let mut segments = Vec::<Vec<String>>::new();
    let mut separators = Vec::<String>::new();
    let mut substitutions = Vec::<ShellParseResult>::new();
    // Pending heredoc delimiters: (delimiter, strip_leading_tabs)
    let mut pending_heredocs: Vec<(String, bool)> = Vec::new();

    while idx < chars.len() {
        let ch = chars[idx];
        let next = chars.get(idx + 1).copied();

        if escaped {
            current_token.push(ch);
            escaped = false;
            idx += 1;
            continue;
        }

        if !in_single && ch == '\\' {
            escaped = true;
            idx += 1;
            continue;
        }

        if ch == '\'' && !in_double {
            if in_single {
                if in_ansi_c_single {
                    current_token.push('\'');
                    in_ansi_c_single = false;
                }
                in_single = false;
            } else {
                in_single = true;
                if current_token.ends_with('$') {
                    current_token.push('\'');
                    in_ansi_c_single = true;
                }
            }
            idx += 1;
            continue;
        }

        if ch == '"' && !in_single {
            in_double = !in_double;
            idx += 1;
            continue;
        }

        // Command substitution: handle $( outside single quotes (works in both
        // unquoted and double-quoted contexts).
        if !in_single && ch == '$' && next == Some('(') {
            let after = chars.get(idx + 2).copied();
            if after == Some('(') {
                return Err(ShellParseError::UnsupportedFeature(
                    "arithmetic expansion".to_string(),
                ));
            }
            let (inner_str, end_idx) = scan_command_substitution(&chars, idx + 2)?;
            if !inner_str.trim().is_empty() {
                let inner_parsed = parse_shell_command(&inner_str)?;
                substitutions.extend(inner_parsed.substitutions);
                substitutions.push(ShellParseResult {
                    segments: inner_parsed.segments,
                    separators: inner_parsed.separators,
                    substitutions: Vec::new(),
                });
            }
            idx = end_idx;
            continue;
        }

        if !in_single && !in_double {
            if ch == '`' {
                return Err(ShellParseError::UnsupportedFeature("backticks".to_string()));
            }
            if (ch == '<' || ch == '>') && next == Some('(') {
                return Err(ShellParseError::UnsupportedFeature(
                    "process substitution".to_string(),
                ));
            }
            if ch == '<' && next == Some('<') {
                let third = chars.get(idx + 2).copied();
                if third == Some('<') {
                    return Err(ShellParseError::UnsupportedFeature(
                        "here-string".to_string(),
                    ));
                }
                // Heredoc: parse the delimiter and queue body for skipping
                let mut hi = idx + 2;
                let strip_tabs = hi < chars.len() && chars[hi] == '-';
                if strip_tabs {
                    hi += 1;
                }
                // Skip optional whitespace between << and delimiter
                while hi < chars.len() && chars[hi] == ' ' {
                    hi += 1;
                }
                let (delim, end_idx) = parse_heredoc_delimiter(&chars, hi)?;
                if delim.is_empty() {
                    return Err(ShellParseError::InvalidSyntax(
                        "empty heredoc delimiter".to_string(),
                    ));
                }
                pending_heredocs.push((delim, strip_tabs));
                idx = end_idx;
                continue;
            }
            if ch == '(' || ch == ')' {
                return Err(ShellParseError::UnsupportedFeature(
                    "subshell grouping".to_string(),
                ));
            }
            if ch == '&' && next != Some('&') {
                let prev = idx.checked_sub(1).and_then(|p| chars.get(p)).copied();
                if next == Some('>') || matches!(prev, Some('>' | '<')) {
                    // Redirection forms like &>, >&2 and 2>&1 are handled below.
                } else {
                    return Err(ShellParseError::UnsupportedFeature(
                        "background execution with &".to_string(),
                    ));
                }
            }
        }

        if !in_single && !in_double {
            if ch == '\n' {
                push_token(&mut current_token, &mut current_segment);
                if !pending_heredocs.is_empty() {
                    // This newline starts the heredoc body — skip past it
                    idx += 1;
                    for (delim, strip_tabs) in pending_heredocs.drain(..) {
                        idx = skip_heredoc_body(&chars, idx, &delim, strip_tabs)?;
                    }
                    // If there's more input after the heredoc, push current segment
                    if idx < chars.len() && !current_segment.is_empty() {
                        segments.push(std::mem::take(&mut current_segment));
                        separators.push(";".to_string());
                    }
                    continue;
                }
                if !current_segment.is_empty() {
                    segments.push(std::mem::take(&mut current_segment));
                    separators.push(";".to_string());
                }
                idx += 1;
                continue;
            }

            if ch.is_whitespace() {
                push_token(&mut current_token, &mut current_segment);
                idx += 1;
                continue;
            }

            if ch == ';' {
                push_separator(
                    ";",
                    &mut current_token,
                    &mut current_segment,
                    &mut segments,
                    &mut separators,
                )?;
                idx += 1;
                continue;
            }

            if ch == '|' {
                let prev = idx.checked_sub(1).and_then(|p| chars.get(p)).copied();
                if prev == Some('>') {
                    // Keep >| together as a single token (noclobber override redirect).
                    current_token.push(ch);
                    idx += 1;
                    continue;
                }
                if next == Some('|') {
                    push_separator(
                        "||",
                        &mut current_token,
                        &mut current_segment,
                        &mut segments,
                        &mut separators,
                    )?;
                    idx += 2;
                    continue;
                }
                push_separator(
                    "|",
                    &mut current_token,
                    &mut current_segment,
                    &mut segments,
                    &mut separators,
                )?;
                idx += 1;
                continue;
            }

            if ch == '&' && next == Some('&') {
                push_separator(
                    "&&",
                    &mut current_token,
                    &mut current_segment,
                    &mut segments,
                    &mut separators,
                )?;
                idx += 2;
                continue;
            }
        }

        current_token.push(ch);
        idx += 1;
    }

    if escaped || in_single || in_double {
        return Err(ShellParseError::UnterminatedQuote);
    }

    if !pending_heredocs.is_empty() {
        return Err(ShellParseError::InvalidSyntax(format!(
            "unterminated heredoc: body not found for delimiter '{}'",
            pending_heredocs[0].0
        )));
    }

    push_token(&mut current_token, &mut current_segment);
    if current_segment.is_empty() {
        return Err(ShellParseError::InvalidSyntax(
            "command cannot end with a separator".to_string(),
        ));
    }
    segments.push(current_segment);

    for segment in &segments {
        for token in segment {
            if let Some(feature) = unsupported_redirection_feature(token) {
                return Err(ShellParseError::UnsupportedFeature(feature.to_string()));
            }
        }
    }

    Ok(ShellParseResult {
        segments,
        separators,
        substitutions,
    })
}

fn parse_heredoc_delimiter(
    chars: &[char],
    start: usize,
) -> Result<(String, usize), ShellParseError> {
    if start >= chars.len() {
        return Err(ShellParseError::InvalidSyntax(
            "missing heredoc delimiter".to_string(),
        ));
    }

    let ch = chars[start];
    if ch == '\'' || ch == '"' {
        // Quoted delimiter: <<'EOF' or <<"EOF"
        let quote = ch;
        let mut idx = start + 1;
        let mut delim = String::new();
        while idx < chars.len() && chars[idx] != quote {
            delim.push(chars[idx]);
            idx += 1;
        }
        if idx >= chars.len() {
            return Err(ShellParseError::UnterminatedQuote);
        }
        idx += 1; // skip closing quote
        Ok((delim, idx))
    } else {
        // Unquoted delimiter: read until whitespace or shell metacharacter
        let mut delim = String::new();
        let mut idx = start;
        while idx < chars.len()
            && !chars[idx].is_whitespace()
            && !matches!(chars[idx], ';' | '|' | '&' | '<' | '>' | '(' | ')')
        {
            delim.push(chars[idx]);
            idx += 1;
        }
        Ok((delim, idx))
    }
}

fn skip_heredoc_body(
    chars: &[char],
    start: usize,
    delimiter: &str,
    strip_tabs: bool,
) -> Result<usize, ShellParseError> {
    let mut idx = start;
    loop {
        let line_start = idx;
        while idx < chars.len() && chars[idx] != '\n' {
            idx += 1;
        }
        let line: String = chars[line_start..idx].iter().collect();
        let trimmed = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            &line
        };
        if trimmed == delimiter {
            // Skip past the newline after the delimiter line (if present)
            if idx < chars.len() && chars[idx] == '\n' {
                idx += 1;
            }
            return Ok(idx);
        }
        if idx >= chars.len() {
            return Err(ShellParseError::InvalidSyntax(format!(
                "unterminated heredoc: delimiter '{}' not found",
                delimiter
            )));
        }
        idx += 1; // skip \n
    }
}

/// Scan forward from `start` (the index right after the opening `(` of `$(`) to
/// find the matching `)`. Returns the inner command string and the index after
/// the closing `)`.
///
/// Handles nested `$(...)`, bare parentheses, and quoted content. Heredoc bodies
/// inside the substitution are not tracked, so an unbalanced `)` inside a heredoc
/// body could cause a mis-parse (rare edge case).
fn scan_command_substitution(
    chars: &[char],
    start: usize,
) -> Result<(String, usize), ShellParseError> {
    let mut depth = 1usize;
    let mut idx = start;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while idx < chars.len() {
        let ch = chars[idx];

        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }

        if !in_single && ch == '\\' {
            escaped = true;
            idx += 1;
            continue;
        }

        if ch == '\'' && !in_double {
            in_single = !in_single;
            idx += 1;
            continue;
        }

        if ch == '"' && !in_single {
            in_double = !in_double;
            idx += 1;
            continue;
        }

        if !in_single && !in_double {
            if ch == '$' && idx + 1 < chars.len() && chars[idx + 1] == '(' {
                depth += 1;
                idx += 2;
                continue;
            }
            if ch == '(' {
                depth += 1;
                idx += 1;
                continue;
            }
            if ch == ')' {
                depth -= 1;
                if depth == 0 {
                    let inner: String = chars[start..idx].iter().collect();
                    return Ok((inner, idx + 1));
                }
                idx += 1;
                continue;
            }
            if ch == '`' {
                // Skip to matching backtick to avoid miscounting parens inside
                idx += 1;
                while idx < chars.len() && chars[idx] != '`' {
                    if chars[idx] == '\\' {
                        idx += 1;
                    }
                    idx += 1;
                }
                if idx >= chars.len() {
                    return Err(ShellParseError::InvalidSyntax(
                        "unterminated backtick in command substitution".to_string(),
                    ));
                }
                idx += 1;
                continue;
            }
        }

        idx += 1;
    }

    Err(ShellParseError::InvalidSyntax(
        "unterminated command substitution".to_string(),
    ))
}

fn push_token(current_token: &mut String, current_segment: &mut Vec<String>) {
    if !current_token.is_empty() {
        current_segment.push(std::mem::take(current_token));
    }
}

fn push_separator(
    separator: &str,
    current_token: &mut String,
    current_segment: &mut Vec<String>,
    segments: &mut Vec<Vec<String>>,
    separators: &mut Vec<String>,
) -> Result<(), ShellParseError> {
    push_token(current_token, current_segment);
    if current_segment.is_empty() {
        return Err(ShellParseError::InvalidSyntax(format!(
            "unexpected separator {separator}"
        )));
    }
    segments.push(std::mem::take(current_segment));
    separators.push(separator.to_string());
    Ok(())
}

fn first_program_token(segment: &[String]) -> Option<&str> {
    segment
        .iter()
        .find(|token| !is_env_assignment(token))
        .map(String::as_str)
}

fn is_env_assignment(token: &str) -> bool {
    let Some((key, _)) = token.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn unsupported_redirection_feature(token: &str) -> Option<&'static str> {
    if is_supported_redirection_token(token) {
        return None;
    }
    if is_any_redirection_token(token) {
        return Some("unsupported redirection syntax");
    }
    None
}

fn is_supported_redirection_token(token: &str) -> bool {
    if matches!(token, ">" | "1>" | ">>" | "1>>" | "2>" | "2>>" | "<" | ">|" | "1>|") {
        return true;
    }
    for prefix in ["2>>", "1>>", ">>", "2>", "1>", ">|", ">", "<"] {
        if let Some(target) = token.strip_prefix(prefix)
            && is_supported_redirection_target(target)
        {
            return true;
        }
    }
    // Fd duplication: 2>&1, >&2, 2>&-, <&0, <&-, etc.
    if is_fd_duplication_token(token) {
        return true;
    }
    // Combined stdout+stderr redirect: &>file, &>>file, &> (standalone)
    if matches!(token, "&>" | "&>>") {
        return true;
    }
    for prefix in ["&>>", "&>"] {
        if let Some(target) = token.strip_prefix(prefix)
            && is_supported_redirection_target(target)
        {
            return true;
        }
    }
    false
}

/// Matches fd duplication/close tokens: `2>&1`, `>&2`, `2>&-`, `<&0`, `<&-`, etc.
fn is_fd_duplication_token(token: &str) -> bool {
    // Strip optional leading fd digit (e.g. the `2` in `2>&1`)
    let s = token
        .strip_prefix(|c: char| c.is_ascii_digit())
        .unwrap_or(token);
    // Must have >& or <&
    let rest = if let Some(rest) = s.strip_prefix(">&") {
        rest
    } else if let Some(rest) = s.strip_prefix("<&") {
        rest
    } else {
        return false;
    };
    // Target must be a single digit (fd number) or `-` (close)
    rest == "-" || (rest.len() == 1 && rest.as_bytes()[0].is_ascii_digit())
}

fn is_any_redirection_token(token: &str) -> bool {
    if token.contains('<') || token.contains('>') {
        return true;
    }
    token.starts_with("&>") || token.starts_with(">&")
}

fn is_supported_redirection_target(target: &str) -> bool {
    !target.is_empty()
        && !matches!(
            target.chars().next(),
            Some('&' | '>' | '<' | '|' | '(' | ')')
        )
}

#[cfg(test)]
mod tests {
    use super::{extract_programs, parse_shell_command};

    #[test]
    fn extracts_pipeline_and_chain_programs() {
        let names = extract_programs("ls -la | grep foo && echo done").expect("parse");
        assert_eq!(names, vec!["ls", "grep", "echo"]);
    }

    #[test]
    fn respects_quoted_separators() {
        let names = extract_programs("echo 'a|b && c;d' | cat").expect("parse");
        assert_eq!(names, vec!["echo", "cat"]);
    }

    #[test]
    fn skips_leading_env_assignments() {
        let names = extract_programs("FOO=bar BAR=baz git status").expect("parse");
        assert_eq!(names, vec!["git"]);
    }

    #[test]
    fn parses_command_substitution_outside_quotes() {
        let parsed = parse_shell_command("echo $(whoami)").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["echo"]);
        assert_eq!(parsed.substitutions.len(), 1);
        assert_eq!(parsed.substitutions[0].segments, vec![vec!["whoami".to_string()]]);
    }

    #[test]
    fn extracts_programs_from_substitutions() {
        let names = extract_programs("echo $(whoami)").expect("parse");
        assert_eq!(names, vec!["echo", "whoami"]);
    }

    #[test]
    fn parses_command_substitution_inside_double_quotes() {
        let parsed = parse_shell_command("echo \"hello $(whoami)\"").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.substitutions.len(), 1);
        assert_eq!(parsed.substitutions[0].segments, vec![vec!["whoami".to_string()]]);
    }

    #[test]
    fn parses_nested_command_substitution() {
        let parsed = parse_shell_command("echo $(cat $(which config))").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.substitutions.len(), 2);
        let programs: Vec<&str> = parsed
            .substitutions
            .iter()
            .flat_map(|s| s.segments.iter().map(|seg| seg[0].as_str()))
            .collect();
        assert!(programs.contains(&"which"));
        assert!(programs.contains(&"cat"));
    }

    #[test]
    fn command_substitution_with_pipeline() {
        let names = extract_programs("echo $(cat /etc/passwd | grep root)").expect("parse");
        assert_eq!(names, vec!["echo", "cat", "grep"]);
    }

    #[test]
    fn empty_command_substitution_is_allowed() {
        let parsed = parse_shell_command("echo $()").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.substitutions.len(), 0);
    }

    #[test]
    fn command_substitution_single_quotes_not_parsed() {
        // $(...) inside single quotes is literal, not a substitution
        let parsed = parse_shell_command("echo '$(whoami)'").expect("parse");
        assert_eq!(parsed.substitutions.len(), 0);
    }

    #[test]
    fn unterminated_command_substitution_errors() {
        let err = parse_shell_command("echo $(whoami").expect_err("must fail");
        assert!(err.to_string().contains("unterminated command substitution"));
    }

    #[test]
    fn arithmetic_expansion_rejected() {
        let err = parse_shell_command("echo $((1+2))").expect_err("must fail");
        assert!(err.to_string().contains("arithmetic expansion"));
    }

    #[test]
    fn parse_returns_segments_and_separators() {
        let parsed = parse_shell_command("git status; echo ok || true").expect("parse");
        assert_eq!(parsed.segments.len(), 3);
        assert_eq!(parsed.separators, vec![";", "||"]);
    }

    #[test]
    fn newline_splits_commands_like_semicolon() {
        let parsed = parse_shell_command("echo ok\nid").expect("parse");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0][0], "echo");
        assert_eq!(parsed.segments[1][0], "id");
        assert_eq!(parsed.separators, vec![";"]);
    }

    #[test]
    fn consecutive_newlines_are_ignored_between_commands() {
        let parsed = parse_shell_command("echo ok\n\nid").expect("parse");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.separators, vec![";"]);
    }

    #[test]
    fn preserves_ansi_c_quote_marker_in_tokens() {
        let parsed =
            parse_shell_command("$'\\143\\165\\162\\154' https://evil.com").expect("parse");
        assert_eq!(parsed.segments[0][0], "$'\\143\\165\\162\\154'");
    }

    #[test]
    fn supports_basic_file_redirection_forms() {
        let parsed =
            parse_shell_command("echo ok > /tmp/out 2>>/tmp/err < /tmp/in").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn supports_descriptor_duplication() {
        let parsed = parse_shell_command("echo ok 2>&1").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert!(parsed.segments[0].contains(&"2>&1".to_string()));
    }

    #[test]
    fn supports_stderr_stdout_merge_shortcut() {
        let parsed = parse_shell_command("echo ok &>/tmp/all.log").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn supports_output_descriptor_target() {
        let parsed = parse_shell_command("echo ok >&2").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert!(parsed.segments[0].contains(&">&2".to_string()));
    }

    #[test]
    fn supports_fd_close() {
        let parsed = parse_shell_command("echo ok 2>&-").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn supports_stdin_fd_duplication() {
        let parsed = parse_shell_command("cat <&3").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }

    // -- Heredoc tests --

    #[test]
    fn heredoc_basic() {
        let parsed = parse_shell_command("cat <<EOF\nhello\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_quoted_delimiter() {
        let parsed = parse_shell_command("cat <<'EOF'\nhello world\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_double_quoted_delimiter() {
        let parsed = parse_shell_command("cat <<\"EOF\"\nhello\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_indented_strip_tabs() {
        let parsed = parse_shell_command("cat <<-EOF\n\thello\n\tEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_in_pipeline() {
        let parsed = parse_shell_command("cat <<EOF | grep hello\nhello\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0], vec!["cat"]);
        assert_eq!(parsed.segments[1], vec!["grep", "hello"]);
        assert_eq!(parsed.separators, vec!["|"]);
    }

    #[test]
    fn heredoc_with_and_chain() {
        let parsed =
            parse_shell_command("cat <<EOF && echo done\nhello\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0], vec!["cat"]);
        assert_eq!(parsed.segments[1], vec!["echo", "done"]);
        assert_eq!(parsed.separators, vec!["&&"]);
    }

    #[test]
    fn heredoc_followed_by_command_on_next_line() {
        let parsed =
            parse_shell_command("cat <<EOF\nhello\nEOF\necho done").expect("parse");
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0], vec!["cat"]);
        assert_eq!(parsed.segments[1], vec!["echo", "done"]);
        assert_eq!(parsed.separators, vec![";"]);
    }

    #[test]
    fn heredoc_multiline_body() {
        let parsed =
            parse_shell_command("cat <<EOF\nline 1\nline 2\nline 3\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_empty_body() {
        let parsed = parse_shell_command("cat <<EOF\nEOF").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["cat"]);
    }

    #[test]
    fn heredoc_unterminated_errors() {
        let err = parse_shell_command("cat <<EOF\nhello\nwhere is the end")
            .expect_err("must fail");
        assert!(err.to_string().contains("unterminated heredoc"));
    }

    #[test]
    fn heredoc_missing_body_errors() {
        let err = parse_shell_command("cat <<EOF").expect_err("must fail");
        assert!(err.to_string().contains("unterminated heredoc"));
    }

    #[test]
    fn heredoc_inside_command_substitution() {
        let parsed =
            parse_shell_command("echo $(cat <<'EOF'\ncommit message\nEOF\n)").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0], vec!["echo"]);
        assert_eq!(parsed.substitutions.len(), 1);
        assert_eq!(parsed.substitutions[0].segments[0], vec!["cat".to_string()]);
    }

    #[test]
    fn git_commit_heredoc_substitution_pattern() {
        let parsed = parse_shell_command(
            "git commit -m \"$(cat <<'EOF'\ncommit message\nEOF\n)\"",
        )
        .expect("parse");
        assert_eq!(parsed.segments[0][0], "git");
        assert_eq!(parsed.substitutions.len(), 1);
        let names = extract_programs(
            "git commit -m \"$(cat <<'EOF'\ncommit message\nEOF\n)\"",
        )
        .expect("parse");
        assert_eq!(names, vec!["git", "cat"]);
    }

    #[test]
    fn rejects_read_write_redirection() {
        let err = parse_shell_command("cat <>/tmp/rw").expect_err("must fail");
        assert!(err.to_string().contains("unsupported shell feature"));
    }

    #[test]
    fn supports_noclobber_override_redirection() {
        let parsed = parse_shell_command("echo ok >|/tmp/out").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn supports_standalone_noclobber_override() {
        let parsed = parse_shell_command("echo ok >| /tmp/out").expect("parse");
        assert_eq!(parsed.segments.len(), 1);
    }
}
