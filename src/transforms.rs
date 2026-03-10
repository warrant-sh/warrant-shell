use std::path::{Path, PathBuf};

pub fn apply_transform(name: &str, input: &str) -> Option<String> {
    match name {
        "literal" => Some(input.to_string()),
        "path" => Some(canonicalize_path(input)),
        "hostname" => extract_hostname(input),
        "email_domain" => extract_email_domain(input),
        "glob" => Some(input.to_string()),
        "git_remote" => extract_git_remote(input),
        _ => None,
    }
}

fn canonicalize_path(input: &str) -> String {
    let path = Path::new(input);
    let absolute = if path.is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    std::fs::canonicalize(&absolute)
        .unwrap_or(absolute)
        .to_string_lossy()
        .to_string()
}

fn extract_hostname(input: &str) -> Option<String> {
    if let Some(stripped) = input.strip_prefix("git@") {
        return stripped
            .split(':')
            .next()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
    }

    let without_scheme = if let Some(idx) = input.find("://") {
        &input[idx + 3..]
    } else {
        input
    };

    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split('@')
        .next_back()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .trim();

    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn extract_email_domain(input: &str) -> Option<String> {
    input
        .split('@')
        .next_back()
        .map(|domain| domain.trim().to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

fn extract_git_remote(input: &str) -> Option<String> {
    if input.contains("://") || input.starts_with("git@") {
        extract_hostname(input)
    } else {
        Some(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::apply_transform;

    #[test]
    fn hostname_from_https_url() {
        assert_eq!(
            apply_transform("hostname", "https://github.com/rust-lang/rust"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn email_domain_extraction() {
        assert_eq!(
            apply_transform("email_domain", "alice@example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn git_remote_extraction() {
        assert_eq!(
            apply_transform("git_remote", "git@github.com:owner/repo.git"),
            Some("github.com".to_string())
        );
    }
}
