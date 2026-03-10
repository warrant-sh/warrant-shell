use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ShellError {
    MissingShell {
        tried: Vec<PathBuf>,
    },
    InvalidConfiguredShell {
        path: PathBuf,
        error: std::io::Error,
    },
    Recursion {
        path: PathBuf,
    },
    CurrentExe(std::io::Error),
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::MissingShell { tried } => {
                let tried = tried
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "unable to resolve real shell; tried: {tried}")
            }
            ShellError::InvalidConfiguredShell { path, error } => {
                write!(
                    f,
                    "WSH_REAL_SHELL is invalid ({}) : {error}",
                    path.display()
                )
            }
            ShellError::Recursion { path } => write!(
                f,
                "WSH_REAL_SHELL points to wsh itself ({}); set it to a real shell like /bin/bash",
                path.display()
            ),
            ShellError::CurrentExe(err) => write!(f, "failed to resolve current executable: {err}"),
        }
    }
}

pub fn resolve_real_shell() -> Result<PathBuf, ShellError> {
    let current_exe = std::env::current_exe().map_err(ShellError::CurrentExe)?;
    resolve_real_shell_with(
        std::env::var_os("WSH_REAL_SHELL"),
        &current_exe,
        &[Path::new("/bin/bash"), Path::new("/bin/sh")],
    )
}

fn resolve_real_shell_with(
    configured: Option<OsString>,
    current_exe: &Path,
    fallbacks: &[&Path],
) -> Result<PathBuf, ShellError> {
    let current_exe = std::fs::canonicalize(current_exe).map_err(ShellError::CurrentExe)?;

    if let Some(raw) = configured {
        let path = PathBuf::from(raw);
        if path.as_os_str().is_empty() {
            return Err(ShellError::InvalidConfiguredShell {
                path,
                error: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "empty configured path",
                ),
            });
        }
        let canonical =
            std::fs::canonicalize(&path).map_err(|error| ShellError::InvalidConfiguredShell {
                path: path.clone(),
                error,
            })?;
        if is_same_binary(&canonical, &current_exe) {
            return Err(ShellError::Recursion { path: canonical });
        }
        return Ok(canonical);
    }

    let mut tried = Vec::new();
    for candidate in fallbacks {
        tried.push((*candidate).to_path_buf());
        let Ok(canonical) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if is_same_binary(&canonical, &current_exe) {
            return Err(ShellError::Recursion { path: canonical });
        }
        return Ok(canonical);
    }

    Err(ShellError::MissingShell { tried })
}

pub fn is_same_binary(a: &Path, b: &Path) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::{ShellError, resolve_real_shell_with};

    #[test]
    fn configured_shell_is_used() {
        let temp = TempDir::new().expect("tempdir");
        let current = temp.path().join("wsh");
        let real = temp.path().join("bash");
        let fallback = temp.path().join("fallback");
        fs::write(&current, "wsh").expect("write current");
        fs::write(&real, "bash").expect("write shell");

        let resolved = resolve_real_shell_with(
            Some(real.as_os_str().to_os_string()),
            &current,
            &[&fallback],
        )
        .expect("resolve");
        assert_eq!(resolved, fs::canonicalize(real).expect("canon real"));
    }

    #[test]
    fn fallback_chain_is_used_when_env_unset() {
        let temp = TempDir::new().expect("tempdir");
        let current = temp.path().join("wsh");
        let missing = temp.path().join("missing");
        let fallback = temp.path().join("bash");
        fs::write(&current, "wsh").expect("write current");
        fs::write(&fallback, "bash").expect("write fallback");

        let resolved =
            resolve_real_shell_with(None, &current, &[&missing, &fallback]).expect("resolve");
        assert_eq!(
            resolved,
            fs::canonicalize(fallback).expect("canon fallback")
        );
    }

    #[test]
    fn missing_configured_shell_errors() {
        let temp = TempDir::new().expect("tempdir");
        let current = temp.path().join("wsh");
        fs::write(&current, "wsh").expect("write current");
        let missing = temp.path().join("missing");

        let err = resolve_real_shell_with(
            Some(missing.as_os_str().to_os_string()),
            &current,
            &[temp.path()],
        )
        .expect_err("must fail");
        assert!(matches!(err, ShellError::InvalidConfiguredShell { .. }));
    }

    #[test]
    fn recursion_detected_for_identical_binary() {
        let temp = TempDir::new().expect("tempdir");
        let current = temp.path().join("wsh");
        fs::write(&current, "wsh").expect("write current");

        let err = resolve_real_shell_with(
            Some(current.as_os_str().to_os_string()),
            &current,
            &[temp.path()],
        )
        .expect_err("must fail");
        assert!(matches!(err, ShellError::Recursion { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn recursion_detected_for_symlink() {
        let temp = TempDir::new().expect("tempdir");
        let current = temp.path().join("wsh");
        let link = temp.path().join("bash");
        fs::write(&current, "wsh").expect("write current");
        symlink(&current, &link).expect("create symlink");

        let err = resolve_real_shell_with(
            Some(link.as_os_str().to_os_string()),
            &current,
            &[temp.path()],
        )
        .expect_err("must fail");
        assert!(matches!(err, ShellError::Recursion { .. }));
    }
}
