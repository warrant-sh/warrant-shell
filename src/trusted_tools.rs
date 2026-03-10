use std::path::{Path, PathBuf};

const TRUSTED_PATH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

pub(crate) fn trusted_curl_path() -> Result<PathBuf, String> {
    trusted_curl_path_with_dirs(TRUSTED_PATH_DIRS)
}

fn trusted_curl_path_with_dirs(trusted_dirs: &[&str]) -> Result<PathBuf, String> {
    for dir in trusted_dirs {
        let candidate = Path::new(dir).join("curl");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let trusted_path = trusted_dirs.join(":");
    let resolved = which::which_in("curl", Some(&trusted_path), "/")
        .map_err(|_| "unable to resolve curl via trusted PATH".to_string())?;

    if trusted_dirs
        .iter()
        .map(Path::new)
        .any(|trusted_dir| resolved.starts_with(trusted_dir))
    {
        Ok(resolved)
    } else {
        Err(format!(
            "resolved curl path {:?} is outside trusted PATH directories",
            resolved
        ))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::trusted_curl_path_with_dirs;

    #[test]
    fn trusted_curl_path_prefers_known_safe_absolute_path() {
        let temp = TempDir::new().expect("tempdir");
        let safe_dir = temp.path().join("safe");
        std::fs::create_dir_all(&safe_dir).expect("create safe dir");
        std::fs::write(safe_dir.join("curl"), "#!/bin/sh\n").expect("write curl");

        let trusted_dirs = [safe_dir.to_string_lossy().to_string()];
        let trusted_dir_refs = trusted_dirs.iter().map(String::as_str).collect::<Vec<_>>();
        let resolved = trusted_curl_path_with_dirs(&trusted_dir_refs).expect("resolve curl");
        assert_eq!(resolved, safe_dir.join("curl"));
    }

    #[test]
    fn trusted_curl_path_errors_when_not_found() {
        let temp = TempDir::new().expect("tempdir");
        let missing_dir = temp.path().join("missing");
        let trusted_dirs = [missing_dir.to_string_lossy().to_string()];
        let trusted_dir_refs = trusted_dirs.iter().map(String::as_str).collect::<Vec<_>>();

        let err = trusted_curl_path_with_dirs(&trusted_dir_refs).expect_err("must fail");
        assert!(err.contains("unable to resolve curl via trusted PATH"));
    }
}
