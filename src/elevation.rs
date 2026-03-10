use std::time::Duration;

use colored::Colorize;
use warrant_core::{
    ElevationOptions, ToolPaths, clear_elevation_session, create_elevation_session, is_elevated,
};

use crate::app::Result;
use crate::audit;

fn current_uid() -> u32 {
    // SAFETY: libc call has no preconditions.
    unsafe { libc::geteuid() }
}

fn elevation_subject_uid() -> u32 {
    let uid = current_uid();
    if uid == 0
        && let Some(sudo_uid) = std::env::var_os("SUDO_UID")
        && let Some(s) = sudo_uid.to_str()
        && let Ok(parsed) = s.parse::<u32>()
    {
        return parsed;
    }
    uid
}

fn is_permission_denied_error(err: &warrant_core::Error) -> bool {
    matches!(
        err,
        warrant_core::Error::Io(io_err)
            if io_err.kind() == std::io::ErrorKind::PermissionDenied
    )
}

fn is_effectively_elevated(paths: &ToolPaths, uid: u32) -> Result<bool> {
    match is_elevated(paths, uid) {
        Ok(true) => Ok(true),
        Ok(false) => match audit::check_elevation_via_daemon(uid) {
            Ok(elevated) => Ok(elevated),
            Err(_) => Ok(false),
        },
        Err(err) if is_permission_denied_error(&err) => {
            match audit::check_elevation_via_daemon(uid) {
                Ok(elevated) => Ok(elevated),
                Err(_) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

pub(crate) fn elevate(paths: &ToolPaths, duration_minutes: u64) -> Result<()> {
    let uid = elevation_subject_uid();
    create_elevation_session(
        paths,
        uid,
        ElevationOptions {
            duration: Duration::from_secs(duration_minutes.saturating_mul(60)),
        },
    )?;

    println!(
        "{} for {} minute(s)",
        "elevated".green().bold(),
        duration_minutes
    );
    Ok(())
}

pub(crate) fn de_elevate(paths: &ToolPaths) -> Result<()> {
    clear_elevation_session(paths, elevation_subject_uid())?;
    println!("{}", "elevation cleared".green().bold());
    Ok(())
}

pub(crate) fn is_elevated_cmd(paths: &ToolPaths) -> Result<()> {
    let elevated = is_effectively_elevated(paths, elevation_subject_uid())?;
    if elevated {
        println!("true");
    } else {
        println!("false");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::elevation_subject_uid;

    #[test]
    fn non_root_uses_effective_uid() {
        // SAFETY: libc call has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return;
        }
        assert_eq!(elevation_subject_uid(), euid);
    }
}
