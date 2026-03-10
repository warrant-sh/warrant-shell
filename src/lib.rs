pub mod app;
pub mod audit;
pub mod bundles;
pub mod cli;
pub mod compiler;
pub mod config;
pub mod denylist_update;
pub mod draft;
pub mod elevation;
pub mod exec;
pub mod guard;
pub mod manifest;
pub mod package_denylist;
pub mod parser;
pub mod paths;
pub mod policy;
pub mod registry;
pub mod setup;
pub mod shell;
pub mod shell_parser;
pub mod transforms;
pub mod trusted_tools;
pub mod tui_edit;

pub const TOOL_NAME: &str = "warrant-shell";
const PRESERVED_WSH_ENV_VARS: &[&str] = &["WSH_GUARD", "WSH_DENYLIST_DIR", "WSH_SESSION_ID"];

pub fn scrub_wsh_env_vars() {
    let keys_to_remove = std::env::vars()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with("WSH_") && !PRESERVED_WSH_ENV_VARS.contains(&key.as_str()))
        .collect::<Vec<_>>();

    for key in keys_to_remove {
        unsafe { std::env::remove_var(key) };
    }
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::{scrub_wsh_env_vars, test_env_lock};

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                unsafe { std::env::set_var(self.key, value) };
            } else {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn scrub_wsh_env_vars_removes_registry_url() {
        let _lock = test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _var = EnvVarGuard::set("WSH_REGISTRY_URL", "https://attacker.example");

        scrub_wsh_env_vars();

        assert!(
            std::env::var_os("WSH_REGISTRY_URL").is_none(),
            "WSH_REGISTRY_URL should be removed",
        );
    }

    #[test]
    fn scrub_wsh_env_vars_keeps_guard() {
        let _lock = test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _var = EnvVarGuard::set("WSH_GUARD", "1");

        scrub_wsh_env_vars();

        assert_eq!(
            std::env::var("WSH_GUARD").ok().as_deref(),
            Some("1"),
            "WSH_GUARD should be preserved",
        );
    }

    #[test]
    fn scrub_wsh_env_vars_keeps_session_id() {
        let _lock = test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _var = EnvVarGuard::set("WSH_SESSION_ID", "session-test");

        scrub_wsh_env_vars();

        assert_eq!(
            std::env::var("WSH_SESSION_ID").ok().as_deref(),
            Some("session-test"),
            "WSH_SESSION_ID should be preserved",
        );
    }

    #[test]
    fn scrub_wsh_env_vars_removes_profile() {
        let _lock = test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _var = EnvVarGuard::set("WSH_PROFILE", "permissive");

        scrub_wsh_env_vars();

        assert!(
            std::env::var_os("WSH_PROFILE").is_none(),
            "WSH_PROFILE should be removed",
        );
    }

    #[test]
    fn scrub_wsh_env_vars_removes_auditd_socket_override() {
        let _lock = test_env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _var = EnvVarGuard::set("WSH_AUDITD_SOCKET", "/tmp/attacker.sock");

        scrub_wsh_env_vars();

        assert!(
            std::env::var_os("WSH_AUDITD_SOCKET").is_none(),
            "WSH_AUDITD_SOCKET should be removed",
        );
    }
}
