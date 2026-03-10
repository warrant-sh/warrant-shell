use std::ffi::OsString;
use std::process::Command as ProcessCommand;
use wsh::app::run_startup_mode;

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
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

fn true_shell_path() -> String {
    let output = ProcessCommand::new("which")
        .arg("true")
        .output()
        .expect("which true should run");
    assert!(
        output.status.success(),
        "which true should succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("which true output should be utf-8")
        .trim()
        .to_string()
}

#[test]
fn interactive_mode_passes_through_to_real_shell() {
    let _real_shell = EnvVarGuard::set("WSH_REAL_SHELL", &true_shell_path());
    let _allow_passthrough = EnvVarGuard::set("WSH_ALLOW_INTERACTIVE_PASSTHROUGH", "1");
    let args = vec!["wsh".to_string()];
    let result = run_startup_mode(&args).expect("interactive startup mode should succeed");
    assert_eq!(result, Some(0));
}

#[test]
fn interactive_login_mode_passes_through_to_real_shell() {
    let _real_shell = EnvVarGuard::set("WSH_REAL_SHELL", &true_shell_path());
    let _allow_passthrough = EnvVarGuard::set("WSH_ALLOW_INTERACTIVE_PASSTHROUGH", "1");
    let args = vec!["wsh".to_string(), "-l".to_string()];
    let result = run_startup_mode(&args).expect("interactive login startup mode should succeed");
    assert_eq!(result, Some(0));
}
