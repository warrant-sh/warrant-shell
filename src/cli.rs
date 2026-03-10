use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::PolicyDefaultMode;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DraftScopeArg {
    System,
    Project,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PackageEcosystemArg {
    Npm,
    Pip,
    Pypi,
    Cargo,
}

impl PackageEcosystemArg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pip | Self::Pypi => "pypi",
            Self::Cargo => "cargo",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "warrant-shell",
    bin_name = "wsh",
    version,
    about = "Warrant-enforced shell command guard"
)]
pub struct Cli {
    #[arg(long, global = true, hide = true)]
    pub paths_root: Option<PathBuf>,
    #[arg(long, global = true)]
    pub profile: Option<String>,
    #[arg(long, global = true, default_value_t = false)]
    pub accept_defaults: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Exec {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Fetch manifest from registry to local cache
    Pull {
        /// Tool name or namespaced ID (omit to pull all)
        name: Option<String>,
    },
    /// Add one or more tools/bundles to local drafts directory
    Add {
        /// Tool or bundle name(s), or namespaced manifest ID(s)
        #[arg(required = true)]
        names: Vec<String>,
        /// Custom registry source (git URL)
        #[arg(long)]
        registry: Option<String>,
        /// Draft location scope (default: system)
        #[arg(long, value_enum, default_value_t = DraftScopeArg::System)]
        scope: DraftScopeArg,
        /// Set all capability decisions to allow (trust this tool fully)
        #[arg(long)]
        allow_all: bool,
    },
    /// Initialize recommended baseline policy bundle
    Init {},
    /// Set up warrant for a specific use case
    Setup {
        /// Bundle name(s) (e.g. claude, codex, rust, github)
        #[arg(required = true)]
        bundles: Vec<String>,
    },
    /// Set default command policy mode for future locks
    SetDefault {
        #[arg(value_enum)]
        mode: PolicyDefaultMode,
        /// Immediately run lock after saving the setting
        #[arg(long)]
        apply: bool,
    },
    /// Edit a tool's draft policy (defaults to VISUAL/EDITOR)
    Edit {
        /// Tool name
        name: String,
        /// Draft location scope (default: system)
        #[arg(long, value_enum, default_value_t = DraftScopeArg::System)]
        scope: DraftScopeArg,
        /// Override editor command (e.g. "vim", "nvim", "hx", "nano")
        #[arg(long, conflicts_with = "tui")]
        editor: Option<String>,
        /// Open an interactive TUI editor
        #[arg(long, conflicts_with = "editor")]
        tui: bool,
        /// Render draft without comments (compact mode)
        #[arg(long, conflicts_with = "tui")]
        compact: bool,
    },
    /// Search for manifests (placeholder — prints bundled list for now)
    Search {
        /// Search query
        query: String,
    },
    /// Check whether a package appears in the bundled malicious package database
    PackageCheck {
        ecosystem: PackageEcosystemArg,
        package: String,
    },
    /// Update the malicious package denylist from Datadog's dataset
    PackageUpdate,
    /// Update wsh/wsh-auditd using official prebuilt binaries and verify daemon health
    Update {
        /// Run health checks only (no install/restart)
        #[arg(long)]
        check: bool,
    },
    /// Completely remove wsh, daemon, and privileged state/config directories
    Uninstall {
        /// Skip interactive confirmation
        #[arg(long)]
        yes: bool,
    },
    Lock {
        #[arg(value_name = "TOOL")]
        tool: Option<String>,
    },
    /// Show locked policy entries (`all`, `list`, or a tool like `git`)
    Policy {
        #[arg(value_name = "TARGET", default_value = "all")]
        target: String,
    },
    Status,
    Profiles,
    Projects,
    Check {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Manage shell guard
    Guard {
        /// The command string to evaluate (used by shell hook)
        #[arg(hide = true, conflicts_with_all = ["all", "off"])]
        command_string: Option<String>,
        /// Guard all shell sessions (dedicated agent machines)
        #[arg(long, conflicts_with = "off")]
        all: bool,
        /// Disable global guard (only agent sessions guarded)
        #[arg(long, conflicts_with = "all")]
        off: bool,
    },
    Explain {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    TestPolicy {
        #[arg(value_name = "TOOL")]
        tool: Option<String>,
    },
    Audit {
        #[arg(long, default_value_t = 20)]
        tail: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        clear: bool,
    },
    AuditVerify {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
    Elevate {
        #[arg(long, default_value_t = 30)]
        duration: u64,
    },
    DeElevate,
    IsElevated,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn parses_accept_defaults_as_global_flag() {
        let cli =
            Cli::try_parse_from(["wsh", "--accept-defaults", "init"]).expect("cli should parse");
        assert!(cli.accept_defaults);
        assert!(matches!(cli.command, Commands::Init {}));
    }

    #[test]
    fn parses_guard_all_flag() {
        let cli = Cli::try_parse_from(["wsh", "guard", "--all"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Guard {
                command_string: None,
                all: true,
                off: false
            }
        ));
    }

    #[test]
    fn parses_guard_off_flag() {
        let cli = Cli::try_parse_from(["wsh", "guard", "--off"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Guard {
                command_string: None,
                all: false,
                off: true
            }
        ));
    }

    #[test]
    fn parses_guard_status_without_flags() {
        let cli = Cli::try_parse_from(["wsh", "guard"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Guard {
                command_string: None,
                all: false,
                off: false
            }
        ));
    }

    #[test]
    fn parses_guard_hook_command_string() {
        let cli = Cli::try_parse_from(["wsh", "guard", "ls -la"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Guard {
                command_string: Some(ref command_string),
                all: false,
                off: false
            } if command_string == "ls -la"
        ));
    }

    #[test]
    fn parses_policy_default_target() {
        let cli = Cli::try_parse_from(["wsh", "policy"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Policy { ref target } if target == "all"
        ));
    }

    #[test]
    fn parses_policy_tool_target() {
        let cli = Cli::try_parse_from(["wsh", "policy", "git"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Policy { ref target } if target == "git"
        ));
    }

    #[test]
    fn parses_add_multiple_names() {
        let cli = Cli::try_parse_from(["wsh", "add", "git", "rust"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Add { ref names, .. } if names == &vec!["git".to_string(), "rust".to_string()]
        ));
    }

    #[test]
    fn parses_uninstall_yes_flag() {
        let cli = Cli::try_parse_from(["wsh", "uninstall", "--yes"]).expect("cli should parse");
        assert!(matches!(cli.command, Commands::Uninstall { yes: true }));
    }

    #[test]
    fn parses_set_default_allow() {
        let cli = Cli::try_parse_from(["wsh", "set-default", "allow"]).expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::SetDefault {
                mode: crate::config::PolicyDefaultMode::Allow,
                apply: false
            }
        ));
    }

    #[test]
    fn parses_set_default_with_apply() {
        let cli =
            Cli::try_parse_from(["wsh", "set-default", "deny", "--apply"]).expect("cli parse");
        assert!(matches!(
            cli.command,
            Commands::SetDefault {
                mode: crate::config::PolicyDefaultMode::Deny,
                apply: true
            }
        ));
    }
}
