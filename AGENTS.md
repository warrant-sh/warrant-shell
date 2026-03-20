# warrant-shell — Agent Rules

## What This Crate Does

Command-line tool (`wsh`) that **enforces** policies — it does not **define** them. The rules about what a tool can do (its capabilities, risk levels, scopes) live in **manifests** in the [registry](https://github.com/warrant-sh/registry). The user's policy decisions (allow/deny per capability) live in local **draft** files. warrant-shell's job is to fetch manifests from the registry, help the user make policy decisions, compile those into a signed warrant, and then enforce that warrant at runtime by checking every command before it executes.

The flow: **registry** (what can a tool do?) → **draft** (what should it be allowed to do?) → **lock** (sign it) → **enforce** (check every command at runtime).

Also includes `wsh-auditd`, a privileged daemon that receives audit events over a Unix socket and writes them to hash-chained ledger files that agents cannot tamper with.

**If you need to change what a tool's capabilities are, that's a registry change, not a warrant-shell change.** See the [registry AGENTS.md](https://github.com/warrant-sh/registry/blob/main/AGENTS.md) for how to write manifests.

## Architecture Overview

**Two binaries:**
- `src/bin/wsh.rs` — the CLI. Entry point calls `app::run()`. Simple dispatch, no logic here.
- `src/bin/wsh_auditd.rs` — privileged audit daemon. Listens on Unix socket, validates via SO_PEERCRED, appends to daily JSONL ledgers with SHA-256 hash chains. One thread per connection.

**Key modules:**

| Module | Purpose |
|--------|---------|
| `app.rs` | Application logic for all CLI subcommands. The big file. |
| `guard.rs` | Shell guard — intercepts commands, parses shell syntax, evaluates each segment against policy. |
| `shell_parser.rs` | Parses compound shell commands (pipes, &&, ||, ;, subshells) into segments. |
| `parser.rs` | Parses a command against its manifest to extract capability + scopes. |
| `audit.rs` | `AuditSink` trait + `FileSink` + `DaemonSink` implementations. Hash-chain logic. |
| `manifest.rs` | Loads and validates manifest TOML files (tool capability maps). |
| `policy.rs` | Reads locked warrant policies from disk, resolves decisions. |
| `exec.rs` | Actually executes commands after policy allows them. |
| `compiler.rs` | Compiles draft policies into locked warrants (merges manifests + user decisions). |
| `elevation.rs` | Temporary privilege elevation sessions (time-limited bypass). |
| `denylist_update.rs` | Downloads malicious package lists from Datadog's dataset. Shared by CLI and daemon. |
| `package_denylist.rs` | Checks packages against the local denylist files. |
| `registry.rs` | Fetches manifests from the registry repo. |
| `bundles.rs` | Named collections of manifests (e.g. "rust" = cargo + rustup + clippy). |
| `config.rs` | User configuration (default policy mode, paths, etc). |
| `paths.rs` | Path resolution. System vs project scope. `PathSource` enum. |
| `transforms.rs` | Scope transforms: literal, path, hostname, email_domain, glob, git_remote. |
| `trusted_tools.rs` | Hardcoded list of tools that bypass policy (e.g. `ls`, `cat`). |
| `setup.rs` | First-run setup wizard. |
| `draft.rs` | Draft policy file management. |
| `tui_edit.rs` | TUI policy editor (ratatui + crossterm). |

## Dependency on warrant-core

warrant-shell depends on `warrant-core` via git:
```toml
warrant-core = { git = "https://github.com/warrant-sh/warrant-core", branch = "main" }
```

Core provides: `ParsedWarrant`, `check()` (the policy engine), `Decision`, `DenyReason`, Ed25519 signing/verification, `ToolPaths`, `ToolId`, lock/review functions.

**Rule:** Never reimplement anything that belongs in core. If you need a policy primitive, it should be in warrant-core. Shell is the CLI wrapper; core is the engine.

## CLI Subcommands

| Command | What it does |
|---------|-------------|
| `exec <cmd>` | Evaluate and execute a command |
| `guard [cmd]` | Shell hook mode — evaluate command from shell precmd |
| `guard --all / --off` | Enable/disable global guard |
| `pull [tool]` | Fetch manifest from registry |
| `add <tools>` | Add tools/bundles to local drafts |
| `init` | Initialize baseline policy |
| `setup <bundles>` | First-run setup for specific use cases |
| `edit <tool>` | Edit draft policy (TUI or editor) |
| `lock [tool]` | Sign and install warrant from draft |
| `policy [target]` | Show locked policy entries |
| `status` | Show installed warrant metadata |
| `check <cmd>` | Dry-run: would this command be allowed? |
| `explain <cmd>` | Show how a command maps to capabilities/scopes |
| `test-policy [tool]` | Run built-in policy tests |
| `audit` | Show recent audit log entries |
| `audit-verify [path]` | Verify hash chain integrity |
| `elevate` | Create temporary elevation session |
| `de-elevate` | Clear elevation session |
| `is-elevated` | Check elevation status |
| `package-check <eco> <pkg>` | Check package against denylist |
| `package-update` | Update denylist from Datadog |
| `update` | Self-update wsh binaries |
| `uninstall` | Remove wsh completely |
| `profiles` | List available profiles |
| `projects` | List project-scoped policies |
| `search <query>` | Search manifest registry |
| `set-default <mode>` | Set default policy mode (allow/deny/prompt) |

## How to Run Tests

```bash
# All tests (unit + integration)
cargo test -p wsh

# Unit tests only (faster)
cargo test -p wsh --lib

# Specific integration test file
cargo test -p wsh --test audit_tests

# Specific test by name
cargo test -p wsh -- test_name_substring
```

**Test count must not decrease.** Run `cargo test -p wsh 2>&1 | grep "test result"` before and after your changes. If your change reduces the number of passing tests, fix it — do not delete or disable tests to make failures go away.

**Test isolation:** Tests that touch env vars use `test_env_lock()` — a global mutex in `lib.rs`. Always acquire this lock in tests that set/unset environment variables.

**Test directories:** Integration tests use `tempfile::tempdir()` with `WARRANT_TEST_ROOT` or `--paths-root` pointing to the temp dir. Never write to real system paths (`/var/lib/`, `/etc/`).

## Integration Test Files

| File | What it tests |
|------|---------------|
| `audit_daemon_tests.rs` | Spawns real daemon, tests socket communication, hash chain verification |
| `audit_tests.rs` | FileSink, DaemonSink, spool fallback, entry serialization |
| `autodiscovery_tests.rs` | Manifest autodiscovery from PATH |
| `cli_integration.rs` | Full CLI subcommand integration (exec, check, pull, add, lock, etc.) |
| `deny_flags_tests.rs` | Flag-based denials, tool_policy deny_flags |
| `manifest_refactor_tests.rs` | Manifest loading, validation, capability mapping |
| `package_denylist_tests.rs` | Package security checks, denylist loading |
| `profile_tests.rs` | Profile switching, profile-scoped policies |
| `security_regression_tests.rs` | Specific attack vectors and regressions |
| `shell_compat_tests.rs` | Shell syntax parsing edge cases |
| `use_case_tests.rs` | End-to-end usage scenarios |

## Common Mistakes

- **DO NOT** compile denylist data into the binary. Use runtime files at `/var/lib/warrant-shell/denylists/` (system) or `<paths-root>/denylists/` (dev). The binary ships empty.
- **DO NOT** use `unwrap()` in daemon code. The daemon must fail-open with logged warnings, never crash on transient errors.
- **DO NOT** invent new manifest schemas — read the existing codebase and `registry/AGENTS.md` first.
- **DO NOT** add new `WSH_*` environment variables without adding them to either `PRESERVED_WSH_ENV_VARS` (if they must survive scrubbing) or leaving them out (scrubbed by default). The scrubbing in `lib.rs` is a security boundary.
- **DO NOT** put policy logic in warrant-shell. Policy evaluation belongs in warrant-core's `check()` function.
- **Always** use `--paths-root` or `WARRANT_TEST_ROOT` in tests. Never touch real system directories.
- **Always** run `cargo fmt` and `cargo clippy -- -D warnings` before committing.

## Key Dependency Choices

Do not switch these without discussion:
- **`warrant-core`** (git dependency on `main` branch) for all policy logic. Never reimplement policy evaluation in this crate.
- **`ed25519-dalek`** for signing. Same library as core — must stay in sync.
- **`sha2`** for audit hash chains.

Everything else (versions, full dependency list, binary names, edition) is in `Cargo.toml`.
