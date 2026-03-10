# Contributing to warrant-shell

Thanks for your interest in contributing to warrant-shell! This guide will help you get started.

## Quick Links

- [Issue Tracker](https://github.com/warrant-sh/warrant-shell/issues)
- [Discussions](https://github.com/warrant-sh/warrant-shell/discussions)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## How to Contribute

### Reporting Bugs

Found a bug? [Open an issue](https://github.com/warrant-sh/warrant-shell/issues/new?template=bug_report.yml) with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behaviour
- Your OS, Rust version, and wsh version (`wsh --version`)

**Security vulnerabilities:** Please do **not** open a public issue. Email [security@warrant.sh](mailto:security@warrant.sh) instead. We'll respond within 48 hours.

### Suggesting Features

Have an idea? [Open a feature request](https://github.com/warrant-sh/warrant-shell/issues/new?template=feature_request.yml). We'd love to hear:

- What problem you're trying to solve
- How you'd expect it to work
- Whether you'd be willing to implement it

### Contributing Code

1. **Fork** the repo and create a branch from `main`
2. **Write tests** for any new functionality
3. **Run the test suite** before submitting:
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```
4. **Open a PR** with a clear description of what changed and why

#### Development Setup

```bash
# Clone both repos (warrant-core is a dependency)
git clone https://github.com/warrant-sh/warrant-core.git
git clone https://github.com/warrant-sh/warrant-shell.git
cd warrant-shell

# Build
cargo build

# Run tests
cargo test

# Run a specific test
cargo test scenario_01
```

**Audit daemon for integration testing:** The audit daemon (`wsh-auditd`) is required for system-mode integration tests. Use the dev install script to set it up locally:

```bash
sudo ./scripts/install-dev.sh
```

This installs the daemon as a system service and creates the required socket and ledger directories. For unit tests that don't need the daemon, the file-based audit sink is used automatically.

#### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix any warnings
- Keep commits focused — one logical change per commit
- Write clear commit messages: `fix(policy): handle symlink resolution in path checks`

#### What Makes a Good PR

- Solves a real problem (linked to an issue when possible)
- Includes tests for new behaviour
- Doesn't break existing tests
- Keeps the diff minimal — avoid unrelated formatting changes
- Updates documentation if behaviour changes

### Contributing Manifests

Tool manifests (in `manifests/bundled/`) are a great way to contribute without touching Rust code. If you use a CLI tool that doesn't have a manifest yet:

1. Create a TOML manifest following the format in existing manifests
2. Cover the tool's key capabilities (what actions does it perform?)
3. Include sensible defaults
4. Open a PR

### Contributing Presets

Safety presets (in `manifests/presets/`) define reusable policy patterns. If you've developed a useful policy pattern:

1. Create a TOML preset following the existing format
2. Document what it does and when to use it in comments
3. Open a PR

## Design Principles

When contributing, keep these principles in mind:

- **Policy lives in TOML, not code.** Nothing is hardcoded. If it's a policy decision, it belongs in a manifest or preset.
- **Deny by default.** If it's not explicitly allowed, it's denied.
- **No paternalism.** wsh enforces the user's policy. It doesn't second-guess them.
- **Audit everything.** Every decision (allow or deny) gets logged.
- **Fail closed.** If something goes wrong, deny the command. Never fail open.

## Getting Help

- **Questions about contributing:** Open a [discussion](https://github.com/warrant-sh/warrant-shell/discussions)
- **Bug reports:** Use the [issue tracker](https://github.com/warrant-sh/warrant-shell/issues)
- **Security issues:** Email [security@warrant.sh](mailto:security@warrant.sh)

## Licence

By contributing, you agree that your contributions will be licensed under the same terms as the project: [MIT](LICENSE) or [Apache 2.0](LICENSE-APACHE), at the user's option.
