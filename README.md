<p align="center">
  <img src="docs/logo.jpg" alt="Warrant" width="120">
</p>

<h1 align="center">warrant-shell (wsh)</h1>

<p align="center">
  Signed capability policies for AI shell agents.
</p>

`wsh` is a command guard for agent-driven shell work. It sits in front of shell execution, checks each command against a signed warrant, and records an audit trail of what was allowed or denied.

It is designed to wrap agent tool calls, not to replace OS sandboxing. Use Docker, Landlock, Firejail, VM isolation, or similar for containment. Use `wsh` to control what an agent is authorized to do inside that environment.

## What `wsh` does

- Wraps shell execution with policy checks
- Enforces signed TOML warrants compiled from manifest-driven drafts
- Logs allow and deny decisions through `wsh-auditd`
- Supports command, file, network, process, git, and environment controls
- Blocks known-dangerous flags and known-malicious packages for supported package managers
- Supports system policies, project policies, and named profiles

The current implementation is manifest-first. `wsh add <tool>` installs draft policy from a signed registry manifest, `wsh lock` compiles and signs the resulting warrant, and `wsh exec -- ...` or the shell guard enforces it.

## How it works

1. `wsh init` installs the baseline manifests: `warrant-sh/coreutils`, `warrant-sh/sanitize-env`, and `warrant-sh/dangerous-patterns`.
2. `wsh add <tool>` pulls more manifests and writes editable drafts.
3. `wsh lock` compiles drafts, signs the warrant, and installs it.
4. `wsh exec -- ...` checks a command before execution.
5. `wsh-auditd` records the decision in a tamper-evident hash-chained audit ledger.

The shell guard mode makes this transparent to the agent. When enabled, agent shell commands are routed through `wsh guard`, so each external command is checked automatically.

## Quick start

Install the current release from the canonical installer:

```bash
curl -fsSL https://warrant.sh/install.sh | sudo sh
```

This is the recommended mode. When run as root, the installer places `wsh` and `wsh-auditd`, creates the daemon service, and enables non-root agent execution with daemon-backed audit logging.

For a tighter socket posture, install with group-based access instead of a world-writable audit socket:

```bash
curl -fsSL https://warrant.sh/install.sh | sudo sh -s -- --group-socket-access
```

Then set up an agent profile:

```bash
wsh setup codex
# or
wsh setup claude
```

`wsh setup` installs common manifests, locks the policy, and configures the shell hook so the agent keeps using its normal CLI while commands are checked underneath.

## Installation and platform support

The installer script at `https://warrant.sh/install.sh` currently supports:

- Linux `amd64`
- Linux `arm64`
- macOS `amd64`
- macOS `arm64`

User-mode install is also supported:

```bash
curl -fsSL https://warrant.sh/install.sh | sh
```

That installs `wsh` only, usually to `~/.local/bin`. Root install is still the expected setup if you want daemon-backed fail-closed auditing.

## Configuration

There are two TOML layers:

### `wsh.toml`

`wsh.toml` is the shareable manifest-selection file. `wsh init` and `wsh add` use it to decide which manifest drafts should exist.

Supported locations:

- `./wsh.toml`
- `./.warrant/wsh.toml`
- `~/.config/wsh/wsh.toml`

Example:

```toml
[config]
schema = "warrant.config.v1"
command_default = "deny"

manifests = [
  "warrant-sh/git",
  "warrant-sh/cargo",
  "warrant-sh/sanitize-env",
  "warrant-sh/dangerous-patterns",
]
```

`command_default` can be:

- `deny`: commands not explicitly allowed are denied
- `allow`: commands not explicitly allowed are permitted unless another control denies them

You can update the system default with:

```bash
wsh set-default deny
wsh set-default allow
sudo wsh set-default allow --apply
```

### Draft policy and locked warrant

Drafts are TOML files generated from manifests and edited with `wsh edit`. `wsh lock` compiles those drafts into the installed warrant used at runtime.

The resulting policy covers capability domains such as:

- `commands`
- `files.read`
- `files.write`
- `files.delete`
- `network`
- `git`
- `process`
- `environment.strip`

At runtime, the installed warrant also carries policy metadata such as `command_default` and `audit_required`.

## Enforcement model

`wsh` is policy enforcement plus audit, not a sandbox.

Important behaviors from the current codebase:

- Shell builtins like `cd`, `echo`, and `export` are skipped by the shell guard to avoid noise.
- Security-relevant builtins like `eval`, `exec`, `source`, and `.` are still evaluated.
- Commands are parsed segment-by-segment across pipelines and chained commands.
- Dangerous flag patterns can be blocked per tool with manifest `deny_flags`.
- Package manifests can enforce package denylist checks for `npm`, `pip`/`pypi`, and `cargo`.
- If `audit_required = true` and audit logging fails, execution is denied.

## Audit logging

`wsh-auditd` receives audit events over a local endpoint, authenticates the caller, and appends JSON lines to a SHA-256 hash-chained ledger.

Useful commands:

```bash
wsh audit --tail 20
wsh audit --json
wsh audit --clear
wsh audit-verify
```

The daemon also supports a relay path for sandboxed agent runs, so `audit_required=true` can stay fail-closed while still letting the daemon own the final ledger.

## Usage examples

Initialize and build a policy:

```bash
wsh init
wsh add git cargo
sudo wsh lock
```

Check a command without running it:

```bash
wsh check git status
wsh explain git push --force origin main
```

Run under enforcement:

```bash
wsh exec -- cargo build
```

Create a project policy:

```bash
cd ~/Work/my-project
wsh add git --scope project
wsh edit git --scope project
sudo wsh lock
```

Use a named profile:

```bash
wsh --profile codex exec -- cargo test
wsh profiles
```

Check package reputation:

```bash
wsh package-check npm left-pad
wsh package-update
```

Inspect installed policy state:

```bash
wsh status
wsh policy all
wsh projects
```

## Current status

`wsh` is alpha.

As of this README update, the crate contains:

- 449 listed tests across unit and integration suites
- Installer support for Linux and macOS on `amd64` and `arm64`
- Two binaries: `wsh` and `wsh-auditd`

Notable coverage in the test suite includes command parsing, manifest compilation, deny-flag enforcement, package denylist behavior, shell compatibility, audit daemon behavior, profiles, project policies, and security regression cases.

## Relationship to `warrant-core`

`wsh` uses [`warrant-core`](https://github.com/warrant-sh/warrant-core) for canonical payload handling, signature verification, locking, installed warrant loading, and elevation session primitives. `wsh` adds the CLI, manifest workflow, shell parsing, enforcement layer, and audit daemon.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE), at your option.
