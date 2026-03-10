# End-to-End Tests

Docker-based integration tests that exercise the full wsh user journey: init → add → lock → exec → audit.

## How it works

Multi-stage Docker build:
1. **Stage 1 (builder):** Compiles wsh in Debian bookworm — cached after first run
2. **Stage 2 (runtime):** Lightweight image with pre-built binaries, no Rust toolchain

First run compiles (~60s). Subsequent runs use cached binaries and start in seconds.

## Prerequisites

- Docker
- The [registry](https://github.com/warrant-sh/registry) is public — tests fetch manifests directly from GitHub
- API keys (only for agent tests — general/security tests need nothing)

## Quick Start

After code changes, always do a clean build and run:

```bash
docker rmi wsh-e2e 2>/dev/null; rm -rf target/dist && source e2e/env.sh && ./e2e/run.sh
```

This ensures:
- **`docker rmi wsh-e2e`** — removes the cached Docker image (forces rebuild with new binaries)
- **`rm -rf target/dist`** — removes stale pre-built binaries (forces fresh musl cross-compile)
- **`source e2e/env.sh`** — loads API keys from `~/.openclaw/workspace/.secrets/`
- **`./e2e/run.sh`** — builds static musl binaries, builds Docker image, runs all suites

To run a single suite:

```bash
docker rmi wsh-e2e 2>/dev/null; rm -rf target/dist && source e2e/env.sh && ./e2e/run.sh claude
```

## Test Suites

### `test-general.sh` — Core Flow (no API keys)

14 phases covering the full lifecycle:

1. Verify pre-built binaries
2. Daemon setup (manual, no systemd)
3. Registry reachable
4. Init (`wsh init --accept-defaults`)
5. Pull manifests from public registry
6. Add a tool (git)
7. Lock warrant
8. Status check
9. Command check (allow/deny)
10. Exec through warrant
11. Audit log verification
12. Package denylist update
13. Elevation flow (elevate → is-elevated → de-elevate)
14. Audit hash chain verify

### `test-security.sh` — Security Hardening

Verifies that warrant-shell blocks what it should: denied paths, deny_flags, command wrappers, privilege escalation, env variable stripping, tamper resistance.

### `test-claude.sh` / `test-codex.sh` — Agent Integration

Set up agent bundles, run through `wsh exec`, verify audit trail and policy enforcement.

## Logs

Each run writes timestamped logs to `e2e/logs/` (gitignored):

```
e2e/logs/general-20260305-183000.log
e2e/logs/security-20260305-183000.log
```
