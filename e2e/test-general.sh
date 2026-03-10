#!/bin/bash
# General e2e test: init → add → lock → exec → audit
# Runs inside Docker container with pre-built wsh binaries at /usr/local/bin/
set -euo pipefail

PASS=0
FAIL=0
SKIP=0
ERRORS=""

log()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$1"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); ERRORS="${ERRORS}\n  - $1"; }
skip() { printf '\033[1;33m[SKIP]\033[0m %s\n' "$1"; SKIP=$((SKIP + 1)); }

# -------------------------------------------------------------------
# Phase 1: Verify pre-built binaries
# -------------------------------------------------------------------
log "Phase 1: Verify pre-built binaries"

if command -v wsh &>/dev/null; then
  pass "wsh binary available"
  log "  version: $(wsh --version)"
else
  fail "wsh binary not found"
  exit 1
fi

if command -v wsh-auditd &>/dev/null; then
  pass "wsh-auditd binary available"
else
  fail "wsh-auditd binary not found"
  exit 1
fi

# -------------------------------------------------------------------
# Phase 2: Daemon setup
# -------------------------------------------------------------------
log "Phase 2: Daemon setup"

sudo mkdir -p /var/lib/warrant-shell/audit /var/run/warrant-shell
sudo chmod 0700 /var/lib/warrant-shell /var/lib/warrant-shell/audit
sudo chmod 0755 /var/run/warrant-shell
openssl rand -hex 32 | sudo tee /var/lib/warrant-shell/hmac.key > /dev/null
sudo chmod 0400 /var/lib/warrant-shell/hmac.key
sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

if [ -S /var/run/warrant-shell/auditd.sock ]; then
  pass "audit daemon running"
else
  fail "audit daemon socket not found"
fi

# -------------------------------------------------------------------
# Phase 3: Registry check
# -------------------------------------------------------------------
log "Phase 3: Registry reachable"

if curl -sf https://raw.githubusercontent.com/warrant-sh/registry/main/registry.toml >/dev/null 2>&1; then
  pass "public registry reachable"
else
  fail "public registry unreachable"
  exit 1
fi

# -------------------------------------------------------------------
# Phase 4: Init
# -------------------------------------------------------------------
log "Phase 4: Init"

if INIT_OUT="$(wsh init --accept-defaults 2>&1)"; then
  echo "$INIT_OUT"
  pass "wsh init completed"
else
  echo "$INIT_OUT"
  fail "wsh init failed"
fi

# -------------------------------------------------------------------
# Phase 5: Pull manifests
# -------------------------------------------------------------------
log "Phase 5: Pull manifests"

if PULL_OUT="$(wsh pull 2>&1)"; then
  echo "$PULL_OUT"
  pass "wsh pull succeeded"
else
  echo "$PULL_OUT"
  fail "wsh pull failed"
fi

# -------------------------------------------------------------------
# Phase 6: Add tool
# -------------------------------------------------------------------
log "Phase 6: Add tool"

if ADD_OUT="$(wsh add warrant-sh/git 2>&1)"; then
  echo "$ADD_OUT"
  pass "wsh add warrant-sh/git succeeded"
else
  echo "$ADD_OUT"
  fail "wsh add warrant-sh/git failed"
fi

# -------------------------------------------------------------------
# Phase 7: Lock warrant
# -------------------------------------------------------------------
log "Phase 7: Lock warrant"

if LOCK_OUT="$(sudo -E wsh lock 2>&1)"; then
  echo "$LOCK_OUT"
  pass "wsh lock succeeded"
else
  echo "$LOCK_OUT"
  fail "wsh lock failed"
fi

# Restart daemon — it needs the signing key created by wsh lock
sudo pkill wsh-auditd 2>/dev/null || true
sleep 1
sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

# -------------------------------------------------------------------
# Phase 8: Status
# -------------------------------------------------------------------
log "Phase 8: Check status"

if STATUS_OUT="$(sudo -E wsh status 2>&1)"; then
  echo "$STATUS_OUT"
  if echo "$STATUS_OUT" | grep -qi "warrant"; then pass "wsh status shows warrant info"
  else fail "wsh status output unexpected"; fi
else
  echo "$STATUS_OUT"
  fail "wsh status failed"
fi

# -------------------------------------------------------------------
# Phase 9: Check command
# -------------------------------------------------------------------
log "Phase 9: Check commands"

if sudo -E wsh check ls /tmp 2>&1; then pass "wsh check: ls allowed"
else fail "wsh check: ls unexpectedly denied"; fi

# -------------------------------------------------------------------
# Phase 10: Exec commands
# -------------------------------------------------------------------
log "Phase 10: Exec commands"

if sudo -E wsh exec ls /tmp 2>&1; then pass "wsh exec ls /tmp succeeded"
else fail "wsh exec ls /tmp failed"; fi

if EXEC_OUT="$(sudo -E wsh exec echo 'hello from wsh e2e' 2>&1)"; then
  if echo "$EXEC_OUT" | grep -q "hello from wsh e2e"; then pass "wsh exec echo succeeded"
  else fail "wsh exec echo output missing expected text"; fi
else
  echo "$EXEC_OUT"
  fail "wsh exec echo failed"
fi

# -------------------------------------------------------------------
# Phase 11: Audit log
# -------------------------------------------------------------------
log "Phase 11: Verify audit log"

if AUDIT_OUT="$(sudo -E wsh audit 2>&1)"; then
  echo "$AUDIT_OUT"
  if echo "$AUDIT_OUT" | grep -q "ls"; then pass "audit log contains ls"
  else fail "audit log missing ls entry"; fi
else
  echo "$AUDIT_OUT"
  fail "wsh audit command failed"
fi

# -------------------------------------------------------------------
# Phase 12: Package denylist
# -------------------------------------------------------------------
log "Phase 12: Package denylist"

if PACKAGE_UPDATE_OUT="$(sudo -E wsh package-update 2>&1)"; then
  echo "$PACKAGE_UPDATE_OUT"
  if echo "$PACKAGE_UPDATE_OUT" | grep -qi "Updated npm denylist"; then
    pass "wsh package-update succeeded and reported denylist update"
  else
    fail "wsh package-update succeeded but output did not confirm denylist update"
  fi
else
  echo "$PACKAGE_UPDATE_OUT"
  fail "wsh package-update failed"
fi

# -------------------------------------------------------------------
# Phase 13: Elevation
# -------------------------------------------------------------------
log "Phase 13: Elevation flow"

if ELEVATE_OUT="$(sudo -E wsh elevate --duration 1 2>&1)"; then
  echo "$ELEVATE_OUT"
else
  echo "$ELEVATE_OUT"
  fail "wsh elevate failed"
fi

if sudo -E wsh is-elevated 2>&1 | grep -q "true"; then pass "elevation active"
else fail "elevation not active"; fi

if DEELEVATE_OUT="$(sudo -E wsh de-elevate 2>&1)"; then
  echo "$DEELEVATE_OUT"
else
  echo "$DEELEVATE_OUT"
  fail "wsh de-elevate failed"
fi

if sudo -E wsh is-elevated 2>&1 | grep -q "true"; then fail "elevation still active after de-elevate"
else pass "elevation cleared"; fi

# -------------------------------------------------------------------
# Phase 14: Audit verify
# -------------------------------------------------------------------
log "Phase 14: Audit verify"

AUDIT_VERIFY_OUT="$(sudo -E wsh audit-verify 2>&1)" && RC=$? || RC=$?
echo "$AUDIT_VERIFY_OUT"
if [ $RC -eq 0 ] && echo "$AUDIT_VERIFY_OUT" | grep -qi "VALID\\|valid\\|ok\\|pass"; then
  pass "audit-verify succeeded and reported valid chain"
else
  fail "audit-verify failed or did not report a valid chain"
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "========================================"
echo "  RESULTS: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "========================================"
if [ $FAIL -gt 0 ]; then
  printf "  Failures:%b\n" "$ERRORS"
  exit 1
fi
exit 0
