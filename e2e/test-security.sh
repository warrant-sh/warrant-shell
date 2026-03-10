#!/bin/bash
# Security e2e tests: deny paths, deny_flags, tamper resistance, daemon failure
# Runs inside Docker container with pre-built binaries at /usr/local/bin/
#
# These tests verify that warrant-shell BLOCKS what it should block.
# The general tests prove things work; these prove they fail safely.
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
# Setup: install, daemon, init, lock
# -------------------------------------------------------------------

sudo mkdir -p /var/lib/warrant-shell/audit /var/run/warrant-shell
sudo chmod 0700 /var/lib/warrant-shell /var/lib/warrant-shell/audit
sudo chmod 0755 /var/run/warrant-shell
openssl rand -hex 32 | sudo tee /var/lib/warrant-shell/hmac.key > /dev/null
sudo chmod 0400 /var/lib/warrant-shell/hmac.key
sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

# Init with baseline bundle (coreutils + sanitize-env + dangerous-patterns)
if INIT_OUT="$(wsh init --accept-defaults 2>&1)"; then
  echo "$INIT_OUT"
else
  echo "$INIT_OUT"
  fail "wsh init failed in setup"
  exit 1
fi

# Also add git so we have a non-coreutils manifest to test
if ADD_GIT_OUT="$(wsh add warrant-sh/git 2>&1)"; then
  echo "$ADD_GIT_OUT"
else
  echo "$ADD_GIT_OUT"
  fail "setup failed: wsh add warrant-sh/git"
  exit 1
fi

# Add codex manifest to test deny_flags
if ADD_CODEX_OUT="$(wsh add warrant-sh/codex 2>&1)"; then
  echo "$ADD_CODEX_OUT"
else
  echo "$ADD_CODEX_OUT"
  fail "setup failed: wsh add warrant-sh/codex"
  exit 1
fi

# Lock the warrant as root (this creates signing keys)
if LOCK_OUT="$(sudo -E wsh lock 2>&1)"; then
  echo "$LOCK_OUT"
else
  echo "$LOCK_OUT"
  fail "setup failed: sudo -E wsh lock"
  exit 1
fi

log "Setup complete — running security tests"
echo ""

# ===================================================================
# SECTION 1: DENY PATH COVERAGE
# ===================================================================
echo "========================================"
echo "  SECTION 1: Command Denial"
echo "========================================"

# -------------------------------------------------------------------
# 1.1: Command not in any manifest → denied
# -------------------------------------------------------------------
log "1.1: Unlisted command denied (python3)"

OUT="$(sudo -E wsh exec python3 --version 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "denied\\|not.*allow\\|no.*manifest\\|not.*capabilities"; then
  pass "python3 denied (not in any manifest)"
else
  echo "  Got: $OUT"
  fail "python3 was allowed (should be denied — not in any manifest)"
fi

# -------------------------------------------------------------------
# 1.2: Another unlisted command
# -------------------------------------------------------------------
log "1.2: Unlisted command denied (curl)"

# curl is in coreutils? Let's check — if not, it should be denied
OUT="$(sudo -E wsh exec wget --version 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "denied\\|not.*allow\\|no.*manifest\\|not.*capabilities"; then
  pass "wget denied (not in any manifest)"
else
  echo "  Got: $OUT"
  fail "wget was allowed (should be denied — not in any manifest)"
fi

# -------------------------------------------------------------------
# 1.3: Dangerous pattern — rm -rf /
# -------------------------------------------------------------------
log "1.3: Dangerous pattern blocked (rm -rf /)"

OUT="$(sudo -E wsh check rm -rf / 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "denied\\|blocked\\|danger"; then
  pass "rm -rf / blocked"
else
  echo "  Got: $OUT"
  fail "rm -rf / was NOT blocked"
fi

# -------------------------------------------------------------------
# 1.4: Dangerous pattern — writing to /etc
# -------------------------------------------------------------------
log "1.4: Dangerous pattern — write to sensitive path"

OUT="$(sudo -E wsh check cp /dev/null /etc/passwd 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "denied\\|blocked\\|danger\\|sensitive\\|capabilities.files.write.paths"; then
  pass "write to /etc/passwd blocked"
else
  echo "  Got: $OUT"
  fail "write to /etc/passwd was NOT blocked"
fi

# -------------------------------------------------------------------
# 1.5: Allowed command still works (sanity check)
# -------------------------------------------------------------------
log "1.5: Allowed command still works (ls)"

OUT="$(sudo -E wsh exec ls /tmp 2>&1)" && RC=$? || RC=$?
if [ $RC -eq 0 ]; then
  pass "ls /tmp still allowed"
else
  echo "  Got: $OUT"
  fail "ls /tmp was denied (should be allowed)"
fi

# -------------------------------------------------------------------
# 1.6: Denied command shows useful error message
# -------------------------------------------------------------------
log "1.6: Denial error message is informative"

OUT="$(sudo -E wsh exec python3 --version 2>&1)" || true
if echo "$OUT" | grep -qi "denied\|not.*allow\|no.*manifest\|not.*capabilities"; then
  pass "denial message explains why"
else
  echo "  Got: $OUT"
  fail "denial message not informative enough"
fi

# ===================================================================
# SECTION 2: DENY_FLAGS
# ===================================================================
echo ""
echo "========================================"
echo "  SECTION 2: deny_flags Enforcement"
echo "========================================"

# -------------------------------------------------------------------
# 2.1: --yolo flag blocked for codex
# -------------------------------------------------------------------
log "2.1: codex --yolo blocked by deny_flags"

OUT="$(sudo -E wsh check codex --yolo 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "yolo\\|deny.flag\\|blocked\\|denied"; then
  pass "codex --yolo denied"
else
  echo "  Got: $OUT"
  fail "codex --yolo was NOT denied"
fi

# -------------------------------------------------------------------
# 2.2: Long form of yolo flag also blocked
# -------------------------------------------------------------------
log "2.2: codex --dangerously-bypass-approvals-and-sandbox blocked"

OUT="$(sudo -E wsh check codex --dangerously-bypass-approvals-and-sandbox 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "dangerously-bypass-approvals-and-sandbox\\|deny.flag\\|blocked\\|denied"; then
  pass "codex --dangerously-bypass-approvals-and-sandbox denied"
else
  echo "  Got: $OUT"
  fail "codex --dangerously-bypass-approvals-and-sandbox was NOT denied"
fi

# -------------------------------------------------------------------
# 2.3: Non-flagged command still allowed (deny_flags not overly broad)
# -------------------------------------------------------------------
log "2.3: git (no deny_flags) still allowed"

OUT="$(sudo -E wsh check git status 2>&1)" && RC=$? || RC=$?
if [ $RC -eq 0 ]; then
  pass "git status allowed (deny_flags not blocking unrelated tools)"
else
  echo "  Got: $OUT"
  fail "git status was denied (deny_flags too broad?)"
fi

# -------------------------------------------------------------------
# 2.4: deny_flags error message mentions the flag
# -------------------------------------------------------------------
log "2.4: deny_flags error message is informative"

OUT="$(sudo -E wsh check codex --yolo 2>&1)" || true
if echo "$OUT" | grep -qi "yolo\|deny.flag\|blocked"; then
  pass "deny_flags message mentions the blocked flag"
else
  echo "  Got: $OUT"
  fail "deny_flags message not informative"
fi

# ===================================================================
# SECTION 3: WARRANT INTEGRITY
# ===================================================================
echo ""
echo "========================================"
echo "  SECTION 3: Warrant Integrity"
echo "========================================"

# -------------------------------------------------------------------
# 3.1: Non-root cannot modify the warrant file
# -------------------------------------------------------------------
log "3.1: Non-root cannot write to warrant file"

WARRANT_FILE="/etc/warrant-shell/warrant.toml"
if [ -f "$WARRANT_FILE" ]; then
  # Use subshell to avoid set -e killing the script on redirection failure
  ( set +e; echo "# tamper" >> "$WARRANT_FILE" ) 2>/dev/null && RC=0 || RC=1
  if [ $RC -ne 0 ]; then
    pass "non-root cannot modify warrant file"
  else
    fail "non-root CAN modify warrant file (permissions too open)"
  fi
else
  fail "warrant file not found at $WARRANT_FILE"
fi

# -------------------------------------------------------------------
# 3.2: Non-root cannot delete the warrant file
# -------------------------------------------------------------------
log "3.2: Non-root cannot delete warrant file"

rm "$WARRANT_FILE" 2>/dev/null && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot delete warrant file"
else
  fail "non-root CAN delete warrant file"
fi

# -------------------------------------------------------------------
# 3.3: Non-root cannot run wsh lock
# -------------------------------------------------------------------
log "3.3: Non-root cannot lock a new warrant"

OUT="$(wsh lock 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot run wsh lock"
else
  fail "non-root CAN run wsh lock (should require root)"
fi

# ===================================================================
# SECTION 4: AUDIT INTEGRITY
# ===================================================================
echo ""
echo "========================================"
echo "  SECTION 4: Audit Integrity"
echo "========================================"

# -------------------------------------------------------------------
# Section 4 preamble: generate audit entries first
# -------------------------------------------------------------------
AUDIT_DIR="/var/lib/warrant-shell/audit"

log "4.0: Generate audit entries for integrity checks"

# One denied and one allowed daemon-mediated exec to ensure audit files exist.
sudo -E wsh exec python3 --version >/dev/null 2>&1 || true
sudo -E wsh exec ls /tmp >/dev/null 2>&1 || true
sleep 1

if ! sudo bash -c "ls '${AUDIT_DIR}'/*.jsonl >/dev/null 2>&1"; then
  fail "audit files were not created after daemon exec activity"
fi

# -------------------------------------------------------------------
# 4.1: Non-root cannot read audit logs directly
# -------------------------------------------------------------------
log "4.1: Non-root cannot read audit log files"

AUDIT_FILE="$(sudo bash -c "ls '${AUDIT_DIR}'/*.jsonl 2>/dev/null | head -1" || true)"
if [ -z "$AUDIT_FILE" ]; then
  fail "no audit file available for non-root read test"
else
  (cat "$AUDIT_FILE" >/dev/null 2>&1) && RC=$? || RC=$?
  if [ $RC -ne 0 ]; then
    pass "non-root cannot read audit logs"
  else
    fail "non-root CAN read audit logs (permissions too open)"
  fi
fi

# -------------------------------------------------------------------
# 4.2: Non-root cannot write to audit directory
# -------------------------------------------------------------------
log "4.2: Non-root cannot write to audit directory"

( set +e; echo "tamper" > "${AUDIT_DIR}/fake.jsonl" ) 2>/dev/null && RC=0 || RC=1
if [ $RC -ne 0 ]; then
  pass "non-root cannot write to audit directory"
else
  fail "non-root CAN write to audit directory"
fi

# -------------------------------------------------------------------
# 4.3: Non-root cannot delete audit logs
# -------------------------------------------------------------------
log "4.3: Non-root cannot delete audit files"

rm -f "${AUDIT_DIR}"/*.jsonl 2>/dev/null && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot delete audit files"
else
  fail "non-root CAN delete audit files"
fi

# -------------------------------------------------------------------
# 4.4: Audit captures denied commands
# -------------------------------------------------------------------
log "4.4: Audit records denials"

AUDIT_OUT="$(sudo -E wsh audit 2>&1)"
if echo "$AUDIT_OUT" | grep -q "DENY"; then
  pass "audit log records denied commands"
else
  fail "audit log does not record denied commands"
fi

# -------------------------------------------------------------------
# 4.5: Audit hash chain is valid
# -------------------------------------------------------------------
log "4.5: Audit hash chain integrity"

VERIFY_OUT="$(sudo -E wsh audit-verify 2>&1)"
if echo "$VERIFY_OUT" | grep -qi "VALID\|valid\|ok\|pass"; then
  pass "audit hash chain is valid"
else
  echo "  Got: $VERIFY_OUT"
  fail "audit hash chain verification failed"
fi

# ===================================================================
# SECTION 5: DAEMON FAILURE MODE
# ===================================================================
echo ""
echo "========================================"
echo "  SECTION 5: Daemon Failure Mode"
echo "========================================"

# -------------------------------------------------------------------
# 5.1: Kill the daemon
# -------------------------------------------------------------------
log "5.1: Kill audit daemon"

PID_FILE="/var/run/warrant-shell/auditd.pid"
DAEMON_PID=""
if [ -f "$PID_FILE" ]; then
  DAEMON_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
fi

# Kill daemon using sudo bash -c (ensures kill built-in is available)
if [ -n "$DAEMON_PID" ]; then
  sudo bash -c "kill -TERM $DAEMON_PID" 2>/dev/null || true
  sleep 1
  sudo bash -c "kill -0 $DAEMON_PID" 2>/dev/null && \
    sudo bash -c "kill -KILL $DAEMON_PID" 2>/dev/null || true
fi
# Fallback: find and kill any remaining wsh-auditd by scanning /proc
for pid_dir in /proc/[0-9]*; do
  pid_num="$(basename "$pid_dir")"
  if sudo cat "/proc/$pid_num/cmdline" 2>/dev/null | tr '\0' ' ' | grep -q wsh-auditd; then
    sudo bash -c "kill -KILL $pid_num" 2>/dev/null || true
  fi
done
sleep 1

# Verify daemon is dead
ALIVE=0
for pid_dir in /proc/[0-9]*; do
  pid_num="$(basename "$pid_dir")"
  if sudo cat "/proc/$pid_num/cmdline" 2>/dev/null | tr '\0' ' ' | grep -q wsh-auditd; then
    ALIVE=1
    break
  fi
done

# Wait briefly for process teardown + socket unlink.
for _ in $(seq 1 30); do
  if ! pgrep -f wsh-auditd >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if [ "$ALIVE" = "0" ]; then
  pass "audit daemon killed"
else
  fail "audit daemon still running after kill"
fi
sleep 1

# -------------------------------------------------------------------
# 5.2: sudo -E wsh exec without daemon — does it fail-closed?
# -------------------------------------------------------------------
log "5.2: sudo -E wsh exec with daemon down"

OUT="$(sudo -E wsh exec ls /tmp 2>&1)" && RC=$? || RC=$?

if [ $RC -ne 0 ]; then
  if echo "$OUT" | grep -qi "daemon\\|audit\\|socket\\|connect"; then
    pass "sudo -E wsh exec fails-closed without audit daemon (audit_required=true)"
  else
    echo "  Got: $OUT"
    fail "exec failed without daemon, but error output was not audit/daemon related"
  fi
else
  fail "sudo -E wsh exec succeeded without daemon (fail-open — should be fail-closed)"
fi

# -------------------------------------------------------------------
# 5.3: Restart daemon and verify recovery
# -------------------------------------------------------------------
log "5.3: Restart daemon and verify recovery"

sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

OUT="$(sudo -E wsh exec echo 'post-recovery' 2>&1)"
if echo "$OUT" | grep -q "post-recovery"; then
  pass "sudo -E wsh exec works after daemon restart"
else
  fail "sudo -E wsh exec broken after daemon restart"
fi

# -------------------------------------------------------------------
# 5.4: Audit chain still valid after restart
# -------------------------------------------------------------------
log "5.4: Audit chain valid after daemon restart"

VERIFY_OUT="$(sudo -E wsh audit-verify 2>&1)"
if echo "$VERIFY_OUT" | grep -qi "VALID\|valid\|ok\|pass"; then
  pass "audit hash chain valid after daemon restart"
else
  echo "  Got: $VERIFY_OUT"
  fail "audit hash chain broken after daemon restart"
fi

# ===================================================================
# SECTION 6: NON-ROOT CANNOT ESCALATE
# ===================================================================
echo ""
echo "========================================"
echo "  SECTION 6: Privilege Escalation"
echo "========================================"

# -------------------------------------------------------------------
# 6.1: Non-root cannot elevate
# -------------------------------------------------------------------
log "6.1: Non-root cannot elevate"

OUT="$(wsh elevate --duration 1 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot elevate"
else
  fail "non-root CAN elevate (should require root)"
fi

# -------------------------------------------------------------------
# 6.2: Non-root cannot clear audit logs
# -------------------------------------------------------------------
log "6.2: Non-root cannot clear audit logs via CLI"

OUT="$(wsh audit --clear 2>&1)" && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot clear audit logs"
else
  fail "non-root CAN clear audit logs"
fi

# -------------------------------------------------------------------
# 6.3: Non-root cannot access HMAC key
# -------------------------------------------------------------------
log "6.3: Non-root cannot read HMAC key"

cat /var/lib/warrant-shell/hmac.key >/dev/null 2>&1 && RC=$? || RC=$?
if [ $RC -ne 0 ]; then
  pass "non-root cannot read HMAC key"
else
  fail "non-root CAN read HMAC key"
fi

# ===================================================================
# Summary
# ===================================================================
echo ""
echo "========================================"
echo "  SECURITY RESULTS: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "========================================"
if [ $FAIL -gt 0 ]; then
  printf "  Failures:%b\n" "$ERRORS"
  exit 1
fi
exit 0
