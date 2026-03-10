#!/bin/bash
# Claude Code integration e2e test
# Tests: policy enforcement (deny unlisted), allowed commands, audit trail
# Requires: ANTHROPIC_API_KEY (for future real invocation tests)
set -euo pipefail

PASS=0
FAIL=0
ERRORS=""

log()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$1"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); ERRORS="${ERRORS}\n  - $1"; }

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY not set — skipping Claude tests"
  exit 0
fi

# -------------------------------------------------------------------
# Setup: install + daemon + claude bundle
# -------------------------------------------------------------------
log "Setup: initialize audit daemon and configure claude bundle"

sudo mkdir -p /var/lib/warrant-shell/audit /var/run/warrant-shell
sudo chmod 0700 /var/lib/warrant-shell /var/lib/warrant-shell/audit
sudo chmod 0755 /var/run/warrant-shell
openssl rand -hex 32 | sudo tee /var/lib/warrant-shell/hmac.key > /dev/null
sudo chmod 0400 /var/lib/warrant-shell/hmac.key
sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

log "Setup: configure claude bundle"
if SETUP_OUT="$(wsh setup claude --accept-defaults 2>&1)"; then
  echo "$SETUP_OUT"
  pass "wsh setup claude succeeded"
else
  echo "$SETUP_OUT"
  log "  setup lock failed, falling back to manual lock"
  if LOCK_OUT="$(sudo -E wsh lock 2>&1)"; then
    echo "$LOCK_OUT"
    pass "fallback sudo -E wsh lock succeeded"
  else
    echo "$LOCK_OUT"
    fail "fallback sudo -E wsh lock failed after setup failure"
    exit 1
  fi
fi

log "Verify: wsh status"
if STATUS_OUT="$(wsh status 2>&1)"; then
  echo "$STATUS_OUT"
  pass "wsh status succeeded"
else
  echo "$STATUS_OUT"
  fail "wsh status failed"
  exit 1
fi

# -------------------------------------------------------------------
# Test 1: Claude CLI available
# -------------------------------------------------------------------
log "Test 1: Claude CLI available"

if command -v claude &>/dev/null; then
  CLAUDE_VER_OUT="$(claude --version 2>&1)" && RC=$? || RC=$?
  echo "$CLAUDE_VER_OUT"
  if [ $RC -eq 0 ] && echo "$CLAUDE_VER_OUT" | grep -Eqi "claude|[0-9]+\\.[0-9]+"; then
    pass "claude CLI version output is valid"
  else
    fail "claude CLI found but --version output was invalid"
  fi
elif CLAUDE_VER_OUT="$(npx claude --version 2>&1)"; then
  echo "$CLAUDE_VER_OUT"
  if echo "$CLAUDE_VER_OUT" | grep -Eqi "claude|[0-9]+\\.[0-9]+"; then
    pass "claude CLI version available via npx"
  else
    fail "npx claude --version output was invalid"
  fi
else
  fail "claude CLI not found"
fi

# -------------------------------------------------------------------
# Test 2: Claude allowed by policy (in claude bundle)
# -------------------------------------------------------------------
log "Test 2: sudo -E wsh exec claude allowed by policy"

CLAUDE_OUT="$(sudo -E wsh exec claude --version 2>&1)" && RC=$? || RC=$?
echo "$CLAUDE_OUT"

if [ $RC -eq 0 ] && echo "$CLAUDE_OUT" | grep -qi "claude"; then
  pass "claude allowed by warrant (claude bundle)"
else
  fail "claude unexpectedly denied (rc=$RC)"
fi

# -------------------------------------------------------------------
# Test 2b: Unlisted command denied (wget not in claude bundle)
# -------------------------------------------------------------------
log "Test 2b: sudo -E wsh exec wget denied by policy"

WGET_OUT="$(sudo -E wsh exec wget --version 2>&1)" && RC=$? || RC=$?
echo "$WGET_OUT"

if [ $RC -ne 0 ] && echo "$WGET_OUT" | grep -qi "denied\|not in capabilities"; then
  pass "wget correctly denied — not in claude bundle"
else
  fail "wget was not denied as expected (rc=$RC)"
fi

# -------------------------------------------------------------------
# Test 3: Allowed command works (git, from claude bundle)
# -------------------------------------------------------------------
log "Test 3: Allowed command (git status) works through wsh exec"

cd /tmp && git init test-repo &>/dev/null && cd test-repo
GIT_OUT="$(sudo -E wsh exec git status 2>&1)"
if echo "$GIT_OUT" | grep -qi "branch\|clean\|nothing to commit"; then
  pass "git status allowed and executed through wsh"
else
  echo "$GIT_OUT"
  fail "git status not working through wsh exec"
fi

# -------------------------------------------------------------------
# Test 4: Dangerous pattern blocked
# -------------------------------------------------------------------
log "Test 4: Dangerous pattern blocked"

DANGER_OUT="$(sudo -E wsh check rm -rf / 2>&1)" && RC=$? || RC=$?
echo "$DANGER_OUT"

if [ $RC -ne 0 ]; then
  pass "dangerous command blocked"
else
  fail "dangerous command was not blocked"
fi

# -------------------------------------------------------------------
# Verify guard hooks installed by wsh setup
# -------------------------------------------------------------------
log "Verifying guard hooks installed by wsh setup"

# Claude uses a Python PreToolUse hook installed to a system path
# macOS: /Library/Application Support/warrant-shell/claude_hook.py
# Linux: /usr/local/lib/warrant-shell/claude_hook.py
if [ -f "/usr/local/lib/warrant-shell/claude_hook.py" ] || \
   [ -f "/Library/Application Support/warrant-shell/claude_hook.py" ]; then
  pass "Claude guard hook installed to system path"
else
  fail "wsh setup did not install Claude guard hook to system path"
fi

if grep -q "claude_hook.py" "$HOME/.claude/settings.json" 2>/dev/null; then
  pass "Claude settings.json references guard hook"
else
  fail "Claude settings.json missing guard hook configuration"
fi

# Claude does NOT use .bashenv — it uses the Python PreToolUse hook.
# No .bashenv check needed for Claude.

# -------------------------------------------------------------------
# Test 5: Claude executes allowed command via wsh
# -------------------------------------------------------------------
log "Test 5: Claude executes allowed command via wsh"

AUDIT_BEFORE="$(sudo -E wsh audit --tail 1000 2>&1 | wc -l)"

AGENT_OUT="$(timeout 60 claude --print --dangerously-skip-permissions \
  "Run exactly this shell command and nothing else: git --version" 2>&1)" && RC=$? || RC=$?
echo "$AGENT_OUT"

if echo "$AGENT_OUT" | grep -qi "Audit logging failed"; then
  fail "claude git: audit logging failed inside sandbox — guard blocked an allowed command"
else
  AUDIT_NEW="$(sudo -E wsh audit --tail 1000 2>&1 | tail -n +$((AUDIT_BEFORE + 1)))"
  if echo "$AUDIT_NEW" | grep -q "ALLOW.*git"; then
    pass "claude invoked git through wsh (new audit entry confirms)"
  else
    fail "claude did not invoke git through wsh — no new audit entry"
  fi
fi

# -------------------------------------------------------------------
# Test 6: Claude denied command captured in audit
# -------------------------------------------------------------------
log "Test 6: Claude denied command captured in audit"

AUDIT_BEFORE="$(sudo -E wsh audit --tail 1000 2>&1 | wc -l)"

AGENT_OUT="$(timeout 60 claude --print --dangerously-skip-permissions \
  "Run exactly this shell command: wget --version. This command WILL be denied by the security policy. That is expected. Do not try alternatives or workarounds. Just run wget --version." 2>&1)" && RC=$? || RC=$?
echo "$AGENT_OUT"

if echo "$AGENT_OUT" | grep -qi "Audit logging failed"; then
  fail "claude wget: audit logging failed inside sandbox — guard could not reach daemon"
else
  AUDIT_NEW="$(sudo -E wsh audit --tail 1000 2>&1 | tail -n +$((AUDIT_BEFORE + 1)))"
  if echo "$AUDIT_NEW" | grep -q "DENY.*wget"; then
    pass "claude attempted wget, wsh denied it (new audit entry confirms)"
  else
    fail "claude wget denial not found in new audit entries"
  fi
fi

# -------------------------------------------------------------------
# Test 7: Audit trail captures allow and deny
# -------------------------------------------------------------------
log "Test 7: Audit trail"

AUDIT_OUT="$(sudo -E wsh audit 2>&1)"
echo "$AUDIT_OUT"

if echo "$AUDIT_OUT" | grep -q "DENY.*wget"; then
  pass "audit captured wget denial"
else
  fail "audit missing wget denial"
fi

if echo "$AUDIT_OUT" | grep -q "ALLOW.*git.*status"; then
  pass "audit captured git allow"
else
  fail "audit missing git allow"
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "========================================"
echo "  CLAUDE TESTS: ${PASS} passed, ${FAIL} failed (10 checks total)"
echo "========================================"
if [ $FAIL -gt 0 ]; then
  printf "  Failures:%b\n" "$ERRORS"
  exit 1
fi
exit 0
