#!/bin/bash
# Codex integration e2e test
# Tests: policy enforcement (deny unlisted), allowed commands, audit trail
# Requires: OPENAI_API_KEY (for future real invocation tests)
set -euo pipefail

PASS=0
FAIL=0
ERRORS=""

log()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$1"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); ERRORS="${ERRORS}\n  - $1"; }

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY not set — skipping Codex tests"
  exit 0
fi

# -------------------------------------------------------------------
# Setup: install + daemon + codex bundle
# -------------------------------------------------------------------
log "Setup: initialize audit daemon and configure codex bundle"

sudo mkdir -p /var/lib/warrant-shell/audit /var/run/warrant-shell
sudo chmod 0700 /var/lib/warrant-shell /var/lib/warrant-shell/audit
sudo chmod 0755 /var/run/warrant-shell
openssl rand -hex 32 | sudo tee /var/lib/warrant-shell/hmac.key > /dev/null
sudo chmod 0400 /var/lib/warrant-shell/hmac.key
sudo /usr/local/bin/wsh-auditd &>/dev/null &
sleep 2

log "Setup: configure Codex auth (API key)"
mkdir -p ~/.codex
cat > ~/.codex/auth.json << EOF
{"auth_mode":"apikey","OPENAI_API_KEY":"${OPENAI_API_KEY}","tokens":null,"last_refresh":null}
EOF

log "Setup: configure codex bundle"
if SETUP_OUT="$(wsh setup codex --accept-defaults 2>&1)"; then
  echo "$SETUP_OUT"
  pass "wsh setup codex succeeded"
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
# Test 1: Codex CLI available
# -------------------------------------------------------------------
log "Test 1: Codex CLI available"

if command -v codex &>/dev/null; then
  CODEX_VER_OUT="$(codex --version 2>&1)" && RC=$? || RC=$?
  echo "$CODEX_VER_OUT"
  if [ $RC -eq 0 ] && echo "$CODEX_VER_OUT" | grep -Eqi "codex|[0-9]+\\.[0-9]+"; then
    pass "codex CLI version output is valid"
  else
    fail "codex CLI found but --version output was invalid"
  fi
elif CODEX_VER_OUT="$(npx codex --version 2>&1)"; then
  echo "$CODEX_VER_OUT"
  if echo "$CODEX_VER_OUT" | grep -Eqi "codex|[0-9]+\\.[0-9]+"; then
    pass "codex CLI version available via npx"
  else
    fail "npx codex --version output was invalid"
  fi
else
  fail "codex CLI not found"
fi

# -------------------------------------------------------------------
# Test 2: Codex allowed by policy (in codex bundle)
# -------------------------------------------------------------------
log "Test 2: sudo -E wsh exec codex allowed by policy"

CODEX_OUT="$(sudo -E wsh exec codex --version 2>&1)" && RC=$? || RC=$?
echo "$CODEX_OUT"

if [ $RC -eq 0 ] && echo "$CODEX_OUT" | grep -qi "codex"; then
  pass "codex allowed by warrant (codex bundle)"
else
  fail "codex unexpectedly denied (rc=$RC)"
fi

# -------------------------------------------------------------------
# Test 2b: Unlisted command denied (wget not in codex bundle)
# -------------------------------------------------------------------
log "Test 2b: sudo -E wsh exec wget denied by policy"

WGET_OUT="$(sudo -E wsh exec wget --version 2>&1)" && RC=$? || RC=$?
echo "$WGET_OUT"

if [ $RC -ne 0 ] && echo "$WGET_OUT" | grep -qi "denied\|not in capabilities"; then
  pass "wget correctly denied — not in codex bundle"
else
  fail "wget was not denied as expected (rc=$RC)"
fi

# -------------------------------------------------------------------
# Test 3: Allowed command works (git, from codex bundle)
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
# Test 4: Audit trail captures both allow and deny
# -------------------------------------------------------------------
log "Test 4: Audit trail"

AUDIT_OUT="$(sudo -E wsh audit --tail 20 2>&1)"
echo "$AUDIT_OUT"

if echo "$AUDIT_OUT" | grep -q "DENY.*wget"; then
  pass "audit captured wget denial"
else
  fail "audit missing wget denial"
fi

if echo "$AUDIT_OUT" | grep -qi "ALLOW.*codex"; then
  pass "audit captured codex allow"
else
  fail "audit missing codex allow"
fi

if echo "$AUDIT_OUT" | grep -q "ALLOW.*git.*status"; then
  pass "audit captured git allow"
else
  fail "audit missing git allow"
fi

# -------------------------------------------------------------------
# Activate guard hooks (simulates opening a new terminal after setup)
# -------------------------------------------------------------------
log "Activating guard hooks installed by wsh setup"
export WSH_GUARD=1
export BASH_ENV="$HOME/.bashenv"
if [ -f "$HOME/.bashenv" ]; then
  source "$HOME/.bashenv"
  pass "guard hooks activated (.bashenv sourced, WSH_GUARD=1, BASH_ENV set)"
else
  fail "wsh setup did not create ~/.bashenv — guard hooks missing"
fi

# -------------------------------------------------------------------
# Test 5: Codex executes allowed command via wsh
# -------------------------------------------------------------------
log "Test 5: Codex executes allowed command via wsh"

AUDIT_BEFORE="$(sudo -E wsh audit --tail 1000 2>&1 | wc -l)"

AGENT_OUT="$(timeout 60 codex exec --full-auto \
  "Run exactly this shell command and nothing else: git --version" 2>&1)" && RC=$? || RC=$?
echo "$AGENT_OUT"

if echo "$AGENT_OUT" | grep -qi "Audit logging failed"; then
  fail "codex git: audit logging failed inside sandbox — guard blocked an allowed command"
else
  AUDIT_NEW="$(sudo -E wsh audit --tail 1000 2>&1 | tail -n +$((AUDIT_BEFORE + 1)))"
  if echo "$AUDIT_NEW" | grep -q "ALLOW.*git"; then
    pass "codex invoked git through wsh (new audit entry confirms)"
  else
    fail "codex did not invoke git through wsh — no new audit entry"
  fi
fi

# -------------------------------------------------------------------
# Test 6: Codex denied command captured in audit
# -------------------------------------------------------------------
log "Test 6: Codex denied command captured in audit"

AUDIT_BEFORE="$(sudo -E wsh audit --tail 1000 2>&1 | wc -l)"

AGENT_OUT="$(timeout 60 codex exec --full-auto \
  "Run exactly this shell command: wget --version. This command WILL be denied by the security policy. That is expected. Do not try alternatives or workarounds. Just run wget --version." 2>&1)" && RC=$? || RC=$?
echo "$AGENT_OUT"

if echo "$AGENT_OUT" | grep -qi "Audit logging failed"; then
  fail "codex wget: audit logging failed inside sandbox — guard could not reach daemon"
else
  AUDIT_NEW="$(sudo -E wsh audit --tail 1000 2>&1 | tail -n +$((AUDIT_BEFORE + 1)))"
  if echo "$AUDIT_NEW" | grep -q "DENY.*wget"; then
    pass "codex attempted wget, wsh denied it (new audit entry confirms)"
  else
    fail "codex wget denial not found in new audit entries"
  fi
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "========================================"
echo "  CODEX TESTS: ${PASS} passed, ${FAIL} failed (11 checks total)"
echo "========================================"
if [ $FAIL -gt 0 ]; then
  printf "  Failures:%b\n" "$ERRORS"
  exit 1
fi
exit 0
