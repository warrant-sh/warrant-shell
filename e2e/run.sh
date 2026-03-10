#!/bin/bash
# Build and run warrant-shell e2e tests
#
# Usage:
#   ./e2e/run.sh             # run all tests
#   ./e2e/run.sh general     # run general tests only
#
# Environment:
#   ANTHROPIC_API_KEY   — required for Claude tests
#   OPENAI_API_KEY      — required for Codex tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="wsh-e2e"
LOG_DIR="${REPO_DIR}/e2e/logs"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
DIST_DIR="${REPO_DIR}/target/dist"

mkdir -p "$LOG_DIR"

SUITE="${1:-all}"

ensure_binaries() {
  if [[ -x "$DIST_DIR/wsh" && -x "$DIST_DIR/wsh-auditd" ]]; then
    return 0
  fi

  echo "==> Prebuilt binaries missing in target/dist; building now..."
  "$REPO_DIR/scripts/build-release-dev.sh"
}

build_image() {
  local build_context
  build_context="$(mktemp -d)"
  trap "rm -rf '$build_context'" EXIT

  ensure_binaries

  echo "==> Preparing minimal build context..."
  cp "$DIST_DIR/wsh" "$build_context/wsh"
  cp "$DIST_DIR/wsh-auditd" "$build_context/wsh-auditd"
  cp "$SCRIPT_DIR"/test-*.sh "$build_context/"

  echo "==> Building e2e image..."
  docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$build_context"
}

build_image

# --- Run suites ---
ENV_FLAGS=""
[[ -n "${ANTHROPIC_API_KEY:-}" ]] && ENV_FLAGS="$ENV_FLAGS -e ANTHROPIC_API_KEY"
[[ -n "${OPENAI_API_KEY:-}" ]] && ENV_FLAGS="$ENV_FLAGS -e OPENAI_API_KEY"

run_suite() {
  local suite="$1"
  local log_file="${LOG_DIR}/${suite}-${TIMESTAMP}.log"
  echo "==> Running: ${suite}"
  echo "    Log: ${log_file}"

  docker run --rm $ENV_FLAGS "$IMAGE_NAME" \
    -c "/home/agent/tests/test-${suite}.sh" \
    2>&1 | tee "$log_file"

  local exit_code=${PIPESTATUS[0]}
  if [[ $exit_code -eq 0 ]]; then echo "==> ✅ ${suite}: PASSED"
  else echo "==> ❌ ${suite}: FAILED (exit $exit_code)"; fi
  return $exit_code
}

OVERALL=0
PASSED=()
FAILED=()
SKIPPED=()
track() {
  local s="$1" r="$2"
  if [[ "$r" == "pass" ]]; then PASSED+=("$s")
  elif [[ "$r" == "fail" ]]; then FAILED+=("$s"); OVERALL=1
  else SKIPPED+=("$s"); fi
}

if [[ "$SUITE" == "all" ]]; then
  run_suite general && track general pass || track general fail
  run_suite security && track security pass || track security fail
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    run_suite claude && track claude pass || track claude fail
  else
    echo "==> ⏭️  claude: SKIPPED (no ANTHROPIC_API_KEY)"
    track claude skip
  fi
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    run_suite codex && track codex pass || track codex fail
  else
    echo "==> ⏭️  codex: SKIPPED (no OPENAI_API_KEY)"
    track codex skip
  fi
else
  run_suite "$SUITE" && track "$SUITE" pass || track "$SUITE" fail
fi

echo ""
echo "========================================"
echo "  E2E SUMMARY"
echo "========================================"
for s in "${PASSED[@]:-}"; do [[ -n "$s" ]] && echo "  ✅ $s"; done
for s in "${FAILED[@]:-}"; do [[ -n "$s" ]] && echo "  ❌ $s"; done
for s in "${SKIPPED[@]:-}"; do [[ -n "$s" ]] && echo "  ⏭️  $s (skipped)"; done
echo ""
[[ $OVERALL -eq 0 ]] && echo "  ALL SUITES PASSED" || echo "  SOME SUITES FAILED"
echo "========================================"
exit $OVERALL
