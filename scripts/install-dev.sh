#!/bin/sh
# warrant-shell dev installer — builds from source via cargo
#
# Usage:
#   ./scripts/install-dev.sh                    # build from local checkout
#   ./scripts/install-dev.sh --git              # build from GitHub main branch
#   ./scripts/install-dev.sh --group-socket-access  # daemon socket mode 0660 + warrant group
#   ./scripts/install-dev.sh                    # prompts for sudo only for daemon setup
#   sudo ./scripts/install-dev.sh --daemon-only # set up audit daemon only (advanced)
#   sudo ./scripts/install-dev.sh --uninstall   # tear down daemon + remove binaries
#
# Requires: cargo (Rust toolchain)

set -eu
SCRIPT_SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

REPO="https://github.com/warrant-sh/warrant-shell.git"
DAEMON_NAME="wsh-auditd"
SERVICE_NAME="wsh-auditd"
DAEMON_STATE_DIR="/var/lib/warrant-shell"
DAEMON_AUDIT_DIR="/var/lib/warrant-shell/audit"
DAEMON_RUN_DIR="/var/run/warrant-shell"
DAEMON_SOCKET="${DAEMON_RUN_DIR}/auditd.sock"
DAEMON_RELAY_SOCKET="/tmp/warrant-shell/auditd.sock"
DAEMON_TCP_ADDR="127.0.0.1:45873"
DAEMON_HMAC_KEY="${DAEMON_STATE_DIR}/hmac.key"
SOCKET_GROUP_NAME="warrant"
SOCKET_ACCESS_MODE="0666"

err() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok() { printf '\033[1;32m==>\033[0m %s\n' "$1"; }

prompt_yes_no() {
  question="$1"
  default_yes="${2:-1}"
  if [ ! -t 0 ]; then
    [ "$default_yes" = "1" ] && return 0 || return 1
  fi
  if [ "$default_yes" = "1" ]; then
    prompt_suffix="[Y/n]"
  else
    prompt_suffix="[y/N]"
  fi
  printf "%s %s " "$question" "$prompt_suffix"
  IFS= read -r answer || answer=""
  answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
  case "$answer" in
    y|yes) return 0 ;;
    n|no) return 1 ;;
    "") [ "$default_yes" = "1" ] && return 0 || return 1 ;;
    *) return 1 ;;
  esac
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       err "Unsupported OS: $(uname -s)" ;;
  esac
}

FROM_GIT=0
UNINSTALL=0
DAEMON_ONLY=0
BUILD_ONLY=0
GROUP_SOCKET_ACCESS=0
for arg in "$@"; do
  case "$arg" in
    --git) FROM_GIT=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --daemon-only) DAEMON_ONLY=1 ;;
    --build-only) BUILD_ONLY=1 ;; # internal flag used by root orchestration
    --group-socket-access) GROUP_SOCKET_ACCESS=1 ;;
  esac
done

if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
  SOCKET_ACCESS_MODE="0660"
fi

ensure_group_exists() {
  group_name="$1"
  if [ "$OS" = "linux" ]; then
    if command -v getent >/dev/null 2>&1 && getent group "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    if ! command -v groupadd >/dev/null 2>&1; then
      err "groupadd is required for --group-socket-access"
    fi
    groupadd "$group_name" >/dev/null 2>&1 || true
    if command -v getent >/dev/null 2>&1 && getent group "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    err "failed to create/access group '$group_name'"
  else
    if dscl . -read "/Groups/$group_name" >/dev/null 2>&1; then
      return 0
    fi
    if ! command -v dseditgroup >/dev/null 2>&1; then
      err "dseditgroup is required for --group-socket-access on macOS"
    fi
    dseditgroup -o create "$group_name" >/dev/null 2>&1 || true
    dscl . -read "/Groups/$group_name" >/dev/null 2>&1 || err "failed to create group '$group_name'"
  fi
}

add_user_to_group() {
  user_name="$1"
  group_name="$2"
  [ -n "$user_name" ] || return 0
  [ "$user_name" = "root" ] && return 0

  if [ "$OS" = "linux" ]; then
    if command -v usermod >/dev/null 2>&1; then
      usermod -a -G "$group_name" "$user_name"
    else
      err "usermod is required to add $user_name to $group_name"
    fi
  else
    dseditgroup -o edit -a "$user_name" -t user "$group_name"
  fi
}

resolve_auditd_path_for_root() {
  if [ -n "${WSH_AUDITD_PATH:-}" ]; then
    printf '%s\n' "$WSH_AUDITD_PATH"
    return 0
  fi
  if command -v wsh-auditd >/dev/null 2>&1; then
    command -v wsh-auditd
    return 0
  fi
  if [ -x "/usr/local/bin/wsh-auditd" ]; then
    printf '%s\n' "/usr/local/bin/wsh-auditd"
    return 0
  fi
  if [ -x "$HOME/.cargo/bin/wsh-auditd" ]; then
    printf '%s\n' "$HOME/.cargo/bin/wsh-auditd"
    return 0
  fi
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    if [ "$OS" = "darwin" ]; then
      SUDO_HOME="$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
    else
      SUDO_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | awk -F: '{print $6}' || true)"
    fi
    if [ -z "$SUDO_HOME" ]; then
      SUDO_HOME="$(eval "printf '%s' ~${SUDO_USER}" 2>/dev/null || true)"
    fi
    if [ -n "$SUDO_HOME" ] && [ -x "$SUDO_HOME/.cargo/bin/wsh-auditd" ]; then
      printf '%s\n' "$SUDO_HOME/.cargo/bin/wsh-auditd"
      return 0
    fi
  fi
  return 1
}

daemon_endpoint_health_check() {
  if ! command -v python3 >/dev/null 2>&1; then
    info "python3 not found — skipping endpoint probe (socket existence checks only)."
    [ -S "$DAEMON_SOCKET" ] && info "system socket present: $DAEMON_SOCKET"
    [ -S "$DAEMON_RELAY_SOCKET" ] && info "relay socket present: $DAEMON_RELAY_SOCKET"
    return 0
  fi
  python3 - "$DAEMON_SOCKET" "$DAEMON_RELAY_SOCKET" "$DAEMON_TCP_ADDR" <<'PY'
import json
import socket
import sys

unix_paths = [sys.argv[1], sys.argv[2]]
tcp_addr = sys.argv[3]
tcp_host, tcp_port = tcp_addr.split(":")
tcp_port = int(tcp_port)

results = []

def check_unix(path):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.8)
        s.connect(path)
        s.sendall((json.dumps({"type":"ping","nonce":"install-health"}) + "\n").encode())
        data = s.recv(512)
        s.close()
        ok = b'"status":"ok"' in data
        return ("ok" if ok else "error", data.decode(errors="replace").strip())
    except Exception as e:
        return ("error", str(e))

def check_tcp(host, port):
    try:
        s = socket.create_connection((host, port), timeout=0.8)
        s.sendall((json.dumps({"type":"ping","nonce":"install-health"}) + "\n").encode())
        data = s.recv(512)
        s.close()
        ok = b'"status":"ok"' in data
        return ("ok" if ok else "error", data.decode(errors="replace").strip())
    except Exception as e:
        return ("error", str(e))

for p in unix_paths:
    status, detail = check_unix(p)
    results.append(("unix", p, status, detail))

status, detail = check_tcp(tcp_host, tcp_port)
results.append(("tcp", f"{tcp_host}:{tcp_port}", status, detail))

for proto, endpoint, status, detail in results:
    print(f"endpoint[{proto}] {endpoint}: {status}")

active = next((r for r in results if r[2] == "ok"), None)
if active:
    print(f"active endpoint: {active[0]} {active[1]}")
else:
    print("active endpoint: none")
    sys.exit(1)
PY
}

OS="$(detect_os)"

# --- Uninstall ---
if [ "$UNINSTALL" = "1" ]; then
  info "Uninstalling warrant-shell (dev)..."

  if [ "$(id -u)" = "0" ]; then
    if [ "$OS" = "linux" ] && [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
      if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        systemctl daemon-reload
      fi
      rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
      info "Removed systemd service."
    elif [ "$OS" = "darwin" ] && [ -f "/Library/LaunchDaemons/sh.warrant.auditd.plist" ]; then
      launchctl bootout system/sh.warrant.auditd 2>/dev/null || true
      rm -f "/Library/LaunchDaemons/sh.warrant.auditd.plist"
      info "Removed launchd service."
    fi
    rm -rf "$DAEMON_RUN_DIR"
    info "Removed runtime directory."
    if [ -d "$DAEMON_AUDIT_DIR" ]; then
      info "Audit data preserved in $DAEMON_STATE_DIR — remove manually if no longer needed."
    fi
  fi

  # Remove cargo-installed binaries
  cargo uninstall wsh 2>/dev/null && info "Removed wsh" || true

  # Clean up user-level shell artifacts
  CLEANUP_HOME="${HOME}"
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    if [ "$OS" = "darwin" ]; then
      CLEANUP_HOME="$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
    else
      CLEANUP_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | awk -F: '{print $6}' || true)"
    fi
    [ -n "$CLEANUP_HOME" ] || CLEANUP_HOME="${HOME}"
  fi

  GUARD_MARKER="# warrant-shell guard"
  LOADER_MARKER="# warrant-shell bashenv loader"

  # Remove marker blocks from shell config files
  remove_marker_block() {
    file="$1"
    marker="$2"
    [ -f "$file" ] || return 0
    if grep -q "$marker" "$file" 2>/dev/null; then
      # Use awk to remove the marker line and subsequent non-blank lines,
      # plus the preceding blank line.
      awk -v marker="$marker" '
        BEGIN { pending="" }
        {
          if ($0 ~ marker) {
            skip=1; pending=""; next
          }
          if (skip) {
            if (/^[[:space:]]*$/) { skip=0; next }
            else { next }
          }
          if (/^[[:space:]]*$/) { pending=pending $0 "\n" }
          else { printf "%s", pending; pending=""; print }
        }
        END { printf "%s", pending }
      ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
      info "Cleaned $marker from $file"
    fi
  }

  remove_marker_block "$CLEANUP_HOME/.zshenv" "$GUARD_MARKER"
  remove_marker_block "$CLEANUP_HOME/.zshrc" "$GUARD_MARKER"
  remove_marker_block "$CLEANUP_HOME/.bashenv" "$GUARD_MARKER"
  remove_marker_block "$CLEANUP_HOME/.bashrc" "$LOADER_MARKER"
  remove_marker_block "$CLEANUP_HOME/.bash_profile" "$LOADER_MARKER"

  # Remove wsh-related aliases (WSH_GUARD aliases and bare agent aliases)
  for rc_file in "$CLEANUP_HOME/.zshrc" "$CLEANUP_HOME/.bashrc"; do
    [ -f "$rc_file" ] || continue
    if grep -qE "(WSH_GUARD=1|alias (claude|codex|aider|goose)='(claude|codex|aider|goose)')" "$rc_file" 2>/dev/null; then
      grep -vE "(WSH_GUARD=1|^alias (claude|codex|aider|goose)='(claude|codex|aider|goose)'$)" "$rc_file" > "${rc_file}.tmp" && mv "${rc_file}.tmp" "$rc_file"
      info "Cleaned wsh aliases from $rc_file"
    fi
  done

  # Remove empty ~/.bashenv
  if [ -f "$CLEANUP_HOME/.bashenv" ]; then
    if [ -z "$(tr -d '[:space:]' < "$CLEANUP_HOME/.bashenv")" ]; then
      rm -f "$CLEANUP_HOME/.bashenv"
      info "Removed empty $CLEANUP_HOME/.bashenv"
    fi
  fi

  # Remove Claude hook file and settings entry
  if [ -f "$CLEANUP_HOME/.claude/hooks/wsh_guard_pretool.py" ]; then
    rm -f "$CLEANUP_HOME/.claude/hooks/wsh_guard_pretool.py"
    info "Removed Claude wsh_guard_pretool.py hook"
  fi
  if [ -f "$CLEANUP_HOME/.claude/settings.json" ] && command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys
path = sys.argv[1]
with open(path) as f:
    s = json.load(f)
pre = s.get('hooks', {}).get('PreToolUse', [])
filtered = [e for e in pre if not any(
    'wsh_guard_pretool.py' in (h.get('command','') if isinstance(h,dict) else '')
    for h in (e.get('hooks',[]) if isinstance(e,dict) else [])
)]
if len(filtered) != len(pre):
    if filtered:
        s['hooks']['PreToolUse'] = filtered
    else:
        s.get('hooks', {}).pop('PreToolUse', None)
    with open(path, 'w') as f:
        json.dump(s, f, indent=2)
        f.write('\n')
    print('Cleaned wsh hook from ' + path)
" "$CLEANUP_HOME/.claude/settings.json" 2>/dev/null && info "Cleaned Claude settings.json" || true
  fi

  ok "Uninstall complete."
  exit 0
fi

# If started with sudo, run cargo install as invoking user first, then finish daemon setup as root.
if [ "$(id -u)" = "0" ] && [ "$DAEMON_ONLY" != "1" ] && [ "$BUILD_ONLY" != "1" ]; then
  if [ -z "${SUDO_USER:-}" ] || [ "${SUDO_USER}" = "root" ]; then
    err "Do not run cargo build/install as root. Run as your user first, then: sudo $SCRIPT_SELF --daemon-only"
  fi

  info "Running cargo build/install as ${SUDO_USER}..."
  if [ "$FROM_GIT" = "1" ]; then
    if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
      sudo -u "$SUDO_USER" "$SCRIPT_SELF" --git --build-only --group-socket-access
    else
      sudo -u "$SUDO_USER" "$SCRIPT_SELF" --git --build-only
    fi
  else
    if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
      sudo -u "$SUDO_USER" "$SCRIPT_SELF" --build-only --group-socket-access
    else
      sudo -u "$SUDO_USER" "$SCRIPT_SELF" --build-only
    fi
  fi

  USER_WSH_AUDITD="$(sudo -u "$SUDO_USER" sh -lc 'command -v wsh-auditd 2>/dev/null || { [ -x "$HOME/.cargo/bin/wsh-auditd" ] && printf "%s\n" "$HOME/.cargo/bin/wsh-auditd"; }')"
  [ -n "$USER_WSH_AUDITD" ] || err "wsh-auditd not found for user ${SUDO_USER} after build."
  case "$USER_WSH_AUDITD" in
    /*) ;;
    *) err "Resolved wsh-auditd path is not absolute: $USER_WSH_AUDITD" ;;
  esac

  info "Continuing with daemon setup as root..."
  if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
    exec env WSH_AUDITD_PATH="$USER_WSH_AUDITD" "$SCRIPT_SELF" --daemon-only --group-socket-access
  else
    exec env WSH_AUDITD_PATH="$USER_WSH_AUDITD" "$SCRIPT_SELF" --daemon-only
  fi
fi

# --- Daemon setup only ---
if [ "$DAEMON_ONLY" = "1" ]; then
  [ "$(id -u)" = "0" ] || err "--daemon-only requires root (use sudo)"

  WSH_AUDITD="$(resolve_auditd_path_for_root || true)"
  [ -n "$WSH_AUDITD" ] || err "wsh-auditd not found. Set WSH_AUDITD_PATH or run ./scripts/install-dev.sh first."
  case "$WSH_AUDITD" in
    /*) ;;
    *) err "WSH_AUDITD_PATH must be an absolute path (got: $WSH_AUDITD)" ;;
  esac
  [ -x "$WSH_AUDITD" ] || err "wsh-auditd binary not executable: $WSH_AUDITD"
  [ -f "$WSH_AUDITD" ] || err "wsh-auditd binary not found at $WSH_AUDITD"

  info "Skipping cargo build; configuring daemon only."
else
# --- Build ---
command -v cargo >/dev/null 2>&1 || err "cargo not found. Install Rust: https://rustup.rs"

if [ "$FROM_GIT" = "1" ]; then
  info "Building from GitHub (main branch)..."
  cargo install --git "$REPO" --bin wsh --bin wsh-auditd
else
  # Build from local checkout — find the repo root
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
  [ -f "$REPO_DIR/Cargo.toml" ] || err "Can't find Cargo.toml — run this from the warrant-shell repo"

  info "Building from local checkout ($REPO_DIR)..."
  cargo install --path "$REPO_DIR" --bin wsh --bin wsh-auditd
fi

# Verify wsh installed
if command -v wsh >/dev/null 2>&1; then
  VERSION="$(wsh --version 2>&1 || echo 'unknown')"
  ok "wsh installed ($VERSION)"
else
  ok "wsh built (may need to add ~/.cargo/bin to PATH)"
fi

# --- Daemon setup (root only) ---
if [ "$(id -u)" != "0" ]; then
  if [ "$BUILD_ONLY" = "1" ]; then
    ok "Build complete (daemon setup deferred to caller)."
    exit 0
  fi
  echo ""
  if prompt_yes_no "Configure/start audit daemon now (requires sudo)?" 1; then
    info "Elevating to configure daemon..."
    USER_WSH_AUDITD="$(command -v wsh-auditd 2>/dev/null || true)"
    [ -n "$USER_WSH_AUDITD" ] || err "wsh-auditd not found in PATH after build."
    case "$USER_WSH_AUDITD" in
      /*) ;;
      *) err "Resolved wsh-auditd path is not absolute: $USER_WSH_AUDITD" ;;
    esac
    if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
      sudo WSH_AUDITD_PATH="$USER_WSH_AUDITD" "$SCRIPT_SELF" --daemon-only --group-socket-access
    else
      sudo WSH_AUDITD_PATH="$USER_WSH_AUDITD" "$SCRIPT_SELF" --daemon-only
    fi
    ok "Daemon setup complete."
  else
    info "Skipping daemon setup."
    info "Run later with:"
    info "  sudo $SCRIPT_SELF --daemon-only"
  fi
  exit 0
fi

WSH_AUDITD="${WSH_AUDITD_PATH:-/usr/local/bin/wsh-auditd}"
[ -x "$WSH_AUDITD" ] || err "wsh-auditd binary not found at $WSH_AUDITD"
fi

info "Setting up audit daemon..."

if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
  info "Enabling group-restricted audit socket access (${SOCKET_GROUP_NAME}, mode ${SOCKET_ACCESS_MODE})..."
  ensure_group_exists "$SOCKET_GROUP_NAME"
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    add_user_to_group "$SUDO_USER" "$SOCKET_GROUP_NAME"
    info "Added user ${SUDO_USER} to group ${SOCKET_GROUP_NAME}."
    info "Group membership changes require a new login/session."
  else
    info "No invoking non-root user detected; ensure agent users are in group ${SOCKET_GROUP_NAME}."
  fi
fi

# Create directories
mkdir -p "$DAEMON_STATE_DIR" && chmod 0700 "$DAEMON_STATE_DIR"
mkdir -p "$DAEMON_AUDIT_DIR" && chmod 0700 "$DAEMON_AUDIT_DIR"
mkdir -p "$DAEMON_RUN_DIR" && chmod 0755 "$DAEMON_RUN_DIR"

# Generate HMAC key if not present
if [ ! -f "$DAEMON_HMAC_KEY" ]; then
  info "Generating HMAC host secret..."
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "$DAEMON_HMAC_KEY"
  elif [ -r /dev/urandom ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$DAEMON_HMAC_KEY"
  else
    err "Cannot generate HMAC key: no openssl or /dev/urandom"
  fi
  chmod 0400 "$DAEMON_HMAC_KEY"
  info "HMAC key created at $DAEMON_HMAC_KEY"
else
  info "HMAC key already exists — preserving."
fi

# Install platform service
if [ "$OS" = "linux" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    info "Installing systemd unit: $UNIT_FILE"
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Warrant Shell Audit Daemon (dev)
After=network.target

[Service]
Type=simple
ExecStart=${WSH_AUDITD}
RuntimeDirectory=warrant-shell
StateDirectory=warrant-shell
Environment=WSH_AUDITD_SOCKET_MODE=${SOCKET_ACCESS_MODE}
Environment=WSH_AUDITD_RELAY_SOCKET_MODE=${SOCKET_ACCESS_MODE}
EOF
    if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
      cat >> "$UNIT_FILE" <<EOF
Group=${SOCKET_GROUP_NAME}
EOF
    fi
    cat >> "$UNIT_FILE" <<EOF
Restart=on-failure
RestartSec=5
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DAEMON_STATE_DIR} ${DAEMON_AUDIT_DIR}
PrivateTmp=no

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
    systemctl restart "$SERVICE_NAME"
    info "systemd service enabled and started."
  else
    info "systemctl not found — skipping systemd service install."
    info "Start the daemon manually: $WSH_AUDITD"
  fi

elif [ "$OS" = "darwin" ]; then
  PLIST_FILE="/Library/LaunchDaemons/sh.warrant.auditd.plist"
  info "Installing launchd plist: $PLIST_FILE"
  cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>sh.warrant.auditd</string>
  <key>ProgramArguments</key>
  <array>
    <string>${WSH_AUDITD}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>WSH_AUDITD_SOCKET_MODE</key>
    <string>${SOCKET_ACCESS_MODE}</string>
    <key>WSH_AUDITD_RELAY_SOCKET_MODE</key>
    <string>${SOCKET_ACCESS_MODE}</string>
  </dict>
EOF
  if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
    cat >> "$PLIST_FILE" <<EOF
  <key>GroupName</key>
  <string>${SOCKET_GROUP_NAME}</string>
EOF
  fi
  cat >> "$PLIST_FILE" <<EOF
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/var/log/warrant-shell/auditd.err.log</string>
  <key>StandardOutPath</key>
  <string>/var/log/warrant-shell/auditd.out.log</string>
</dict>
</plist>
EOF
  mkdir -p /var/log/warrant-shell

  # Fully stop existing service before re-bootstrapping
  launchctl bootout system/sh.warrant.auditd 2>/dev/null || true
  # Kill any lingering daemon process
  pkill -f wsh-auditd 2>/dev/null || true
  sleep 1
  # Remove stale socket
  rm -f "$DAEMON_SOCKET"

  launchctl bootstrap system "$PLIST_FILE"
  info "launchd service loaded and started."
fi

# Health check
sleep 1
if [ -S "$DAEMON_SOCKET" ]; then
  ok "Audit daemon is running (socket: $DAEMON_SOCKET)"
else
  sleep 2
  if [ -S "$DAEMON_SOCKET" ]; then
    ok "Audit daemon is running (socket: $DAEMON_SOCKET)"
  else
    info "Warning: daemon socket not yet available at $DAEMON_SOCKET"
    if [ "$OS" = "linux" ]; then
      info "Check status: systemctl status $SERVICE_NAME"
      info "Check logs: journalctl -u $SERVICE_NAME -n 20"
    else
      info "Check status: launchctl list sh.warrant.auditd"
    fi
  fi
fi

info "Audit daemon endpoint health check..."
if daemon_endpoint_health_check; then
  ok "Audit endpoint health check passed."
else
  info "Warning: endpoint health check failed. Check logs/status and retry."
fi

echo ""
ok "Dev install complete. Ready for testing."
