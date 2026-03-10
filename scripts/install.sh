#!/bin/sh
# warrant-shell (wsh) installer
# Canonical URL: https://warrant.sh/install.sh
#
# Usage:
#   curl -fsSL https://warrant.sh/install.sh | sh            # user mode (wsh only)
#   curl -fsSL https://warrant.sh/install.sh | sudo sh       # system mode (wsh + audit daemon)
#   curl -fsSL https://warrant.sh/install.sh | sudo sh -s -- --group-socket-access
#   curl -fsSL https://warrant.sh/install.sh | sh -s -- --uninstall
#
# When run as root, the installer also sets up the audit daemon (wsh-auditd) as a
# system service. This is required for non-root agent execution with audit_required=true.
#
# Environment variables:
#   WSH_INSTALL_DIR  — override install directory (default: ~/.local/bin or /usr/local/bin)
#   WSH_NO_DAEMON    — set to 1 to skip audit daemon setup even when running as root

set -eu

REPO="warrant-sh/warrant-shell"
BINARY_NAME="wsh"
DAEMON_NAME="wsh-auditd"
SERVICE_NAME="wsh-auditd"

# Daemon paths
DAEMON_STATE_DIR="/var/lib/warrant-shell"
DAEMON_AUDIT_DIR="/var/lib/warrant-shell/audit"
DAEMON_DENYLIST_DIR="/var/lib/warrant-shell/denylists"
DAEMON_RUN_DIR="/var/run/warrant-shell"
DAEMON_SOCKET="${DAEMON_RUN_DIR}/auditd.sock"
DAEMON_RELAY_SOCKET="/tmp/warrant-shell/auditd.sock"
DAEMON_TCP_ADDR="127.0.0.1:45873"
DAEMON_HMAC_KEY="${DAEMON_STATE_DIR}/hmac.key"
SOCKET_GROUP_NAME="warrant"
SOCKET_ACCESS_MODE="0666"
GROUP_SOCKET_ACCESS=0
UNINSTALL_REQUESTED=0

for arg in "$@"; do
  case "$arg" in
    --group-socket-access) GROUP_SOCKET_ACCESS=1 ;;
    --uninstall) UNINSTALL_REQUESTED=1 ;;
  esac
done

if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
  SOCKET_ACCESS_MODE="0660"
fi

err() {
  printf '\033[1;31merror:\033[0m %s\n' "$1" >&2
  exit 1
}

info() {
  printf '\033[1;34m==>\033[0m %s\n' "$1"
}

ok() {
  printf '\033[1;32m==>\033[0m %s\n' "$1"
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       err "Unsupported OS: $(uname -s). Only Linux and macOS are supported." ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)   echo "arm64" ;;
    *)               err "Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported." ;;
  esac
}

detect_install_dir() {
  if [ -n "${WSH_INSTALL_DIR:-}" ]; then
    echo "$WSH_INSTALL_DIR"
  elif [ "$(id -u)" = "0" ]; then
    echo "/usr/local/bin"
  else
    echo "$HOME/.local/bin"
  fi
}

sha256_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  else
    err "No SHA-256 tool available (need sha256sum, shasum, or openssl)."
  fi
}

download_to_file() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    err "Neither curl nor wget found. Please install one and try again."
  fi
}

verify_tarball_checksum() {
  tarball="$1"
  checksum_file="$2"
  expected="$(awk 'NF {print $1; exit}' "$checksum_file" | tr -d '\r' | tr 'A-F' 'a-f')"
  [ -n "$expected" ] || err "Checksum file is empty or invalid."
  actual="$(sha256_file "$tarball" | tr 'A-F' 'a-f')"
  [ "$actual" = "$expected" ] || err "Checksum mismatch for ${tarball}: expected ${expected}, got ${actual}"
}

ensure_group_exists() {
  group_name="$1"
  os_name="$2"
  if [ "$os_name" = "linux" ]; then
    if command -v getent >/dev/null 2>&1 && getent group "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    command -v groupadd >/dev/null 2>&1 || err "groupadd is required for --group-socket-access"
    groupadd "$group_name" >/dev/null 2>&1 || true
    if command -v getent >/dev/null 2>&1 && getent group "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    err "failed to create/access group '$group_name'"
  else
    if dscl . -read "/Groups/$group_name" >/dev/null 2>&1; then
      return 0
    fi
    command -v dseditgroup >/dev/null 2>&1 || err "dseditgroup is required for --group-socket-access on macOS"
    dseditgroup -o create "$group_name" >/dev/null 2>&1 || true
    dscl . -read "/Groups/$group_name" >/dev/null 2>&1 || err "failed to create group '$group_name'"
  fi
}

add_user_to_group() {
  user_name="$1"
  group_name="$2"
  os_name="$3"
  [ -n "$user_name" ] || return 0
  [ "$user_name" = "root" ] && return 0

  if [ "$os_name" = "linux" ]; then
    command -v usermod >/dev/null 2>&1 || err "usermod is required to add $user_name to $group_name"
    usermod -a -G "$group_name" "$user_name"
  else
    dseditgroup -o edit -a "$user_name" -t user "$group_name"
  fi
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

main() {
  OS="$(detect_os)"
  ARCH="$(detect_arch)"
  INSTALL_DIR="$(detect_install_dir)"
  TARBALL="wsh-${OS}-${ARCH}.tar.gz"
  URL="https://github.com/${REPO}/releases/latest/download/${TARBALL}"
  CHECKSUM_URL="${URL}.sha256"

  info "Detected ${OS}/${ARCH}"
  info "Downloading ${TARBALL}..."

  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT

  download_to_file "$URL" "$TMPDIR/$TARBALL" || err "Download failed. Check that a release exists at:\n  $URL"
  info "Downloading checksum..."
  download_to_file "$CHECKSUM_URL" "$TMPDIR/$TARBALL.sha256" || err "Checksum download failed. Expected:\n  $CHECKSUM_URL"
  info "Verifying checksum..."
  verify_tarball_checksum "$TMPDIR/$TARBALL" "$TMPDIR/$TARBALL.sha256"

  info "Extracting..."
  tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR" || err "Failed to extract archive. The download may be corrupt."

  # Find the binary (could be at top level or in a subdirectory)
  BINARY="$(find "$TMPDIR" -name "$BINARY_NAME" -type f | head -1)"
  [ -n "$BINARY" ] || err "Binary '$BINARY_NAME' not found in archive."

  info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
  mkdir -p "$INSTALL_DIR"
  mv "$BINARY" "$INSTALL_DIR/$BINARY_NAME"
  chmod +x "$INSTALL_DIR/$BINARY_NAME"

  # Add to PATH if needed (non-root only)
  if [ "$(id -u)" != "0" ] && ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    info "Adding ${INSTALL_DIR} to PATH..."

    SHELL_NAME="$(basename "${SHELL:-/bin/sh}")"
    case "$SHELL_NAME" in
      zsh)
        RC="$HOME/.zshrc"
        ;;
      bash)
        if [ -f "$HOME/.bash_profile" ]; then
          RC="$HOME/.bash_profile"
        else
          RC="$HOME/.bashrc"
        fi
        ;;
      fish)
        RC="$HOME/.config/fish/config.fish"
        ;;
      *)
        RC="$HOME/.profile"
        ;;
    esac

    LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
    if [ -f "$RC" ] && grep -qF "$INSTALL_DIR" "$RC" 2>/dev/null; then
      : # already there
    else
      printf '\n# Added by wsh installer\n%s\n' "$LINE" >> "$RC"
      info "Added to ${RC} — restart your shell or run: source ${RC}"
    fi

    export PATH="${INSTALL_DIR}:$PATH"
  fi

  # Verify wsh
  if "$INSTALL_DIR/$BINARY_NAME" --version >/dev/null 2>&1; then
    VERSION="$("$INSTALL_DIR/$BINARY_NAME" --version 2>&1)"
    ok "wsh installed successfully! (${VERSION})"
  else
    ok "wsh installed to ${INSTALL_DIR}/${BINARY_NAME}"
  fi

  # Fetch manifests from registry
  info "Fetching manifests from registry..."
  if "$INSTALL_DIR/$BINARY_NAME" pull >/dev/null 2>&1; then
    ok "Manifests downloaded from registry."
  else
    info "Warning: manifest fetch failed (offline?). Run 'wsh pull' later to download manifests."
  fi

  # Install Claude guard hook to root-owned path (system mode)
  if [ "$(id -u)" = "0" ]; then
    install_system_claude_hook
  fi

  # Set up audit daemon if running as root (system mode)
  if [ "$(id -u)" = "0" ] && [ "${WSH_NO_DAEMON:-0}" != "1" ]; then
    setup_audit_daemon
  elif [ "$(id -u)" != "0" ]; then
    echo ""
    info "Running in user mode — audit daemon not installed."
    info "For non-root agent execution with audit_required=true, re-run with sudo:"
    info "  curl -fsSL https://warrant.sh/install.sh | sudo sh"
  fi

  echo ""
  echo "  Get started: https://warrant.sh/docs/getting-started/"
  echo ""
}

# --- Claude Guard Hook (root only) ---

install_system_claude_hook() {
  if [ "$OS" = "darwin" ]; then
    HOOK_DIR="/Library/Application Support/warrant-shell"
    HOOK_OWNER="root:wheel"
  else
    HOOK_DIR="/usr/local/lib/warrant-shell"
    HOOK_OWNER="root:root"
  fi
  HOOK_PATH="${HOOK_DIR}/claude_hook.py"

  mkdir -p "$HOOK_DIR"
  # Extract the guard script from the wsh binary's embedded copy
  HOOK_SCRIPT="$(find "$TMPDIR" -name "claude_hook.py" -type f 2>/dev/null | head -1)"
  if [ -z "$HOOK_SCRIPT" ]; then
    # The hook script is embedded in the wsh binary; generate it here.
    cat > "$HOOK_PATH" <<'HOOKEOF'
#!/usr/bin/env python3
import json
import os
import subprocess
import sys

def main():
    if os.getenv("WSH_GUARD") == "0":
        return 0

    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0

    if data.get("tool_name") != "Bash":
        return 0

    command = data.get("tool_input", {}).get("command", "")
    if not isinstance(command, str) or not command.strip():
        return 0

    result = subprocess.run(
        ["wsh", "guard", command],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "denied by warrant policy").strip()
        if message:
            print(message, file=sys.stderr)
        return 2

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
HOOKEOF
  else
    cp "$HOOK_SCRIPT" "$HOOK_PATH"
  fi

  chown "$HOOK_OWNER" "$HOOK_PATH"
  chmod 0555 "$HOOK_PATH"
  ok "Claude guard hook installed to $HOOK_PATH (root-owned, read-only)"
}

uninstall_system_claude_hook() {
  if [ "$OS" = "darwin" ]; then
    HOOK_DIR="/Library/Application Support/warrant-shell"
  else
    HOOK_DIR="/usr/local/lib/warrant-shell"
  fi
  if [ -f "$HOOK_DIR/claude_hook.py" ]; then
    rm -f "$HOOK_DIR/claude_hook.py"
    rmdir "$HOOK_DIR" 2>/dev/null || true
    info "Removed Claude guard hook from $HOOK_DIR"
  fi
}

# --- Audit Daemon Setup (root only) ---

setup_audit_daemon() {
  info "Setting up audit daemon (wsh-auditd)..."
  if [ "$GROUP_SOCKET_ACCESS" = "1" ]; then
    info "Enabling group-restricted audit socket access (${SOCKET_GROUP_NAME}, mode ${SOCKET_ACCESS_MODE})..."
    ensure_group_exists "$SOCKET_GROUP_NAME" "$OS"
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
      add_user_to_group "$SUDO_USER" "$SOCKET_GROUP_NAME" "$OS"
      info "Added user ${SUDO_USER} to group ${SOCKET_GROUP_NAME}."
      info "Group membership changes require a new login/session."
    else
      info "No invoking non-root user detected; ensure agent users are in group ${SOCKET_GROUP_NAME}."
    fi
  fi

  # Extract daemon binary from archive (same tarball, same archive)
  DAEMON_BINARY="$(find "$TMPDIR" -name "$DAEMON_NAME" -type f | head -1)"
  if [ -z "$DAEMON_BINARY" ]; then
    info "Daemon binary not found in archive — skipping daemon setup."
    info "wsh-auditd will be available in a future release."
    return 0
  fi

  mv "$DAEMON_BINARY" "$INSTALL_DIR/$DAEMON_NAME"
  chmod +x "$INSTALL_DIR/$DAEMON_NAME"
  info "Installed $DAEMON_NAME to $INSTALL_DIR/$DAEMON_NAME"

  # Create state directories
  mkdir -p "$DAEMON_STATE_DIR"
  chmod 0700 "$DAEMON_STATE_DIR"

  mkdir -p "$DAEMON_AUDIT_DIR"
  chmod 0700 "$DAEMON_AUDIT_DIR"

  mkdir -p "$DAEMON_DENYLIST_DIR"
  chmod 0755 "$DAEMON_DENYLIST_DIR"

  mkdir -p "$DAEMON_RUN_DIR"
  chmod 0755 "$DAEMON_RUN_DIR"

  # Generate HMAC key if not present (preserve across upgrades)
  if [ ! -f "$DAEMON_HMAC_KEY" ]; then
    info "Generating HMAC host secret..."
    # 32 bytes of randomness, hex-encoded
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex 32 > "$DAEMON_HMAC_KEY"
    elif [ -r /dev/urandom ]; then
      head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$DAEMON_HMAC_KEY"
    else
      err "Cannot generate HMAC key: no openssl or /dev/urandom available."
    fi
    chmod 0400 "$DAEMON_HMAC_KEY"
    info "HMAC key created at $DAEMON_HMAC_KEY (daemon-only readable)"
  else
    info "HMAC key already exists — preserving."
  fi

  # Install platform service
  if [ "$OS" = "darwin" ]; then
    install_launchd_service
  elif [ "$OS" = "linux" ]; then
    install_systemd_service
  fi

  info "Downloading initial package denylist data..."
  if "$INSTALL_DIR/$BINARY_NAME" package-update; then
    info "Initial denylist update completed."
  else
    info "Warning: initial denylist update failed. Retry with: sudo $INSTALL_DIR/$BINARY_NAME package-update"
  fi

  # Health check
  sleep 1
  if [ -S "$DAEMON_SOCKET" ]; then
    ok "Audit daemon is running (socket: $DAEMON_SOCKET)"
  else
    # Give it a moment more
    sleep 2
    if [ -S "$DAEMON_SOCKET" ]; then
      ok "Audit daemon is running (socket: $DAEMON_SOCKET)"
    else
      info "Warning: daemon socket not yet available at $DAEMON_SOCKET"
      info "Check status with: systemctl status $SERVICE_NAME (Linux) or launchctl list $SERVICE_NAME (macOS)"
    fi
  fi

  info "Audit daemon endpoint health check..."
  if daemon_endpoint_health_check; then
    ok "Audit endpoint health check passed."
  else
    info "Warning: endpoint health check failed. Check logs/status and retry."
  fi
}

install_systemd_service() {
  UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  info "Installing systemd unit: $UNIT_FILE"

  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Warrant Shell Audit Daemon
Documentation=https://warrant.sh/docs/audit/
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${DAEMON_NAME}
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

# Security hardening
NoNewPrivileges=yes
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
}

install_launchd_service() {
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
    <string>${INSTALL_DIR}/${DAEMON_NAME}</string>
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
  pkill -f wsh-auditd 2>/dev/null || true
  sleep 1
  rm -f "$DAEMON_SOCKET"

  launchctl bootstrap system "$PLIST_FILE"
  info "launchd service loaded and started."
}

# --- Uninstall ---

uninstall() {
  OS="$(detect_os)"
  info "Uninstalling warrant-shell..."

  # Stop and remove daemon service
  if [ "$(id -u)" = "0" ]; then
    if [ "$OS" = "linux" ] && [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
      systemctl stop "$SERVICE_NAME" 2>/dev/null || true
      systemctl disable "$SERVICE_NAME" 2>/dev/null || true
      rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
      systemctl daemon-reload
      info "Removed systemd service."
    elif [ "$OS" = "darwin" ] && [ -f "/Library/LaunchDaemons/sh.warrant.auditd.plist" ]; then
      launchctl bootout system/sh.warrant.auditd 2>/dev/null || true
      rm -f "/Library/LaunchDaemons/sh.warrant.auditd.plist"
      info "Removed launchd service."
    fi

    # Remove Claude guard hook
    uninstall_system_claude_hook

    # Remove daemon binary
    for dir in /usr/local/bin /usr/bin; do
      [ -f "$dir/$DAEMON_NAME" ] && rm -f "$dir/$DAEMON_NAME" && info "Removed $dir/$DAEMON_NAME"
    done

    # Archive audit ledger (don't delete data)
    if [ -d "$DAEMON_AUDIT_DIR" ]; then
      ARCHIVE="/var/lib/warrant-shell/audit-archive-$(date +%Y%m%d-%H%M%S).tar.gz"
      tar -czf "$ARCHIVE" -C "$DAEMON_STATE_DIR" audit/ 2>/dev/null && \
        info "Audit ledger archived to $ARCHIVE" || \
        info "Warning: could not archive audit ledger."
    fi

    # Remove runtime state (but preserve archive)
    rm -rf "$DAEMON_RUN_DIR"
    info "Removed runtime directory."
  fi

  # Remove wsh binary
  INSTALL_DIR="$(detect_install_dir)"
  if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    info "Removed $INSTALL_DIR/$BINARY_NAME"
  fi

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

  remove_marker_block() {
    file="$1"
    marker="$2"
    [ -f "$file" ] || return 0
    if grep -q "$marker" "$file" 2>/dev/null; then
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

  # Remove wsh-related aliases
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
def is_wsh_hook(e):
    for h in (e.get('hooks', []) if isinstance(e, dict) else []):
        cmd = h.get('command', '') if isinstance(h, dict) else ''
        if 'wsh_guard_pretool.py' in cmd or 'claude_hook.py' in cmd:
            return True
    return False
filtered = [e for e in pre if not is_wsh_hook(e)]
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
  if [ -d "$DAEMON_AUDIT_DIR" ]; then
    info "Audit data preserved in $DAEMON_STATE_DIR — remove manually if no longer needed."
  fi
}

# --- Entry point ---

# Check for --uninstall flag
if [ "$UNINSTALL_REQUESTED" = "1" ]; then
  uninstall
  exit 0
fi

main
