use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use warrant_core::ToolPaths;

pub const SYSTEM_AUDITD_SOCKET: &str = "/var/run/warrant-shell/auditd.sock";
pub const DEFAULT_DAEMON_SOCKET: &str = SYSTEM_AUDITD_SOCKET;
pub const SANDBOX_RELAY_AUDITD_SOCKET: &str = "/tmp/warrant-shell/auditd.sock";
pub const DEFAULT_DAEMON_TCP_ADDR: &str = "127.0.0.1:45873";
pub const DEFAULT_DAEMON_LEDGER_DIR: &str = "/var/lib/warrant-shell/audit";
pub const SPOOL_DIR: &str = "/tmp/warrant-shell/spool";
pub const HEARTBEAT_PATH: &str = "/tmp/warrant-shell/daemon.heartbeat";
const HEARTBEAT_STALENESS_SECS: u64 = 30;
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailure {
    pub line_number: usize,
    pub expected_prev_hash: String,
    pub found_prev_hash: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub total_entries: usize,
    pub valid: bool,
    pub failure: Option<VerifyFailure>,
}

pub trait AuditSink: Send + Sync {
    fn log(&self, entry: &AuditEntry) -> io::Result<()>;
    fn read_entries(&self) -> io::Result<Vec<AuditEntry>>;
    fn clear(&self) -> io::Result<()>;
    fn log_path(&self) -> io::Result<PathBuf>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub profile: Option<String>,
    pub decision: Decision,
    pub command: Vec<String>,
    pub program: String,
    pub resolved_program: Option<String>,
    pub reason: String,
    pub policy_hash: Option<String>,
    pub session_id: Option<String>,
    pub elevated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripped_env_var_count: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct DecisionMetadata<'a> {
    pub reason: &'a str,
    pub elevated: bool,
    pub profile: Option<&'a str>,
    pub resolved_program: Option<&'a str>,
    pub stripped_env_var_count: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct FileSink {
    paths: Option<ToolPaths>,
}

impl FileSink {
    pub fn new(paths: Option<ToolPaths>) -> Self {
        Self { paths }
    }
}

impl AuditSink for FileSink {
    fn log(&self, entry: &AuditEntry) -> io::Result<()> {
        let log_path = self.log_path()?;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        ensure_regular_or_missing(&log_path)?;

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let mut file = open_file_nofollow(&mut options, &log_path)?;

        serde_json::to_writer(&mut file, entry)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn read_entries(&self) -> io::Result<Vec<AuditEntry>> {
        let path = self.log_path()?;
        ensure_regular_or_missing(&path)?;
        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut options = OpenOptions::new();
        options.read(true);
        let file = open_file_nofollow(&mut options, &path)?;
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => out.push(entry),
                Err(err) => eprintln!("warning: invalid audit log entry skipped: {err}"),
            }
        }
        Ok(out)
    }

    fn clear(&self) -> io::Result<()> {
        let path = self.log_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        ensure_regular_or_missing(&path)?;
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        open_file_nofollow(&mut options, &path)?;
        Ok(())
    }

    fn log_path(&self) -> io::Result<PathBuf> {
        #[cfg(test)]
        if let Some(root) = std::env::var_os("WARRANT_TEST_ROOT") {
            return Ok(PathBuf::from(root).join("audit.log"));
        }

        #[cfg(test)]
        if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg_data_home)
                .join("warrant-shell")
                .join("audit.log"));
        }

        if let Some(paths) = self.paths.as_ref()
            && let Some(parent) = paths.installed_warrant_path.parent()
        {
            return Ok(parent.join("audit.log"));
        }

        let system_dir = PathBuf::from("/var/log/warrant-shell");
        if fs::create_dir_all(&system_dir).is_ok() {
            return Ok(system_dir.join("audit.log"));
        }
        user_state_audit_path()
    }
}

fn open_file_nofollow(options: &mut OpenOptions, path: &Path) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[derive(Debug, Clone)]
pub struct DaemonSink {
    socket_path: PathBuf,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonRequest<'a> {
    Audit {
        entry: &'a AuditEntry,
        actor_uid: Option<u32>,
        actor_gid: Option<u32>,
    },
    ElevationCheck {
        uid: u32,
    },
    Ping {
        nonce: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum LoggingDaemonEndpoint {
    Unix(PathBuf),
    Tcp(String),
}

impl DaemonSink {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

#[cfg(unix)]
impl AuditSink for DaemonSink {
    fn log(&self, entry: &AuditEntry) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut last_err: Option<io::Error> = None;

        for _ in 0..3 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);

            match log_once(entry, &self.socket_path, remaining) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }

            if Instant::now() >= deadline {
                break;
            }
            let sleep_for =
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now()));
            if !sleep_for.is_zero() {
                thread::sleep(sleep_for);
            }
        }

        Err(last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "daemon ack timeout")))
    }

    fn read_entries(&self) -> io::Result<Vec<AuditEntry>> {
        Err(io::Error::other(
            "read_entries not supported via daemon sink - use wsh audit command",
        ))
    }

    fn clear(&self) -> io::Result<()> {
        Err(io::Error::other(
            "clear not supported via daemon sink - use wsh audit command",
        ))
    }

    fn log_path(&self) -> io::Result<PathBuf> {
        Ok(self.socket_path.clone())
    }
}

#[cfg(unix)]
fn log_once(entry: &AuditEntry, socket_path: &Path, timeout: Duration) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_read_timeout(Some(timeout))?;

    let request = DaemonRequest::Audit {
        entry,
        actor_uid: current_uid(),
        actor_gid: current_gid(),
    };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    parse_ack(stream)
}

#[cfg(unix)]
fn log_once_tcp(entry: &AuditEntry, addr: &str, timeout: Duration) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_read_timeout(Some(timeout))?;

    let request = DaemonRequest::Audit {
        entry,
        actor_uid: current_uid(),
        actor_gid: current_gid(),
    };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    parse_ack(stream)
}

#[cfg(unix)]
fn parse_ack<R: std::io::Read>(stream: R) -> io::Result<()> {
    let mut ack = String::new();
    let mut reader = BufReader::new(stream);
    if reader.read_line(&mut ack)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed without ACK",
        ));
    }

    #[derive(Deserialize)]
    struct Ack {
        status: String,
        message: Option<String>,
    }

    let ack: Ack = serde_json::from_str(ack.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon ACK: {err}"),
        )
    })?;

    if ack.status == "ok" {
        Ok(())
    } else {
        Err(io::Error::other(
            ack.message
                .unwrap_or_else(|| "daemon reported error".to_string()),
        ))
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(unsafe { libc::geteuid() })
}

#[cfg(unix)]
fn current_gid() -> Option<u32> {
    Some(unsafe { libc::getegid() })
}

/// Ping the daemon with a signed challenge-response to verify it's the real daemon.
/// Sends a random nonce; the daemon signs it with the ed25519 private key.
/// Requires an authenticated challenge-response signature from the daemon.
#[cfg(unix)]
fn ping_daemon(socket_path: &Path, public_key_path: &Path) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "audit daemon not reachable ({}): {err}",
                socket_path.display()
            ),
        )
    })?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Generate a random nonce for challenge-response
    let nonce: String = {
        let mut buf = [0u8; 16];
        use std::io::Read;
        fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
        buf.iter().map(|b| format!("{b:02x}")).collect()
    };

    let request = DaemonRequest::Ping {
        nonce: Some(nonce.clone()),
    };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    // Read response
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    if reader.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed without ping response",
        ));
    }

    let resp: Value = serde_json::from_str(line.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon ping response: {err}"),
        )
    })?;

    if resp.get("status").and_then(|s| s.as_str()) != Some("ok") {
        return Err(io::Error::other(
            resp.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("daemon ping failed")
                .to_string(),
        ));
    }

    let sig_hex = resp
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| io::Error::other("daemon ping response missing signature"))?;
    if !sig_hex.len().is_multiple_of(2) {
        return Err(io::Error::other(
            "invalid signature hex length in ping response",
        ));
    }
    let verifying_key = warrant_core::read_verifying_key(public_key_path)
        .map_err(|err| io::Error::other(format!("failed to read signing public key: {err}")))?;
    let sig_bytes: Vec<u8> = (0..sig_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| io::Error::other("invalid signature hex in ping response"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| io::Error::other("invalid ed25519 signature length in ping response"))?;
    verifying_key
        .verify_strict(nonce.as_bytes(), &signature)
        .map_err(|_| {
            io::Error::other(
                "daemon ping signature verification failed — \
                 possible spoofed daemon or key mismatch",
            )
        })?;

    Ok(())
}

#[cfg(unix)]
fn ping_daemon_tcp(addr: &str, public_key_path: &Path) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("audit daemon not reachable (tcp://{addr}): {err}"),
        )
    })?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;

    let nonce: String = {
        let mut buf = [0u8; 16];
        use std::io::Read;
        fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
        buf.iter().map(|b| format!("{b:02x}")).collect()
    };

    let request = DaemonRequest::Ping {
        nonce: Some(nonce.clone()),
    };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    if reader.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed without ping response",
        ));
    }

    let resp: Value = serde_json::from_str(line.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon ping response: {err}"),
        )
    })?;

    if resp.get("status").and_then(|s| s.as_str()) != Some("ok") {
        return Err(io::Error::other(
            resp.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("daemon ping failed")
                .to_string(),
        ));
    }

    let sig_hex = resp
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| io::Error::other("daemon ping response missing signature"))?;
    if !sig_hex.len().is_multiple_of(2) {
        return Err(io::Error::other(
            "invalid signature hex length in ping response",
        ));
    }
    let verifying_key = warrant_core::read_verifying_key(public_key_path)
        .map_err(|err| io::Error::other(format!("failed to read signing public key: {err}")))?;
    let sig_bytes: Vec<u8> = (0..sig_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| io::Error::other("invalid signature hex in ping response"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| io::Error::other("invalid ed25519 signature length in ping response"))?;
    verifying_key
        .verify_strict(nonce.as_bytes(), &signature)
        .map_err(|_| {
            io::Error::other(
                "daemon ping signature verification failed — \
                 possible spoofed daemon or key mismatch",
            )
        })?;

    Ok(())
}

pub fn verify_daemon_health(paths: &ToolPaths) -> io::Result<()> {
    if !is_system_install_path(&paths.installed_warrant_path) {
        return Ok(());
    }

    resolve_logging_daemon_endpoint(paths).map(|_| ())
}

#[cfg(unix)]
fn resolve_logging_daemon_endpoint(paths: &ToolPaths) -> io::Result<LoggingDaemonEndpoint> {
    if !is_system_install_path(&paths.installed_warrant_path) {
        return Ok(LoggingDaemonEndpoint::Unix(logging_daemon_socket_path()));
    }

    let public_key_path = if paths.signing_public_key_path.exists() {
        paths.signing_public_key_path.clone()
    } else {
        let relay_key = PathBuf::from("/tmp/warrant-shell/signing/public.key");
        if relay_key.exists() {
            relay_key
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "audit daemon signing public key missing at {} and {}; refusing unauthenticated daemon",
                    paths.signing_public_key_path.display(),
                    "/tmp/warrant-shell/signing/public.key"
                ),
            ));
        }
    };

    let mut last_err: Option<io::Error> = None;
    let mut endpoint_labels = Vec::new();
    for endpoint in logging_daemon_endpoint_candidates() {
        let label = match &endpoint {
            LoggingDaemonEndpoint::Unix(path) => path.display().to_string(),
            LoggingDaemonEndpoint::Tcp(addr) => format!("tcp://{addr}"),
        };
        endpoint_labels.push(label);
        let ping_result = match &endpoint {
            LoggingDaemonEndpoint::Unix(path) => ping_daemon(path, public_key_path.as_path()),
            LoggingDaemonEndpoint::Tcp(addr) => ping_daemon_tcp(addr, public_key_path.as_path()),
        };
        match ping_result {
            Ok(()) => return Ok(endpoint),
            Err(err) => last_err = Some(err),
        }
    }

    let detail = last_err
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "audit daemon not running on {} ({detail}). \
             Install with: curl -fsSL https://warrant.sh/install.sh | sudo sh",
            endpoint_labels.join(", ")
        ),
    ))
}

#[cfg(not(unix))]
fn resolve_logging_daemon_endpoint(_paths: &ToolPaths) -> io::Result<LoggingDaemonEndpoint> {
    Err(io::Error::other("daemon sink is only supported on Unix"))
}

#[cfg(unix)]
pub fn check_elevation_via_daemon(uid: u32) -> io::Result<bool> {
    let socket_path = elevation_socket_path();

    if !is_trusted_elevation_socket(&socket_path) {
        return Ok(false);
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut last_err: Option<io::Error> = None;

    for _ in 0..3 {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);

        match check_elevation_once(uid, &socket_path, remaining) {
            Ok(elevated) => return Ok(elevated),
            Err(err) => last_err = Some(err),
        }

        if Instant::now() >= deadline {
            break;
        }
        let sleep_for =
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now()));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "daemon response timeout")))
}

#[cfg(unix)]
fn is_trusted_elevation_socket(socket_path: &Path) -> bool {
    if socket_path != Path::new(SYSTEM_AUDITD_SOCKET) {
        eprintln!(
            "warning: unauthenticated elevation requested via non-system socket {}; defaulting to not elevated",
            socket_path.display()
        );
        return false;
    }

    let metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) => {
            eprintln!(
                "warning: elevation socket {} is unavailable ({err}); defaulting to not elevated",
                socket_path.display()
            );
            return false;
        }
    };

    if !metadata.file_type().is_socket() {
        eprintln!(
            "warning: elevation socket {} is not a unix socket; defaulting to not elevated",
            socket_path.display()
        );
        return false;
    }

    let uid = metadata.uid();
    let gid = metadata.gid();
    let mode = metadata.mode() & 0o777;
    if !has_strict_elevation_socket_ownership(uid, gid, mode) {
        eprintln!(
            "warning: rejecting unauthenticated elevation from socket {} (uid={}, gid={}, mode={:o}); defaulting to not elevated",
            socket_path.display(),
            uid,
            gid,
            mode
        );
        return false;
    }

    true
}

#[cfg(unix)]
fn has_strict_elevation_socket_ownership(uid: u32, _gid: u32, mode: u32) -> bool {
    // Group can vary by service manager/platform (e.g. launchd/systemd), so
    // trust root ownership plus an expected daemon-managed socket mode.
    uid == 0 && matches!(mode, 0o600 | 0o660 | 0o666 | 0o700)
}

#[cfg(unix)]
fn check_elevation_once(uid: u32, socket_path: &Path, timeout: Duration) -> io::Result<bool> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_read_timeout(Some(timeout))?;

    let request = DaemonRequest::ElevationCheck { uid };
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    if reader.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed without response",
        ));
    }

    #[derive(Deserialize)]
    struct ElevationResponse {
        status: String,
        elevated: Option<bool>,
        message: Option<String>,
    }

    let response: ElevationResponse = serde_json::from_str(line.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon response: {err}"),
        )
    })?;

    if response.status == "ok" {
        Ok(response.elevated.unwrap_or(false))
    } else {
        Err(io::Error::other(
            response
                .message
                .unwrap_or_else(|| "daemon reported error".to_string()),
        ))
    }
}

#[cfg(not(unix))]
pub fn check_elevation_via_daemon(_uid: u32) -> io::Result<bool> {
    Err(io::Error::other("daemon sink is only supported on Unix"))
}

#[cfg(not(unix))]
impl AuditSink for DaemonSink {
    fn log(&self, _entry: &AuditEntry) -> io::Result<()> {
        Err(io::Error::other("daemon sink is only supported on Unix"))
    }

    fn read_entries(&self) -> io::Result<Vec<AuditEntry>> {
        Err(io::Error::other("daemon sink is only supported on Unix"))
    }

    fn clear(&self) -> io::Result<()> {
        Err(io::Error::other("daemon sink is only supported on Unix"))
    }

    fn log_path(&self) -> io::Result<PathBuf> {
        Ok(self.socket_path.clone())
    }
}

pub fn log_decision(
    paths: &ToolPaths,
    decision: Decision,
    command: &[String],
    meta: DecisionMetadata<'_>,
) -> io::Result<()> {
    let entry = AuditEntry {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        profile: meta
            .profile
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var("WSH_PROFILE").ok()),
        decision,
        command: command.to_vec(),
        program: command.first().cloned().unwrap_or_default(),
        resolved_program: meta.resolved_program.map(ToOwned::to_owned),
        reason: meta.reason.to_string(),
        policy_hash: policy_hash_for_warrant(&paths.installed_warrant_path)?,
        session_id: std::env::var("WSH_SESSION_ID").ok(),
        elevated: meta.elevated,
        stripped_env_var_count: meta.stripped_env_var_count,
    };

    // In system mode, audit writes MUST go through the daemon. If the daemon isn't
    // running, the write fails and fail-closed denies the command. No silent fallback.
    //
    // In --paths-root mode (testing/dev), use FileSink directly since there's no daemon.
    // Detect this by checking if the installed warrant path is under a custom root
    // (i.e. not the system path).
    let is_system_mode = is_system_install_path(&paths.installed_warrant_path);

    if !is_system_mode {
        // --paths-root / dev mode: direct file writes are fine
        return FileSink::new(Some(paths.clone())).log(&entry);
    }

    match log_to_daemon(paths, &entry) {
        Ok(()) => Ok(()),
        Err(err) if is_connectivity_error(&err) && !is_authentication_error(&err) => {
            if is_daemon_alive() {
                write_entry_to_spool(&entry)?;
                Ok(())
            } else {
                Err(err)
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn log_to_daemon(paths: &ToolPaths, entry: &AuditEntry) -> io::Result<()> {
    let public_key_path = if paths.signing_public_key_path.exists() {
        paths.signing_public_key_path.clone()
    } else {
        let relay_key = PathBuf::from("/tmp/warrant-shell/signing/public.key");
        if relay_key.exists() {
            relay_key
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "audit daemon signing public key missing at {} and {}; refusing unauthenticated daemon",
                    paths.signing_public_key_path.display(),
                    "/tmp/warrant-shell/signing/public.key"
                ),
            ));
        }
    };

    let mut last_err: Option<io::Error> = None;
    let mut endpoint_labels = Vec::new();
    for endpoint in logging_daemon_endpoint_candidates() {
        let label = match &endpoint {
            LoggingDaemonEndpoint::Unix(path) => path.display().to_string(),
            LoggingDaemonEndpoint::Tcp(addr) => format!("tcp://{addr}"),
        };
        endpoint_labels.push(label);

        let ping_result = match &endpoint {
            LoggingDaemonEndpoint::Unix(path) => ping_daemon(path, public_key_path.as_path()),
            LoggingDaemonEndpoint::Tcp(addr) => ping_daemon_tcp(addr, public_key_path.as_path()),
        };
        if let Err(err) = ping_result {
            last_err = Some(err);
            continue;
        }

        let log_result = match &endpoint {
            LoggingDaemonEndpoint::Unix(path) => DaemonSink::new(path.clone()).log(entry),
            LoggingDaemonEndpoint::Tcp(addr) => log_once_tcp(entry, addr, Duration::from_secs(1)),
        };
        match log_result {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }

    let (kind, detail) = if let Some(err) = last_err {
        (err.kind(), err.to_string())
    } else {
        (io::ErrorKind::NotFound, "unknown error".to_string())
    };
    Err(io::Error::new(
        kind,
        format!(
            "audit daemon not running on {} ({detail}). \
             Install with: curl -fsSL https://warrant.sh/install.sh | sudo sh",
            endpoint_labels.join(", ")
        ),
    ))
}

#[cfg(not(unix))]
fn log_to_daemon(_paths: &ToolPaths, _entry: &AuditEntry) -> io::Result<()> {
    Err(io::Error::other("daemon sink is only supported on Unix"))
}

fn write_entry_to_spool(entry: &AuditEntry) -> io::Result<PathBuf> {
    write_entry_to_spool_dir(entry, Path::new(SPOOL_DIR))
}

fn daemon_heartbeat_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_AUDITD_HEARTBEAT_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    PathBuf::from(HEARTBEAT_PATH)
}

fn is_daemon_alive() -> bool {
    let path = daemon_heartbeat_path();
    let content = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let heartbeat_epoch = match content.trim().parse::<u64>() {
        Ok(ts) => ts,
        Err(_) => return false,
    };
    let now_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return false,
    };
    now_epoch.abs_diff(heartbeat_epoch) <= HEARTBEAT_STALENESS_SECS
}

fn write_entry_to_spool_dir(entry: &AuditEntry, spool_dir: &Path) -> io::Result<PathBuf> {
    ensure_spool_dir(spool_dir)?;
    let pid = std::process::id();
    let epoch_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    for _ in 0..16 {
        let suffix = random_hex_4()?;
        let file_path = spool_dir.join(format!("{epoch_millis}-{pid}-{suffix}.jsonl"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file_path)
        {
            Ok(mut file) => {
                serde_json::to_writer(&mut file, entry)?;
                file.write_all(b"\n")?;
                #[cfg(unix)]
                {
                    if let Err(err) =
                        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644))
                    {
                        let is_permission_like = err.kind() == io::ErrorKind::PermissionDenied
                            || err.raw_os_error() == Some(libc::EPERM);
                        if !is_permission_like {
                            return Err(err);
                        }
                    }
                }
                return Ok(file_path);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create unique spool file",
    ))
}

fn ensure_spool_dir(spool_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(spool_dir)?;
    #[cfg(unix)]
    {
        if let Err(err) = fs::set_permissions(spool_dir, fs::Permissions::from_mode(0o1733)) {
            let is_permission_like = err.kind() == io::ErrorKind::PermissionDenied
                || err.raw_os_error() == Some(libc::EPERM);
            if !is_permission_like {
                return Err(err);
            }
        }
    }
    Ok(())
}

fn is_connectivity_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::UnexpectedEof
    )
}

fn is_authentication_error(err: &io::Error) -> bool {
    let text = err.to_string();
    text.contains("refusing unauthenticated daemon")
        || text.contains("signature verification failed")
        || text.contains("missing signature")
}

fn random_hex_4() -> io::Result<String> {
    let mut bytes = [0u8; 2];
    #[cfg(unix)]
    {
        fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        bytes[0] = (nanos & 0xff) as u8;
        bytes[1] = ((nanos >> 8) & 0xff) as u8;
    }
    Ok(format!("{:02x}{:02x}", bytes[0], bytes[1]))
}

pub fn read_entries() -> io::Result<Vec<AuditEntry>> {
    FileSink::new(None).read_entries()
}

pub fn read_entries_with_paths(paths: Option<&ToolPaths>) -> io::Result<Vec<AuditEntry>> {
    // In system mode, read from the daemon's ledger directory
    if let Some(p) = paths
        && is_system_install_path(&p.installed_warrant_path)
    {
        return read_entries_from_ledger_dir(daemon_ledger_dir().as_path());
    }
    FileSink::new(paths.cloned()).read_entries()
}

/// Read all audit entries from the daemon's ledger directory (all .jsonl files, sorted by date)
fn read_entries_from_ledger_dir(dir: &Path) -> io::Result<Vec<AuditEntry>> {
    let mut entries = Vec::new();
    let mut files: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort_by_key(|e| e.file_name());

    for file_entry in files {
        let file = fs::File::open(file_entry.path())?;
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

pub fn clear_log() -> io::Result<()> {
    FileSink::new(None).clear()
}

pub fn clear_log_with_paths(paths: Option<&ToolPaths>) -> io::Result<()> {
    FileSink::new(paths.cloned()).clear()
}

pub fn audit_log_path(paths: Option<&ToolPaths>) -> io::Result<PathBuf> {
    FileSink::new(paths.cloned()).log_path()
}

pub fn daemon_ledger_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("WSH_AUDITD_LEDGER_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }

    PathBuf::from(DEFAULT_DAEMON_LEDGER_DIR)
}

fn elevation_socket_path() -> PathBuf {
    // Production mode must never trust caller-provided socket overrides.
    // Tests can still inject a socket path through env for harnessed daemons.
    #[cfg(test)]
    {
        if let Some(path) = auditd_socket_env_override() {
            return path;
        }
    }
    PathBuf::from(SYSTEM_AUDITD_SOCKET)
}

fn logging_daemon_socket_path() -> PathBuf {
    logging_daemon_endpoint_candidates()
        .into_iter()
        .find_map(|endpoint| match endpoint {
            LoggingDaemonEndpoint::Unix(path) => Some(path),
            LoggingDaemonEndpoint::Tcp(_) => None,
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON_SOCKET))
}

#[cfg(unix)]
fn logging_daemon_endpoint_candidates() -> Vec<LoggingDaemonEndpoint> {
    #[cfg(test)]
    {
        if let Some(path) = auditd_socket_env_override() {
            return vec![LoggingDaemonEndpoint::Unix(path)];
        }
    }
    vec![
        LoggingDaemonEndpoint::Unix(PathBuf::from(DEFAULT_DAEMON_SOCKET)),
        LoggingDaemonEndpoint::Unix(PathBuf::from(SANDBOX_RELAY_AUDITD_SOCKET)),
        LoggingDaemonEndpoint::Tcp(DEFAULT_DAEMON_TCP_ADDR.to_string()),
    ]
}

#[cfg(not(unix))]
fn logging_daemon_endpoint_candidates() -> Vec<LoggingDaemonEndpoint> {
    vec![LoggingDaemonEndpoint::Unix(PathBuf::from(
        DEFAULT_DAEMON_SOCKET,
    ))]
}

#[cfg(test)]
fn auditd_socket_env_override() -> Option<PathBuf> {
    std::env::var_os("WSH_AUDITD_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub fn verify_ledger(ledger_path: &Path) -> io::Result<VerifyResult> {
    let file = OpenOptions::new().read(true).open(ledger_path)?;
    let mut reader = BufReader::new(file);
    let mut raw_line = String::new();
    let mut prev_line: Option<String> = None;
    let mut total_entries = 0usize;
    let mut file_line_number = 0usize;

    loop {
        raw_line.clear();
        let n = reader.read_line(&mut raw_line)?;
        if n == 0 {
            break;
        }
        file_line_number += 1;

        let line = normalize_ledger_line(&raw_line);
        if line.trim().is_empty() {
            continue;
        }

        let parsed: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                return Ok(VerifyResult {
                    total_entries,
                    valid: false,
                    failure: Some(VerifyFailure {
                        line_number: file_line_number,
                        expected_prev_hash: expected_prev_hash(prev_line.as_deref()),
                        found_prev_hash: None,
                        details: format!("invalid JSON: {err}"),
                    }),
                });
            }
        };

        let found_prev_hash = parsed
            .as_object()
            .and_then(|obj| obj.get("prev_hash"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let expected = expected_prev_hash(prev_line.as_deref());
        if found_prev_hash.as_deref() != Some(expected.as_str()) {
            return Ok(VerifyResult {
                total_entries,
                valid: false,
                failure: Some(VerifyFailure {
                    line_number: file_line_number,
                    expected_prev_hash: expected,
                    found_prev_hash,
                    details: "prev_hash mismatch".to_string(),
                }),
            });
        }

        total_entries += 1;
        prev_line = Some(line.to_string());
    }

    Ok(VerifyResult {
        total_entries,
        valid: true,
        failure: None,
    })
}

fn expected_prev_hash(prev_line: Option<&str>) -> String {
    match prev_line {
        Some(line) => sha256_hex(line.as_bytes()),
        None => ZERO_HASH.to_string(),
    }
}

fn normalize_ledger_line(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn policy_hash_for_warrant(path: &Path) -> io::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(Some(format!("{:x}", hasher.finalize())))
}

/// Returns true if the warrant path looks like a system-mode install
/// (e.g. /Library/Application Support/warrant-shell/ or /etc/warrant-shell/).
/// Returns false for --paths-root custom directories used in testing.
pub(crate) fn is_system_install_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/Library/Application Support/warrant-shell")
        || s.starts_with("/etc/warrant-shell")
        || s.starts_with("/var/lib/warrant-shell")
}

fn ensure_regular_or_missing(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "audit log path {} is not a regular file",
            path.display()
        ))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn user_state_audit_path() -> io::Result<PathBuf> {
    if let Some(xdg_state_home) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(xdg_state_home)
            .join("warrant-shell")
            .join("audit.log"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("warrant-shell")
            .join("audit.log"));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "unable to resolve secure user state directory for audit log",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use super::has_strict_elevation_socket_ownership;
    use super::{AuditEntry, Decision, is_daemon_alive, write_entry_to_spool_dir};

    fn heartbeat_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("heartbeat env mutex")
    }

    fn set_heartbeat_env(path: &std::path::Path) {
        // SAFETY: tests serialize env mutation with heartbeat_env_lock().
        unsafe {
            std::env::set_var("WSH_AUDITD_HEARTBEAT_PATH", path);
        }
    }

    fn clear_heartbeat_env() {
        // SAFETY: tests serialize env mutation with heartbeat_env_lock().
        unsafe {
            std::env::remove_var("WSH_AUDITD_HEARTBEAT_PATH");
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_root_owned_socket_is_rejected_for_elevation_trust() {
        assert!(!has_strict_elevation_socket_ownership(1000, 1000, 0o600));
        assert!(!has_strict_elevation_socket_ownership(0, 1, 0o755));
        assert!(has_strict_elevation_socket_ownership(0, 0, 0o600));
        assert!(has_strict_elevation_socket_ownership(0, 1, 0o666));
        assert!(has_strict_elevation_socket_ownership(0, 0, 0o700));
    }

    #[test]
    fn spool_write_persists_jsonl_entry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spool_dir = temp.path().join("spool");
        let entry = AuditEntry {
            timestamp: "2026-03-07T00:00:00Z".to_string(),
            profile: Some("codex".to_string()),
            decision: Decision::Allow,
            command: vec!["echo".to_string(), "hello".to_string()],
            program: "echo".to_string(),
            resolved_program: Some("/bin/echo".to_string()),
            reason: "test".to_string(),
            policy_hash: Some("abc123".to_string()),
            session_id: Some("session-test".to_string()),
            elevated: false,
            stripped_env_var_count: Some(1),
        };

        let path = write_entry_to_spool_dir(&entry, &spool_dir).expect("write spool file");
        assert!(path.exists());

        let data = fs::read_to_string(path).expect("read spool file");
        let parsed = serde_json::from_str::<AuditEntry>(data.trim()).expect("parse json");
        assert_eq!(parsed.timestamp, entry.timestamp);
        assert_eq!(parsed.profile, entry.profile);
        assert_eq!(parsed.command, entry.command);
        assert_eq!(parsed.reason, entry.reason);
    }

    #[test]
    fn heartbeat_fresh_returns_alive() {
        let _guard = heartbeat_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let heartbeat = temp.path().join("daemon.heartbeat");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix epoch")
            .as_secs();
        fs::write(&heartbeat, format!("{now}\n")).expect("write heartbeat");
        set_heartbeat_env(&heartbeat);
        assert!(is_daemon_alive());
        clear_heartbeat_env();
    }

    #[test]
    fn heartbeat_stale_returns_dead() {
        let _guard = heartbeat_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let heartbeat = temp.path().join("daemon.heartbeat");
        let stale = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix epoch")
            .as_secs()
            .saturating_sub(60);
        fs::write(&heartbeat, format!("{stale}\n")).expect("write heartbeat");
        set_heartbeat_env(&heartbeat);
        assert!(!is_daemon_alive());
        clear_heartbeat_env();
    }

    #[test]
    fn heartbeat_missing_returns_dead() {
        let _guard = heartbeat_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let heartbeat = temp.path().join("missing.heartbeat");
        set_heartbeat_env(&heartbeat);
        assert!(!is_daemon_alive());
        clear_heartbeat_env();
    }

    #[test]
    fn heartbeat_invalid_returns_dead() {
        let _guard = heartbeat_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let heartbeat = temp.path().join("daemon.heartbeat");
        fs::write(&heartbeat, "garbage\n").expect("write heartbeat");
        set_heartbeat_env(&heartbeat);
        assert!(!is_daemon_alive());
        clear_heartbeat_env();
    }
}
