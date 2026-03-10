use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wsh::audit::{AuditEntry, HEARTBEAT_PATH, SPOOL_DIR};
use wsh::denylist_update::{
    DEFAULT_DENYLIST_DIR, denylist_files_exist, download_and_write_denylists,
};

const DEFAULT_SOCKET_PATH: &str = "/var/run/warrant-shell/auditd.sock";
const DEFAULT_RELAY_SOCKET_PATH: &str = "/tmp/warrant-shell/auditd.sock";
const SYSTEM_WARRANT_PATH: &str = "/etc/warrant-shell/warrant.toml";
const SYSTEM_PUBLIC_KEY_PATH: &str = "/etc/warrant-shell/signing/public.key";
const RELAY_WARRANT_PATH: &str = "/tmp/warrant-shell/warrant.toml";
const RELAY_SIGNING_DIR: &str = "/tmp/warrant-shell/signing";
const RELAY_PUBLIC_KEY_PATH: &str = "/tmp/warrant-shell/signing/public.key";
const DEFAULT_TCP_ADDR: &str = "127.0.0.1:45873";
const DEFAULT_PID_PATH: &str = "/var/run/warrant-shell/auditd.pid";
const DEFAULT_LEDGER_DIR: &str = "/var/lib/warrant-shell/audit";
const DEFAULT_SOCKET_MODE: u32 = 0o666;
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_LINE_BYTES: usize = 1_048_576;
const MAX_MESSAGES_PER_CONNECTION: usize = 1_000;
const CLOCK_ROLLBACK_TOLERANCE_SECS: u64 = 5;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

static RUNNING: AtomicBool = AtomicBool::new(true);
static RELOAD_SIGNING_KEY: AtomicBool = AtomicBool::new(false);
static LAST_OBSERVED_EPOCH_SECS: AtomicU64 = AtomicU64::new(0);
/// Raw pointer to a leaked CString of the socket path, for async-signal-safe cleanup.
/// Written once before the main loop; the signal handler calls libc::unlink on it.
static SOCKET_PATH_PTR: std::sync::atomic::AtomicPtr<libc::c_char> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
/// Raw pointer to a leaked CString of the relay socket path for signal cleanup.
static RELAY_SOCKET_PATH_PTR: std::sync::atomic::AtomicPtr<libc::c_char> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
/// Raw pointer to a leaked CString of the pid file path, for async-signal-safe cleanup.
static PID_PATH_PTR: std::sync::atomic::AtomicPtr<libc::c_char> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
/// Raw pointer to a leaked CString of the heartbeat file path, for signal cleanup.
static HEARTBEAT_PATH_PTR: std::sync::atomic::AtomicPtr<libc::c_char> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct PeerCred {
    uid: u32,
    gid: u32,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonRequest {
    Audit { entry: AuditEntry },
    ElevationCheck { uid: u32 },
    Ping { nonce: Option<String> },
}

#[derive(Debug, Clone, Deserialize)]
struct SessionToken {
    uid: u32,
    expires_at_epoch_secs: u64,
    mac: Option<String>,
}

struct LedgerState {
    ledger_dir: PathBuf,
    current_day: Option<String>,
    current_file: Option<PathBuf>,
    prev_hash: String,
}

impl LedgerState {
    fn new(ledger_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&ledger_dir)?;
        Ok(Self {
            ledger_dir,
            current_day: None,
            current_file: None,
            prev_hash: ZERO_HASH.to_string(),
        })
    }

    fn append_entry(&mut self, entry: &AuditEntry, peer: PeerCred) -> io::Result<()> {
        let day = Utc::now().format("%Y-%m-%d").to_string();
        self.ensure_day(&day)?;

        let mut map = match serde_json::to_value(entry)? {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        map.insert("actor_uid".to_string(), Value::from(peer.uid));
        map.insert("actor_gid".to_string(), Value::from(peer.gid));
        map.insert(
            "prev_hash".to_string(),
            Value::String(self.prev_hash.clone()),
        );

        let line = serde_json::to_string(&Value::Object(map))?;
        let path = self
            .current_file
            .as_ref()
            .ok_or_else(|| io::Error::other("ledger file not initialized"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;

        self.prev_hash = sha256_hex(line.as_bytes());
        Ok(())
    }

    fn ensure_day(&mut self, day: &str) -> io::Result<()> {
        if self.current_day.as_deref() == Some(day) && self.current_file.is_some() {
            return Ok(());
        }

        let file_path = self.ledger_dir.join(format!("audit-{day}.jsonl"));
        let prev_hash = hash_of_last_line(&file_path)?.unwrap_or_else(|| ZERO_HASH.to_string());

        self.current_day = Some(day.to_string());
        self.current_file = Some(file_path);
        self.prev_hash = prev_hash;
        Ok(())
    }
}

fn hash_of_last_line(path: &Path) -> io::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut last_line: Option<String> = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last_line = Some(line);
        }
    }
    Ok(last_line.map(|line| sha256_hex(line.as_bytes())))
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn session_dir_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_SESSION_DIR") {
        return PathBuf::from(path);
    }
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/warrant-shell/sessions")
    } else {
        PathBuf::from("/run/warrant-shell")
    }
}

fn host_secret_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_HOST_SECRET_PATH") {
        return PathBuf::from(path);
    }
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/warrant-shell/host.key")
    } else {
        PathBuf::from("/var/lib/warrant-shell/hmac.key")
    }
}

fn has_basic_secret_entropy(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    !bytes.iter().all(|byte| *byte == bytes[0])
}

fn load_host_secret_if_exists(path: &Path) -> io::Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    verify_private_file_permissions(path)?;
    let text = fs::read_to_string(path)?;
    let Some(decoded) = hex_decode(text.trim()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid host secret encoding",
        ));
    };
    if decoded.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid host secret length",
        ));
    }
    if !has_basic_secret_entropy(&decoded) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host secret has insufficient entropy",
        ));
    }
    Ok(Some(decoded))
}

fn verify_mac_hex(
    secret: &[u8],
    uid: u32,
    expires_at_epoch_secs: u64,
    host_binding: &str,
    mac_hex: &str,
) -> io::Result<bool> {
    let payload = format!("{uid}:{expires_at_epoch_secs}:{host_binding}");
    let Some(provided) = hex_decode(mac_hex) else {
        return Ok(false);
    };
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hmac key"))?;
    mac.update(payload.as_bytes());
    Ok(mac.verify_slice(&provided).is_ok())
}

fn checked_now_epoch_secs() -> io::Result<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let previous = LAST_OBSERVED_EPOCH_SECS.load(Ordering::SeqCst);
    if previous > 0 && now.saturating_add(CLOCK_ROLLBACK_TOLERANCE_SECS) < previous {
        return Err(io::Error::other(
            "system clock moved backwards; refusing elevation check",
        ));
    }
    if now > previous {
        LAST_OBSERVED_EPOCH_SECS.store(now, Ordering::SeqCst);
    }
    Ok(now)
}
fn verify_private_file_permissions(path: &Path) -> io::Result<()> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "insecure permissions for {} (mode {mode:o})",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn check_elevation(uid: u32) -> io::Result<(bool, Option<u64>)> {
    let session_path = session_dir_path().join(format!("session-{uid}"));
    if !session_path.exists() {
        return Ok((false, None));
    }

    let host_secret_path = host_secret_path();
    let Some(host_secret) = load_host_secret_if_exists(&host_secret_path)? else {
        return Ok((false, None));
    };

    verify_private_file_permissions(&session_path)?;
    let raw = fs::read_to_string(&session_path)?;
    let token: SessionToken = match serde_json::from_str(&raw) {
        Ok(token) => token,
        Err(err) => {
            eprintln!(
                "wsh-auditd warning: failed to parse elevation token at {}: {err}",
                session_path.display()
            );
            return Ok((false, None));
        }
    };

    if token.uid != uid {
        return Ok((false, None));
    }
    let Some(mac_hex) = token.mac.as_deref() else {
        eprintln!(
            "wsh-auditd warning: elevation token at {} is missing mac",
            session_path.display()
        );
        return Ok((false, None));
    };
    let host_binding = warrant_core::current_host_binding();
    if !verify_mac_hex(
        &host_secret,
        token.uid,
        token.expires_at_epoch_secs,
        &host_binding,
        mac_hex,
    )? {
        eprintln!(
            "wsh-auditd warning: elevation token at {} has invalid mac",
            session_path.display()
        );
        return Ok((false, None));
    }

    let elevated = checked_now_epoch_secs()? <= token.expires_at_epoch_secs;
    if elevated {
        Ok((true, Some(token.expires_at_epoch_secs)))
    } else {
        Ok((false, Some(token.expires_at_epoch_secs)))
    }
}

fn handle_audit(
    entry: &AuditEntry,
    peer: PeerCred,
    ledger: Arc<Mutex<LedgerState>>,
) -> io::Result<Value> {
    let append_result = {
        let mut state = ledger
            .lock()
            .map_err(|_| io::Error::other("ledger lock poisoned"))?;
        state.append_entry(entry, peer)
    };

    Ok(match append_result {
        Ok(()) => json!({"status": "ok"}),
        Err(err) => json!({"status": "error", "message": err.to_string()}),
    })
}

fn ensure_spool_dir_ready() -> io::Result<()> {
    let spool_dir = Path::new(SPOOL_DIR);
    fs::create_dir_all(spool_dir)?;
    if let Err(err) = fs::set_permissions(spool_dir, fs::Permissions::from_mode(0o1733)) {
        let is_permission_like =
            err.kind() == io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(libc::EPERM);
        if !is_permission_like {
            return Err(err);
        }
    }
    Ok(())
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

fn write_heartbeat(path: &Path) -> io::Result<()> {
    let epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    writeln!(file, "{epoch_secs}")?;
    Ok(())
}

fn ingest_spool_entries(ledger: Arc<Mutex<LedgerState>>) -> io::Result<()> {
    ensure_spool_dir_ready()?;

    let mut files = Vec::new();
    for entry in fs::read_dir(SPOOL_DIR)? {
        let entry = match entry {
            Ok(value) => value,
            Err(err) => {
                eprintln!("wsh-auditd warning: failed to read spool directory entry: {err}");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "jsonl") {
            files.push(path);
        }
    }
    files.sort();

    for path in files {
        let raw = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!(
                    "wsh-auditd warning: failed to read spool file {}: {err}",
                    path.display()
                );
                continue;
            }
        };

        let entry = match serde_json::from_str::<AuditEntry>(raw.trim()) {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!(
                    "wsh-auditd warning: invalid spool entry {}: {err}",
                    path.display()
                );
                continue;
            }
        };

        let peer = match fs::metadata(&path) {
            Ok(meta) => PeerCred {
                uid: meta.uid(),
                gid: meta.gid(),
            },
            Err(err) => {
                eprintln!(
                    "wsh-auditd warning: failed to stat spool file {}: {err}",
                    path.display()
                );
                PeerCred { uid: 0, gid: 0 }
            }
        };

        let append_result = {
            let mut state = ledger
                .lock()
                .map_err(|_| io::Error::other("ledger lock poisoned"))?;
            state.append_entry(&entry, peer)
        };
        match append_result {
            Ok(()) => {
                if let Err(err) = fs::remove_file(&path) {
                    eprintln!(
                        "wsh-auditd warning: ingested spool entry but failed to delete {}: {err}",
                        path.display()
                    );
                }
            }
            Err(err) => eprintln!(
                "wsh-auditd warning: failed to append spool entry {}: {err}",
                path.display()
            ),
        }
    }

    Ok(())
}

fn handle_connection(
    mut stream: UnixStream,
    ledger: Arc<Mutex<LedgerState>>,
    signing_key: Arc<RwLock<Option<SigningKey>>>,
) -> io::Result<()> {
    // Accepted sockets can inherit nonblocking behavior from the listener.
    // Request/response handling expects blocking reads per client connection.
    stream.set_nonblocking(false)?;
    let peer = match peer_credentials(&stream) {
        Ok(peer) => peer,
        Err(err) => {
            eprintln!(
                "wsh-auditd warning: rejecting connection without verified peer credentials: {err}"
            );
            return Err(err);
        }
    };
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut message_count = 0usize;

    loop {
        if message_count >= MAX_MESSAGES_PER_CONNECTION {
            eprintln!(
                "wsh-auditd warning: dropping connection after {MAX_MESSAGES_PER_CONNECTION} messages"
            );
            break;
        }

        let mut line = String::new();
        let n = {
            let mut limited = reader.by_ref().take(MAX_LINE_BYTES as u64);
            limited.read_line(&mut line)?
        };
        if n == 0 {
            break;
        }
        if n == MAX_LINE_BYTES && !line.ends_with('\n') {
            let mut probe = [0u8; 1];
            let extra = reader.read(&mut probe)?;
            if extra > 0 && probe[0] != b'\n' {
                eprintln!(
                    "wsh-auditd warning: dropping connection due to oversized request line (>1MB)"
                );
                break;
            }
        }
        message_count += 1;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let ack = match serde_json::from_str::<DaemonRequest>(trimmed) {
            Ok(DaemonRequest::Audit { entry }) => handle_audit(&entry, peer, Arc::clone(&ledger))?,
            Ok(DaemonRequest::Ping { nonce }) => {
                if let Some(nonce) = &nonce {
                    match signing_key.read() {
                        Ok(key) => {
                            if let Some(signing_key) = key.as_ref() {
                                let sig = signing_key.sign(nonce.as_bytes());
                                let sig_hex = sig
                                    .to_bytes()
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<String>();
                                json!({"status": "ok", "sig": sig_hex})
                            } else {
                                json!({"status":"ok","sig":null,"message":"signing key not loaded yet"})
                            }
                        }
                        Err(_) => json!({"status":"error","message":"signing key lock poisoned"}),
                    }
                } else {
                    json!({"status":"ok"})
                }
            }
            Ok(DaemonRequest::ElevationCheck { uid }) => {
                if peer.uid != 0 && peer.uid != uid {
                    json!({"status":"error","message":"uid mismatch"})
                } else {
                    match check_elevation(uid) {
                        Ok((true, Some(expires_at))) => {
                            json!({"status":"ok","elevated":true,"expires_at":expires_at})
                        }
                        Ok((true, None)) => json!({"status":"ok","elevated":true}),
                        Ok((false, _)) => json!({"status":"ok","elevated":false}),
                        Err(err) => json!({"status":"error","message":err.to_string()}),
                    }
                }
            }
            Err(_) => match serde_json::from_str::<AuditEntry>(trimmed) {
                Ok(entry) => handle_audit(&entry, peer, Arc::clone(&ledger))?,
                Err(err) => {
                    json!({"status": "error", "message": format!("invalid audit entry: {err}")})
                }
            },
        };

        let mut response = serde_json::to_string(&ack)?;
        response.push('\n');
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
    }

    Ok(())
}

fn handle_tcp_connection(
    mut stream: TcpStream,
    ledger: Arc<Mutex<LedgerState>>,
    signing_key: Arc<RwLock<Option<SigningKey>>>,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut message_count = 0usize;

    loop {
        if message_count >= MAX_MESSAGES_PER_CONNECTION {
            eprintln!(
                "wsh-auditd warning: dropping tcp connection after {MAX_MESSAGES_PER_CONNECTION} messages"
            );
            break;
        }

        let mut line = String::new();
        let n = {
            let mut limited = reader.by_ref().take(MAX_LINE_BYTES as u64);
            limited.read_line(&mut line)?
        };
        if n == 0 {
            break;
        }
        if n == MAX_LINE_BYTES && !line.ends_with('\n') {
            let mut probe = [0u8; 1];
            let extra = reader.read(&mut probe)?;
            if extra > 0 && probe[0] != b'\n' {
                eprintln!(
                    "wsh-auditd warning: dropping tcp connection due to oversized request line (>1MB)"
                );
                break;
            }
        }
        message_count += 1;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let ack = match serde_json::from_str::<DaemonRequest>(trimmed) {
            Ok(DaemonRequest::Audit { entry }) => {
                // TCP fallback has no kernel peer-credential API; do not trust
                // caller-supplied identity fields.
                let peer = PeerCred { uid: 0, gid: 0 };
                handle_audit(&entry, peer, Arc::clone(&ledger))?
            }
            Ok(DaemonRequest::Ping { nonce }) => {
                if let Some(nonce) = &nonce {
                    match signing_key.read() {
                        Ok(key) => {
                            if let Some(signing_key) = key.as_ref() {
                                let sig = signing_key.sign(nonce.as_bytes());
                                let sig_hex = sig
                                    .to_bytes()
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<String>();
                                json!({"status": "ok", "sig": sig_hex})
                            } else {
                                json!({"status":"ok","sig":null,"message":"signing key not loaded yet"})
                            }
                        }
                        Err(_) => json!({"status":"error","message":"signing key lock poisoned"}),
                    }
                } else {
                    json!({"status":"ok"})
                }
            }
            Ok(DaemonRequest::ElevationCheck { .. }) => {
                json!({"status":"error","message":"elevation_check unsupported over tcp"})
            }
            Err(_) => match serde_json::from_str::<AuditEntry>(trimmed) {
                Ok(entry) => {
                    let peer = PeerCred { uid: 0, gid: 0 };
                    handle_audit(&entry, peer, Arc::clone(&ledger))?
                }
                Err(err) => {
                    json!({"status": "error", "message": format!("invalid audit entry: {err}")})
                }
            },
        };

        let mut response = serde_json::to_string(&ack)?;
        response.push('\n');
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerCred {
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCred> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { uid, gid })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn peer_credentials(_stream: &UnixStream) -> io::Result<PeerCred> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credential verification is unsupported on this platform",
    ))
}

extern "C" fn signal_handler(sig: i32) {
    if sig == libc::SIGHUP {
        RELOAD_SIGNING_KEY.store(true, Ordering::SeqCst);
        return;
    }

    RUNNING.store(false, Ordering::SeqCst);
    // Async-signal-safe socket cleanup: unlink via raw pointer (no allocations).
    // Prevents stale sockets that let clients connect to a dead daemon.
    let ptr = SOCKET_PATH_PTR.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe { libc::unlink(ptr) };
    }
    let ptr = RELAY_SOCKET_PATH_PTR.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe { libc::unlink(ptr) };
    }
    let ptr = PID_PATH_PTR.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe { libc::unlink(ptr) };
    }
    let ptr = HEARTBEAT_PATH_PTR.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe { libc::unlink(ptr) };
    }
}

fn install_signal_handlers() -> io::Result<()> {
    let handler = signal_handler as *const () as libc::sighandler_t;
    let sigterm_res = unsafe { libc::signal(libc::SIGTERM, handler) };
    if sigterm_res == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }

    let sigint_res = unsafe { libc::signal(libc::SIGINT, handler) };
    if sigint_res == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }

    let sighup_res = unsafe { libc::signal(libc::SIGHUP, handler) };
    if sighup_res == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn resolve_denylist_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_DENYLIST_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    PathBuf::from(DEFAULT_DENYLIST_DIR)
}

fn spawn_denylist_updater() {
    let denylist_dir = resolve_denylist_dir();
    thread::spawn(move || {
        if !denylist_files_exist(&denylist_dir) {
            match download_and_write_denylists(&denylist_dir) {
                Ok(summary) => {
                    eprintln!(
                        "wsh-auditd denylist bootstrap update complete: npm={}, pypi={}",
                        summary.npm_count, summary.pypi_count
                    );
                }
                Err(err) => {
                    eprintln!("wsh-auditd warning: denylist bootstrap update failed: {err}");
                }
            }
        }

        loop {
            thread::sleep(Duration::from_secs(86_400));
            match download_and_write_denylists(&denylist_dir) {
                Ok(summary) => {
                    eprintln!(
                        "wsh-auditd denylist update complete: npm={}, pypi={}",
                        summary.npm_count, summary.pypi_count
                    );
                }
                Err(err) => {
                    eprintln!("wsh-auditd warning: denylist auto-update failed: {err}");
                }
            }
        }
    });
}

fn default_signing_private_key_path() -> io::Result<PathBuf> {
    let paths = warrant_core::ToolPaths::for_tool(wsh::TOOL_NAME)
        .map_err(|err| io::Error::other(format!("failed to resolve tool paths: {err}")))?;
    Ok(paths.signing_private_key_path)
}

fn copy_file_to_relay(source: &Path, destination: &Path) -> io::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    fs::copy(source, destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn set_permissions_best_effort(path: &Path, mode: u32, label: &str) -> io::Result<()> {
    if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        let is_permission_like =
            err.kind() == io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(libc::EPERM);
        if is_permission_like {
            eprintln!(
                "wsh-auditd warning: failed to set {label} permissions on {}: {err}",
                path.display()
            );
        } else {
            return Err(err);
        }
    }
    Ok(())
}

fn sync_relay_warrant_files() {
    let warrant_source = Path::new(SYSTEM_WARRANT_PATH);
    let warrant_destination = Path::new(RELAY_WARRANT_PATH);
    if let Err(err) = copy_file_to_relay(warrant_source, warrant_destination) {
        eprintln!(
            "wsh-auditd warning: failed to copy {} to {}: {err}",
            warrant_source.display(),
            warrant_destination.display()
        );
    }

    let relay_signing_dir = Path::new(RELAY_SIGNING_DIR);
    if let Err(err) = fs::create_dir_all(relay_signing_dir) {
        eprintln!(
            "wsh-auditd warning: failed to create relay signing directory {}: {err}",
            relay_signing_dir.display()
        );
    } else if let Err(err) =
        fs::set_permissions(relay_signing_dir, fs::Permissions::from_mode(0o755))
    {
        eprintln!(
            "wsh-auditd warning: failed to set permissions on relay signing directory {}: {err}",
            relay_signing_dir.display()
        );
    }

    let public_key_source = Path::new(SYSTEM_PUBLIC_KEY_PATH);
    let public_key_destination = Path::new(RELAY_PUBLIC_KEY_PATH);
    if let Err(err) = copy_file_to_relay(public_key_source, public_key_destination) {
        eprintln!(
            "wsh-auditd warning: failed to copy {} to {}: {err}",
            public_key_source.display(),
            public_key_destination.display()
        );
    }
}

fn run() -> io::Result<()> {
    install_signal_handlers()?;

    let socket_path = daemon_socket_path();
    let relay_socket_path = daemon_relay_socket_path();
    let tcp_addr = daemon_tcp_addr();
    let socket_mode = daemon_socket_mode();
    let relay_socket_mode = daemon_relay_socket_mode();
    let pid_path = daemon_pid_path();
    let ledger_dir = daemon_ledger_dir();
    let heartbeat_path = daemon_heartbeat_path();

    // Store socket path as a leaked CString for async-signal-safe cleanup on SIGTERM.
    if let Ok(cstr) = std::ffi::CString::new(socket_path.to_string_lossy().as_bytes().to_vec()) {
        let leaked = cstr.into_raw();
        SOCKET_PATH_PTR.store(leaked, Ordering::SeqCst);
    }
    let relay_enabled = relay_socket_path != socket_path;
    if relay_enabled
        && let Ok(cstr) =
            std::ffi::CString::new(relay_socket_path.to_string_lossy().as_bytes().to_vec())
    {
        let leaked = cstr.into_raw();
        RELAY_SOCKET_PATH_PTR.store(leaked, Ordering::SeqCst);
    }
    if let Ok(cstr) = std::ffi::CString::new(pid_path.to_string_lossy().as_bytes().to_vec()) {
        let leaked = cstr.into_raw();
        PID_PATH_PTR.store(leaked, Ordering::SeqCst);
    }
    if let Ok(cstr) = std::ffi::CString::new(heartbeat_path.to_string_lossy().as_bytes().to_vec()) {
        let leaked = cstr.into_raw();
        HEARTBEAT_PATH_PTR.store(leaked, Ordering::SeqCst);
    }

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if relay_enabled
        && let Some(parent) = relay_socket_path.parent()
    {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = heartbeat_path.parent() {
        fs::create_dir_all(parent)?;
    }
    ensure_spool_dir_ready()?;

    match fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    if relay_enabled {
        match fs::remove_file(&relay_socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    match fs::remove_file(&pid_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    match fs::remove_file(&heartbeat_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let listener = UnixListener::bind(&socket_path)?;
    let relay_listener = if relay_enabled {
        Some(UnixListener::bind(&relay_socket_path)?)
    } else {
        None
    };
    let tcp_listener = if let Some(addr) = tcp_addr.as_deref() {
        Some(TcpListener::bind(addr)?)
    } else {
        None
    };
    fs::write(&pid_path, format!("{}\n", std::process::id()))?;
    set_permissions_best_effort(&pid_path, 0o644, "pid file")?;
    if let Err(err) = write_heartbeat(&heartbeat_path) {
        eprintln!(
            "wsh-auditd warning: failed to write heartbeat {}: {err}",
            heartbeat_path.display()
        );
    }

    set_permissions_best_effort(&socket_path, socket_mode, "socket")?;
    if relay_enabled {
        set_permissions_best_effort(&relay_socket_path, relay_socket_mode, "relay socket")?;
    }

    listener.set_nonblocking(true)?;
    if let Some(relay_listener) = relay_listener.as_ref() {
        relay_listener.set_nonblocking(true)?;
    }
    if let Some(tcp_listener) = tcp_listener.as_ref() {
        tcp_listener.set_nonblocking(true)?;
    }

    sync_relay_warrant_files();

    eprintln!("wsh-auditd listening on {}", socket_path.display());
    if relay_enabled {
        eprintln!(
            "wsh-auditd relay listening on {}",
            relay_socket_path.display()
        );
    }
    if let Some(addr) = tcp_addr.as_deref() {
        eprintln!("wsh-auditd tcp listening on {addr}");
    }

    let ledger = Arc::new(Mutex::new(LedgerState::new(ledger_dir)?));

    // Signing key is optional at startup. It may be created later by `wsh lock`,
    // which then triggers a SIGHUP reload.
    let signing_key_path = if let Some(path) = std::env::var_os("WSH_SIGNING_PRIVATE_KEY") {
        PathBuf::from(path)
    } else {
        default_signing_private_key_path()?
    };
    let initial_signing_key = if signing_key_path.exists() {
        let loaded = warrant_core::read_signing_key(&signing_key_path).map_err(|err| {
            io::Error::other(format!(
                "failed to load signing key {}: {err}",
                signing_key_path.display()
            ))
        })?;
        eprintln!("wsh-auditd: loaded signing key for authenticated pings");
        Some(loaded)
    } else {
        eprintln!(
            "wsh-auditd warning: signing key {} not found at startup; authenticated ping unavailable until SIGHUP reload",
            signing_key_path.display()
        );
        None
    };
    let signing_key = Arc::new(RwLock::new(initial_signing_key));

    spawn_denylist_updater();
    let active_connections = Arc::new(AtomicUsize::new(0));
    let mut last_spool_check = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);

    while RUNNING.load(Ordering::SeqCst) {
        if RELOAD_SIGNING_KEY.swap(false, Ordering::SeqCst) {
            match warrant_core::read_signing_key(&signing_key_path) {
                Ok(reloaded) => {
                    if let Ok(mut guard) = signing_key.write() {
                        *guard = Some(reloaded);
                        eprintln!("wsh-auditd: reloaded signing key");
                    } else {
                        eprintln!(
                            "wsh-auditd warning: failed to reload signing key: lock poisoned"
                        );
                    }
                }
                Err(err) => eprintln!("wsh-auditd warning: failed to reload signing key: {err}"),
            }
            sync_relay_warrant_files();
            if let Err(err) = ingest_spool_entries(Arc::clone(&ledger)) {
                eprintln!("wsh-auditd warning: spool ingestion failed after SIGHUP: {err}");
            }
            last_spool_check = Instant::now();
        }

        if last_spool_check.elapsed() >= Duration::from_secs(1) {
            if let Err(err) = ingest_spool_entries(Arc::clone(&ledger)) {
                eprintln!("wsh-auditd warning: spool ingestion failed: {err}");
            }
            last_spool_check = Instant::now();
        }

        let mut accepted_any = false;
        let mut listeners = vec![&listener];
        if let Some(relay_listener) = relay_listener.as_ref() {
            listeners.push(relay_listener);
        }
        for current_listener in listeners {
            match current_listener.accept() {
                Ok((stream, _addr)) => {
                    accepted_any = true;
                    if active_connections.load(Ordering::SeqCst) >= MAX_ACTIVE_CONNECTIONS {
                        eprintln!(
                            "wsh-auditd warning: refusing connection (active limit {MAX_ACTIVE_CONNECTIONS} reached)"
                        );
                        continue;
                    }
                    let ledger = Arc::clone(&ledger);
                    let signing_key = Arc::clone(&signing_key);
                    let active_connections = Arc::clone(&active_connections);
                    active_connections.fetch_add(1, Ordering::SeqCst);
                    thread::spawn(move || {
                        if let Err(err) = handle_connection(stream, ledger, signing_key) {
                            eprintln!("wsh-auditd connection error: {err}");
                        }
                        active_connections.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    eprintln!("wsh-auditd accept error: {err}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        if let Some(tcp_listener) = tcp_listener.as_ref() {
            loop {
                match tcp_listener.accept() {
                    Ok((stream, _addr)) => {
                        accepted_any = true;
                        if active_connections.load(Ordering::SeqCst) >= MAX_ACTIVE_CONNECTIONS {
                            eprintln!(
                                "wsh-auditd warning: refusing tcp connection (active limit {MAX_ACTIVE_CONNECTIONS} reached)"
                            );
                            continue;
                        }
                        let ledger = Arc::clone(&ledger);
                        let signing_key = Arc::clone(&signing_key);
                        let active_connections = Arc::clone(&active_connections);
                        active_connections.fetch_add(1, Ordering::SeqCst);
                        thread::spawn(move || {
                            if let Err(err) = handle_tcp_connection(stream, ledger, signing_key) {
                                eprintln!("wsh-auditd tcp connection error: {err}");
                            }
                            active_connections.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        eprintln!("wsh-auditd tcp accept error: {err}");
                        thread::sleep(Duration::from_millis(100));
                        break;
                    }
                }
            }
        }
        if let Err(err) = write_heartbeat(&heartbeat_path) {
            eprintln!(
                "wsh-auditd warning: failed to write heartbeat {}: {err}",
                heartbeat_path.display()
            );
        }
        if !accepted_any {
            thread::sleep(Duration::from_millis(50));
        }
    }
    drop(listener);
    drop(relay_listener);
    drop(tcp_listener);

    match fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => eprintln!("wsh-auditd cleanup error: {err}"),
    }
    if relay_enabled {
        match fs::remove_file(&relay_socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => eprintln!("wsh-auditd cleanup error: {err}"),
        }
    }
    match fs::remove_file(&pid_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => eprintln!("wsh-auditd cleanup error: {err}"),
    }
    match fs::remove_file(&heartbeat_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => eprintln!("wsh-auditd cleanup error: {err}"),
    }

    Ok(())
}

fn daemon_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_AUDITD_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

fn daemon_relay_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_AUDITD_RELAY_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    #[cfg(test)]
    if let Some(primary) = std::env::var_os("WSH_AUDITD_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        && let Some(parent) = primary.parent()
    {
        return parent.join("auditd-relay.sock");
    }
    PathBuf::from(DEFAULT_RELAY_SOCKET_PATH)
}

fn daemon_tcp_addr() -> Option<String> {
    match std::env::var_os("WSH_AUDITD_TCP_ADDR") {
        Some(raw) => {
            let value = raw.to_string_lossy().trim().to_string();
            if value.is_empty() { None } else { Some(value) }
        }
        None => Some(DEFAULT_TCP_ADDR.to_string()),
    }
}

fn daemon_pid_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_AUDITD_PID_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    PathBuf::from(DEFAULT_PID_PATH)
}

fn daemon_socket_mode() -> u32 {
    const ALLOWED_MODES: [u32; 4] = [0o600, 0o660, 0o666, 0o700];
    let Some(raw) = std::env::var_os("WSH_AUDITD_SOCKET_MODE") else {
        return DEFAULT_SOCKET_MODE;
    };
    let value = raw.to_string_lossy().trim().to_string();
    if value.is_empty() {
        return DEFAULT_SOCKET_MODE;
    }

    let trimmed = value.strip_prefix("0o").unwrap_or(&value);
    let trimmed = if trimmed.len() > 1 && trimmed.starts_with('0') {
        &trimmed[1..]
    } else {
        trimmed
    };

    match u32::from_str_radix(trimmed, 8) {
        Ok(mode) if ALLOWED_MODES.contains(&mode) => mode,
        _ => {
            eprintln!(
                "wsh-auditd warning: invalid WSH_AUDITD_SOCKET_MODE='{}'; using default {:o}",
                value, DEFAULT_SOCKET_MODE
            );
            DEFAULT_SOCKET_MODE
        }
    }
}

fn daemon_relay_socket_mode() -> u32 {
    const ALLOWED_MODES: [u32; 4] = [0o600, 0o660, 0o666, 0o700];
    let Some(raw) = std::env::var_os("WSH_AUDITD_RELAY_SOCKET_MODE") else {
        return DEFAULT_SOCKET_MODE;
    };
    let value = raw.to_string_lossy().trim().to_string();
    if value.is_empty() {
        return DEFAULT_SOCKET_MODE;
    }

    let trimmed = value.strip_prefix("0o").unwrap_or(&value);
    let trimmed = if trimmed.len() > 1 && trimmed.starts_with('0') {
        &trimmed[1..]
    } else {
        trimmed
    };

    match u32::from_str_radix(trimmed, 8) {
        Ok(mode) if ALLOWED_MODES.contains(&mode) => mode,
        _ => {
            eprintln!(
                "wsh-auditd warning: invalid WSH_AUDITD_RELAY_SOCKET_MODE='{}'; using default {:o}",
                value, DEFAULT_SOCKET_MODE
            );
            DEFAULT_SOCKET_MODE
        }
    }
}

fn daemon_ledger_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("WSH_AUDITD_LEDGER_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return path;
    }
    PathBuf::from(DEFAULT_LEDGER_DIR)
}

fn main() {
    // Note: wsh-auditd intentionally does NOT call scrub_wsh_env_vars().
    // The daemon is a privileged process started by root/systemd, not an
    // agent-facing CLI. It needs WSH_AUDITD_* env vars for testing and
    // deployment flexibility. The scrub is a security measure for the wsh
    // CLI binary to prevent agents from manipulating env-based overrides.
    if let Err(err) = run() {
        eprintln!("wsh-auditd error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{HmacSha256, default_signing_private_key_path, verify_mac_hex};
    use hmac::Mac;

    fn compute_mac_hex(
        secret: &[u8],
        uid: u32,
        expires_at_epoch_secs: u64,
        host_binding: &str,
    ) -> String {
        let payload = format!("{uid}:{expires_at_epoch_secs}:{host_binding}");
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
        mac.update(payload.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn default_signing_key_path_matches_warrant_core_paths() {
        let expected = warrant_core::ToolPaths::for_tool(wsh::TOOL_NAME)
            .expect("tool paths")
            .signing_private_key_path;
        assert_eq!(
            default_signing_private_key_path().expect("default path"),
            expected
        );
    }

    #[test]
    fn verify_mac_hex_accepts_host_bound_payload() {
        let secret = [7u8; 32];
        let uid = 1000;
        let expires_at_epoch_secs = 1_900_000_000;
        let host_binding = "host-A";
        let mac_hex = compute_mac_hex(&secret, uid, expires_at_epoch_secs, host_binding);
        assert!(
            verify_mac_hex(&secret, uid, expires_at_epoch_secs, host_binding, &mac_hex)
                .expect("verify")
        );
    }

    #[test]
    fn verify_mac_hex_rejects_wrong_host_binding() {
        let secret = [9u8; 32];
        let uid = 1000;
        let expires_at_epoch_secs = 1_900_000_000;
        let mac_hex = compute_mac_hex(&secret, uid, expires_at_epoch_secs, "host-A");
        assert!(
            !verify_mac_hex(&secret, uid, expires_at_epoch_secs, "host-B", &mac_hex)
                .expect("verify")
        );
    }
}
