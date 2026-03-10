use std::fs;
use std::io;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use ed25519_dalek::{Signature, SigningKey, Verifier};
#[cfg(unix)]
use hmac::{Hmac, Mac};
use serde_json::Value;
#[cfg(unix)]
use warrant_core::current_host_binding;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use wsh::audit::{AuditEntry, AuditSink, DaemonSink, Decision, verify_ledger};
#[cfg(unix)]
type HmacSha256 = Hmac<Sha256>;

#[cfg(unix)]
fn start_daemon(socket_path: &Path, ledger_dir: &Path, pid_path: &Path) -> io::Result<Child> {
    start_daemon_with_signing_key(socket_path, ledger_dir, pid_path, None)
}

#[cfg(unix)]
fn start_daemon_with_signing_key(
    socket_path: &Path,
    ledger_dir: &Path,
    pid_path: &Path,
    signing_key_path: Option<&Path>,
) -> io::Result<Child> {
    let bin_path = assert_cmd::cargo::cargo_bin!("wsh-auditd");
    let mut command = Command::new(bin_path);
    let relay_socket_path = socket_path
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .join("auditd-relay.sock");
    command
        .env("WSH_AUDITD_SOCKET", socket_path)
        .env("WSH_AUDITD_RELAY_SOCKET", relay_socket_path)
        .env("WSH_AUDITD_TCP_ADDR", "")
        .env("WSH_AUDITD_LEDGER_DIR", ledger_dir)
        .env("WSH_AUDITD_PID_FILE", pid_path);
    if let Some(path) = signing_key_path {
        command.env("WSH_SIGNING_PRIVATE_KEY", path);
    } else {
        // Point at a non-existent path inside the temp dir so the daemon
        // does not try to read the system signing key (which may exist but
        // be unreadable by the test user).
        let fallback = socket_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("signing/private.key");
        command.env("WSH_SIGNING_PRIVATE_KEY", fallback);
    }
    command.spawn()
}

fn wait_for_socket(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("daemon socket did not appear: {}", path.display()),
    ))
}

fn wait_for_file(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("file did not appear: {}", path.display()),
    ))
}

fn wait_for_absence(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("path still exists: {}", path.display()),
    ))
}

fn ledger_file_path(ledger_dir: &Path) -> io::Result<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(ledger_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("audit-") && name.ends_with(".jsonl"))
            .unwrap_or(false)
        {
            files.push(path);
        }
    }

    if files.len() != 1 {
        return Err(io::Error::other(format!(
            "expected exactly one ledger file, found {}",
            files.len()
        )));
    }
    Ok(files.remove(0))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn write_valid_ledger(path: &Path, entries: &[Value]) -> io::Result<()> {
    let mut lines = Vec::new();
    let mut prev_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for entry in entries {
        let mut map = entry
            .as_object()
            .cloned()
            .ok_or_else(|| io::Error::other("entry is not an object"))?;
        map.insert("prev_hash".to_string(), Value::String(prev_hash.clone()));
        let line = serde_json::to_string(&Value::Object(map))?;
        prev_hash = sha256_hex(&line);
        lines.push(line);
    }

    fs::write(path, format!("{}\n", lines.join("\n")))?;
    Ok(())
}

#[cfg(unix)]
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write file");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).expect("chmod");
}

#[cfg(unix)]
fn write_session_token(session_dir: &Path, host_secret: &[u8], uid: u32, expires_at: u64) {
    fs::create_dir_all(session_dir).expect("mkdir sessions");
    let host_binding = current_host_binding();
    let payload = format!("{uid}:{expires_at}:{host_binding}");
    let mut mac = HmacSha256::new_from_slice(host_secret).expect("hmac");
    mac.update(payload.as_bytes());
    let mac_hex = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let token = json!({
        "uid": uid,
        "created_at_epoch_secs": now_epoch_secs(),
        "expires_at_epoch_secs": expires_at,
        "mac": mac_hex,
    });
    let token_path = session_dir.join(format!("session-{uid}"));
    write_private_file(
        &token_path,
        &serde_json::to_string_pretty(&token).expect("serialize token"),
    );
}

#[cfg(unix)]
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() >= 2 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() == 3 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(unix)]
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks_exact(2) {
        let high = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => chunk[0] - b'a' + 10,
            b'A'..=b'F' => chunk[0] - b'A' + 10,
            _ => return None,
        };
        let low = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => chunk[1] - b'a' + 10,
            b'A'..=b'F' => chunk[1] - b'A' + 10,
            _ => return None,
        };
        out.push((high << 4) | low);
    }
    Some(out)
}

#[cfg(unix)]
fn request_elevation(socket_path: &Path, uid: u32) -> Value {
    let mut stream = UnixStream::connect(socket_path).expect("connect daemon");
    let request = json!({"type":"elevation_check","uid":uid});
    serde_json::to_writer(&mut stream, &request).expect("write request");
    stream.write_all(b"\n").expect("write newline");
    stream.flush().expect("flush");

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    let n = reader.read_line(&mut response).expect("read response");
    assert!(n > 0, "daemon returned no response");
    serde_json::from_str(response.trim()).expect("parse response")
}

#[cfg(unix)]
fn stop_daemon(child: &mut Child) -> io::Result<()> {
    let pid = child.id() as i32;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }

    child.kill()?;
    let _ = child.wait();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "daemon did not terminate after SIGTERM",
    ))
}

#[cfg(unix)]
#[test]
fn daemon_sink_writes_ledger_with_hash_chain() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp.path().join("auditd.sock");
    let ledger_dir = temp.path().join("ledger");
    let pid_path = temp.path().join("auditd.pid");

    let mut child = start_daemon(&socket_path, &ledger_dir, &pid_path).expect("start daemon");
    wait_for_socket(&socket_path).expect("socket ready");

    let sink = DaemonSink::new(socket_path.clone());
    let entry1 = AuditEntry {
        timestamp: "2026-02-20T10:00:00Z".to_string(),
        profile: Some("default".to_string()),
        decision: Decision::Allow,
        command: vec!["echo".to_string(), "one".to_string()],
        program: "echo".to_string(),
        resolved_program: Some("/bin/echo".to_string()),
        reason: "policy_check_passed".to_string(),
        policy_hash: Some("abc123".to_string()),
        session_id: Some("session-1".to_string()),
        elevated: false,
        stripped_env_var_count: Some(0),
    };
    let entry2 = AuditEntry {
        timestamp: "2026-02-20T10:00:01Z".to_string(),
        profile: Some("default".to_string()),
        decision: Decision::Deny,
        command: vec!["rm".to_string(), "-rf".to_string(), "/".to_string()],
        program: "rm".to_string(),
        resolved_program: Some("/bin/rm".to_string()),
        reason: "blocked pattern".to_string(),
        policy_hash: Some("def456".to_string()),
        session_id: Some("session-2".to_string()),
        elevated: false,
        stripped_env_var_count: None,
    };

    sink.log(&entry1).expect("write first entry");
    sink.log(&entry2).expect("write second entry");

    thread::sleep(Duration::from_millis(100));

    let ledger_file = ledger_file_path(&ledger_dir).expect("ledger file");
    let text = fs::read_to_string(&ledger_file).expect("read ledger");
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "expected 2 ledger lines in {ledger_file:?}");

    let first: Value = serde_json::from_str(lines[0]).expect("first json");
    let second: Value = serde_json::from_str(lines[1]).expect("second json");

    let zero_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(first["prev_hash"], zero_hash);
    assert_eq!(first["program"], "echo");
    assert!(first.get("actor_uid").is_some());
    assert!(first.get("actor_gid").is_some());

    let first_line_hash = sha256_hex(lines[0]);
    assert_eq!(second["prev_hash"], first_line_hash);
    assert_eq!(second["program"], "rm");

    stop_daemon(&mut child).expect("stop daemon");
}

#[cfg(unix)]
#[test]
fn daemon_elevation_check_reports_valid_and_expired_sessions() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp.path().join("auditd.sock");
    let ledger_dir = temp.path().join("ledger");
    let pid_path = temp.path().join("auditd.pid");
    let session_dir = temp.path().join("sessions");
    let host_secret_path = temp.path().join("host.key");
    let uid = unsafe { libc::geteuid() };
    let host_secret = [
        0x10_u8, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c,
        0x2d, 0x1e, 0x0f,
    ];
    let host_secret_hex = host_secret
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    write_private_file(&host_secret_path, &host_secret_hex);

    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("wsh-auditd"))
        .env("WSH_AUDITD_SOCKET", &socket_path)
        .env(
            "WSH_AUDITD_RELAY_SOCKET",
            socket_path
                .parent()
                .unwrap_or_else(|| Path::new("/tmp"))
                .join("auditd-relay.sock"),
        )
        .env("WSH_AUDITD_LEDGER_DIR", &ledger_dir)
        .env("WSH_AUDITD_PID_FILE", &pid_path)
        .env("WSH_AUDITD_TCP_ADDR", "")
        .env("WSH_SESSION_DIR", &session_dir)
        .env("WSH_HOST_SECRET_PATH", &host_secret_path)
        .env("WSH_SIGNING_PRIVATE_KEY", temp.path().join("signing/private.key"))
        .spawn()
        .expect("start daemon");
    wait_for_socket(&socket_path).expect("socket ready");

    let expires_future = now_epoch_secs().saturating_add(60);
    write_session_token(&session_dir, &host_secret, uid, expires_future);
    let active = request_elevation(&socket_path, uid);
    assert_eq!(active["status"], "ok");
    assert_eq!(active["elevated"], true);
    assert_eq!(active["expires_at"], expires_future);

    let expires_past = now_epoch_secs().saturating_sub(60);
    write_session_token(&session_dir, &host_secret, uid, expires_past);
    let expired = request_elevation(&socket_path, uid);
    assert_eq!(expired["status"], "ok");
    assert_eq!(expired["elevated"], false);

    stop_daemon(&mut child).expect("stop daemon");
}

#[cfg(unix)]
#[test]
fn daemon_writes_and_cleans_pid_file() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp.path().join("auditd.sock");
    let ledger_dir = temp.path().join("ledger");
    let pid_path = temp.path().join("auditd.pid");

    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("wsh-auditd"))
        .env("WSH_AUDITD_SOCKET", &socket_path)
        .env(
            "WSH_AUDITD_RELAY_SOCKET",
            socket_path
                .parent()
                .unwrap_or_else(|| Path::new("/tmp"))
                .join("auditd-relay.sock"),
        )
        .env("WSH_AUDITD_LEDGER_DIR", &ledger_dir)
        .env("WSH_AUDITD_PID_FILE", &pid_path)
        .env("WSH_AUDITD_TCP_ADDR", "")
        .env("WSH_SIGNING_PRIVATE_KEY", temp.path().join("signing/private.key"))
        .spawn()
        .expect("start daemon");

    wait_for_socket(&socket_path).expect("socket ready");
    wait_for_file(&pid_path).expect("pid file ready");
    let pid_text = fs::read_to_string(&pid_path).expect("read pid file");
    let pid = pid_text.trim().parse::<u32>().expect("pid parse");
    assert_eq!(pid, child.id(), "pid file should match daemon pid");

    stop_daemon(&mut child).expect("stop daemon");
    wait_for_absence(&pid_path).expect("pid file removed on shutdown");
    wait_for_absence(&socket_path).expect("socket removed on shutdown");
}

#[cfg(unix)]
#[test]
fn daemon_lazy_loads_signing_key_after_lock() {
    let temp = TempDir::new().expect("tempdir");
    let socket_path = temp.path().join("auditd.sock");
    let ledger_dir = temp.path().join("ledger");
    let pid_path = temp.path().join("auditd.pid");
    let signing_key_path = temp.path().join("signing/private.key");

    let mut child = start_daemon_with_signing_key(
        &socket_path,
        &ledger_dir,
        &pid_path,
        Some(&signing_key_path),
    )
    .expect("start daemon");
    wait_for_socket(&socket_path).expect("socket ready");

    let mut stream = UnixStream::connect(&socket_path).expect("connect daemon");
    let reader_stream = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(reader_stream);

    serde_json::to_writer(&mut stream, &json!({"type":"ping","nonce":"test-nonce-1"}))
        .expect("write first ping");
    stream.write_all(b"\n").expect("write newline");
    stream.flush().expect("flush first ping");

    let mut response = String::new();
    let bytes = reader
        .read_line(&mut response)
        .expect("read first response");
    assert!(bytes > 0, "daemon returned no first response");
    let first: Value = serde_json::from_str(response.trim()).expect("parse first response");
    assert_eq!(first["status"], "ok");
    assert!(
        first["sig"].is_null(),
        "expected null sig in ping response before key exists"
    );

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let encoded = base64_encode(&signing_key.to_bytes());
    fs::create_dir_all(
        signing_key_path
            .parent()
            .expect("signing key path should have parent"),
    )
    .expect("create signing key parent");
    write_private_file(&signing_key_path, &encoded);

    let pid = child.id() as i32;
    let hup_rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(hup_rc, 0, "failed to send SIGHUP: {}", io::Error::last_os_error());
    thread::sleep(Duration::from_millis(100));

    serde_json::to_writer(&mut stream, &json!({"type":"ping","nonce":"test-nonce-2"}))
        .expect("write second ping");
    stream.write_all(b"\n").expect("write newline");
    stream.flush().expect("flush second ping");

    response.clear();
    let bytes = reader
        .read_line(&mut response)
        .expect("read second response");
    assert!(bytes > 0, "daemon returned no second response");
    let second: Value = serde_json::from_str(response.trim()).expect("parse second response");
    assert_eq!(second["status"], "ok");
    let sig_hex = second["sig"].as_str().expect("expected sig field");
    let sig_bytes = hex_decode(sig_hex).expect("sig should be valid hex");
    let signature = Signature::from_slice(&sig_bytes).expect("sig should be 64-byte Ed25519");
    signing_key
        .verifying_key()
        .verify(b"test-nonce-2", &signature)
        .expect("signature should verify");

    drop(reader);
    drop(stream);
    stop_daemon(&mut child).expect("stop daemon");
}

#[test]
fn verify_ledger_passes_for_valid_chain() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("audit-2026-02-20.jsonl");

    write_valid_ledger(
        &ledger,
        &[
            json!({"program":"echo","reason":"ok","actor_uid":0,"actor_gid":0}),
            json!({"program":"ls","reason":"ok","actor_uid":0,"actor_gid":0}),
            json!({"program":"cat","reason":"ok","actor_uid":0,"actor_gid":0}),
        ],
    )
    .expect("write ledger");

    let result = verify_ledger(&ledger).expect("verify");
    assert!(result.valid);
    assert_eq!(result.total_entries, 3);
    assert!(result.failure.is_none());
}

#[test]
fn verify_ledger_detects_tampered_middle_entry() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("audit-2026-02-20.jsonl");

    write_valid_ledger(
        &ledger,
        &[
            json!({"program":"echo","reason":"ok","actor_uid":0,"actor_gid":0}),
            json!({"program":"ls","reason":"ok","actor_uid":0,"actor_gid":0}),
            json!({"program":"cat","reason":"ok","actor_uid":0,"actor_gid":0}),
        ],
    )
    .expect("write ledger");

    let text = fs::read_to_string(&ledger).expect("read ledger");
    let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
    let mut middle: Value = serde_json::from_str(&lines[1]).expect("middle json");
    middle["reason"] = Value::String("tampered".to_string());
    lines[1] = serde_json::to_string(&middle).expect("serialize tampered");
    fs::write(&ledger, format!("{}\n", lines.join("\n"))).expect("rewrite ledger");

    let result = verify_ledger(&ledger).expect("verify");
    assert!(!result.valid);
    assert_eq!(result.total_entries, 2);
    let failure = result.failure.expect("failure");
    assert_eq!(failure.line_number, 3);
    assert_eq!(failure.details, "prev_hash mismatch");
}

#[test]
fn verify_ledger_empty_file_is_valid() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("audit-empty.jsonl");
    fs::write(&ledger, "").expect("write empty file");

    let result = verify_ledger(&ledger).expect("verify");
    assert!(result.valid);
    assert_eq!(result.total_entries, 0);
    assert!(result.failure.is_none());
}

#[test]
fn verify_ledger_single_entry_zero_hash_is_valid() {
    let temp = TempDir::new().expect("tempdir");
    let ledger = temp.path().join("audit-single.jsonl");
    write_valid_ledger(
        &ledger,
        &[json!({"program":"echo","reason":"ok","actor_uid":0,"actor_gid":0})],
    )
    .expect("write ledger");

    let result = verify_ledger(&ledger).expect("verify");
    assert!(result.valid);
    assert_eq!(result.total_entries, 1);
    assert!(result.failure.is_none());
}
