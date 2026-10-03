//! End-to-end integration tests for the `igrisd` IPC boundary.
//!
//! Each test binds a fresh daemon on a private socket and a private audit log
//! under a unique temporary directory, so tests never touch the user's real
//! socket or log and can run in parallel.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use igris_permd::Policy;
use igris_proto::{read_frame, write_frame, ReadFrame, Response, MAX_REQUEST_SIZE};
use igrisd::config::Config;
use igrisd::server::Server;

/// A running test daemon with its paths.
struct TestDaemon {
    socket_path: PathBuf,
    audit_path: PathBuf,
    dir: PathBuf,
    fs_root: PathBuf,
    server: Arc<Server>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestDaemon {
    fn start(policy: Policy) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("igrisd-it-{}-{unique}", std::process::id()));
        let socket_path = dir.join("igrisd.sock");
        let audit_path = dir.join("audit.log");
        let fs_root = dir.join("root");
        std::fs::create_dir_all(&fs_root).expect("create fs root");

        // Populate the filesystem root with fixture data.
        std::fs::write(fs_root.join("hello.txt"), b"hello igris").expect("write fixture");
        std::fs::create_dir(fs_root.join("subdir")).expect("mkdir fixture");
        std::fs::write(fs_root.join("big.bin"), vec![b'z'; 4096]).expect("write fixture");
        for i in 0..20 {
            std::fs::write(fs_root.join(format!("entry{i:02}.txt")), b"x").expect("write fixture");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(fs_root.join("hello.txt"), fs_root.join("inner-link.txt"))
                .expect("inner symlink");
            std::os::unix::fs::symlink("/etc/hostname", fs_root.join("escape-link.txt"))
                .expect("escape symlink");
        }

        let config = Config::with_fs_root(&socket_path, &audit_path, &fs_root);
        let server = Arc::new(Server::bind(&config, policy).expect("bind test server"));

        let runner = server.clone();
        let handle = thread::spawn(move || {
            let _ = runner.run();
        });

        // Wait for the socket to accept a connection.
        for _ in 0..200 {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        Self {
            socket_path,
            audit_path,
            dir,
            fs_root,
            server,
            handle: Some(handle),
        }
    }

    /// Call an fs operation with the given params JSON fragment.
    fn fs_call(&self, op: &str, id: &str, params: serde_json::Value) -> Response {
        let payload = serde_json::json!({
            "version": 1,
            "id": id,
            "op": op,
            "params": params,
        });
        self.raw_exchange(payload.to_string().as_bytes())
    }

    fn fs_path(&self, rel: &str) -> String {
        self.fs_root.join(rel).to_string_lossy().into_owned()
    }

    /// Connect and send raw bytes (already framed or not).
    fn raw_exchange(&self, payload: &[u8]) -> Response {
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect");
        write_frame(&mut stream, payload).expect("write frame");
        match read_frame(&mut stream, MAX_REQUEST_SIZE).expect("read frame") {
            ReadFrame::Received(bytes) => serde_json::from_slice(&bytes).expect("parse response"),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    fn call(&self, op: &str, id: &str) -> Response {
        let payload = serde_json::json!({
            "version": 1,
            "id": id,
            "op": op,
            "params": {},
        });
        self.raw_exchange(payload.to_string().as_bytes())
    }

    fn audit_lines(&self) -> Vec<serde_json::Value> {
        let Ok(contents) = std::fs::read_to_string(&self.audit_path) else {
            return Vec::new();
        };
        contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("audit line is valid json"))
            .collect()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.server.shutdown();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn milestone_one() -> Policy {
    Policy::milestone_one()
}

fn milestone_two() -> Policy {
    Policy::milestone_two()
}

#[test]
fn valid_system_info_succeeds() {
    let daemon = TestDaemon::start(milestone_one());
    let response = daemon.call("system.info", "req-ok");

    assert!(response.ok, "expected success, got {response:?}");
    assert_eq!(response.id.as_deref(), Some("req-ok"));
    let result = response.result.expect("result present");
    assert!(result.get("hostname").is_some());
    assert!(result.get("kernel_release").is_some());
    assert!(result.get("architecture").is_some());
    assert!(result.get("uptime_seconds").is_some());
    assert!(result["memory"]["total_kb"].as_u64().unwrap_or(0) > 0);

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1, "one audit record per request");
    assert_eq!(audit[0]["operation"], "system.info");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
    assert_eq!(audit[0]["request_id"], "req-ok");
}

#[test]
fn malformed_json_is_rejected() {
    let daemon = TestDaemon::start(milestone_one());
    let response = daemon.raw_exchange(b"{ this is not json");

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn missing_fields_are_rejected() {
    let daemon = TestDaemon::start(milestone_one());
    let payload = serde_json::json!({ "version": 1, "op": "system.info", "params": {} });
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
}

#[test]
fn unknown_operation_is_rejected() {
    let daemon = TestDaemon::start(milestone_one());
    let response = daemon.call("system.exec", "req-unknown");

    assert!(!response.ok);
    assert_eq!(response.id.as_deref(), Some("req-unknown"));
    assert_eq!(response.error.expect("error").code, "UNKNOWN_OPERATION");
}

#[test]
fn unsupported_version_is_rejected() {
    let daemon = TestDaemon::start(milestone_one());
    let payload = serde_json::json!({
        "version": 999, "id": "req-v", "op": "system.info", "params": {}
    });
    let response = daemon.raw_exchange(payload.to_string().as_bytes());
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "UNSUPPORTED_VERSION");
}

#[test]
fn oversized_request_is_rejected_deterministically() {
    let daemon = TestDaemon::start(milestone_one());
    let mut stream = UnixStream::connect(&daemon.socket_path).expect("connect");
    // Declare a body larger than the maximum, then send nothing more.
    let declared = (MAX_REQUEST_SIZE as u32) + 1;
    stream
        .write_all(&declared.to_be_bytes())
        .expect("write length prefix");

    let response = match read_frame(&mut stream, igris_proto::MAX_RESPONSE_SIZE)
        .expect("read response")
    {
        ReadFrame::Received(bytes) => serde_json::from_slice::<Response>(&bytes).expect("parse"),
        other => panic!("unexpected frame: {other:?}"),
    };
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "TOO_LARGE");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    let entry = &audit[0];
    assert_eq!(entry["decision"], "deny");
    assert_eq!(entry["result"], "error");
}

#[test]
fn default_policy_denies_system_info() {
    // A deny-all policy must refuse everything, including system.info.
    let daemon = TestDaemon::start(Policy::deny_all());
    let response = daemon.call("system.info", "req-denied");

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "DENIED");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "denied");
    assert_eq!(audit[0]["operation"], "system.info");
}

#[test]
fn client_disconnect_is_handled_cleanly() {
    let daemon = TestDaemon::start(milestone_one());
    // Connect and drop without sending anything.
    drop(UnixStream::connect(&daemon.socket_path).expect("connect"));
    // The daemon must still serve a subsequent request.
    let response = daemon.call("system.info", "req-after-disconnect");
    assert!(response.ok);
}

#[test]
fn multiple_requests_on_one_connection() {
    let daemon = TestDaemon::start(milestone_one());
    let mut stream = UnixStream::connect(&daemon.socket_path).expect("connect");

    for id in ["multi-1", "multi-2"] {
        let payload = serde_json::json!({
            "version": 1, "id": id, "op": "system.info", "params": {}
        });
        write_frame(&mut stream, payload.to_string().as_bytes()).expect("write");
        let response = match read_frame(&mut stream, MAX_REQUEST_SIZE).expect("read") {
            ReadFrame::Received(bytes) => {
                serde_json::from_slice::<Response>(&bytes).expect("parse")
            }
            other => panic!("unexpected frame: {other:?}"),
        };
        assert!(response.ok);
        assert_eq!(response.id.as_deref(), Some(id));
    }

    assert_eq!(daemon.audit_lines().len(), 2);
}

#[test]
fn fs_list_succeeds() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.list",
        "fs-list-1",
        serde_json::json!({"path": daemon.fs_root.to_string_lossy()}),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert!(result.get("entries").is_some());
    assert_eq!(result["truncated"], false);
    let entries = result["entries"].as_array().expect("entries array");
    assert!(entries.iter().any(|e| e["name"] == "hello.txt"));
    assert!(entries
        .iter()
        .any(|e| e["name"] == "subdir" && e["kind"] == "directory"));
    // The resolved host path must not leak into the payload.
    assert!(result.get("resolved").is_none());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "fs.list");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn fs_stat_succeeds() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.stat",
        "fs-stat-1",
        serde_json::json!({"path": daemon.fs_path("hello.txt")}),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["kind"], "file");
    assert_eq!(result["size_bytes"], 11);
    assert!(result["mode"].as_u64().unwrap_or(0) > 0);
    assert!(result.get("uid").is_some());
    assert!(result["path"].as_str().unwrap_or("").ends_with("hello.txt"));

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "fs.stat");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn fs_read_succeeds() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.read",
        "fs-read-1",
        serde_json::json!({"path": daemon.fs_path("hello.txt")}),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["encoding"], "base64");
    assert_eq!(result["size_bytes"], 11);
    assert_eq!(result["truncated"], false);

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "fs.read");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
    // Audit must not contain file contents.
    assert!(!audit[0].to_string().contains("hello igris"));
}

#[test]
fn fs_read_truncates_correctly() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.read",
        "fs-read-trunc",
        serde_json::json!({"path": daemon.fs_path("big.bin"), "max_bytes": 100}),
    );

    assert!(response.ok);
    let result = response.result.expect("result present");
    assert_eq!(result["truncated"], true);
    assert_eq!(result["size_bytes"], 100);
}

#[test]
fn fs_list_truncates_correctly() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.list",
        "fs-list-trunc",
        serde_json::json!({"path": daemon.fs_root.to_string_lossy(), "max_entries": 5}),
    );

    assert!(response.ok);
    let result = response.result.expect("result present");
    assert_eq!(result["truncated"], true);
    assert_eq!(result["entries"].as_array().expect("entries").len(), 5);
}

#[test]
fn traversal_outside_root_is_denied() {
    let daemon = TestDaemon::start(milestone_two());
    let escape = format!("{}/../..", daemon.fs_root.display());
    let response = daemon.fs_call("fs.stat", "fs-trav", serde_json::json!({"path": escape}));

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
    assert!(!audit[0]
        .to_string()
        .contains(daemon.fs_root.to_str().unwrap_or("")));
}

#[test]
fn outside_root_absolute_path_is_denied() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.read",
        "fs-outside",
        serde_json::json!({"path": "/etc/hostname"}),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn escaping_symlink_is_denied() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.read",
        "fs-symlink",
        serde_json::json!({"path": daemon.fs_path("escape-link.txt")}),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
}

#[test]
fn inner_symlink_is_allowed() {
    let daemon = TestDaemon::start(milestone_two());
    let response = daemon.fs_call(
        "fs.read",
        "fs-inner-symlink",
        serde_json::json!({"path": daemon.fs_path("inner-link.txt")}),
    );
    assert!(response.ok, "inner symlink should resolve: {response:?}");
}

#[test]
fn malformed_fs_params_return_bad_request() {
    let daemon = TestDaemon::start(milestone_two());

    let missing = daemon.fs_call("fs.list", "fs-bad-1", serde_json::json!({}));
    assert_eq!(missing.error.expect("error").code, "BAD_REQUEST");

    let wrong_type = daemon.fs_call("fs.read", "fs-bad-2", serde_json::json!({"path": 7}));
    assert_eq!(wrong_type.error.expect("error").code, "BAD_REQUEST");

    let bad_limit = daemon.fs_call(
        "fs.list",
        "fs-bad-3",
        serde_json::json!({"path": daemon.fs_path("."), "max_entries": 0}),
    );
    assert_eq!(bad_limit.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 3);
    assert!(audit
        .iter()
        .all(|a| a["decision"] == "deny" && a["result"] == "error"));
}

#[test]
fn deny_all_policy_denies_fs_tools() {
    let daemon = TestDaemon::start(Policy::deny_all());
    let response = daemon.fs_call(
        "fs.read",
        "fs-denied",
        serde_json::json!({"path": daemon.fs_path("hello.txt")}),
    );
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "DENIED");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "denied");
}

#[test]
fn milestone_one_policy_still_denies_fs_tools() {
    let daemon = TestDaemon::start(milestone_one());
    let response = daemon.fs_call(
        "fs.list",
        "fs-m1",
        serde_json::json!({"path": daemon.fs_path(".")}),
    );
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "DENIED");
}
