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
        Self::start_with_writable_paths(policy, &[])
    }

    fn start_with_writable_paths(policy: Policy, writable_paths: &[&str]) -> Self {
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

        // Writable paths supplied as relative paths under fs_root.
        let writable_paths: Vec<std::path::PathBuf> = writable_paths
            .iter()
            .map(|relative| {
                let path = fs_root.join(relative);
                std::fs::create_dir_all(&path).expect("create writable directory");
                path
            })
            .collect();

        let config = if writable_paths.is_empty() {
            Config::with_fs_root(&socket_path, &audit_path, &fs_root)
        } else {
            Config::with_writable_paths(&socket_path, &audit_path, &fs_root, writable_paths)
        };

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

fn milestone_three() -> Policy {
    Policy::milestone_three()
}

/// Milestone 5 policy with process control enabled.
fn milestone_five_process_control() -> Policy {
    Policy::milestone_five(true, true)
}

/// Milestone 5 policy with process control disabled.
fn milestone_five_no_process_control() -> Policy {
    Policy::milestone_five(true, false)
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

#[test]
fn process_list_succeeds() {
    let daemon = TestDaemon::start(milestone_three());
    let payload = serde_json::json!({"version": 1, "id": "proc-list-1", "op": "process.list", "params": {"max": 16}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    let entries = result["entries"].as_array().expect("entries array");
    assert!(entries.len() <= 16);
    for entry in entries {
        assert!(entry["pid"].as_u64().unwrap_or(0) >= 1);
        assert!(entry.get("name").is_some());
        assert!(entry.get("state").is_some());
        assert!(entry.get("uid").is_some());
        assert!(entry.get("gid").is_some());
        // No sensitive fields may be present.
        for forbidden in ["cmdline", "environ", "exe", "cwd", "root"] {
            assert!(entry.get(forbidden).is_none(), "field {forbidden} leaked");
        }
    }

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "process.list");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn process_list_is_sorted_and_bounded() {
    let daemon = TestDaemon::start(milestone_three());
    let payload = serde_json::json!({"version": 1, "id": "proc-list-2", "op": "process.list", "params": {"max": 4}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(response.ok);
    let result = response.result.expect("result present");
    let entries = result["entries"].as_array().expect("entries array");
    assert!(entries.len() <= 4);
    let pids: Vec<u64> = entries
        .iter()
        .map(|e| e["pid"].as_u64().unwrap_or(0))
        .collect();
    let mut sorted = pids.clone();
    sorted.sort_unstable();
    assert_eq!(pids, sorted);
}

#[test]
fn process_stat_succeeds_for_a_known_live_process() {
    let daemon = TestDaemon::start(milestone_three());
    let pid = std::process::id();
    let payload = serde_json::json!({"version": 1, "id": "proc-stat-1", "op": "process.stat", "params": {"pid": pid}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["pid"].as_u64(), Some(pid as u64));
    assert!(!result["name"].as_str().unwrap_or("").is_empty());
    assert!(result["ppid"].as_u64().unwrap_or(0) >= 1);

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "process.stat");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn process_children_succeeds() {
    let daemon = TestDaemon::start(milestone_three());
    let pid = std::process::id();
    let payload = serde_json::json!({"version": 1, "id": "proc-children-1", "op": "process.children", "params": {"pid": pid}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["parent_pid"].as_u64(), Some(pid as u64));
    if let Some(entries) = result["entries"].as_array() {
        for entry in entries {
            assert_eq!(entry["ppid"].as_u64(), Some(pid as u64));
        }
    }

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "process.children");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn malformed_process_params_return_bad_request() {
    let daemon = TestDaemon::start(milestone_three());

    let missing_pid =
        serde_json::json!({"version": 1, "id": "pp-1", "op": "process.stat", "params": {}});
    let response = daemon.raw_exchange(missing_pid.to_string().as_bytes());
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let wrong_type = serde_json::json!({"version": 1, "id": "pp-2", "op": "process.stat", "params": {"pid": "abc"}});
    let response = daemon.raw_exchange(wrong_type.to_string().as_bytes());
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let pid_zero =
        serde_json::json!({"version": 1, "id": "pp-3", "op": "process.stat", "params": {"pid": 0}});
    let response = daemon.raw_exchange(pid_zero.to_string().as_bytes());
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let bad_max =
        serde_json::json!({"version": 1, "id": "pp-4", "op": "process.list", "params": {"max": 0}});
    let response = daemon.raw_exchange(bad_max.to_string().as_bytes());
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 4);
    assert!(audit
        .iter()
        .all(|a| a["decision"] == "deny" && a["result"] == "error"));
}

#[test]
fn nonexistent_pid_returns_not_found() {
    let daemon = TestDaemon::start(milestone_three());
    let payload = serde_json::json!({"version": 1, "id": "pp-nf", "op": "process.stat", "params": {"pid": 4_000_000}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());

    assert!(!response.ok);
    let code = response.error.expect("error").code;
    assert!(code == "NOT_FOUND" || code == "FS_ERROR", "got {code}");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn deny_all_policy_denies_process_tools() {
    let daemon = TestDaemon::start(Policy::deny_all());
    let payload =
        serde_json::json!({"version": 1, "id": "pp-deny", "op": "process.list", "params": {}});
    let response = daemon.raw_exchange(payload.to_string().as_bytes());
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "DENIED");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "denied");
}

#[test]
fn fs_write_succeeds() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/created.txt");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-ok",
        serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "confirm": true
        }),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["size_bytes"], 5);
    assert_eq!(result["overwritten"], false);
    assert_eq!(std::fs::read(&target).expect("read back"), b"hello");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "fs.write");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
    let audit_raw = std::fs::read_to_string(&daemon.audit_path).unwrap_or_default();
    assert!(!audit_raw.contains("aGVsbG8="), "audit must not log base64");
    assert!(!audit_raw.contains("hello"), "audit must not log contents");
}

#[test]
fn fs_write_overwrites_existing_file() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/existing.txt");
    std::fs::write(&target, b"old").expect("seed");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-over",
        serde_json::json!({
            "path": target,
            "content_base64": "bmV3",
            "confirm": true
        }),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["overwritten"], true);
    assert_eq!(std::fs::read(&target).expect("read back"), b"new");

    let audit = daemon.audit_lines();
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn fs_write_denied_with_empty_writable_allow_list() {
    let daemon = TestDaemon::start(Policy::milestone_four(true));
    let target = daemon.fs_path("hello.txt");
    let original = std::fs::read(&target).expect("seed");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-nowrites",
        serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "confirm": true
        }),
    );

    assert!(!response.ok);
    assert_eq!(std::fs::read(&target).expect("unchanged"), original);

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn fs_write_missing_confirmation_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/confirm.txt");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-noconfirm",
        serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8="
        }),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
    assert!(!std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn fs_write_outside_writable_allow_list_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("blocked.txt");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-blocked",
        serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "confirm": true
        }),
    );

    assert!(!response.ok);
    assert!(!std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
}

#[test]
fn fs_write_malformed_base64_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/bad-base64.txt");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-badb64",
        serde_json::json!({
            "path": target,
            "content_base64": "not-base64!",
            "confirm": true
        }),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
    assert!(!std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
}

#[test]
fn fs_write_exceeding_max_bytes_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/too-large.txt");
    let response = daemon.fs_call(
        "fs.write",
        "fs-write-toobig",
        serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "max_bytes": 4,
            "confirm": true
        }),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
    assert!(!std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
}

#[test]
fn fs_delete_succeeds_for_regular_file() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/delete-me.txt");
    std::fs::write(&target, b"bye").expect("seed");
    let response = daemon.fs_call(
        "fs.delete",
        "fs-delete-ok",
        serde_json::json!({"path": target, "confirm": true}),
    );

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["deleted"], true);
    assert!(!std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "fs.delete");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
}

#[test]
fn fs_delete_denied_with_empty_writable_allow_list() {
    let daemon = TestDaemon::start(Policy::milestone_four(true));
    let target = daemon.fs_path("subdir/victim.txt");
    std::fs::write(&target, b"keep").expect("seed");
    let response = daemon.fs_call(
        "fs.delete",
        "fs-del-noallow",
        serde_json::json!({"path": target, "confirm": true}),
    );

    assert!(!response.ok);
    assert!(std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

#[test]
fn fs_delete_missing_confirmation_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/confirm-delete.txt");
    std::fs::write(&target, b"keep").expect("seed");
    let response = daemon.fs_call(
        "fs.delete",
        "fs-del-noconfirm",
        serde_json::json!({"path": target}),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");
    assert!(std::path::Path::new(&target).exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
}

#[test]
fn fs_delete_directory_is_rejected() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/subdir");
    std::fs::create_dir(&target).expect("mkdir");
    let response = daemon.fs_call(
        "fs.delete",
        "fs-del-dir",
        serde_json::json!({"path": target, "confirm": true}),
    );

    assert!(!response.ok);
    assert!(std::path::Path::new(&target).is_dir());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["result"], "error");
}

#[test]
#[cfg(unix)]
fn fs_delete_symlink_removes_link_not_target() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let target = daemon.fs_path("writable/real.txt");
    let link = daemon.fs_path("writable/link.txt");
    std::fs::write(&target, b"keep").expect("seed");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let response = daemon.fs_call(
        "fs.delete",
        "fs-del-link",
        serde_json::json!({"path": link, "confirm": true}),
    );

    assert!(response.ok, "expected success, got {response:?}");
    assert!(!std::path::Path::new(&link).exists());
    assert_eq!(std::fs::read(&target).expect("target kept"), b"keep");
}

#[test]
#[cfg(unix)]
fn escaping_symlink_is_rejected_and_target_untouched() {
    let daemon = TestDaemon::start_with_writable_paths(Policy::milestone_four(true), &["writable"]);
    let link = daemon.fs_path("writable/escape.txt");
    std::os::unix::fs::symlink("/etc/hostname", &link).expect("symlink");

    let write_response = daemon.fs_call(
        "fs.write",
        "fs-esc-write",
        serde_json::json!({
            "path": link,
            "content_base64": "aGVsbG8=",
            "confirm": true
        }),
    );
    assert!(!write_response.ok);

    let delete_response = daemon.fs_call(
        "fs.delete",
        "fs-esc-del",
        serde_json::json!({"path": link, "confirm": true}),
    );
    assert!(!delete_response.ok);

    assert!(std::path::Path::new("/etc/hostname").exists());

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 2);
    assert!(audit
        .iter()
        .all(|a| a["decision"] == "deny" && a["result"] == "error"));
}

/// proc.signal is denied when process control is disabled.
#[test]
fn proc_signal_denied_when_process_control_disabled() {
    let daemon = TestDaemon::start(milestone_five_no_process_control());
    let pid = std::process::id();
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-1",
            "op": "proc.signal",
            "params": {"pid": pid, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "DENIED");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "proc.signal");
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "denied");
}

/// proc.signal rejects missing confirm.
#[test]
fn proc_signal_missing_confirm_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let pid = std::process::id();
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-2",
            "op": "proc.signal",
            "params": {"pid": pid, "signal": 15}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    let err = response.error.as_ref().expect("error");
    assert_eq!(err.code, "BAD_REQUEST");
    assert!(err.message.contains("confirm"));

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal rejects confirm: false.
#[test]
fn proc_signal_confirm_false_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let pid = std::process::id();
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-3",
            "op": "proc.signal",
            "params": {"pid": pid, "signal": 15, "confirm": false}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    let err = response.error.as_ref().expect("error");
    assert_eq!(err.code, "BAD_REQUEST");
    assert!(err.message.contains("confirm"));

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal rejects unsupported signal.
#[test]
fn proc_signal_unsupported_signal_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let pid = std::process::id();
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-4",
            "op": "proc.signal",
            "params": {"pid": pid, "signal": 9, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    let err = response.error.as_ref().expect("error");
    assert_eq!(err.code, "BAD_REQUEST");
    assert!(err.message.contains("allow-list"));

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal rejects PID 0.
#[test]
fn proc_signal_pid_zero_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-5",
            "op": "proc.signal",
            "params": {"pid": 0, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal rejects negative PID.
#[test]
fn proc_signal_negative_pid_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-6",
            "op": "proc.signal",
            "params": {"pid": -1, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, "BAD_REQUEST");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal rejects self-signaling.
#[test]
fn proc_signal_self_signaling_rejected() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let pid = std::process::id();
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-7",
            "op": "proc.signal",
            "params": {"pid": pid, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    let err = response.error.as_ref().expect("error");
    assert_eq!(err.code, "BAD_REQUEST");
    assert!(err.message.contains("self"));

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["decision"], "deny");
    assert_eq!(audit[0]["result"], "error");
}

/// proc.signal returns sanitized NOT_FOUND for nonexistent PID.
#[test]
fn proc_signal_nonexistent_pid_returns_not_found() {
    let daemon = TestDaemon::start(milestone_five_process_control());
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-8",
            "op": "proc.signal",
            "params": {"pid": 4_000_000, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    assert!(!response.ok);
    let code = response.error.expect("error").code;
    assert!(code == "NOT_FOUND" || code == "FS_ERROR", "got {code}");

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["result"], "error");
    // Audit must not contain PID or signal details.
    let audit_str = audit[0].to_string();
    assert!(!audit_str.contains("4000000"));
    assert!(!audit_str.contains("15"));
}

/// proc.signal can send SIGTERM to a controlled child process.
#[test]
fn proc_signal_succeeds_on_controlled_child() {
    use std::process::Command;
    use std::time::Duration;

    let daemon = TestDaemon::start(milestone_five_process_control());

    // Spawn a child process that ignores SIGTERM so we can verify it was sent.
    // Use a simple sleep process.
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep child");
    let child_pid = child.id();

    // Give the child a moment to start.
    std::thread::sleep(Duration::from_millis(50));

    // Send SIGTERM via proc.signal.
    let response = daemon.raw_exchange(
        serde_json::json!({
            "version": 1,
            "id": "ps-9",
            "op": "proc.signal",
            "params": {"pid": child_pid, "signal": 15, "confirm": true}
        })
        .to_string()
        .as_bytes(),
    );

    // Clean up the child regardless of test outcome.
    let _ = child.kill();
    let _ = child.wait();

    assert!(response.ok, "expected success, got {response:?}");
    let result = response.result.expect("result present");
    assert_eq!(result["sent"], true);

    let audit = daemon.audit_lines();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["operation"], "proc.signal");
    assert_eq!(audit[0]["decision"], "allow");
    assert_eq!(audit[0]["result"], "success");
    // Audit must not contain PID, signal, or process details.
    let audit_str = audit[0].to_string();
    assert!(!audit_str.contains(&child_pid.to_string()));
    assert!(!audit_str.contains("15"));
    assert!(!audit_str.contains("sleep"));
}
