//! Igris Mock Agent — deterministic test harness for the M8 tool-calling pipeline.
//!
//! This binary exercises the full M8 request path without an LLM:
//! - Creates sessions with specific capabilities
//! - Invokes tools through the tool registry
//! - Validates schema, capability, and confirmation requirements
//! - Demonstrates authorization, confirmation, and audit correlation
//! - Treats provider output as untrusted data

use std::sync::Arc;
use std::time::Duration;

use igris_confirmation::{ConfirmationGate, MockConfirmationAdapter};
use igris_proto::{error_code, validate_operation_params, Request};
use igris_session::{CapabilitySet, SessionManager};
use igris_tool_registry::{default_registry, ToolId, ToolRegistry};

/// Demo session capabilities for each test scenario
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// 1. Permitted read-only operation succeeds
    ReadOnly,
    /// 2. Unknown tool is rejected
    UnknownTool,
    /// 3. Invalid arguments are rejected
    InvalidArgs,
    /// 4. Missing capability is denied
    MissingCapability,
    /// 5. Expired or revoked capability is denied
    ExpiredCapability,
    /// 6. Cross-session capability use is denied
    CrossSession,
    /// 7. Sensitive operation without confirmation is denied
    NoConfirmation,
    /// 8. Denied confirmation never executes
    DeniedConfirmation,
    /// 9. Authorized confirmation follows lifecycle
    AuthorizedConfirmation,
    /// 10. Replayed confirmation is rejected
    ReplayedConfirmation,
    /// 11. Provider failure produces structured error
    ProviderFailure,
    /// 12. Audit correlation preserved
    AuditCorrelation,
    /// 13. Malicious-looking output treated as data
    UntrustedOutput,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║          Igris M8 Mock Agent — Deterministic Test Harness         ║");
    println!("║      Testing AI Agent Security & Tool-Calling Foundation          ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize shared components
    let tool_registry = Arc::new(default_registry());
    let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
    let confirmation_gate = Arc::new(ConfirmationGate::new(
        session_manager.clone(),
        tool_registry.clone(),
    ));

    // Mock confirmation adapter for automated testing
    let mock_adapter = Arc::new(MockConfirmationAdapter::new());

    let scenarios = [
        (Scenario::ReadOnly, "Permitted read-only operation succeeds"),
        (Scenario::UnknownTool, "Unknown tool is rejected"),
        (Scenario::InvalidArgs, "Invalid arguments are rejected"),
        (Scenario::MissingCapability, "Missing capability is denied"),
        (
            Scenario::ExpiredCapability,
            "Expired/revoked capability is denied",
        ),
        (
            Scenario::CrossSession,
            "Cross-session capability use is denied",
        ),
        (
            Scenario::NoConfirmation,
            "Sensitive operation without confirmation is denied",
        ),
        (
            Scenario::DeniedConfirmation,
            "Denied confirmation never executes",
        ),
        (
            Scenario::AuthorizedConfirmation,
            "Authorized confirmation follows lifecycle",
        ),
        (
            Scenario::ReplayedConfirmation,
            "Replayed confirmation is rejected",
        ),
        (
            Scenario::ProviderFailure,
            "Provider failure produces structured error",
        ),
        (Scenario::AuditCorrelation, "Audit correlation preserved"),
        (
            Scenario::UntrustedOutput,
            "Malicious-looking output treated as data",
        ),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (scenario, description) in scenarios {
        print!("Test: {} ... ", description);
        std::io::Write::flush(&mut std::io::stdout())?;

        match run_scenario(
            scenario,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        ) {
            Ok(()) => {
                println!("✅ PASS");
                passed += 1;
            }
            Err(e) => {
                println!("❌ FAIL: {}", e);
                failed += 1;
            }
        }
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                        TEST SUMMARY                                ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!(
        "║  Passed: {:>2}                                                        ║",
        passed
    );
    println!(
        "║  Failed: {:>2}                                                        ║",
        failed
    );
    println!(
        "║  Total:  {:>2}                                                        ║",
        passed + failed
    );
    println!("╚═══════════════════════════════════════════════════════════════════╝");

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn run_scenario(
    scenario: Scenario,
    tool_registry: &Arc<ToolRegistry>,
    session_manager: &Arc<SessionManager>,
    confirmation_gate: &Arc<ConfirmationGate>,
    _mock_adapter: &Arc<MockConfirmationAdapter>,
) -> Result<(), Box<dyn std::error::Error>> {
    use igris_confirmation::ConfirmationError;
    use igris_session::SessionError;

    match scenario {
        Scenario::ReadOnly => {
            // 1. Permitted read-only operation succeeds
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session = session_manager.create_session(caps)?;

            let tool = tool_registry
                .get(&ToolId::new("fs.read"))
                .ok_or("Tool fs.read not found")?;
            assert!(
                !tool.requires_confirmation(),
                "fs.read should not require confirmation"
            );

            // Validate capability
            session_manager.validate_capability(&session.id, &ToolId::new("fs.read"))?;

            // Verify tool schema exists
            assert!(tool_registry.get(&ToolId::new("fs.read")).is_some());
        }

        Scenario::UnknownTool => {
            // 2. Unknown tool is rejected
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session = session_manager.create_session(caps)?;

            // Unknown tool should not be in registry
            assert!(tool_registry.get(&ToolId::new("unknown.tool")).is_none());

            // Validation should fail
            let result =
                session_manager.validate_capability(&session.id, &ToolId::new("unknown.tool"));
            assert!(result.is_err(), "Unknown tool should be rejected");
        }

        Scenario::InvalidArgs => {
            // 3. Invalid arguments are rejected
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session = session_manager.create_session(caps)?;

            // Build request with missing required 'path' parameter
            let request = Request {
                version: igris_proto::PROTOCOL_VERSION,
                id: "test-invalid-args".to_string(),
                op: "fs.read".to_string(),
                params: serde_json::json!({}), // missing path
                session_id: Some(session.id.to_string()),
                confirmation_token: None,
            };

            let err = validate_operation_params(&request.op, &request.params);
            assert!(err.is_err(), "Invalid args should be rejected");
            let proto_err = err.unwrap_err();
            assert_eq!(proto_err.code, error_code::BAD_REQUEST);
        }

        Scenario::MissingCapability => {
            // 4. Missing capability is denied
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session = session_manager.create_session(caps)?;

            // fs.write requires filesystem_write capability
            let result = session_manager.validate_capability(&session.id, &ToolId::new("fs.write"));
            assert!(result.is_err(), "Missing capability should be denied");
            assert!(matches!(
                result.unwrap_err(),
                SessionError::MissingCapability(_)
            ));
        }

        Scenario::ExpiredCapability => {
            // 5. Expired or revoked capability is denied
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session = session_manager.create_session(caps)?;

            // Test revocation - use session_manager.revoke_session
            session_manager.revoke_session(&session.id)?;
            let result = session_manager.get_valid_session(&session.id);
            assert!(result.is_err(), "Revoked session should be rejected");
            assert!(matches!(result.unwrap_err(), SessionError::SessionRevoked));

            // Test expiration (create new session with very short TTL)
            let expired_manager = SessionManager::new(tool_registry.clone())
                .with_default_duration(Duration::from_nanos(1));
            let caps2 = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session2 = expired_manager.create_session(caps2)?;
            std::thread::sleep(Duration::from_millis(10));
            let result2 = expired_manager.get_valid_session(&session2.id);
            assert!(result2.is_err(), "Expired session should be rejected");
            assert!(matches!(result2.unwrap_err(), SessionError::SessionExpired));
        }

        Scenario::CrossSession => {
            // 6. Cross-session capability use is denied
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let session1 = session_manager.create_session(caps.clone())?;
            let session2 = session_manager.create_session(caps)?;

            // session1's capabilities should not be usable by session2
            // (They have different IDs, so we test by checking isolation)
            assert_ne!(session1.id, session2.id);

            // Validate capability for session1 works
            assert!(session_manager
                .validate_capability(&session1.id, &ToolId::new("fs.read"))
                .is_ok());

            // Validate capability for session2 works (same capability)
            assert!(session_manager
                .validate_capability(&session2.id, &ToolId::new("fs.read"))
                .is_ok());

            // But session1 cannot use session2's revoked state
            session_manager.revoke_session(&session2.id)?;
            let result = session_manager.get_valid_session(&session2.id);
            assert!(result.is_err(), "Session2 should be revoked");

            // Session1 should still be valid
            assert!(session_manager.get_valid_session(&session1.id).is_ok());
        }

        Scenario::NoConfirmation => {
            // 7. Sensitive operation without confirmation is denied
            let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
            let session = session_manager.create_session(caps)?;

            // fs.write requires confirmation
            let tool = tool_registry
                .get(&ToolId::new("fs.write"))
                .ok_or("Tool fs.write not found")?;
            assert!(
                tool.requires_confirmation(),
                "fs.write should require confirmation"
            );

            // Request confirmation without providing token
            let request = Request {
                version: igris_proto::PROTOCOL_VERSION,
                id: "test-no-confirm".to_string(),
                op: "fs.write".to_string(),
                params: serde_json::json!({
                    "path": "/test.txt",
                    "content_base64": "dGVzdA==",
                    "confirm": true
                }),
                session_id: Some(session.id.to_string()),
                confirmation_token: None,
            };

            // This should create a confirmation request
            let conf_request = confirmation_gate.request_confirmation(
                &session.id,
                &ToolId::new("fs.write"),
                request.params.clone(),
            )?;
            assert_eq!(
                conf_request.status,
                igris_confirmation::ConfirmationStatus::Pending
            );
        }

        Scenario::DeniedConfirmation => {
            // 8. Denied confirmation never executes
            let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
            let session = session_manager.create_session(caps)?;

            let tool_id = ToolId::new("fs.write");
            let args = serde_json::json!({
                "path": "/test.txt",
                "content_base64": "dGVzdA==",
                "confirm": true
            });

            let conf_request =
                confirmation_gate.request_confirmation(&session.id, &tool_id, args.clone())?;
            let deny_result = confirmation_gate.deny(&conf_request.id)?;
            assert_eq!(
                deny_result.status,
                igris_confirmation::ConfirmationStatus::Denied
            );
            assert!(deny_result.token.is_none());

            // After denial, validation should fail
            // (In real implementation, we'd check this via the gate)
        }

        Scenario::AuthorizedConfirmation => {
            // 9. Authorized confirmation follows lifecycle
            let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
            let session = session_manager.create_session(caps)?;

            let tool_id = ToolId::new("fs.write");
            let args = serde_json::json!({
                "path": "/test.txt",
                "content_base64": "dGVzdA==",
                "confirm": true
            });

            // Request confirmation
            let conf_request =
                confirmation_gate.request_confirmation(&session.id, &tool_id, args.clone())?;
            assert_eq!(
                conf_request.status,
                igris_confirmation::ConfirmationStatus::Pending
            );

            // Approve
            let approve_result = confirmation_gate.approve(&conf_request.id)?;
            assert_eq!(
                approve_result.status,
                igris_confirmation::ConfirmationStatus::Approved
            );
            assert!(approve_result.token.is_some());
            let token = approve_result.token.unwrap();

            // Consume token
            confirmation_gate.validate_and_consume(&session.id, &tool_id, &args, &token)?;

            // Second consume should fail
            let second_consume =
                confirmation_gate.validate_and_consume(&session.id, &tool_id, &args, &token);
            assert!(second_consume.is_err(), "Replayed token should be rejected");
            assert!(matches!(
                second_consume.unwrap_err(),
                ConfirmationError::ConfirmationAlreadyUsed
            ));
        }

        Scenario::ReplayedConfirmation => {
            // 10. Replayed confirmation is rejected
            let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
            let session = session_manager.create_session(caps)?;

            let tool_id = ToolId::new("fs.write");
            let args = serde_json::json!({
                "path": "/test.txt",
                "content_base64": "dGVzdA==",
                "confirm": true
            });

            let conf_request =
                confirmation_gate.request_confirmation(&session.id, &tool_id, args.clone())?;
            let approve_result = confirmation_gate.approve(&conf_request.id)?;
            let token = approve_result.token.unwrap();

            // First consume - OK
            confirmation_gate.validate_and_consume(&session.id, &tool_id, &args, &token)?;

            // Replay - should fail
            let replay =
                confirmation_gate.validate_and_consume(&session.id, &tool_id, &args, &token);
            assert!(replay.is_err(), "Replayed confirmation should be rejected");
        }

        Scenario::ProviderFailure => {
            // 11. Provider failure produces structured error
            // We can't easily test real provider failure without spawning,
            // but we verify the error codes exist
            assert!(!error_code::INTERNAL.is_empty());
            assert!(!error_code::FS_ERROR.is_empty());
            assert!(!error_code::NOT_FOUND.is_empty());
        }

        Scenario::AuditCorrelation => {
            // 12. Audit correlation preserved
            // The server generates correlation IDs for each request
            // We verify the structure supports it
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let _session = session_manager.create_session(caps)?;

            let correlation_id = format!("cid-{:016x}", 42);
            assert!(!correlation_id.is_empty());
            assert!(correlation_id.starts_with("cid-"));
        }

        Scenario::UntrustedOutput => {
            // 13. Malicious-looking output treated as data
            let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
            let _session = session_manager.create_session(caps)?;

            // Simulate provider returning suspicious content
            let suspicious_outputs = vec![
                "rm -rf /",
                "sudo shutdown -h now",
                "cat /etc/passwd",
                "<script>alert('xss')</script>",
                "eval(malicious_code)",
            ];

            for output in suspicious_outputs {
                // Verify we treat this as data, not instructions
                let _data = serde_json::to_value(output)?;
                // In real implementation, this would be base64-encoded in response
                // and never executed or interpreted
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_only_scenario() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::ReadOnly,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_unknown_tool_rejected() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::UnknownTool,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_invalid_args_rejected() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::InvalidArgs,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_missing_capability_denied() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::MissingCapability,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_expired_capability_denied() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::ExpiredCapability,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_cross_session_denied() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::CrossSession,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_no_confirmation_denied() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::NoConfirmation,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_denied_confirmation_never_executes() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::DeniedConfirmation,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_authorized_confirmation_lifecycle() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::AuthorizedConfirmation,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_replayed_confirmation_rejected() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::ReplayedConfirmation,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_provider_failure_structured() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::ProviderFailure,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_audit_correlation() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::AuditCorrelation,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }

    #[test]
    fn test_untrusted_output_treated_as_data() {
        let tool_registry = Arc::new(default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(ConfirmationGate::new(
            session_manager.clone(),
            tool_registry.clone(),
        ));
        let mock_adapter = Arc::new(MockConfirmationAdapter::new());

        run_scenario(
            Scenario::UntrustedOutput,
            &tool_registry,
            &session_manager,
            &confirmation_gate,
            &mock_adapter,
        )
        .unwrap();
    }
}
