//! Igris permission / policy broker.
//!
//! This crate owns the authorization decision for every IPC operation. It is
//! deliberately kept separate from `igrisd` so the daemon never embeds policy:
//! `igrisd` validates and routes, `igris_permd` decides.
//!
//! The engine is **default deny**. A policy starts by denying everything and
//! only explicitly listed operations are allowed. There is intentionally no
//! "allow all" development mode.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// The operation is explicitly permitted by policy.
    Allow,
    /// The operation is not permitted (the default for everything).
    Deny,
}

impl Decision {
    /// Lower-case name used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A default-deny policy holding the set of explicitly allowed operations.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    allowed: BTreeSet<String>,
}

impl Policy {
    /// A policy that denies every operation.
    pub fn deny_all() -> Self {
        Self {
            allowed: BTreeSet::new(),
        }
    }

    /// The policy in force for Milestone 1: allow exactly `system.info`.
    pub fn milestone_one() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(igris_proto::OP_SYSTEM_INFO.to_string());
        Self { allowed }
    }

    /// The policy in force for Milestone 2: allow `system.info` plus the
    /// read-only filesystem tools.
    pub fn milestone_two() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(igris_proto::OP_SYSTEM_INFO.to_string());
        allowed.insert(igris_proto::OP_FS_LIST.to_string());
        allowed.insert(igris_proto::OP_FS_STAT.to_string());
        allowed.insert(igris_proto::OP_FS_READ.to_string());
        Self { allowed }
    }

    /// The policy in force for Milestone 3: Milestone 2 grants plus the
    /// read-only process observation operations.
    pub fn milestone_three() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(igris_proto::OP_SYSTEM_INFO.to_string());
        allowed.insert(igris_proto::OP_FS_LIST.to_string());
        allowed.insert(igris_proto::OP_FS_STAT.to_string());
        allowed.insert(igris_proto::OP_FS_READ.to_string());
        allowed.insert(igris_proto::OP_PROCESS_LIST.to_string());
        allowed.insert(igris_proto::OP_PROCESS_STAT.to_string());
        allowed.insert(igris_proto::OP_PROCESS_CHILDREN.to_string());
        Self { allowed }
    }

    /// Allow an operation explicitly. Returns `true` if it was newly added.
    pub fn allow(&mut self, op: impl Into<String>) -> bool {
        self.allowed.insert(op.into())
    }

    /// Whether an operation is explicitly allowed.
    pub fn is_allowed(&self, op: &str) -> bool {
        self.allowed.contains(op)
    }

    /// Evaluate an operation against the policy. Default deny.
    pub fn evaluate(&self, op: &str) -> Decision {
        if self.is_allowed(op) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// The operations explicitly allowed by this policy.
    pub fn allowed_operations(&self) -> impl Iterator<Item = &str> {
        self.allowed.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_denies_everything() {
        let policy = Policy::deny_all();
        assert_eq!(policy.evaluate(igris_proto::OP_SYSTEM_INFO), Decision::Deny);
        assert_eq!(policy.evaluate("fs.read"), Decision::Deny);
        assert_eq!(policy.evaluate(""), Decision::Deny);
    }

    #[test]
    fn milestone_one_allows_only_system_info() {
        let policy = Policy::milestone_one();
        assert_eq!(
            policy.evaluate(igris_proto::OP_SYSTEM_INFO),
            Decision::Allow
        );
        assert_eq!(policy.evaluate("proc.list"), Decision::Deny);
        assert_eq!(policy.evaluate("system.exec"), Decision::Deny);
    }

    #[test]
    fn milestone_two_allows_system_info_and_fs_tools() {
        let policy = Policy::milestone_two();
        assert_eq!(
            policy.evaluate(igris_proto::OP_SYSTEM_INFO),
            Decision::Allow
        );
        assert_eq!(policy.evaluate(igris_proto::OP_FS_LIST), Decision::Allow);
        assert_eq!(policy.evaluate(igris_proto::OP_FS_STAT), Decision::Allow);
        assert_eq!(policy.evaluate(igris_proto::OP_FS_READ), Decision::Allow);
    }

    #[test]
    fn milestone_two_denies_unrelated_operations() {
        let policy = Policy::milestone_two();
        assert_eq!(policy.evaluate("fs.write"), Decision::Deny);
        assert_eq!(policy.evaluate("fs.delete"), Decision::Deny);
        assert_eq!(policy.evaluate("proc.list"), Decision::Deny);
        assert_eq!(policy.evaluate("system.exec"), Decision::Deny);
        assert_eq!(policy.evaluate(""), Decision::Deny);
    }

    #[test]
    fn milestone_one_behavior_is_unchanged() {
        let policy = Policy::milestone_one();
        assert_eq!(
            policy.evaluate(igris_proto::OP_SYSTEM_INFO),
            Decision::Allow
        );
        assert_eq!(policy.evaluate(igris_proto::OP_FS_READ), Decision::Deny);
        assert_eq!(policy.evaluate(igris_proto::OP_FS_LIST), Decision::Deny);
    }

    #[test]
    fn milestone_three_allows_process_tools_and_m2_set() {
        let policy = Policy::milestone_three();
        assert_eq!(
            policy.evaluate(igris_proto::OP_SYSTEM_INFO),
            Decision::Allow
        );
        assert_eq!(policy.evaluate(igris_proto::OP_FS_LIST), Decision::Allow);
        assert_eq!(policy.evaluate(igris_proto::OP_FS_STAT), Decision::Allow);
        assert_eq!(policy.evaluate(igris_proto::OP_FS_READ), Decision::Allow);
        assert_eq!(
            policy.evaluate(igris_proto::OP_PROCESS_LIST),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(igris_proto::OP_PROCESS_STAT),
            Decision::Allow
        );
        assert_eq!(
            policy.evaluate(igris_proto::OP_PROCESS_CHILDREN),
            Decision::Allow
        );
    }

    #[test]
    fn milestone_three_denies_unrelated_operations() {
        let policy = Policy::milestone_three();
        assert_eq!(policy.evaluate("process.kill"), Decision::Deny);
        assert_eq!(policy.evaluate("process.exec"), Decision::Deny);
        assert_eq!(policy.evaluate("fs.write"), Decision::Deny);
        assert_eq!(policy.evaluate("events.subscribe"), Decision::Deny);
    }

    #[test]
    fn earlier_policies_remain_narrow() {
        let m1 = Policy::milestone_one();
        assert_eq!(m1.evaluate(igris_proto::OP_PROCESS_LIST), Decision::Deny);
        let m2 = Policy::milestone_two();
        assert_eq!(m2.evaluate(igris_proto::OP_PROCESS_LIST), Decision::Deny);
        assert_eq!(m2.evaluate(igris_proto::OP_PROCESS_STAT), Decision::Deny);
    }

    #[test]
    fn explicit_allow_is_the_only_grant() {
        let mut policy = Policy::deny_all();
        assert_eq!(policy.evaluate("fs.read"), Decision::Deny);
        assert!(policy.allow("fs.read"));
        assert!(!policy.allow("fs.read"), "second insert is not new");
        assert_eq!(policy.evaluate("fs.read"), Decision::Allow);
        assert_eq!(policy.evaluate("fs.write"), Decision::Deny);
    }

    #[test]
    fn decision_strings_are_stable() {
        assert_eq!(Decision::Allow.as_str(), "allow");
        assert_eq!(Decision::Deny.as_str(), "deny");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn allowed_operations_lists_grants() {
        let policy = Policy::milestone_one();
        let ops: Vec<&str> = policy.allowed_operations().collect();
        assert_eq!(ops, vec![igris_proto::OP_SYSTEM_INFO]);
    }
}
