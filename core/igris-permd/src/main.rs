//! `igris-permd` inspection binary (Phase: Milestone 1).
//!
//! Prints the Milestone 1 policy and evaluates operations supplied on the
//! command line. This is a read-only diagnostic tool; it performs no system
//! access and holds no privileges. The daemon links the same policy engine as
//! a library, so there is a single source of truth for permissions.

use std::process::ExitCode;

use igris_permd::{Decision, Policy};

fn main() -> ExitCode {
    let policy = Policy::milestone_one();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("igris-permd policy (default deny, Milestone 1)");
        for op in policy.allowed_operations() {
            println!("  allow  {op}");
        }
        println!("  deny   <everything else>");
        return ExitCode::SUCCESS;
    }

    let mut denied = false;
    for op in &args {
        let decision = policy.evaluate(op);
        if decision == Decision::Deny {
            denied = true;
        }
        println!("{:<7} {op}", decision);
    }
    if denied {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
