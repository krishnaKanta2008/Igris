//! Igris core service daemon library.
//!
//! `igrisd` is the privileged IPC hub. It validates untrusted input, consults
//! the permission policy in [`igris_permd`], routes allowed operations to
//! narrowly scoped providers, and writes an append-only audit record for every
//! request. It never executes a shell or arbitrary subprocess.

pub mod audit;
pub mod config;
pub mod providers;
pub mod server;
