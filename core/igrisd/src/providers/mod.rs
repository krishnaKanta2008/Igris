//! Narrowly scoped, trusted providers.
//!
//! Each provider exposes exactly one capability and reads only from explicit,
//! non-sensitive system sources. There is deliberately no generic file or
//! process interface here: a provider is added only when a milestone requires
//! it, and it is permissioned individually.

pub mod system_info;

pub mod fs;

pub use system_info::{collect, CpuInfo, MemoryInfo, SystemInfo};
