//! # rabs-wkr — the RABS trusted worker daemon
//!
//! Owns (plan §10.9): the authenticated ATP worker session; worker
//! capability and pressure reporting; CAS/object fetch and seeding;
//! canonical sandbox/execroot materialization; compiler/linker/build-script/
//! test process execution in managed process groups with cgroup/PID-namespace
//! descendant containment (risk R90); filesystem/process/network input
//! observation; streaming diagnostics and early `.rmeta` artifacts; output
//! harvesting, digest verification, and staging under candidate pins;
//! **prepared-result offers** — a worker NEVER commits an action pointer
//! (invariant I10; risk R50: there is no worker-authoritative commit
//! message anywhere in the protocol); cancellation/drain; crash recovery
//! (durable boot generation + fresh process-incarnation ID on every start,
//! one active incarnation per identity/generation — I47).
//!
//! This is a specialized worker, deliberately NOT a mode added to a broad
//! generic daemon binary (the plan explicitly rejects extending `atpd`).

pub mod session;
