//! # rabs-sandbox — snapshots, canonical execroot, isolation, observation
//!
//! Owns (Epics D and E): mutation-safe coherent source snapshot capture with
//! retry (I2); the canonical virtual execroot — fixed visible paths under
//! `/__rabs/...` with hidden attempt-specific physical backing roots
//! (I1/I20); Linux mount/user/pid/network namespaces and cgroup v2
//! envelopes; canonical Cargo-driver launch (I19 — the Cargo *process* runs
//! inside the canonical namespace for workspace authority); immutable source
//! mounts and closed authoritative input views with abort-on-new-read (I3);
//! toolchain/sysroot/SDK mounts; stable `CARGO_HOME`/`HOME`/`OUT_DIR`/
//! incremental/temp/locale/hostname/secret-slot surfaces; complete explicit
//! environment construction (I21 — never `getenv` tracing); filesystem
//! read/failed-open/enumeration/symlink/subprocess/network observation;
//! strict-hermetic versus host-audit isolation profiles with recorded
//! enforcement evidence (I25/I28); path-leak detection; output-path and
//! side-effect enforcement; source-capture confidentiality policy (I38 —
//! `.gitignore` is never a security boundary); cleanup and failure bundles.
//!
//! Platform truth this crate must never forget: macOS APFS clones do not
//! give concurrent processes one canonical visible path (risk R47); vDSO
//! clock and multi-interface entropy escape syscall tracers (risk R46);
//! a Unix process group is not a descendant boundary — cgroup/PID-namespace
//! or VM containment backs any no-orphans claim (risk R90).
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - May depend on `rabs-protocol` (and, as Epics D/E land, explicitly
//!   reviewed nix/namespace crates).
//! - **No Tokio, no Asupersync** here; async orchestration adapts in
//!   `rabs-asupersync`.
//! - Any privileged operation lives in a separate, audited, bounded helper
//!   binary listed in the unsafe-boundary ledger — never in this library.

pub mod layout;
pub mod leak_scanner;
pub mod source_capture;
