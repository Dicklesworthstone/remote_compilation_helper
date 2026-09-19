//! # rabsd — the RABS edge + coordinator daemon
//!
//! The initial deployment ships `rabs-edge` and `rabs-coord` in this one
//! binary, but their **authority, durable state, and protocol interfaces
//! remain distinct from the beginning** (plan Part I §1). The role split is
//! structural: [`edge`] and [`coord`] are separate modules with separate
//! state, and the RABS/ATP application protocol between them exists even
//! in-process, so splitting into two binaries later is a deployment change,
//! not a redesign.
//!
//! Role authority is deliberately asymmetric:
//! - the **edge** owns the sub-10 ms wrapper path and safe local fallback;
//! - the **coordinator** alone owns fleet-wide singleflight, leases,
//!   scheduling decisions, and committed action-result pointers (I5/I10);
//! - workers (`rabs-wkr`) prepare and offer results but never commit.

pub mod coord;
pub mod doctor;
pub mod edge;
pub mod janitor;

#[cfg(test)]
pub(crate) mod test_util {
    /// A temporary directory that is private to its owner, whatever the
    /// host's umask is.
    ///
    /// Unit tests that mount a temp root DIRECTLY need this. Under rch a
    /// worker's TMPDIR points into the workspace, and on a host whose
    /// default umask is group-writable — 0002, the Debian/Ubuntu default
    /// for user-private groups — the directory comes out 0775.
    /// `mount_and_reconcile` then refuses it, correctly: a CAS root that
    /// anyone in the group can write is exactly what that check exists to
    /// reject.
    ///
    /// The product is right and the fixture was wrong. Without this the
    /// suite passes on fleet workers whose umask is 0022 and fails on the
    /// ones whose umask is 0002, which is indistinguishable from a real
    /// regression until you check the host.
    pub fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private temp dir");
        }
        dir
    }
}
