//! Pooled target-dir cache key (bd-session-history-remediation-ocv9i.11.2).
//!
//! Pooled Rust target dirs let independent builds share a warm cache instead of
//! each carving a fresh `target/` — but only when sharing is *safe*. Two builds
//! may reuse the same pooled dir iff every dimension that can change the
//! compiled artifacts matches: the originating repo, the toolchain, the target
//! triple, the cargo profile, and the enabled feature/runtime set. Mixing any
//! of these in one directory corrupts the cache (stale rebuilds, wrong-feature
//! artifacts, cross-project contamination) — the exact failure session history
//! attributed to ad-hoc shared target dirs.
//!
//! [`PooledTargetDimensions`] captures those dimensions and
//! [`PooledTargetKey`] derives a stable, filesystem-safe key from them. The
//! derivation is **pure** (no clock, no env) so it is unit-testable and
//! reproducible: identical dimensions always yield the same key, and any
//! difference yields a different one. The hash is domain-separated per field so
//! adjacent fields can never run together into a colliding key (e.g. repo `ab`
//! + toolchain `c` must not equal repo `a` + toolchain `bc`).
//!
//! The reaper that *evicts* stale pooled dirs, the active-build protection that
//! pins in-use keys, and the opt-out config knob are the daemon-side half of
//! this bead; this module is the shared key contract both the pooled-dir layout
//! and the reaper key off.

use blake3::Hasher;

/// Root directory name under which pooled target dirs live, mirroring the
/// `.rch-target` convention RCH already rewrites `CARGO_TARGET_DIR` to.
pub const POOLED_TARGET_ROOT: &str = ".rch-pool";

/// The dimensions that must match for two builds to safely share a pooled
/// target dir. Any field differing means a different (non-shared) pooled dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledTargetDimensions {
    /// Stable repo identity (e.g. the canonical project root or its hash).
    /// Prevents cross-project contamination of a shared pool.
    pub repo_identity: String,
    /// Toolchain channel or pinned version (e.g. `nightly-2025-11-01`).
    pub toolchain: String,
    /// Target triple (e.g. `x86_64-unknown-linux-gnu`, `wasm32-unknown-unknown`).
    pub target_triple: String,
    /// Cargo profile (e.g. `dev`, `release`).
    pub profile: String,
    /// Enabled cargo features. Order- and duplicate-insensitive (canonicalized
    /// before hashing), so `["a","b"]` and `["b","a","a"]` share a pool.
    pub features: Vec<String>,
    /// Extra runtime dimension that changes artifacts (e.g. `bun`, `node`,
    /// `wasm`), when relevant. `None` for a plain Rust build.
    pub runtime: Option<String>,
}

impl PooledTargetDimensions {
    /// Construct the minimal Rust build dimensions (no features/runtime).
    #[must_use]
    pub fn new(
        repo_identity: impl Into<String>,
        toolchain: impl Into<String>,
        target_triple: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            repo_identity: repo_identity.into(),
            toolchain: toolchain.into(),
            target_triple: target_triple.into(),
            profile: profile.into(),
            features: Vec::new(),
            runtime: None,
        }
    }

    /// Set the feature set (builder style); canonicalized at hash time.
    #[must_use]
    pub fn with_features<I, S>(mut self, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.features = features.into_iter().map(Into::into).collect();
        self
    }

    /// Set the runtime dimension (builder style).
    #[must_use]
    pub fn with_runtime(mut self, runtime: impl Into<String>) -> Self {
        self.runtime = Some(runtime.into());
        self
    }

    /// Features sorted and de-duplicated — the canonical form used for hashing
    /// and for an auditable view of what a pool key covers.
    #[must_use]
    pub fn canonical_features(&self) -> Vec<String> {
        let mut f = self.features.clone();
        f.sort();
        f.dedup();
        f
    }
}

/// A derived pooled target-dir key. Stable across processes and hosts for the
/// same dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledTargetKey {
    hex: String,
}

/// Feed one domain-separated, length-prefixed field into the hasher so adjacent
/// fields can never concatenate into a colliding pre-image.
fn absorb(hasher: &mut Hasher, tag: &str, value: &str) {
    // tag\0 <len-as-decimal>\0 value\0 — the length prefix plus the NUL
    // terminators make the framing unambiguous regardless of field contents.
    hasher.update(tag.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    hasher.update(b"\0");
}

impl PooledTargetKey {
    /// Derive the key from dimensions. Pure and total.
    #[must_use]
    pub fn derive(dims: &PooledTargetDimensions) -> Self {
        let mut hasher = Hasher::new();
        absorb(&mut hasher, "v", "1"); // key-schema version, so we can rotate.
        absorb(&mut hasher, "repo", &dims.repo_identity);
        absorb(&mut hasher, "toolchain", &dims.toolchain);
        absorb(&mut hasher, "triple", &dims.target_triple);
        absorb(&mut hasher, "profile", &dims.profile);
        absorb(&mut hasher, "runtime", dims.runtime.as_deref().unwrap_or(""));
        // Canonicalized features, count-prefixed then each length-framed, so the
        // feature *set* (not its order or multiplicity) determines the key.
        let features = dims.canonical_features();
        absorb(&mut hasher, "features.n", &features.len().to_string());
        for feature in &features {
            absorb(&mut hasher, "feature", feature);
        }
        // 128-bit truncation: ample collision resistance for a cache key while
        // keeping the directory name short.
        let hex = hasher.finalize().to_hex();
        Self {
            hex: hex[..32].to_string(),
        }
    }

    /// The stable hex key (filesystem-safe: lowercase hex only).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.hex
    }

    /// The pooled target directory name for this key, e.g.
    /// `.rch-pool/<key>`. Always filesystem-safe.
    #[must_use]
    pub fn pooled_dir_name(&self) -> String {
        format!("{POOLED_TARGET_ROOT}/{}", self.hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PooledTargetDimensions {
        PooledTargetDimensions::new(
            "/data/projects/acme",
            "nightly-2025-11-01",
            "x86_64-unknown-linux-gnu",
            "dev",
        )
    }

    fn key_of(dims: &PooledTargetDimensions) -> String {
        PooledTargetKey::derive(dims).as_str().to_string()
    }

    #[test]
    fn cache_reuse_identical_dimensions_share_a_key() {
        // The whole point of pooling: same dimensions => same warm cache.
        assert_eq!(key_of(&base()), key_of(&base()));
    }

    #[test]
    fn feature_order_and_duplicates_do_not_change_the_key() {
        let a = base().with_features(["serde", "tokio"]);
        let b = base().with_features(["tokio", "serde", "serde"]);
        assert_eq!(key_of(&a), key_of(&b), "feature SET must determine the key");
    }

    #[test]
    fn incompatible_features_get_separate_pools() {
        // Different feature sets must NOT share a pool (wrong-feature artifacts).
        let none = base();
        let with = base().with_features(["tokio"]);
        let other = base().with_features(["async-std"]);
        assert_ne!(key_of(&none), key_of(&with));
        assert_ne!(key_of(&with), key_of(&other));
    }

    #[test]
    fn distinct_repos_never_share_a_pool() {
        let acme = base();
        let other = PooledTargetDimensions::new(
            "/data/projects/other",
            "nightly-2025-11-01",
            "x86_64-unknown-linux-gnu",
            "dev",
        );
        assert_ne!(
            key_of(&acme),
            key_of(&other),
            "cross-project contamination guard"
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous_no_contamination() {
        // repo `ab` + toolchain `c` must not collide with repo `a` + toolchain `bc`.
        let left = PooledTargetDimensions::new("ab", "c", "t", "dev");
        let right = PooledTargetDimensions::new("a", "bc", "t", "dev");
        assert_ne!(key_of(&left), key_of(&right));
        // Likewise across the triple/profile boundary.
        let p1 = PooledTargetDimensions::new("r", "t", "abc", "");
        let p2 = PooledTargetDimensions::new("r", "t", "ab", "c");
        assert_ne!(key_of(&p1), key_of(&p2));
    }

    #[test]
    fn each_dimension_change_changes_the_key() {
        let b = base();
        let bk = key_of(&b);
        assert_ne!(
            bk,
            key_of(&PooledTargetDimensions::new(
                b.repo_identity.clone(),
                "nightly-2026-01-01",
                b.target_triple.clone(),
                b.profile.clone(),
            )),
            "toolchain"
        );
        assert_ne!(
            bk,
            key_of(&PooledTargetDimensions::new(
                b.repo_identity.clone(),
                b.toolchain.clone(),
                "wasm32-unknown-unknown",
                b.profile.clone(),
            )),
            "triple"
        );
        assert_ne!(
            bk,
            key_of(&PooledTargetDimensions::new(
                b.repo_identity.clone(),
                b.toolchain.clone(),
                b.target_triple.clone(),
                "release",
            )),
            "profile"
        );
        assert_ne!(bk, key_of(&base().with_runtime("bun")), "runtime");
    }

    #[test]
    fn key_is_filesystem_safe_and_stable_length() {
        let key = PooledTargetKey::derive(&base().with_features(["a", "b"]));
        let s = key.as_str();
        assert_eq!(s.len(), 32, "128-bit truncated hex");
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only: {s}"
        );
        assert_eq!(key.pooled_dir_name(), format!(".rch-pool/{s}"));
    }

    #[test]
    fn runtime_none_and_empty_string_are_equivalent() {
        // A plain Rust build (runtime None) keys the same as runtime="" — the
        // absence of a runtime dimension, not a distinct value.
        let none = base();
        let mut empty = base();
        empty.runtime = Some(String::new());
        assert_eq!(key_of(&none), key_of(&empty));
    }
}
