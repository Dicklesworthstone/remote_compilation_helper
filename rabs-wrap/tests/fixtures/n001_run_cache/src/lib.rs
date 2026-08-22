//! Fixture library: consumes the build script's outputs so cargo's
//! fingerprint and output-cache machinery is fully exercised.

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Value produced by the generated unit (proves OUT_DIR materialized).
pub fn probe_value() -> u32 {
    generated()
}
