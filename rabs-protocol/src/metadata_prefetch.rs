//! Optional private transfer of one completed rustc metadata file before exit.
//!
//! These bytes are hints, not a process result, publication, or Cargo readiness.
//! A receiver may consume them only after the ordinary terminal result selects
//! the same exact name, length, digest and mode. Missing or partial hints miss.

/// Exact negotiated capability. Unselected peers never send intermediate data.
pub const VERSION: &str = "rmeta-prefetch-v1";
/// A single bounded immutable candidate per active execution, at each endpoint.
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
/// One scheduling quantum; cancellation and completion run between chunks.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Restrict the optional optimization to one flat, explicitly declared output.
/// The owning artifact declaration independently validates all other names.
#[must_use]
pub fn candidate<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut selected = None;
    for name in names {
        if name.ends_with(".rmeta") {
            if selected.is_some()
                || name.len() > 1024
                || name.contains(['/', '\\', ':'])
                || name.chars().any(char::is_control)
            {
                return None;
            }
            selected = Some(name);
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_exact_flat_metadata_name_is_eligible() {
        assert_eq!(
            candidate(["a.d", "liba.rmeta", "liba.rlib"]),
            Some("liba.rmeta")
        );
        for names in [
            vec![],
            vec!["a.rlib"],
            vec!["a.rmeta", "b.rmeta"],
            vec!["deps/a.rmeta"],
            vec!["../a.rmeta"],
            vec!["a\\b.rmeta"],
            vec!["a\n.rmeta"],
        ] {
            assert_eq!(candidate(names), None);
        }
    }
}
