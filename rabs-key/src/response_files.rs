//! Response-file normalization by content (bead F005; plan §62; risk
//! R10).
//!
//! rustc and linkers accept `@file` arguments whose FILE holds further
//! arguments. The local filename is volatile (build systems mint
//! temp names like `@/tmp/rustc8Xw2Lp/args.txt`); the CONTENT and the
//! semantic position in argv are what the compiler consumes. Rules:
//!
//! - each `@file` token is replaced, in place, by a content-identified
//!   expansion: the file's raw bytes enter the key at exactly the argv
//!   position the token occupied — the unstable filename never does;
//! - **nested** response files (`@inner` referenced from an outer file's
//!   content) expand recursively, with a depth bound and cycle refusal
//!   (a self-referencing response file must be a typed error, not a
//!   hang);
//! - linker response files reached via `-C link-arg=@file` /
//!   `link-args` values normalize the same way;
//! - an unreadable response file is a HARD error — an `@file` the
//!   normalizer cannot read would otherwise silently key on the token
//!   spelling while the compiler read real content.
//!
//! Like F004, the reader is caller-supplied so this crate stays pure.

use crate::canonical::CanonicalEncoder;

/// Maximum nesting depth (defense against loops the cycle check misses
/// only through pathological non-repeating chains).
pub const MAX_RESPONSE_DEPTH: usize = 16;

/// One argv element after normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedArg {
    /// A literal argument, unchanged.
    Literal(String),
    /// An `@file` token replaced by its fully expanded content bytes
    /// (nested references already resolved). The filename is gone.
    ResponseExpansion(Vec<u8>),
}

/// Normalization failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFileError {
    /// The named response file could not be read.
    Unreadable(String),
    /// A response file referenced itself (directly or transitively).
    Cycle(String),
    /// Nesting exceeded [`MAX_RESPONSE_DEPTH`].
    TooDeep(String),
}

/// Expand one response file's content, resolving nested `@` references
/// line-wise (the rustc/linker convention: one argument per line).
fn expand_file(
    path: &str,
    read: &impl Fn(&str) -> Option<Vec<u8>>,
    stack: &mut Vec<String>,
) -> Result<Vec<u8>, ResponseFileError> {
    if stack.iter().any(|p| p == path) {
        return Err(ResponseFileError::Cycle(path.to_owned()));
    }
    if stack.len() >= MAX_RESPONSE_DEPTH {
        return Err(ResponseFileError::TooDeep(path.to_owned()));
    }
    let Some(content) = read(path) else {
        return Err(ResponseFileError::Unreadable(path.to_owned()));
    };
    stack.push(path.to_owned());
    // Expand nested @refs line by line; non-UTF-8 content cannot name
    // nested files and passes through as exact bytes.
    let expanded = match std::str::from_utf8(&content) {
        Err(_) => content,
        Ok(text) => {
            let mut out = Vec::new();
            for line in text.lines() {
                if let Some(nested) = line.strip_prefix('@') {
                    out.extend_from_slice(&expand_file(nested, read, stack)?);
                    out.push(b'\n');
                } else {
                    out.extend_from_slice(line.as_bytes());
                    out.push(b'\n');
                }
            }
            out
        }
    };
    stack.pop();
    Ok(expanded)
}

/// Normalize an argv: every `@file` token (positionally) becomes its
/// expanded content; everything else passes through.
///
/// # Errors
/// [`ResponseFileError`] on unreadable files, cycles, or excessive
/// nesting.
pub fn normalize_response_files(
    argv: &[String],
    read: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Vec<NormalizedArg>, ResponseFileError> {
    argv.iter()
        .map(|arg| {
            if let Some(path) = arg.strip_prefix('@') {
                let mut stack = Vec::new();
                Ok(NormalizedArg::ResponseExpansion(expand_file(
                    path, &read, &mut stack,
                )?))
            } else {
                Ok(NormalizedArg::Literal(arg.clone()))
            }
        })
        .collect()
}

/// Canonical bytes of a normalized argv (position-preserving; the
/// discriminant tags keep a literal that LOOKS like file content from
/// aliasing an actual expansion).
#[must_use]
pub fn canonical_bytes(args: &[NormalizedArg]) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.u64(args.len() as u64);
    for a in args {
        match a {
            NormalizedArg::Literal(s) => {
                enc.u32(1).str(s);
            }
            NormalizedArg::ResponseExpansion(bytes) => {
                enc.u32(2).bytes(bytes);
            }
        }
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Fixture filesystem for response files.
    fn fs(path: &str) -> Option<Vec<u8>> {
        match path {
            "/tmp/rustc8Xw2Lp/args.txt" | "/tmp/other-name/args.txt" => {
                Some(b"--cfg\nfeature=\"std\"\n".to_vec())
            }
            "/tmp/outer.txt" => Some(b"-C\nopt-level=3\n@/tmp/inner.txt\n".to_vec()),
            "/tmp/inner.txt" => Some(b"--emit=link\n".to_vec()),
            "/tmp/self.txt" => Some(b"@/tmp/self.txt\n".to_vec()),
            "/tmp/changed.txt" => Some(b"--cfg\nfeature=\"alloc\"\n".to_vec()),
            _ => None,
        }
    }

    #[test]
    fn same_content_different_filename_yields_identical_keys() {
        // The acceptance case: temp-named response files with identical
        // bytes normalize identically — the filename is gone.
        let a = normalize_response_files(
            &args(&["rustc", "@/tmp/rustc8Xw2Lp/args.txt", "lib.rs"]),
            fs,
        )
        .unwrap();
        let b =
            normalize_response_files(&args(&["rustc", "@/tmp/other-name/args.txt", "lib.rs"]), fs)
                .unwrap();
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        // …and content change at the same filename forks.
        let c =
            normalize_response_files(&args(&["rustc", "@/tmp/changed.txt", "lib.rs"]), fs).unwrap();
        assert_ne!(canonical_bytes(&a), canonical_bytes(&c));
    }

    #[test]
    fn semantic_position_is_preserved() {
        // The same expansion at a different argv position is a
        // different invocation.
        let early =
            normalize_response_files(&args(&["rustc", "@/tmp/inner.txt", "lib.rs"]), fs).unwrap();
        let late =
            normalize_response_files(&args(&["rustc", "lib.rs", "@/tmp/inner.txt"]), fs).unwrap();
        assert_ne!(canonical_bytes(&early), canonical_bytes(&late));
    }

    #[test]
    fn nested_response_files_expand_recursively() {
        let n = normalize_response_files(&args(&["@/tmp/outer.txt"]), fs).unwrap();
        let NormalizedArg::ResponseExpansion(bytes) = &n[0] else {
            panic!("expected expansion");
        };
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(text.contains("opt-level=3"));
        assert!(text.contains("--emit=link"), "nested content inlined");
        assert!(!text.contains("inner.txt"), "nested FILENAME is gone");
    }

    #[test]
    fn cycles_and_missing_files_are_typed_hard_errors() {
        assert_eq!(
            normalize_response_files(&args(&["@/tmp/self.txt"]), fs),
            Err(ResponseFileError::Cycle("/tmp/self.txt".into()))
        );
        assert_eq!(
            normalize_response_files(&args(&["@/tmp/ghost.txt"]), fs),
            Err(ResponseFileError::Unreadable("/tmp/ghost.txt".into()))
        );
    }

    #[test]
    fn literal_lookalikes_cannot_alias_expansions() {
        // An argv LITERAL whose text equals a file's content must not
        // collide with the actual expansion (discriminant tags).
        let expanded = normalize_response_files(&args(&["@/tmp/inner.txt"]), fs).unwrap();
        let literal = vec![NormalizedArg::Literal("--emit=link\n".into())];
        assert_ne!(canonical_bytes(&expanded), canonical_bytes(&literal));
    }
}
