//! Pure validation of the exact source declaration in a saved worker request.
//!
//! Fresh execution, result-only continuation and operator recovery share this
//! decoder. It validates source identity and Cargo-home projection policy
//! without capturing files, opening a checkout or obtaining execution rights.

use rabs_sandbox::cargo_home::{
    CARGO_HOME_SOURCE_VERSION, CargoHomeProjection, ISOLATED_CARGO_HOME_SOURCE_VERSION,
    ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
};
use rabs_sandbox::source_transfer::{MAX_SOURCE_FILES, SourceFile, SourceManifest};
use serde_json::Value;
use std::io;

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

pub(super) fn digest(value: &Value) -> io::Result<[u8; 32]> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid("source digest is not a string"))?;
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "source digest must be 64 lowercase hex digits",
    )?;
    let mut digest = [0_u8; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

/// Decode only JSON shape; the worker shares the sandbox's versioned cache
/// projection policy. The original field remains unchanged in the saved request
/// and its fingerprint. This validates intent, not Cargo resolution provenance.
fn validate_cargo_home(request: &Value, manifest: &SourceManifest) -> io::Result<()> {
    let Some(home) = request.get("cargo_home") else {
        return Ok(());
    };
    require(
        home.as_object().is_some_and(|object| object.len() == 2)
            && (home["version"] == CARGO_HOME_SOURCE_VERSION
                || home["version"] == ISOLATED_CARGO_HOME_SOURCE_VERSION
                || home["version"] == ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION),
        "cargo_home requires a supported version and prefix",
    )?;
    let prefix = home["prefix"]
        .as_str()
        .ok_or_else(|| invalid("cargo_home prefix must be a string"))?;
    CargoHomeProjection::for_version(
        home["version"]
            .as_str()
            .ok_or_else(|| invalid("cargo_home version must be a string"))?,
        prefix,
        manifest,
    )?;
    Ok(())
}

/// Validate the optional source declaration without requiring source bytes.
/// Resume and verified local delivery recovery use this without a checkout.
pub fn request_manifest(request: &Value) -> io::Result<Option<SourceManifest>> {
    require(
        request.get("source_files").is_none()
            && request.get("source_roots").is_none()
            && request.get("cargo_source").is_none(),
        "source_files/source_roots/cargo_source are preparation specifications, not execution manifests; use --worker-prepare",
    )?;
    let Some(value) = request.get("source_manifest") else {
        require(
            request.get("cargo_home").is_none(),
            "cargo_home requires an uploaded source_manifest",
        )?;
        return Ok(None);
    };
    require(
        request.get("workspace_backing").is_none(),
        "source_manifest and workspace_backing are mutually exclusive",
    )?;
    require(
        value.as_object().is_some_and(|object| object.len() == 2),
        "source manifest requires exactly files and manifest_sha256",
    )?;
    let rows = value["files"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_SOURCE_FILES)
        .ok_or_else(|| invalid("source file list outside its bound"))?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        require(
            row.as_object().is_some_and(|object| object.len() == 4),
            "invalid source file fields",
        )?;
        files.push(SourceFile {
            path: row["path"]
                .as_str()
                .ok_or_else(|| invalid("invalid source path"))?
                .to_owned(),
            len: row["bytes"]
                .as_u64()
                .ok_or_else(|| invalid("invalid source length"))?,
            sha256: digest(&row["sha256"])?,
            executable: row["executable"]
                .as_bool()
                .ok_or_else(|| invalid("invalid source executable bit"))?,
        });
    }
    let manifest = SourceManifest::new(files)?;
    require(
        manifest.digest() == digest(&value["manifest_sha256"])?,
        "source manifest digest mismatch",
    )?;
    validate_cargo_home(request, &manifest)?;
    Ok(Some(manifest))
}
