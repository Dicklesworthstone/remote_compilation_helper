//! Physically allocated worker-local emergency storage for recovery metadata.
//!
//! This module builds the shell wrappers; `rch-wkr recovery-reserve` (Rust,
//! already deployed on every worker) owns the reserve itself, so a full worker
//! needs to install nothing before recovering. Only known, finite
//! admission/GC/cancellation transactions use the inherited lease. Build
//! processes and source release waiters never do.

use std::io::{Read as _, Write as _};

/// GC control scratch uses the same filesystem whose reserve was released.
/// The fallback preserves unwrapped read-only inventories and isolated guard
/// fixtures; production recovery wrappers always set `RCH_GC_SCRATCH`.
///
/// `rch_gc_reserve_claim` binds or settles an emergency GC claim through the
/// lease this shell inherited from `rch-wkr recovery-reserve`. Without a lease
/// it is a no-op; with one, a missing worker binary refuses.
pub const GC_SHELL_HELPERS: &str = r#"
rch_gc_mktemp() {
    if [ -n "${RCH_GC_SCRATCH-}" ]; then
        mktemp "$RCH_GC_SCRATCH/rch-gc.XXXXXXXXXX";
    else
        mktemp 2>/dev/null || mktemp -p "${__tmpbase:-${TMPDIR:-/tmp}}" 2>/dev/null;
    fi;
};
rch_gc_reserve_claim() {
    [ -n "${RCH_RECOVERY_RESERVE_FD-}" ] || return 0;
    [ -n "${RCH_RECOVERY_RESERVE_WKR-}" ] || return 1;
    "$RCH_RECOVERY_RESERVE_WKR" recovery-reserve "$1" "$__gc_source_registry" "$2";
};
"#;

/// Exit status and stderr marker of every refused reserve operation.
pub const UNSAFE_EXIT: i32 = 74;
/// Exit status of a reserve that cannot be funded (ENOSPC, quota, headroom).
pub const PRESSURE_EXIT: i32 = 75;
/// The `rch-wkr recovery-reserve probe` reply. Wrappers require it before
/// running an operation, so a worker with an older `rch-wkr` refuses with an
/// explicit marker instead of misreading its argument parser's exit status.
pub const PROBE_REPLY: &str = "rch-wkr recovery-reserve v1";

// A fixed alphabet prevents recursive shell-quote expansion through the hook's
// nested SSH/flock controllers. Compression is essential too: the daemon's
// process-identity and GC protocol exceeds Linux's per-argument limit when
// merely base64 encoded. Both ends use standard zlib framing.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode(input: &[u8]) -> String {
    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    for bytes in input.chunks(3) {
        result.push(char::from(ALPHABET[(bytes[0] >> 2) as usize]));
        result.push(char::from(
            ALPHABET[((bytes[0] & 3) << 4 | bytes.get(1).copied().unwrap_or(0) >> 4) as usize],
        ));
        if let Some(second) = bytes.get(1) {
            result.push(char::from(
                ALPHABET[((second & 15) << 2 | bytes.get(2).copied().unwrap_or(0) >> 6) as usize],
            ));
        } else {
            result.push('=');
        }
        if let Some(third) = bytes.get(2) {
            result.push(char::from(ALPHABET[(third & 63) as usize]));
        } else {
            result.push('=');
        }
    }
    result
}

/// Strict inverse of `encode`: only the alphabet, whole quanta, and at most
/// two trailing `=`. Anything else is a damaged argument, never guessed at.
fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, quantum) in bytes.chunks(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let padding = quantum
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'=')
            .count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut value = 0u32;
        for &byte in &quantum[..4 - padding] {
            let digit = ALPHABET.iter().position(|&candidate| candidate == byte)?;
            value = value << 6 | u32::try_from(digit).ok()?;
        }
        value <<= 6 * u32::try_from(padding).ok()?;
        let decoded = value.to_be_bytes();
        output.extend_from_slice(&decoded[1..4 - padding]);
    }
    Some(output)
}

fn pack(input: &str) -> String {
    let mut compressed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed
        .write_all(input.as_bytes())
        .expect("compression into an in-memory vector");
    encode(&compressed.finish().expect("finish in-memory compression"))
}

/// Decode a wrapper payload argument (zlib, then the alphabet above) back to
/// its shell text. `rch-wkr recovery-reserve` is the only consumer.
///
/// # Errors
///
/// Returns a description when the argument is not exactly what `pack`
/// produces: a foreign character, bad padding, a damaged zlib stream or text
/// that is not UTF-8.
pub fn unpack(argument: &str) -> Result<String, String> {
    let compressed = decode(argument).ok_or("payload is not valid base64")?;
    let mut text = String::new();
    flate2::read::ZlibDecoder::new(compressed.as_slice())
        .read_to_string(&mut text)
        .map_err(|error| format!("payload does not decompress: {error}"))?;
    Ok(text)
}

fn command(operation: &str, registry: &str, payload: &str, reconcile: &str) -> String {
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let payload = format!("{GC_SHELL_HELPERS}\n{payload}");
    // Git for Windows rewrites arguments that look like POSIX paths when it
    // starts a native .exe; base64 may begin with '/'. rch-wkr removes both
    // variables again before it runs the payload.
    format!(
        "( {locate}\
         export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'; \
         if ! rch_wkr_locate; then \
         printf 'RCH_RECOVERY_RESERVE_UNSAFE %s: rch-wkr is not installed on this worker%s\\n' {registry} \"${{RCH_WKR_BIN:+ (RCH_WKR_BIN=$RCH_WKR_BIN)}}\" >&2; exit {UNSAFE_EXIT}; fi; \
         if [ \"$(\"$RCH_WKR\" recovery-reserve probe 2>/dev/null)\" != {probe} ]; then \
         printf 'RCH_RECOVERY_RESERVE_UNSAFE %s: %s predates recovery-reserve; deploy the matching rch-wkr\\n' {registry} \"$RCH_WKR\" >&2; exit {UNSAFE_EXIT}; fi; \
         RCH_RECOVERY_RESERVE_WKR=$RCH_WKR; export RCH_RECOVERY_RESERVE_WKR; \
         exec \"$RCH_WKR\" recovery-reserve {operation} {registry} {payload} {reconcile} )",
        locate = crate::wkr_locate::WKR_LOCATE_SHELL,
        probe = quote(PROBE_REPLY),
        registry = quote(registry),
        payload = quote(&pack(&payload)),
        reconcile = quote(&pack(&format!("{GC_SHELL_HELPERS}\n{reconcile}"))),
    )
}

/// Provision/replenish before a writable-registry health probe. A spent reserve
/// with an unretired GC claim remains unavailable, even if its flock is free.
#[must_use]
pub fn readiness_command(registry: &str) -> String {
    command("ready", registry, "", "")
}

/// Wrap only a short new-admission metadata transaction, never its build or
/// source-authority release waiter. Lock order is reserve, then metadata.
#[must_use]
pub fn admission_command(registry: &str, payload: &str) -> String {
    command("admit", registry, payload, "")
}

/// Let a finite cancellation metadata operation use this namespace's existing
/// reserve. Wrap the entire operation BEFORE its activity and metadata locks;
/// never wrap an inner transaction, a build, or a source release waiter.
///
/// This does not create a reserve, reconcile a GC claim, or grant cancellation
/// authority. A namespace without a reserve retains its ordinary protocol.
/// Existing but malformed reserve state refuses without running the operation.
#[must_use]
pub fn recovery_command(registry: &str, payload: &str) -> String {
    command("recover", registry, payload, "")
}

/// Wrap a known GC transaction and its existing exact-claim reconciliation.
/// Callers should use `stale_target_reap::with_gc_recovery_reserve` so the
/// reconciliation policy stays shared with the ordinary GC recovery command.
#[must_use]
pub(crate) fn gc_command(registry: &str, payload: &str, reconcile: &str) -> String {
    command("gc", registry, payload, reconcile)
}

/// Pin a wrapper from this module to one rch-wkr instead of the installed
/// candidates. Tests use it to run the binary built from their own tree, never
/// whatever a test host happens to have installed. Production wrappers always
/// resolve the worker's deployed rch-wkr.
#[must_use]
pub fn with_worker_binary(wrapper: &str, binary: &std::path::Path) -> String {
    let body = wrapper
        .strip_prefix("( ")
        .expect("recovery-reserve wrappers are subshells");
    format!(
        "( RCH_WKR_BIN={}; {body}",
        shell_escape::escape(binary.to_string_lossy())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_has_standard_padding_and_no_shell_metacharacters() {
        for (input, output) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v")] {
            assert_eq!(encode(input.as_bytes()), output);
            assert_eq!(decode(output).as_deref(), Some(input.as_bytes()));
        }
        let packed = pack(GC_SHELL_HELPERS);
        assert!(
            packed
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
        );
        assert_eq!(unpack(&packed).as_deref(), Ok(GC_SHELL_HELPERS));
    }

    #[test]
    fn unpack_refuses_anything_pack_cannot_produce() {
        let packed = pack("printf ready");
        for damaged in [
            format!("{packed}="),
            format!("{packed}A"),
            packed.replacen(|c: char| c.is_ascii_alphanumeric(), "-", 1),
            format!("=A{}", &packed[2..]),
            "Zm9v".to_owned(), // valid base64, not a zlib stream
        ] {
            assert!(unpack(&damaged).is_err(), "accepted {damaged:?}");
        }
    }

    #[test]
    fn wrapper_runs_the_worker_binary_never_an_interpreter() {
        let command = admission_command(
            "/var/tmp/rch-source-authority-locks/claims-v1",
            "printf ready",
        );
        assert!(command.contains("rch_wkr_locate"));
        assert!(command.contains("exec \"$RCH_WKR\" recovery-reserve admit "));
        assert!(command.contains(&format!("!= '{PROBE_REPLY}'")));
        assert!(!command.to_ascii_lowercase().contains("pyth"));
        assert!(GC_SHELL_HELPERS.contains("\"$RCH_RECOVERY_RESERVE_WKR\" recovery-reserve"));
    }

    #[test]
    fn full_gc_wrapper_fits_nested_remote_shell_arguments() {
        let registry = crate::stale_target_reap::SOURCE_CLAIM_REGISTRY;
        let payloads = [
            crate::stale_target_reap::worker_sweep_command_under_pressure(
                "/data/tmp/rch",
                60,
                Some(60),
                Some(1024 * 1024),
                100,
            ),
            crate::stale_target_reap::enumerate_targets_command("/data/tmp/rch"),
        ];
        for payload in payloads {
            let mut wrapped =
                crate::stale_target_reap::with_gc_recovery_reserve(registry, &payload);
            for _ in 0..4 {
                wrapped = format!("sh -c {}", shell_escape::escape(wrapped.into()));
            }
            assert!(
                wrapped.len() < 126 * 1024,
                "nested reserve/GC command exceeds Linux's per-argument allowance: {} bytes",
                wrapped.len(),
            );
        }
    }

    #[cfg(unix)]
    fn run_wrapper(command: &str, wkr: &str) -> std::process::Output {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("RCH_WKR_BIN", wkr)
            .output()
            .expect("run wrapper")
    }

    #[cfg(unix)]
    #[test]
    fn missing_or_older_worker_binary_refuses_without_running_the_payload() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("payload-ran");
        let payload = format!("touch {}", marker.display());
        let registry = directory.path().join("authority/claims");
        let command = admission_command(registry.to_str().unwrap(), &payload);

        let missing = run_wrapper(&command, "/nonexistent/rch-wkr");
        assert_eq!(missing.status.code(), Some(UNSAFE_EXIT));
        assert!(
            String::from_utf8_lossy(&missing.stderr).starts_with(&format!(
                "RCH_RECOVERY_RESERVE_UNSAFE {}: rch-wkr is not installed",
                registry.display()
            ))
        );

        // An rch-wkr from before this subcommand rejects it as clap does.
        let older = directory.path().join("rch-wkr");
        std::fs::write(
            &older,
            "#!/bin/sh\necho \"error: unrecognized subcommand '$1'\" >&2\nexit 2\n",
        )
        .unwrap();
        std::fs::set_permissions(&older, std::fs::Permissions::from_mode(0o755)).unwrap();
        let skewed = run_wrapper(&command, older.to_str().unwrap());
        assert_eq!(skewed.status.code(), Some(UNSAFE_EXIT));
        assert!(String::from_utf8_lossy(&skewed.stderr).contains("predates recovery-reserve"));
        assert!(!marker.exists(), "a refused wrapper ran its payload");
        assert!(!registry.exists(), "a refused wrapper touched the registry");
    }

    #[cfg(unix)]
    #[test]
    fn a_pinned_binary_replaces_every_installed_candidate() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let calls = directory.path().join("calls");
        let pinned = directory.path().join("pinned wkr");
        std::fs::write(
            &pinned,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$2\" = probe ] && echo '{PROBE_REPLY}'\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o755)).unwrap();
        let command = with_worker_binary(&admission_command("/registry", "true"), &pinned);
        assert!(command.starts_with("( RCH_WKR_BIN='"));

        // The environment names a missing binary; the pinned one still runs.
        let output = run_wrapper(&command, "/nonexistent/rch-wkr");
        assert!(output.status.success(), "{output:?}");
        let calls = std::fs::read_to_string(calls).unwrap();
        let operations: Vec<_> = calls
            .lines()
            .map(|line| line.split(' ').take(3).collect::<Vec<_>>().join(" "))
            .collect();
        assert_eq!(
            operations,
            ["recovery-reserve probe", "recovery-reserve admit /registry"]
        );
    }
}
