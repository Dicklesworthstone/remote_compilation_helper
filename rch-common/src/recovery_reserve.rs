//! Physically allocated worker-local emergency storage for GC ownership records.
//!
//! The helper runs from memory, so a full worker does not need to install a
//! script before recovering. Only known, finite admission/GC transactions use
//! the inherited lease. Build processes and source release waiters never do.

use std::io::Write as _;
use std::sync::LazyLock;

const PROGRAM: &str = include_str!("recovery_reserve.py");
const BOOTSTRAP: &str = "import base64,os,zlib;exec(compile(zlib.decompress(base64.b64decode(os.environ['RCH_RECOVERY_RESERVE_PROGRAM'])),'<rch-recovery-reserve>','exec'))";
static ENCODED_PROGRAM: LazyLock<String> = LazyLock::new(|| pack(PROGRAM));

/// GC control scratch uses the same filesystem whose reserve was released.
/// The fallback preserves unwrapped read-only inventories and isolated guard
/// fixtures; production recovery wrappers always set `RCH_GC_SCRATCH`.
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
    [ -n "${RCH_RECOVERY_RESERVE_BOOTSTRAP-}" ] || return 1;
    python3 -I -S -B -c "$RCH_RECOVERY_RESERVE_BOOTSTRAP" "$1" "$__gc_source_registry" "$2";
};
"#;

// A fixed alphabet prevents recursive shell-quote expansion through the hook's
// nested SSH/flock controllers. Compression is essential too: the daemon's
// process-identity and GC protocol exceeds Linux's per-argument limit when
// merely base64 encoded. Both ends use standard zlib framing.
fn encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

fn pack(input: &str) -> String {
    let mut compressed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed
        .write_all(input.as_bytes())
        .expect("compression into an in-memory vector");
    encode(&compressed.finish().expect("finish in-memory compression"))
}

fn command(operation: &str, registry: &str, payload: &str, reconcile: &str) -> String {
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let payload = format!("{GC_SHELL_HELPERS}\n{payload}");
    format!(
        "( RCH_RECOVERY_RESERVE_PROGRAM={program}; \
         RCH_RECOVERY_RESERVE_BOOTSTRAP={bootstrap}; \
         export RCH_RECOVERY_RESERVE_PROGRAM RCH_RECOVERY_RESERVE_BOOTSTRAP; \
         python3 -I -S -B -c \"$RCH_RECOVERY_RESERVE_BOOTSTRAP\" {operation} {registry} {payload} {reconcile} )",
        program = *ENCODED_PROGRAM,
        bootstrap = quote(BOOTSTRAP),
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

/// Wrap a known GC transaction and its existing exact-claim reconciliation.
/// Callers should use `stale_target_reap::with_gc_recovery_reserve` so the
/// reconciliation policy stays shared with the ordinary GC recovery command.
#[must_use]
pub(crate) fn gc_command(registry: &str, payload: &str, reconcile: &str) -> String {
    command("gc", registry, payload, reconcile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_has_standard_padding_and_no_shell_metacharacters() {
        for (input, output) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v")] {
            assert_eq!(encode(input.as_bytes()), output);
        }
        assert!(
            pack(PROGRAM)
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
        );
    }

    #[test]
    fn recovery_program_runs_without_a_worker_script_file() {
        let command = admission_command(
            "/var/tmp/rch-source-authority-locks/claims-v1",
            "printf ready",
        );
        assert!(command.contains("python3 -I -S -B -c"));
        assert!(command.contains(" admit "));
        assert!(!command.contains("recovery_reserve.py"));
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
    #[test]
    fn admission_wrapper_preserves_piped_roots_and_shared_lease() {
        let directory = tempfile::tempdir().expect("private admission fixture");
        let registry = directory.path().join("authority/claims");
        let payload = "test -n \"$RCH_RECOVERY_RESERVE_FD\" && \
                       test \"$RCH_RECOVERY_RESERVE_MODE\" = shared && cat";
        let wrapped = admission_command(registry.to_str().unwrap(), payload);
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                &format!("printf '/data/project\\n/data/dependency\\n' | {wrapped}"),
            ])
            .output()
            .expect("execute actual admission wrapper");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(output.stdout, b"/data/project\n/data/dependency\n");
        assert_eq!(
            std::fs::metadata(registry.join(".recovery-v1/reserve.v1"))
                .unwrap()
                .len(),
            64 * 1024 * 1024,
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_recovery_reserve_preserves_ownership_on_full_filesystems() {
        let guard = crate::stale_target_reap::source_claim_gc_guard_fragment_with_registry(
            "__RCH_TEST_REGISTRY__",
        );
        let output = std::process::Command::new("python3")
            .arg("-B")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/recovery_reserve.py"
            ))
            .env("RCH_TEST_GC_RESERVE_GUARD", guard)
            .output()
            .expect("python3 must run the native recovery reserve regressions");
        assert!(
            output.status.success(),
            "native reserve tests failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
