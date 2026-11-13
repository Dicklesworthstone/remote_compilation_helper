//! Production shell contracts for native launch and timeout helpers.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::process::Command;

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("native-launch-contract-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap()
}

#[test]
fn production_launch_and_timeout_restore_every_standard_descriptor_mask() {
    let directory = fixture();
    let witness = r#"
state=0
( : 3<&0 ) 2>/dev/null && state=$((state | 1))
( : 3>&1 ) 2>/dev/null && state=$((state | 2))
( : 3>&2 ) && state=$((state | 4))
printf '%s' "$state" > "$1"
"#;
    let script = format!(
        "{}\nuname() {{ printf Darwin; }}\n\
         mask=$1\n\
         if [ \"$((mask & 1))\" -ne 0 ]; then exec 0<&-; fi\n\
         if [ \"$((mask & 2))\" -ne 0 ]; then exec 1>&-; fi\n\
         if [ \"$((mask & 4))\" -ne 0 ]; then exec 2>&-; fi\n\
         if [ \"$2\" = setsid ]; then\n\
             rch_scope_launch_exec /bin/sh -c \"$3\" stdio-witness \"$4\"\n\
         else\n\
             rch_group_timeout --signal=KILL 2s /bin/sh -c \"$3\" stdio-witness \"$4\"\n\
         fi",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    for route in ["setsid", "timeout"] {
        for mask in 0_u8..=7 {
            let result = directory.path().join(format!("{route}-{mask}"));
            let output = Command::new("/bin/sh")
                .args(["-c", &script, "closed-stdio"])
                .arg(mask.to_string())
                .arg(route)
                .arg(witness)
                .arg(&result)
                .env_clear()
                .env("PATH", "")
                .env("RCH_WKR_BIN", WORKER)
                .output()
                .unwrap();
            assert!(output.status.success(), "{route} mask {mask}: {output:?}");
            assert!(output.stdout.is_empty(), "{route} mask {mask}: {output:?}");
            assert!(output.stderr.is_empty(), "{route} mask {mask}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(result).unwrap(),
                (7 ^ mask).to_string(),
                "{route} reopened a descriptor from original mask {mask}"
            );
        }
    }
}

#[test]
fn production_timeout_fallback_preserves_exit_two_and_refuses_missing_worker() {
    let run = |worker_path: &str| {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "{}\nrch_group_timeout --signal=KILL 2s /bin/sh -c 'printf reached; exit 2'",
                rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
            ))
            .env_clear()
            .env("PATH", "")
            .env("RCH_WKR_BIN", worker_path)
            .output()
            .unwrap()
    };
    let output = run(WORKER);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(output.stdout, b"reached");
    assert!(output.stderr.is_empty(), "{output:?}");

    let output = run("/no-such-rch-worker");
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        output.stderr.starts_with(b"RCH_SCOPED_LAUNCH_UNAVAILABLE:"),
        "{output:?}"
    );
}
