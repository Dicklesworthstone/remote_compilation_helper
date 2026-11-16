//! Scope supervisor integration against the compiled production shell constant.
#[cfg(target_os = "linux")]
#[test]
fn scoped_launch_lifecycle() {
    let directory = tempfile::Builder::new()
        .prefix("scoped-launch-contract-")
        .disable_cleanup(true)
        .tempdir()
        .expect("protocol fixture directory");
    let script = directory.path().join("protocol.sh");
    std::fs::write(&script, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled protocol");
    for shell in ["/bin/sh", "/bin/bash"] {
        let status = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/remote_scoped_launch.py"
            ))
            // Transport cases below now execute the compiled protocol directly.
            .args(["ScopedLaunch", "ProcessGroupLaunch"])
            .env("RCH_TEST_PROTOCOL_SCRIPT", &script)
            .env("RCH_TEST_SHELL", shell)
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
            .status()
            .expect("scope lifecycle tests require python3 and the selected shell");
        assert!(
            status.success(),
            "scope lifecycle contract failed under {shell}"
        );
    }
}

#[cfg(target_os = "linux")]
mod native_transport {
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    use rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT as PROTOCOL;

    const SHELLS: [&str; 2] = ["/bin/sh", "/bin/bash"];

    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("scoped-launch-transport-")
            .disable_cleanup(true)
            .tempdir()
            .expect("transport fixture directory")
    }

    fn invoke(shell: &str, script: &str) -> Command {
        // The fixture's outside deadline bounds a broken protocol as well as
        // its inherited pipe holders. Production leaf deadlines remain inside
        // it and are independently asserted by the timing cases below.
        let mut command = Command::new("/usr/bin/timeout");
        command
            .args(["--signal=KILL", "10s", shell, "-c", script, "rch-observer"])
            .env_remove("RCH_TIMING_SCALE")
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary());
        command
    }

    fn assert_success(output: &Output, expected: &[u8]) {
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, expected, "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    fn quote_source(source: &str) -> String {
        let mut quoted = String::new();
        for character in source.chars() {
            match character {
                '!' => quoted.push_str("${rch_literal_bang}"),
                '\\' | '"' | '$' | '`' => {
                    quoted.push('\\');
                    quoted.push(character);
                }
                _ => quoted.push(character),
            }
        }
        quoted
    }

    #[test]
    fn worker_scale_validates_fractional_caps_and_default() {
        let script = format!(
            "{PROTOCOL}\nrch_timing_budget 5; printf '%s:' \"$rch_timing_scaled\"\n\
             rch_timing_budget 200; printf '%s\\n' \"$rch_timing_scaled\"\n"
        );
        for shell in SHELLS {
            for (scale, expected) in [
                (None, b"5:200\n".as_slice()),
                (Some("1"), b"5:200\n"),
                (Some("2"), b"10:400\n"),
                (Some("1.25"), b"7:250\n"),
                (Some("10"), b"50:2000\n"),
            ] {
                let mut command = invoke(shell, &script);
                if let Some(scale) = scale {
                    command.env("RCH_TIMING_SCALE", scale);
                }
                let output = command.output().expect("observe scaled shell budgets");
                assert_success(&output, expected);
            }
        }
    }

    #[test]
    fn invalid_worker_scale_refuses_before_command_evaluation() {
        let script = format!("{PROTOCOL}\nprintf UNEXPECTED\n");
        for shell in SHELLS {
            for scale in [
                "",
                "0",
                "0.99",
                "-1",
                "10.1",
                "NaN",
                "inf",
                "-inf",
                "1e9999",
                "1e-9999",
                " 2",
                "2 ",
                "1_0",
                "1;printf INJECTED",
                "$(printf INJECTED)",
            ] {
                let output = invoke(shell, &script)
                    .env("RCH_TIMING_SCALE", scale)
                    .output()
                    .expect("reject malformed shell timing scale");
                assert_eq!(output.status.code(), Some(125), "{scale:?}: {output:?}");
                assert!(output.stdout.is_empty(), "{scale:?}: {output:?}");
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(error.contains("invalid RCH_TIMING_SCALE"), "{error}");
                assert!(!error.contains("INJECTED"), "{error}");
            }
        }
    }

    #[test]
    fn scaled_control_capture_admits_delayed_success() {
        let script =
            format!("{PROTOCOL}\nrch_control_capture 1s /bin/sh -c 'sleep 1.4; printf ready'\n");
        for shell in SHELLS {
            for (scale, succeeds) in [("1", false), ("2", true), ("1.25", true)] {
                let started = Instant::now();
                let output = invoke(shell, &script)
                    .env("RCH_TIMING_SCALE", scale)
                    .output()
                    .expect("observe delayed capture within the scaled budget");
                assert!(started.elapsed() < Duration::from_secs(5), "{output:?}");
                assert_eq!(output.status.success(), succeeds, "{output:?}");
                assert_eq!(
                    output.stdout,
                    if succeeds { b"ready".as_slice() } else { b"" },
                    "{output:?}"
                );
            }
        }
    }

    #[test]
    fn scaled_capture_cannot_disable_near_exhausted_deadline() {
        let script = format!(
            "{PROTOCOL}\n\
             rch_observation_clock_checked || exit 99\n\
             rch_observation_deadline=$((rch_observation_now + 50))\n\
             rch_control_capture 1s /bin/sh -c 'printf UNEXPECTED'\n"
        );
        for shell in SHELLS {
            for scale in ["1", "2", "1.25", "10"] {
                let output = invoke(shell, &script)
                    .env("RCH_TIMING_SCALE", scale)
                    .output()
                    .expect("refuse a subsecond remaining control budget");
                assert_eq!(output.status.code(), Some(125), "{output:?}");
                assert!(output.stdout.is_empty(), "{output:?}");
            }
        }
    }

    #[test]
    fn one_literal_hydrates_the_exact_child_program() {
        let fragments = [
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            include_str!("../src/remote_process.sh"),
            include_str!("../src/remote_scoped_launch.sh"),
        ];
        for source in fragments {
            assert_eq!(PROTOCOL.matches(&quote_source(source)).count(), 1);
        }
        let expected = fragments.join("\n");
        let script = format!("{PROTOCOL}\nprintf '%s' \"$rch_launch_source\"\n");
        for shell in SHELLS {
            let output = invoke(shell, &script)
                .output()
                .expect("hydrate the compiled child source");
            assert_success(&output, expected.as_bytes());
        }
    }

    #[test]
    fn hydration_preserves_binary_stdin_and_literal_arguments() {
        let directory = fixture();
        let input = directory.path().join("binary-stdin");
        let payload: Vec<u8> = (0..64).flat_map(|_| 0_u8..=255).collect();
        std::fs::write(&input, &payload).expect("write binary stdin fixture");
        let arguments = [
            "",
            "quote'!\\",
            "$(printf INJECTED)",
            "line\nRCH_SCOPED_LAUNCH_SOURCE_104\nend",
        ];
        let mut expected = Vec::new();
        for argument in arguments {
            expected.extend_from_slice(argument.as_bytes());
            expected.push(0);
        }
        expected.extend_from_slice(&payload);
        let script = format!("{PROTOCOL}\nprintf '%s\\0' \"$@\"; command cat\n");
        for shell in SHELLS {
            let output = invoke(shell, &script)
                .args(arguments)
                .env("rch_launch_source", "printf INJECTED >&2; exit 99")
                .stdin(Stdio::from(File::open(&input).expect("open binary stdin")))
                .output()
                .expect("hydrate source without consuming payload stdin");
            assert_success(&output, &expected);
        }
    }

    #[test]
    fn four_quoted_transports_reach_the_protocol() {
        for shell in SHELLS {
            let mut script =
                format!("{PROTOCOL}\nrch_valid_pgid 42 || exit 90; printf '%s' \"$1\"\n");
            for _ in 0..4 {
                script = format!(
                    "exec {shell} -c {} rch-transport \"$@\"",
                    shell_escape::unix::escape(script.into())
                );
            }
            assert!(script.len() < 110_000, "{} transport bytes", script.len());
            let output = invoke(shell, &script)
                .arg("reached'!$()\\")
                .output()
                .expect("execute four enclosing transport layers");
            assert_success(&output, b"reached'!$()\\");
        }
    }

    #[test]
    fn bootstrap_does_not_execute_a_path_supplied_source_reader() {
        let directory = fixture();
        let fake_reader = directory.path().join("cat");
        std::fs::write(
            &fake_reader,
            "#!/bin/sh\nprintf 'printf INJECTED; exit 0\\n'\nexit 1\n",
        )
        .expect("write hostile source reader fixture");
        std::fs::set_permissions(&fake_reader, std::fs::Permissions::from_mode(0o700))
            .expect("make source reader executable");
        let script = format!("{PROTOCOL}\nprintf AFTER\n");
        for shell in SHELLS {
            let output = invoke(shell, &script)
                .env("PATH", directory.path())
                .output()
                .expect("load literal protocol without external source reader");
            assert_success(&output, b"AFTER");
        }
    }
}

#[cfg(target_os = "linux")]
mod native_result_recovery {
    use std::process::{Command, Output};

    use rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT as PROTOCOL;

    // These tests launch and drain real process groups. They fault one
    // observation or kill the group after the real leader publishes its result.
    // The child receives the unchanged production protocol and no test hooks.
    fn alias(source: &str, name: &str, replacement: &str) -> String {
        let declaration = format!("{name}() ");
        assert_eq!(source.matches(&declaration).count(), 1);
        let (_, definition) = source.split_once(&declaration).unwrap();
        let closing = if definition.starts_with('{') {
            "\n}"
        } else {
            assert!(definition.starts_with('('));
            "\n)"
        };
        let end = definition.find(closing).unwrap() + closing.len();
        format!("{replacement}() {}\n", &definition[..end])
    }

    const OBSERVATION_FAULT: &str = r#"
# Isolate optional host policy; all process identity and cleanup remain real.
rch_policy_select_file() { rch_policy_file=; }
rch_fixture_fault() {
    [ "$RCH_RESULT_TEST_MODE" != control ] || return 1
    [ ! -e "$RCH_RESULT_TEST_ROOT/injected" ] || return 1
    rch_fixture_mode=${RCH_RESULT_TEST_MODE#exited-}
    if [ "$rch_fixture_mode" = before-admission ]; then
        [ "${__sl_admitted:-0}" = 0 ] && [ -n "${__sl_child_start:-}" ] || return 1
        rch_fixture_attempt=0
        while [ ! -f "$__sl_record" ]; do
            rch_fixture_attempt=$((rch_fixture_attempt + 1))
            [ "$rch_fixture_attempt" -lt 500 ] || exit 98
            sleep 0.01 || exit 98
        done
        (umask 077; printf 'RCH_SCOPED_RESULT_V1:%s:%s:%s:0\n' \
            "$__sl_build" "$__sl_child" "$__sl_child_start" > "$__sl_control/result") || exit 98
    else
        [ "${__sl_admitted:-0}" = 1 ] || return 1
        rch_fixture_ready="$__sl_control/result"
        [ "$rch_fixture_mode" != missing ] || rch_fixture_ready="$RCH_RESULT_TEST_ROOT/started"
        rch_fixture_attempt=0
        while [ ! -f "$rch_fixture_ready" ]; do
            rch_fixture_attempt=$((rch_fixture_attempt + 1))
            [ "$rch_fixture_attempt" -lt 500 ] || exit 98
            sleep 0.01 || exit 98
        done
    fi
    : > "$RCH_RESULT_TEST_ROOT/injected" || exit 98
    case "$rch_fixture_mode" in
        wrong-build)
            printf 'RCH_SCOPED_RESULT_V1:4243:%s:%s:0\n' \
                "$__sl_child" "$__sl_child_start" > "$__sl_control/result";;
        wrong-birth)
            printf 'RCH_SCOPED_RESULT_V1:%s:%s:%s:0\n' \
                "$__sl_build" "$__sl_child" "$((__sl_child_start + 1))" > "$__sl_control/result";;
        malformed) printf 'extra\n' >> "$__sl_control/result";;
        mode) chmod 644 "$__sl_control/result";;
        hardlink) ln "$__sl_control/result" "$RCH_RESULT_TEST_ROOT/result-alias";;
        record) printf 'damaged record\n' > "$__sl_record";;
        deadline) printf 'deadline\n' > "$__sl_control/deadline";;
        cancelled) kill -TERM "$$";;
    esac
    return 0
}
rch_scope_launch_clock() {
    case "$RCH_RESULT_TEST_MODE" in
        process|exited|exited-*) ;;
        *) if rch_fixture_fault; then return 1; fi;;
    esac
    rch_fixture_clock
}
rch_scope_launch_process() {
    if [ "$1" = "${__sl_child:-}" ] && [ "$RCH_RESULT_TEST_MODE" = process ] &&
        rch_fixture_fault; then return 2; fi
    case "$RCH_RESULT_TEST_MODE" in
        exited|exited-*)
            if [ "$1" = "${__sl_child:-}" ] && rch_fixture_fault; then
                # Stop the real group after result publication (or the started
                # marker for the missing-result control). Recheck the fixture's
                # leader identity before signalling; observe actual death.
                rch_fixture_process "$__sl_child" &&
                    [ "$rch_launch_group" = "$__sl_child" ] &&
                    [ "$rch_launch_birth" = "$__sl_child_start" ] || exit 98
                kill -KILL -"$__sl_child" || exit 98
                rch_fixture_attempt=0
                while :; do
                    rch_fixture_process "$__sl_child"
                    rch_fixture_liveness=$?
                    [ "$rch_fixture_liveness" != 1 ] || return 1
                    [ "$rch_fixture_liveness" = 0 ] || exit 98
                    rch_fixture_attempt=$((rch_fixture_attempt + 1))
                    [ "$rch_fixture_attempt" -lt 500 ] || exit 98
                    sleep 0.01 || exit 98
                done
            fi;;
    esac
    rch_fixture_process "$@"
}
rch_remote_cancel_loaded() {
    rch_fixture_cancel "$@"
    rch_fixture_cleanup=$?
    # Simulate unavailable final evidence only after actually draining the
    # owned group, so even the negative control leaves no live fixture work.
    if [ "${RCH_RESULT_TEST_MODE#exited-}:$rch_fixture_cleanup" = cleanup:0 ]; then return 44; fi
    return "$rch_fixture_cleanup"
}
exec 3>&2
rch_scope_launch_supervise "$RCH_RESULT_TEST_ROOT/receipt" 0 RCH_RESULT_TEST_DEADLINE 4242 \
    /bin/sh -c '
        printf "PAYLOAD_START\n"
        : > "$RCH_RESULT_TEST_ROOT/started"
        if [ "${RCH_RESULT_TEST_MODE#exited-}" = missing ]; then sleep 30; fi
        printf "PAYLOAD_DONE\n"
        exit "$RCH_RESULT_TEST_STATUS"
    '
"#;

    fn run(shell: &str, mode: &str, payload_status: i32) -> (tempfile::TempDir, Output) {
        let directory = tempfile::Builder::new()
            .prefix("scoped-result-recovery-")
            .disable_cleanup(true)
            .tempdir()
            .expect("result recovery fixture directory");
        let launch = include_str!("../src/remote_scoped_launch.sh");
        let process = include_str!("../src/remote_process.sh");
        let script = format!(
            "{PROTOCOL}\n{}{}{}{OBSERVATION_FAULT}",
            alias(launch, "rch_scope_launch_clock", "rch_fixture_clock"),
            alias(launch, "rch_scope_launch_process", "rch_fixture_process"),
            alias(process, "rch_remote_cancel_loaded", "rch_fixture_cancel"),
        );
        // timeout owns a separate observer group even inside PID namespaces.
        // Its guard is outside the production deadlines being exercised.
        let output = Command::new("/usr/bin/timeout")
            .args([
                "--signal=KILL",
                "15s",
                shell,
                "-c",
                &script,
                "rch-result-observer",
            ])
            .env_remove("RCH_TIMING_SCALE")
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
            .env("RCH_RESULT_TEST_ROOT", directory.path())
            .env("RCH_RESULT_TEST_MODE", mode)
            .env("RCH_RESULT_TEST_STATUS", payload_status.to_string())
            .output()
            .expect("run the real supervisor with a single observation fault");
        assert_eq!(
            directory.path().join("injected").exists(),
            mode != "control",
            "fault did not reach its intended boundary: {shell}, {mode}: {output:?}",
        );
        (directory, output)
    }

    #[test]
    fn finished_payload_keeps_its_status_after_a_failed_observation() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in ["control", "clock", "process"] {
                for status in [0, 37] {
                    let (directory, output) = run(shell, mode, status);
                    assert_eq!(output.status.code(), Some(status), "{mode}: {output:?}");
                    assert_eq!(output.stdout, b"PAYLOAD_START\nPAYLOAD_DONE\n");
                    assert!(output.stderr.is_empty(), "{mode}: {output:?}");
                    let result = std::fs::read_to_string(
                        directory.path().join("receipt.supervisor.v1/result"),
                    )
                    .unwrap();
                    assert!(result.starts_with("RCH_SCOPED_RESULT_V1:4242:"));
                    assert!(result.ends_with(&format!(":{status}\n")));
                }
            }
        }
    }

    #[test]
    fn finished_payload_keeps_its_status_after_its_leader_exits() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for status in [0, 37, 101] {
                let (directory, output) = run(shell, "exited", status);
                assert_eq!(output.status.code(), Some(status), "{output:?}");
                assert_eq!(output.stdout, b"PAYLOAD_START\nPAYLOAD_DONE\n");
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!error.contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"));
                assert!(!error.contains("RCH_RESULT_TEST_DEADLINE"));
                let result = std::fs::read_to_string(
                    directory.path().join("receipt.supervisor.v1/result"),
                )
                .unwrap();
                assert!(result.starts_with("RCH_SCOPED_RESULT_V1:4242:"));
                assert!(result.ends_with(&format!(":{status}\n")));
            }
        }
    }

    #[test]
    fn exited_leader_cannot_authorize_an_invalid_payload_result() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in [
                "exited-missing",
                "exited-wrong-build",
                "exited-wrong-birth",
                "exited-malformed",
                "exited-mode",
                "exited-hardlink",
            ] {
                let (directory, output) = run(shell, mode, 0);
                assert_eq!(output.status.code(), Some(137), "{mode}: {output:?}");
                assert_eq!(
                    output.stdout,
                    if mode == "exited-missing" {
                        b"PAYLOAD_START\n".as_slice()
                    } else {
                        b"PAYLOAD_START\nPAYLOAD_DONE\n".as_slice()
                    },
                    "{mode}: {output:?}",
                );
                assert!(
                    !String::from_utf8_lossy(&output.stderr)
                        .contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"),
                    "{mode}: {output:?}",
                );
                if mode == "exited-missing" {
                    assert!(
                        !directory
                            .path()
                            .join("receipt.supervisor.v1/result")
                            .exists()
                    );
                }
            }
        }
    }

    #[test]
    fn exited_leader_result_still_requires_cleanup_and_an_intact_record() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in ["exited-record", "exited-cleanup"] {
                let (directory, output) = run(shell, mode, 0);
                assert_eq!(output.status.code(), Some(255), "{mode}: {output:?}");
                assert_eq!(output.stdout, b"PAYLOAD_START\nPAYLOAD_DONE\n");
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(error.contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"));
                assert!(error.contains("reason=exited,admitted=1"));
                assert!(directory.path().join("receipt.supervisor.v1/result").is_file());
            }
        }
    }

    #[test]
    fn result_recovery_keeps_admission_identity_and_cleanup_requirements() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in [
                "before-admission",
                "missing",
                "wrong-build",
                "wrong-birth",
                "malformed",
                "mode",
                "hardlink",
                "record",
                "cleanup",
            ] {
                let (directory, output) = run(shell, mode, 0);
                assert_eq!(output.status.code(), Some(255), "{mode}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"),
                    "{mode}: {output:?}",
                );
                assert!(directory.path().join("receipt.supervisor.v1").is_dir());
                if mode == "before-admission" {
                    assert!(output.stdout.is_empty(), "{output:?}");
                    assert!(!directory.path().join("receipt.supervisor.v1/go").exists());
                } else if mode == "missing" {
                    assert_eq!(output.stdout, b"PAYLOAD_START\n");
                    assert!(
                        !directory
                            .path()
                            .join("receipt.supervisor.v1/result")
                            .exists()
                    );
                }
            }
        }
    }

    #[test]
    fn deadline_and_cancellation_still_override_a_finished_payload() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for (mode, expected) in [
                ("deadline", 137),
                ("cancelled", 143),
                ("exited-deadline", 137),
                ("exited-cancelled", 143),
            ] {
                let (_, output) = run(shell, mode, 0);
                assert_eq!(output.status.code(), Some(expected), "{mode}: {output:?}");
                assert_eq!(output.stdout, b"PAYLOAD_START\nPAYLOAD_DONE\n");
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!error.contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"));
                assert_eq!(
                    error.contains("RCH_RESULT_TEST_DEADLINE"),
                    matches!(mode, "deadline" | "exited-deadline")
                );
            }
        }
    }

    const WATCHDOG_FAULT: &str = r#"
rch_fixture_watchdog_fault() {
    [ "$RCH_WATCHDOG_TEST_MODE" = "$1" ] && [ -f "$RCH_WATCHDOG_TEST_ROOT/armed" ] || return 1
    : > "$RCH_WATCHDOG_TEST_ROOT/injected" || exit 98
}
rch_scope_launch_parent_alive() {
    rch_fixture_parent_alive || return 1
    if rch_fixture_watchdog_fault parent; then return 1; fi
}
rch_remote_leader_matches() {
    rch_fixture_leader_matches || return 1
    if rch_fixture_watchdog_fault leader; then return 1; fi
}
rch_scope_launch_clock() {
    rch_fixture_clock || return 1
    if rch_fixture_watchdog_fault clock; then return 1; fi
}
"#;

    fn run_watchdog(shell: &str, mode: &str) -> Output {
        let directory = tempfile::Builder::new()
            .prefix("scoped-watchdog-diagnostic-")
            .disable_cleanup(true)
            .tempdir()
            .expect("watchdog diagnostic fixture directory");
        let launch = include_str!("../src/remote_scoped_launch.sh");
        let process = include_str!("../src/remote_process.sh");
        let child_hooks = format!(
            "\n{}{}{}{WATCHDOG_FAULT}",
            alias(
                launch,
                "rch_scope_launch_parent_alive",
                "rch_fixture_parent_alive",
            ),
            alias(
                process,
                "rch_remote_leader_matches",
                "rch_fixture_leader_matches",
            ),
            alias(launch, "rch_scope_launch_clock", "rch_fixture_clock"),
        );
        // Fault only the in-group watchdog, after the actual payload starts.
        // The outside supervisor retains all of its production observations.
        let script = format!(
            r#"{PROTOCOL}
rch_policy_select_file() {{ rch_policy_file=; }}
rch_launch_source="$rch_launch_source"{}
exec 3>&2
rch_scope_launch_supervise "$RCH_WATCHDOG_TEST_ROOT/receipt" "$RCH_WATCHDOG_TEST_LIMIT" \
    RCH_WATCHDOG_TEST_DEADLINE 4343 /bin/sh -c '
        printf "PAYLOAD_START\n"
        : > "$RCH_WATCHDOG_TEST_ROOT/armed"
        case "$RCH_WATCHDOG_TEST_MODE" in
            signal) kill -KILL "$$";;
            control) sleep 0.5;;
            *) sleep 3;;
        esac
        printf "PAYLOAD_DONE\n"
    '
"#,
            shell_escape::unix::escape(child_hooks.into()),
        );
        let output = Command::new("/usr/bin/timeout")
            .args([
                "--signal=KILL",
                "15s",
                shell,
                "-c",
                &script,
                "rch-watchdog-observer",
            ])
            .env_remove("RCH_TIMING_SCALE")
            .env("RCH_WKR_BIN", rch_common::testing::worker_binary())
            .env("RCH_WATCHDOG_TEST_ROOT", directory.path())
            .env("RCH_WATCHDOG_TEST_MODE", mode)
            .env(
                "RCH_WATCHDOG_TEST_LIMIT",
                if mode == "deadline" { "1" } else { "0" },
            )
            .output()
            .expect("run the real watchdog with one failed check");
        assert_eq!(
            directory.path().join("injected").exists(),
            matches!(mode, "parent" | "leader" | "clock"),
            "watchdog fault missed its intended boundary: {shell}, {mode}: {output:?}",
        );
        output
    }

    #[test]
    fn watchdog_reports_the_failed_check_without_changing_exit_status() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in ["parent", "leader", "clock"] {
                let output = run_watchdog(shell, mode);
                assert_eq!(output.status.code(), Some(137), "{mode}: {output:?}");
                assert_eq!(output.stdout, b"PAYLOAD_START\n", "{output:?}");
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(
                    error.contains(&format!(
                        "RCH_SCOPED_COMPLETION_DETAIL:reason=watchdog-{mode}"
                    )),
                    "{mode}: {output:?}",
                );
                assert!(!error.contains("RCH_WATCHDOG_TEST_DEADLINE"));
                assert!(!error.contains("RCH_SCOPED_COMPLETION_UNCONFIRMED"));
            }
        }
    }

    #[test]
    fn ordinary_payload_exit_and_deadline_are_not_reported_as_watchdog_faults() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mode in ["control", "signal", "deadline"] {
                let output = run_watchdog(shell, mode);
                assert_eq!(
                    output.status.code(),
                    Some(if mode == "control" { 0 } else { 137 }),
                    "{mode}: {output:?}",
                );
                assert_eq!(
                    output.stdout,
                    if mode == "control" {
                        b"PAYLOAD_START\nPAYLOAD_DONE\n".as_slice()
                    } else {
                        b"PAYLOAD_START\n".as_slice()
                    },
                );
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!error.contains("reason=watchdog-"), "{mode}: {output:?}");
                assert_eq!(
                    error.contains("RCH_WATCHDOG_TEST_DEADLINE"),
                    mode == "deadline",
                    "{mode}: {output:?}",
                );
            }
        }
    }
}
