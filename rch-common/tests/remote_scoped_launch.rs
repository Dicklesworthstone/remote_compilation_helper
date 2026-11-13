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
