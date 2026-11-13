//! Exercise the shipped namespace adapter and matching native worker together.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::Instant;

const CONTROL: &str = include_str!("../src/hook/source_namespace_control.sh");

struct Fixture {
    directory: tempfile::TempDir,
    tools: PathBuf,
    worker: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("rch-native-namespace-adapter-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let tools = directory.path().join("tools");
        fs::create_dir(&tools).unwrap();
        symlink("/bin/sh", tools.join("sh")).unwrap();
        let worker = directory.path().join("matching ' worker");
        symlink(rch_common::testing::worker_binary(), &worker).unwrap();
        Self {
            directory,
            tools,
            worker,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn command(&self, contracts: &[&str]) -> Command {
        let arguments = contracts
            .iter()
            .map(|value| shell_escape::escape((*value).into()).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let adapter = format!(
            "{}\nset -- {arguments}\n{CONTROL}",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
        );
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &adapter])
            .env_clear()
            .env("PATH", &self.tools)
            .env("HOME", self.directory.path())
            .env("RCH_WKR_BIN", &self.worker)
            .env("RCH_TIMING_SCALE", "1")
            .env("TOKIO_WORKER_THREADS", "0")
            .env("TMPDIR", self.path("missing/tmp"))
            .env("RCH_LOG_FILE", self.path("missing/worker.log"));
        command
    }

    async fn run(&self, contract: &str, program: &str) -> Output {
        capture(self.command(&[contract]), program.as_bytes()).await
    }

    fn worker_script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path(name);
        let script = format!("#!/bin/sh\nset -eu\n{body}\n");
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

async fn capture(mut command: Command, program: &[u8]) -> Output {
    rch_common::ssh::capture_control_output(
        &mut command,
        Some(program),
        8192,
        131_072,
        Instant::now() + Duration::from_secs(22),
    )
    .await
    .expect("the native namespace adapter must settle within its outer deadline")
}

fn assert_reply(output: &Output, code: i32, stdout: &[u8]) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, stdout, "{output:?}");
}

fn quote(path: &Path) -> String {
    shell_escape::escape(path.to_str().unwrap().into()).into_owned()
}

#[tokio::test]
async fn native_adapter_preserves_all_exact_result_contracts_without_worker_tools() {
    let fixture = Fixture::new();
    for (contract, replies) in [
        ("RCH_TOPOLOGY_OK", vec!["RCH_TOPOLOGY_OK\n"]),
        (
            "RCH_SOURCE_CANCELLATION_SETTLED",
            vec!["RCH_SOURCE_CANCELLATION_SETTLED\n"],
        ),
        (
            "RCH_SOURCE_AUTHORITY_NAMESPACE",
            vec![
                "RCH_SOURCE_AUTHORITY_NAMESPACE current\n",
                "RCH_SOURCE_AUTHORITY_NAMESPACE legacy\n",
            ],
        ),
        (
            "RCH_SOURCE_AUTHORITY_DISCOVERY",
            vec![
                "RCH_SOURCE_AUTHORITY_DISCOVERY current\n",
                "RCH_SOURCE_AUTHORITY_DISCOVERY legacy\n",
                "RCH_SOURCE_AUTHORITY_DISCOVERY absent\n",
            ],
        ),
        ("RCH_SOURCE_INTENT_CANCEL", vec!["owned", "unowned"]),
        ("RCH_SOURCE_INTENT_RELEASED", vec!["released", "pending"]),
        ("RCH_SOURCE_INTENT_CANCELLED", vec!["cancelled", "pending"]),
        (
            "RCH_SOURCE_INTENT_CANCELLATION_STATE",
            vec!["cancellation", "pending"],
        ),
        ("RCH_SOURCE_INTENT_FINISHED", vec![""]),
    ] {
        for reply in replies {
            let program = format!(
                "printf 'diagnostic\\n' >&2\nprintf %s {}\n",
                shell_escape::escape(reply.into()),
            );
            let output = fixture.run(contract, &program).await;
            assert_reply(&output, 0, reply.as_bytes());
            assert_eq!(output.stderr, b"diagnostic\n");
            assert!(!fixture.path("missing").exists());
        }
    }
    let output = capture(fixture.command(&[]), b"printf 'RCH_TOPOLOGY_OK\\n'\n").await;
    assert_reply(&output, 0, b"RCH_TOPOLOGY_OK\n");
}

#[tokio::test]
async fn native_adapter_refuses_missing_workers_and_preserves_old_worker_refusal() {
    let fixture = Fixture::new();
    let mutation = fixture.path("must-not-run");
    let program = format!(
        "printf invoked > {}; printf 'RCH_TOPOLOGY_OK\\n'\n",
        quote(&mutation)
    );
    let mut command = fixture.command(&["RCH_TOPOLOGY_OK"]);
    command.env("RCH_WKR_BIN", fixture.path("missing-worker"));
    let output = capture(command, program.as_bytes()).await;
    assert_reply(&output, 73, b"");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE")
    );
    assert!(!mutation.exists());

    let old = fixture.worker_script(
        "old-worker",
        "[ \"$*\" = 'source-control --protocol v1 RCH_TOPOLOGY_OK' ] || exit 91\n\
         printf '%s\\n' \"error: unrecognized subcommand 'source-control'\" >&2\nexit 2",
    );
    let mut command = fixture.command(&["RCH_TOPOLOGY_OK"]);
    command.env("RCH_WKR_BIN", old);
    let output = capture(command, program.as_bytes()).await;
    assert_reply(&output, 2, b"");
    assert_eq!(
        output.stderr,
        b"error: unrecognized subcommand 'source-control'\n"
    );
    assert!(!mutation.exists());
}

#[tokio::test]
async fn native_adapter_rejects_unknown_contracts_and_invalid_scale_before_mutation() {
    let fixture = Fixture::new();
    let mutation = fixture.path("unexpected-mutation");
    let program = format!(
        "printf changed > {}; printf 'RCH_TOPOLOGY_OK\\n'\n",
        quote(&mutation),
    );
    for contracts in [
        vec!["unknown"],
        vec!["RCH_TOPOLOGY_OK", "surplus"],
        vec!["RCH_TOPOLOGY_OK; printf injected"],
    ] {
        let output = capture(fixture.command(&contracts), program.as_bytes()).await;
        assert_reply(&output, 73, b"");
        assert!(!mutation.exists());
    }
    for scale in ["", "0", "0.99", "11", "NaN", "inf", "1e999", "1; exit 0"] {
        let mut command = fixture.command(&["RCH_TOPOLOGY_OK"]);
        command.env("RCH_TIMING_SCALE", scale);
        let output = capture(command, program.as_bytes()).await;
        assert_reply(&output, 73, b"");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("RCH_TIMING_SCALE"),
            "scale={scale:?}: {output:?}",
        );
        assert!(!mutation.exists());
    }
}

#[tokio::test]
async fn native_adapter_does_not_repair_partial_or_failed_control_replies() {
    let fixture = Fixture::new();
    for (contract, printed) in [
        ("RCH_TOPOLOGY_OK", "RCH_TOPOLOGY_OK"),
        ("RCH_TOPOLOGY_OK", "RCH_TOPOLOGY_OK\\n\\n"),
        ("RCH_TOPOLOGY_OK", "RCH_TOPOLOGY_OK\\n\\000"),
        ("RCH_SOURCE_CANCELLATION_SETTLED", "RCH_TOPOLOGY_OK\\n"),
        (
            "RCH_SOURCE_AUTHORITY_NAMESPACE",
            "RCH_SOURCE_AUTHORITY_NAMESPACE absent\\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_DISCOVERY",
            "RCH_SOURCE_AUTHORITY_DISCOVERY current",
        ),
        ("RCH_SOURCE_INTENT_CANCEL", "owned\\n"),
        ("RCH_SOURCE_INTENT_RELEASED", "released\\000"),
        ("RCH_SOURCE_INTENT_CANCELLED", "cancelledpending"),
        ("RCH_SOURCE_INTENT_CANCELLATION_STATE", "cancellation\\n"),
        ("RCH_SOURCE_INTENT_CANCELLATION_STATE", "pending\\000"),
        ("RCH_SOURCE_INTENT_FINISHED", "finished"),
    ] {
        let program = format!("printf '{printed}'\n");
        let output = fixture.run(contract, &program).await;
        assert_reply(&output, 73, b"");
    }
    for (ending, status) in [
        ("exit 2", 2),
        ("exit 73", 73),
        ("exit 75", 75),
        ("kill -KILL $$", 137),
    ] {
        let output = fixture
            .run(
                "RCH_SOURCE_INTENT_CANCELLATION_STATE",
                &format!("printf 'original diagnostic\\n' >&2; printf cancellation; {ending}\n"),
            )
            .await;
        assert_reply(&output, status, b"");
        assert!(output.stderr.starts_with(b"original diagnostic\n"));
        if status == 137 {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(diagnostic.contains("RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED"));
            assert!(diagnostic.contains("signal_origin=unknown"));
        } else {
            assert_eq!(output.stderr, b"original diagnostic\n");
        }
    }
}

#[tokio::test]
async fn native_adapter_keeps_large_program_and_inherited_authority_on_stdin() {
    let fixture = Fixture::new();
    let evidence = fixture.path("authority ' descriptor");
    fs::write(&evidence, b"retained-authority\n").unwrap();
    let adapter = format!(
        "exec 7<{}\n{}\nset -- RCH_TOPOLOGY_OK\n{CONTROL}",
        quote(&evidence),
        rch_common::wkr_locate::WKR_LOCATE_SHELL,
    );
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &adapter])
        .env_clear()
        .env("PATH", &fixture.tools)
        .env("RCH_WKR_BIN", &fixture.worker)
        .env("RCH_TIMING_SCALE", "1")
        .env("TOKIO_WORKER_THREADS", "0")
        .env("TMPDIR", fixture.path("missing/tmp"));
    let mut program = format!("#{}\n", "x".repeat(2048)).repeat(100);
    program.push_str("IFS= read -r authority <&7\n[ \"$authority\" = retained-authority ] || exit 79\nprintf 'RCH_TOPOLOGY_OK\\n'\n");
    assert!(program.len() > 131_072);
    let output = capture(command, program.as_bytes()).await;
    assert_reply(&output, 0, b"RCH_TOPOLOGY_OK\n");
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(evidence).unwrap(), b"retained-authority\n");
    assert!(!fixture.path("missing").exists());
}

#[tokio::test]
async fn native_adapter_enforces_output_byte_caps_without_shortening_complete_diagnostics() {
    let fixture = Fixture::new();
    let diagnostic = "e".repeat(64);
    let program = format!(
        "i=0; while [ \"$i\" -lt 1024 ]; do printf %s {diagnostic} >&2; i=$((i + 1)); done\nprintf 'RCH_TOPOLOGY_OK\\n'\n",
    );
    let output = fixture.run("RCH_TOPOLOGY_OK", &program).await;
    assert_reply(&output, 0, b"RCH_TOPOLOGY_OK\n");
    assert_eq!(output.stderr, vec![b'e'; 65_536]);
    for program in [
        format!("{program}printf x >&2\n"),
        "printf 'RCH_TOPOLOGY_OK\\n'; i=0; while [ \"$i\" -lt 4096 ]; do printf x; i=$((i + 1)); done\n".to_string(),
    ] {
        let output = fixture.run("RCH_TOPOLOGY_OK", &program).await;
        assert_reply(&output, 73, b"");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("output exceeded its byte bound"),
            "{output:?}",
        );
    }
}
mod admission_timing {
    use std::fs::{self, File, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::process::Output;
    use std::time::{Duration, Instant};

    use rustix::fs::FlockOperation;
    use tokio::process::Command;
    use tokio::task::JoinHandle;

    struct Fixture {
        directory: tempfile::TempDir,
        worker: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                directory: tempfile::Builder::new()
                    .prefix("rch-source-admission-timing-")
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap(),
                worker: rch_common::testing::worker_binary(),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.directory.path().join(name)
        }

        fn attempts(&self) -> usize {
            match fs::read_to_string(self.path("attempts")) {
                Ok(text) => text.lines().count(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => panic!("read admission attempts: {error}"),
            }
        }

        fn start(
            &self,
            body: &str,
            retry_seconds: u64,
            scale: &str,
            timeout: Duration,
        ) -> AdmissionRun {
            let program = format!(
                "rch_source_attempt() {{ (\nset -eu\n\
                 exec 9<>{lock}\nflock -x 9\n\
                 printf 'attempt\\n' >> {counter}\n{body}\n); }}\n\
                 rch_admission_retry_seconds={retry_seconds}\n{locator}\n{admission}",
                lock = quote(&self.path("source.lock")),
                counter = quote(&self.path("attempts")),
                locator = rch_common::wkr_locate::WKR_LOCATE_SHELL,
                admission = include_str!("../src/hook/source_claim_admission.sh"),
            );
            let adapter = format!(
                "{}\nset -- RCH_SOURCE_INTENT_CANCEL\n{}",
                rch_common::wkr_locate::WKR_LOCATE_SHELL,
                include_str!("../src/hook/source_namespace_control.sh"),
            );
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", &adapter])
                .env("RCH_WKR_BIN", &self.worker)
                .env("RCH_TIMING_SCALE", scale)
                .env("LC_ALL", "C")
                .env("PATH", "/usr/bin:/bin");
            let deadline = Instant::now() + timeout;
            AdmissionRun {
                task: Some(tokio::spawn(async move {
                    rch_common::ssh::capture_control_output(
                        &mut command,
                        Some(program.as_bytes()),
                        8192,
                        131_072,
                        deadline.into(),
                    )
                    .await
                })),
            }
        }

        async fn wait_for_attempts(&self, run: &mut AdmissionRun, count: usize, timeout: Duration) {
            let deadline = Instant::now() + timeout;
            while self.attempts() < count {
                if run.task.as_ref().unwrap().is_finished() {
                    let output = run.finish().await;
                    panic!(
                        "admission ended before recovery: status={:?}, stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr),
                    );
                }
                assert!(Instant::now() < deadline, "admission made no progress");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        fn conflict_until_released(&self) -> String {
            format!(
                "if [ ! -e {ready} ]; then\n\
                   printf '%s\\n' 'RCH: durable source ownership: unfinished overlapping source owner' >&2\n\
                   exit 75\nfi\n\
                 printf 'retained admission\\n' > {mutation}\nprintf owned\n",
                ready = quote(&self.path("released")),
                mutation = quote(&self.path("admitted")),
            )
        }

        fn acquire_released_lock(&self) -> File {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.path("source.lock"))
                .unwrap();
            rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
                .expect("settled admission must release its real lock");
            file
        }
    }

    struct AdmissionRun {
        task: Option<JoinHandle<std::io::Result<Output>>>,
    }

    impl AdmissionRun {
        async fn finish(&mut self) -> Output {
            self.task
                .take()
                .unwrap()
                .await
                .expect("admission capture task")
                .expect("admission must complete within its bounded capture")
        }
    }

    impl Drop for AdmissionRun {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                // Dropping the capture future stops its owned observer group;
                // the native guardian independently observes owner death.
                task.abort();
            }
        }
    }

    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }

    fn assert_output(output: &Output, status: i32, stdout: &[u8]) {
        assert_eq!(
            output.status.code(),
            Some(status),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(output.stdout, stdout);
    }

    #[tokio::test]
    async fn scaled_window_accepts_recovery_after_old_six_attempt_ceiling() {
        let fixture = Fixture::new();
        let mut run = fixture.start(
            &fixture.conflict_until_released(),
            5,
            "2",
            Duration::from_secs(18),
        );
        fixture
            .wait_for_attempts(&mut run, 7, Duration::from_secs(12))
            .await;
        assert!(!fixture.path("admitted").exists());
        fs::write(fixture.path("released"), b"").unwrap();
        let output = run.finish().await;
        assert_output(&output, 0, b"owned");
        assert!(fixture.attempts() > 6);
        assert_eq!(
            fs::read(fixture.path("admitted")).unwrap(),
            b"retained admission\n",
        );
        let _released_lock = fixture.acquire_released_lock();
    }

    #[tokio::test]
    async fn default_elapsed_expiry_cannot_admit_after_late_owner_release() {
        let fixture = Fixture::new();
        let started = Instant::now();
        let mut run = fixture.start(
            &fixture.conflict_until_released(),
            5,
            "1",
            Duration::from_secs(9),
        );
        let output = run.finish().await;
        assert_output(&output, 75, b"");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unfinished overlapping source owner"),
        );
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(9));
        let attempts = fixture.attempts();
        assert!(attempts >= 2);
        assert!(!fixture.path("admitted").exists());
        {
            let _released_lock = fixture.acquire_released_lock();
            fs::write(fixture.path("released"), b"").unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fixture.attempts(), attempts);
        assert!(!fixture.path("admitted").exists());
    }

    #[tokio::test]
    async fn first_slow_success_keeps_its_enclosing_execution_allowance() {
        let fixture = Fixture::new();
        let started = Instant::now();
        let mut run = fixture.start("sleep 1.3\nprintf owned\n", 1, "1", Duration::from_secs(6));
        let output = run.finish().await;
        assert_output(&output, 0, b"owned");
        assert!(output.stderr.is_empty());
        assert!(started.elapsed() >= Duration::from_millis(1200));
        assert_eq!(fixture.attempts(), 1);
    }

    #[tokio::test]
    async fn late_mutating_success_is_unconfirmed_and_never_retried() {
        let fixture = Fixture::new();
        let body = format!(
            "if [ \"$(wc -l < {counter})\" -eq 1 ]; then\n\
               printf '%s\\n' 'RCH: durable source ownership: unfinished overlapping source owner' >&2\n\
               exit 75\nfi\n\
             printf 'retained admission\\n' > {mutation}\nsleep 1.3\nprintf owned\n",
            counter = quote(&fixture.path("attempts")),
            mutation = quote(&fixture.path("admitted")),
        );
        let mut run = fixture.start(&body, 2, "1", Duration::from_secs(6));
        let output = run.finish().await;
        // This attempt mutated. Retryable status 75 or its ready bytes would mistake
        // uncertain publication for a pre-grant ownership conflict.
        assert_output(&output, 73, b"");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains("unfinished overlapping source owner"));
        assert!(diagnostic.contains("RCH_SOURCE_ADMISSION_UNCONFIRMED"));
        assert_eq!(
            fs::read(fixture.path("admitted")).unwrap(),
            b"retained admission\n",
        );
        assert_eq!(fixture.attempts(), 2, "unconfirmed mutation was retried");
        let _released_lock = fixture.acquire_released_lock();
    }

    #[tokio::test]
    async fn non_conflict_statuses_and_failed_setup_are_terminal() {
        let fixture = Fixture::new();
        for status in [1, 73, 76, 137] {
            let before = fixture.attempts();
            let mut run = fixture.start(
                &format!("printf owned\nexit {status}\n"),
                2,
                "1",
                Duration::from_secs(5),
            );
            assert_output(&run.finish().await, status, b"");
            assert_eq!(fixture.attempts(), before + 1);
        }
        let before = fixture.attempts();
        let mut run = fixture.start("false\nprintf owned\n", 2, "1", Duration::from_secs(5));
        assert_output(&run.finish().await, 1, b"");
        assert_eq!(fixture.attempts(), before + 1);
    }
}
