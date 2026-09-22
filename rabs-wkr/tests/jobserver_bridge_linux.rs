//! I004 acceptance (Linux): THE WORKER-SIDE JOBSERVER BRIDGE. A real
//! nested-make tree runs INSIDE the canonical namespace through a real
//! `rabs-wkr` TCP session. The tree deliberately uses PLAIN `make` in
//! recipes (not `$(MAKE)`), which without the bridge lets every
//! sub-master mint its OWN full-size pool — parallelism multiplying by
//! tree depth. With [`JobserverBridge`](rabs_wkr::jobserver::JobserverBridge)
//! all descendants share ONE fifo budget carried through the HOME
//! bind by PATH, sized by the coordinator's `jobserver_grant`: observed
//! leaf concurrency never exceeds the grant. Skips loudly where the
//! canonical namespace is unavailable.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn worker_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wkr")
}

fn toolchain_dir() -> String {
    let cargo = std::env::var("CARGO").expect("CARGO set");
    std::path::Path::new(&cargo)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("<root>/bin/cargo")
        .display()
        .to_string()
}

fn canonical_supported() -> bool {
    rabs_sandbox::canonical_namespace::HostIsolationSupport::probe()
        .missing_for_canonical()
        .is_empty()
}

struct OwnedWorker(Child);

impl Drop for OwnedWorker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl OwnedWorker {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().expect("worker status") {
                return status;
            }
            assert!(Instant::now() < deadline, "worker did not drain and exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn spawn_worker(addr: &str, state: &std::path::Path) -> OwnedWorker {
    OwnedWorker(Command::new(worker_bin())
        .args(["--coordinator", addr, "--worker-id", "i004-wkr", "--once"])
        .env("RABS_WORKER_STATE_DIR", state)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker"))
}

fn read_line<R: BufRead>(reader: &mut R) -> String {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read frame");
    assert!(n > 0, "worker closed the session unexpectedly");
    line.trim_end().to_string()
}

/// Maximum number of simultaneously-open [start, end) intervals
/// (nanosecond timestamps, one pair per leaf job, file order preserved).
fn max_concurrency(intervals: &[(u128, u128)]) -> u32 {
    let mut starts: Vec<u128> = intervals.iter().map(|(s, _)| *s).collect();
    let mut ends: Vec<u128> = intervals.iter().map(|(_, e)| *e).collect();
    starts.sort_unstable();
    ends.sort_unstable();
    let (mut live, mut max, mut ei) = (0u32, 0u32, 0usize);
    for &s in &starts {
        while ei < ends.len() && ends[ei] <= s {
            live -= 1;
            ei += 1;
        }
        live += 1;
        max = max.max(live);
    }
    max
}

#[test]
fn nested_make_tree_respects_the_worker_grant() {
    if !canonical_supported() {
        eprintln!("SKIP: canonical namespace unavailable on this host");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let state = tempfile::tempdir().unwrap();
    let mut worker = spawn_worker(&addr, &state.path().join("journal"));

    listener.set_nonblocking(true).unwrap();
    let (stream, _peer) = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "worker connection deadline");
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => panic!("accept: {e}"),
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    // Handshake.
    let hello = read_line(&mut reader);
    assert!(hello.contains("worker-hello"), "{hello}");
    writeln!(writer, "{{\"kind\":\"session-ok\",\"session_id\":9}}").unwrap();

    // The nested tree: three PLAIN sub-makes x three leaves each. Every
    // leaf stamps ONE atomic "start end" line at exit into the shared
    // file, so cross-sub-make concurrency is measurable host-side
    // without interleaved-append corruption.
    let toolchain = toolchain_dir();
    let workspace = tempfile::tempdir().unwrap();
    // This is legal source, not a worker runtime directory reservation.
    // Previously it prevented the actual executor from starting at all.
    std::fs::write(workspace.path().join(".rabs-jobserver"), b"source-owned").unwrap();
    std::fs::write(
        workspace.path().join("top.mk"),
        "all: s1 s2 s3\ns%:\n\t@make -s -f sub.mk job=$@\n",
    )
    .expect("top makefile");
    std::fs::write(
        workspace.path().join("sub.mk"),
        concat!(
            "job ?= x\n",
            "all: j1 j2 j3\n",
            "j%:\n",
            "\t@sh -c 's=$$(date +%s%N); sleep 0.5; e=$$(date +%s%N); ",
            "echo \"$$s $$e\" >> /__rabs/workspace/intervals.txt'\n",
        ),
    )
    .expect("sub makefile");

    let request = format!(
        "{{\"kind\":\"canonical-exec\",\"request_id\":4242,\
         \"program\":\"make\",\
         \"args\":[\"-s\",\"-f\",\"top.mk\",\"all\"],\
         \"toolchain_backing\":\"{}\",\
         \"workspace_backing\":\"{}\",\
         \"jobserver_grant\":2}}",
        toolchain,
        workspace.path().display(),
    );
    writeln!(writer, "{request}").unwrap();

    let result = read_line(&mut reader);
    assert!(result.contains("exec-result"), "{result}");
    assert!(result.contains("\"executed\":true"), "{result}");
    assert!(
        result.contains("\"exit_code\":0"),
        "nested make failed: {result}"
    );
    // CAPACITY PROOF: parse the leaf interval lines and sweep for peak
    // simultaneous jobs. One implicit slot plus C-1 FIFO tokens is C,
    // not C+1. Each nested make's implicit slot is the parent recipe's
    // occupied slot, not new capacity. The original declared grant is
    // the ceiling; a relaxed grant+2 bound would hide over-allocation.
    let raw = std::fs::read_to_string(workspace.path().join("intervals.txt"))
        .expect("leaf interval stamps visible host-side through the bind");
    let intervals: Vec<(u128, u128)> = raw
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next()) {
                (Some(s), Some(e)) => Some((s.parse::<u128>().ok()?, e.parse::<u128>().ok()?)),
                _ => None,
            }
        })
        .collect();
    assert_eq!(
        intervals.len(),
        9,
        "all nine leaves ran exactly once: {raw:?}"
    );
    for (s, e) in &intervals {
        assert!(e > s, "leaf end after start: ({s},{e})");
    }
    const GRANT: u32 = 2;
    let peak = max_concurrency(&intervals);
    assert!(
        peak <= GRANT,
        "worker capacity violated: {peak} concurrent leaves under a grant of {GRANT}"
    );

    // The source-owned name is unchanged; all coordination is outside
    // the workspace. The only added file is the declared test observation.
    assert_eq!(
        std::fs::read(workspace.path().join(".rabs-jobserver")).unwrap(),
        b"source-owned"
    );
    let mut names: Vec<_> = std::fs::read_dir(workspace.path()).unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names, [".rabs-jobserver", "intervals.txt", "sub.mk", "top.mk"]);

    let status = worker.wait();
    assert_eq!(status.code(), Some(0), "clean worker exit after --once");
}
