//! A caller that gave up before the worker printed must not crash the worker.
//! `println!` to a closed pipe panics, and the release profile aborts, which
//! made apport write a ~288 MB core per timed-out capability probe on trj.

#[cfg(unix)]
#[test]
fn printing_to_a_closed_pipe_exits_141_instead_of_aborting() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_rch-wkr"))
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run candidate worker");
    // Close the only reader before the worker writes its first line.
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("worker exits");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.signal(),
        None,
        "worker died by signal: {stderr}"
    );
    assert_eq!(output.status.code(), Some(141), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
