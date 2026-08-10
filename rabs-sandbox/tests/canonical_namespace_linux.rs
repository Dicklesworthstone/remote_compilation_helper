//! D003 acceptance (Linux): the canonical namespace boots Cargo on a
//! fixture workspace, the StrictHermeticLinux boundary holds when probed
//! from INSIDE the namespace, and a nested action view is closed.
//!
//! These tests execute real `bwrap` namespaces, so they require a Linux
//! host whose [`HostIsolationSupport`] probe passes (unprivileged userns +
//! bubblewrap — the RABS fleet workers provide this). On any other host
//! they SKIP loudly rather than fake a pass: a typed skip is honest; a
//! mocked namespace would be worthless as acceptance evidence.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_namespace::{
    ActionViewSpec, Bind, CanonicalNamespaceSpec, HostIsolationSupport, build_action_view_argv,
    build_canonical_argv, command_for,
};
use rabs_sandbox::layout;

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run namespace acceptance tests; missing {:?}",
            support.missing_for_canonical()
        );
        None
    }
}

fn base_env() -> Vec<(String, String)> {
    vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("HOME".to_string(), layout::HOME.to_string()),
        ("TMPDIR".to_string(), layout::TMP.to_string()),
    ]
}

fn run(launch: &rabs_sandbox::canonical_namespace::NamespaceLaunch) -> std::process::Output {
    command_for(launch)
        .output()
        .expect("bwrap must be spawnable on a supported host")
}

/// The boundary, probed from INSIDE: hostname, env closure, pid namespace,
/// absent host paths, network isolation.
#[test]
fn strict_hermetic_boundary_holds_from_inside() {
    let Some(support) = supported() else { return };

    let ws = tempfile::tempdir().unwrap();
    let mut spec = CanonicalNamespaceSpec::new();
    spec.rw_binds.push(Bind::new(ws.path(), layout::WORKSPACE));
    spec.env = base_env();
    spec.env
        .push(("RABS_MARKER".to_string(), "boundary-test".to_string()));

    // One shell script asserts every boundary property and prints a
    // machine-checkable verdict per line.
    let script = r#"
        echo "hostname=$(hostname)"
        echo "marker=${RABS_MARKER:-ABSENT}"
        echo "leaked_home=${LEAK_CANARY:-ABSENT}"
        echo "pid=$$"
        [ -d /__rabs/workspace ] && echo "workspace=present"
        [ ! -e /root ] && [ ! -e /home ] && echo "host_homes=absent"
        [ -w /__rabs/tmp ] && echo "tmp=writable"
        if [ -d /sys/class/net ]; then ls /sys/class/net; else echo "sysnet=absent"; fi
    "#;
    let launch = build_canonical_argv(
        &spec,
        &support,
        "/bin/sh",
        &["-c".to_string(), script.to_string()],
    )
    .unwrap();
    assert!(launch.boundary.satisfies_strict_hermetic_linux());

    // Plant a canary in OUR env that must NOT leak through --clearenv.
    let out = {
        let mut cmd = command_for(&launch);
        cmd.env("LEAK_CANARY", "host-value");
        cmd.output().unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "boundary script failed: {stdout}");
    assert!(stdout.contains("hostname=rabs"), "uts: {stdout}");
    assert!(stdout.contains("marker=boundary-test"), "env set: {stdout}");
    assert!(stdout.contains("leaked_home=ABSENT"), "clearenv: {stdout}");
    assert!(stdout.contains("workspace=present"), "mounts: {stdout}");
    assert!(
        stdout.contains("host_homes=absent"),
        "closed view: {stdout}"
    );
    assert!(stdout.contains("tmp=writable"), "tmpfs: {stdout}");
    // Pid namespace: the shell is among the very first pids.
    let pid: i64 = stdout
        .lines()
        .find_map(|l| l.strip_prefix("pid="))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(pid <= 10, "expected near-init pid inside pid ns, got {pid}");
    // Network: no sysfs mounted (sysnet=absent) or only loopback listed.
    let net_ok = stdout.contains("sysnet=absent")
        || stdout
            .lines()
            .filter(|l| !l.contains('='))
            .all(|l| l.trim().is_empty() || l.trim() == "lo");
    assert!(net_ok, "network view must be empty/loopback: {stdout}");
}

/// ACCEPTANCE: the canonical namespace boots Cargo on a fixture workspace.
/// The worker's own active toolchain is bound read-only at the fixed
/// `/__rabs/toolchain` path, exactly as D005 will mount pinned toolchains.
#[test]
fn canonical_namespace_boots_cargo_on_fixture_workspace() {
    let Some(support) = supported() else { return };

    // Resolve the running toolchain directory from the cargo that invoked
    // this test process ($CARGO points into <toolchain>/bin/cargo).
    let cargo_path = std::env::var("CARGO").expect("cargo sets $CARGO for test processes");
    let toolchain_dir = std::path::Path::new(&cargo_path)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("toolchain layout <root>/bin/cargo")
        .to_path_buf();

    // Fixture workspace in a hidden backing dir.
    let ws = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ws.path().join("src")).unwrap();
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"rabs-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(
        ws.path().join("src/main.rs"),
        "fn main() { println!(\"canonical\"); }\n",
    )
    .unwrap();
    let out_backing = tempfile::tempdir().unwrap();
    let home_backing = tempfile::tempdir().unwrap();
    let cargo_home_backing = tempfile::tempdir().unwrap();

    let mut spec = CanonicalNamespaceSpec::new();
    spec.rw_binds.push(Bind::new(ws.path(), layout::WORKSPACE));
    spec.rw_binds.push(Bind::new(
        out_backing.path(),
        format!("{}/fixture", layout::OUT),
    ));
    spec.rw_binds
        .push(Bind::new(home_backing.path(), layout::HOME));
    spec.rw_binds
        .push(Bind::new(cargo_home_backing.path(), layout::CARGO_HOME));
    spec.ro_binds
        .push(Bind::new(&toolchain_dir, layout::TOOLCHAIN));
    spec.env = vec![
        (
            "PATH".to_string(),
            format!("{}/bin:/usr/bin:/bin", layout::TOOLCHAIN),
        ),
        ("HOME".to_string(), layout::HOME.to_string()),
        ("TMPDIR".to_string(), layout::TMP.to_string()),
        ("CARGO_HOME".to_string(), layout::CARGO_HOME.to_string()),
        (
            "CARGO_TARGET_DIR".to_string(),
            format!("{}/fixture", layout::OUT),
        ),
        ("RUSTUP_HOME".to_string(), "/nonexistent-rustup".to_string()),
    ];

    let launch = build_canonical_argv(
        &spec,
        &support,
        "cargo",
        &["build".to_string(), "--offline".to_string()],
    )
    .unwrap();
    assert!(launch.boundary.satisfies_strict_hermetic_linux());

    let out = run(&launch);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "cargo build inside canonical namespace failed:\n{stderr}"
    );
    // The artifact landed in the HIDDEN backing dir behind /__rabs/out.
    assert!(
        out_backing.path().join("debug/rabs-fixture").exists(),
        "built binary must appear in the backing target dir"
    );
}

/// The nested per-action view is CLOSED: a path visible in the canonical
/// namespace is absent in a view that does not declare it.
#[test]
fn action_view_hides_undeclared_inputs() {
    let Some(support) = supported() else { return };

    let declared = tempfile::tempdir().unwrap();
    std::fs::write(declared.path().join("input.txt"), "declared").unwrap();
    let undeclared = tempfile::tempdir().unwrap();
    std::fs::write(undeclared.path().join("secret.txt"), "undeclared").unwrap();
    let outdir = tempfile::tempdir().unwrap();

    let view = ActionViewSpec {
        input_binds: vec![Bind::new(declared.path(), layout::WORKSPACE)],
        output_binds: vec![Bind::new(outdir.path(), format!("{}/unit", layout::OUT))],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: layout::WORKSPACE.into(),
    };
    let script = format!(
        "[ -f /__rabs/workspace/input.txt ] && echo declared=present; \
         [ ! -e {} ] && echo undeclared_backing=absent; \
         [ ! -e /__rabs/repos ] && echo undeclared_visible=absent; \
         echo out=$(test -w /__rabs/out/unit && echo writable)",
        undeclared.path().display()
    );
    let launch =
        build_action_view_argv(&view, &support, "/bin/sh", &["-c".to_string(), script]).unwrap();
    let out = run(&launch);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "view script failed: {stdout}");
    assert!(stdout.contains("declared=present"), "{stdout}");
    assert!(stdout.contains("undeclared_backing=absent"), "{stdout}");
    assert!(stdout.contains("undeclared_visible=absent"), "{stdout}");
    assert!(stdout.contains("out=writable"), "{stdout}");
}
