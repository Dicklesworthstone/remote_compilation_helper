//! D017 acceptance (Linux): a probe INSIDE the canonical namespace
//! observes only the canonical machine face — hostname `rabs` (UTS +
//! /proc view), `C.UTF-8` locale and `TZ=UTC` in env, and a /dev whose
//! every entry classifies as Approved. Violations would classify per
//! effect class via the same classifier the test drives.
//!
//! Executes real `bwrap` namespaces; skips loudly when unsupported.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::CanonicalMountPlan;
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::pseudo_files::{PseudoFileEffect, canonical_values, classify_device};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D017 acceptance; missing {:?}",
            support.missing_for_canonical()
        );
        None
    }
}

fn toolchain_dir() -> std::path::PathBuf {
    let cargo_path = std::env::var("CARGO").expect("cargo sets $CARGO for tests");
    std::path::Path::new(&cargo_path)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("<root>/bin/cargo")
        .to_path_buf()
}

/// ACCEPTANCE: the sandboxed probe sees only canonical values.
#[test]
fn sandboxed_probe_observes_only_canonical_machine_face() {
    let Some(support) = supported() else { return };

    let ws = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let plan = CanonicalMountPlan::new(toolchain_dir(), ws.path(), cargo_home.path(), home.path());
    let spec = plan.to_spec().unwrap();

    let script = "echo HOSTNAME=$(cat /proc/sys/kernel/hostname); \
                  echo LANG=$LANG; echo LC_ALL=$LC_ALL; echo TZ=$TZ; \
                  echo DEVICES=$(ls /dev | tr '\\n' ',')";
    let launch = build_canonical_argv(
        &spec,
        &support,
        "/bin/sh",
        &["-c".to_string(), script.to_string()],
    )
    .unwrap();
    let out = command_for(&launch).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "probe failed: {stdout}");

    let field = |key: &str| -> String {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(field("HOSTNAME"), canonical_values::HOSTNAME);
    assert_eq!(field("LANG"), canonical_values::LOCALE);
    assert_eq!(field("LC_ALL"), canonical_values::LOCALE);
    assert_eq!(field("TZ"), canonical_values::TIMEZONE);

    let devices: Vec<String> = field("DEVICES")
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    assert!(!devices.is_empty(), "the probe must actually see /dev");
    for device in &devices {
        assert_eq!(
            classify_device(device),
            PseudoFileEffect::Approved,
            "unapproved device visible in canonical /dev: {device} \
             (classified {:?})",
            classify_device(device)
        );
    }
}
