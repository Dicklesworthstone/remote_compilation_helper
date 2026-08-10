//! Render the host's Layer-0 config pack (bead B015 driver support):
//! assembles the B014 pack from ambient toolchain evidence and prints
//! the Cargo config to stdout, so the benchmark script can apply the
//! layer0 variant exactly as the pack defines it.
use rabs_key::layer0_pack::{PackEvidence, assemble};

fn main() {
    let rustc = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc -vV");
    let version = String::from_utf8_lossy(&rustc.stdout).into_owned();
    let release_line = version
        .lines()
        .find(|line| line.starts_with("release: "))
        .unwrap_or("release: unknown")
        .to_string();
    let mut linker_version_lines = Vec::new();
    for linker in ["wild", "ld.lld", "lld", "mold"] {
        if let Ok(output) = std::process::Command::new(linker).arg("--version").output()
            && output.status.success()
            && let Some(first) = String::from_utf8_lossy(&output.stdout).lines().next()
        {
            linker_version_lines.push(first.to_string());
        }
    }
    let evidence = PackEvidence {
        rustc_version_line: release_line,
        linker_version_lines,
        sccache_available: probe("sccache", "--version"),
        hakari_available: probe("cargo", "hakari"),
    };
    print!("{}", assemble(&evidence).render_config());
}

fn probe(bin: &str, arg: &str) -> bool {
    std::process::Command::new(bin)
        .arg(arg)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
