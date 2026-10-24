//! Explicit, host-local Cargo root admission; separate from the worker daemon.

#[cfg(target_os = "linux")]
fn main() {
    rabs_wkr::root_admission::main_entry(std::env::args_os().skip(1).collect());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rabs-cargo-root {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    eprintln!("rabs-cargo-root: managed local roots require Linux cgroup v2");
    std::process::exit(2);
}
