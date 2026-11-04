//! Explicit, host-local Cargo root admission; separate from the worker daemon.

fn main() {
    if let Some(info) = rabs_protocol::release_authorization::build_info_for_args(
        "rabs-cargo-root",
        std::env::args_os().skip(1),
    ) {
        println!("{info}");
        return;
    }

    #[cfg(target_os = "linux")]
    rabs_wkr::root_admission::main_entry(std::env::args_os().skip(1).collect());

    #[cfg(not(target_os = "linux"))]
    {
        if std::env::args().nth(1).as_deref() == Some("--version") {
            println!("rabs-cargo-root {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        eprintln!("rabs-cargo-root: managed local roots require Linux cgroup v2");
        std::process::exit(2);
    }
}
