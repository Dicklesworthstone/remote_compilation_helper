//! Locate the deployed `rch-wkr` from a worker-side shell snippet.
//!
//! Worker-side protocol logic is Rust in `rch-wkr` subcommands (AGENTS.md
//! RULE 0.75: Rust only). Snippets sent over SSH run `rch_wkr_locate`, then
//! call `"$RCH_WKR" <subcommand>`. The candidates and their order match the
//! capability probe (`capability_probe::remote_worker_binary_paths`), so the
//! binary a snippet runs is the one admission already vetted. Git for Windows
//! workers use the native `.exe` under the same home.
//!
//! `RCH_WKR_BIN`, when set, names the exact binary instead. Tests point it at
//! the freshly built `rch-wkr`; nothing in production sets it.

/// POSIX sh: defines `rch_wkr_locate`, which sets `RCH_WKR` to the deployed
/// binary and returns 0, or clears it and returns 127 when none is installed.
/// Callers must refuse with their own marker on failure, never fall back.
pub const WKR_LOCATE_SHELL: &str = include_str!("wkr_locate.sh");

#[cfg(test)]
mod tests {
    use super::WKR_LOCATE_SHELL;

    #[cfg(unix)]
    fn locate(home: &std::path::Path, bin: Option<&std::path::Path>) -> (i32, String) {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg(format!(
                "{WKR_LOCATE_SHELL}\nrch_wkr_locate; status=$?; printf '%s' \"$RCH_WKR\"; exit $status"
            ))
            .env("HOME", home)
            .env_remove("RCH_WKR_BIN");
        if let Some(bin) = bin {
            command.env("RCH_WKR_BIN", bin);
        }
        let output = command.output().expect("run sh");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn explicit_binary_must_exist_and_be_executable() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join("wkr");
        assert_eq!(locate(home.path(), Some(&bin)).0, 127, "missing binary");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(locate(home.path(), Some(&bin)).0, 127, "not executable");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            locate(home.path(), Some(&bin)),
            (0, bin.to_string_lossy().into_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn home_install_is_found_when_no_system_binary_exists() {
        use std::os::unix::fs::PermissionsExt as _;
        if std::path::Path::new("/usr/local/bin/rch-wkr").exists() {
            // The system location wins by design; this host cannot isolate
            // the home candidate.
            return;
        }
        let home = tempfile::tempdir().unwrap();
        assert_eq!(locate(home.path(), None).0, 127);
        let bin = home.path().join(".local/bin/rch-wkr");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            locate(home.path(), None),
            (0, bin.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn candidates_match_the_capability_probe_order() {
        let paths = crate::capability_probe::remote_worker_binary_paths("u", None);
        assert_eq!(paths, ["/usr/local/bin/rch-wkr", "~/.local/bin/rch-wkr"]);
        let system = WKR_LOCATE_SHELL.find("/usr/local/bin/rch-wkr").unwrap();
        let home = WKR_LOCATE_SHELL.find("/.local/bin/rch-wkr\"").unwrap();
        assert!(system < home);
        assert!(WKR_LOCATE_SHELL.contains("/.local/bin/rch-wkr.exe"));
    }
}
