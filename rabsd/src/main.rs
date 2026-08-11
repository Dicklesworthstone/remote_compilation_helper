//! `rabsd` — the RABS edge+coordinator daemon binary (bead S1; the
//! bridge plan's first process). Boots the real asupersync runtime
//! island via `rabs_asupersync::daemon_runtime` and prints the
//! obligation-accounted shutdown receipt as its final line.
//!
//! CLI (manual parsing — the sub-10ms `--version`/`--check-config`
//! budget rules out heavyweight argument machinery):
//!
//! - `--version` / `--help`
//! - `--check-config` — parse + validate config, print resolved values
//! - `--run-for-ms N` — auto-shutdown after N ms (acceptance harness)
//! - default: run until SIGTERM/SIGINT (asupersync signal listener)
//!
//! Config: `[rabs]` table in the RCH config file (`$RABS_CONFIG` file
//! override first, else `~/.config/rch/config.toml`), env overrides
//! `RABS_SOCKET_PATH`/`RABS_LOG_LEVEL`. UNKNOWN `[rabs]` keys are a
//! typed refusal, not a silent ignore (config drift must be loud).

use rabs_asupersync::daemon_runtime::{DaemonRunOptions, run_daemon};
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, PartialEq, Eq)]
struct RabsConfig {
    socket_path: String,
    log_level: String,
}

impl Default for RabsConfig {
    fn default() -> Self {
        Self {
            socket_path: default_under_home(".cache/rch/rabsd.sock"),
            log_level: "info".to_string(),
        }
    }
}

fn default_under_home(rel: &str) -> String {
    std::env::var("HOME").map_or_else(|_| format!("/tmp/{rel}"), |h| format!("{h}/{rel}"))
}

/// Parse the `[rabs]` table. Unknown keys refuse loudly.
fn parse_config(text: &str) -> Result<RabsConfig, String> {
    let value: toml::Table = text.parse().map_err(|e| format!("config parse: {e}"))?;
    let mut config = RabsConfig::default();
    if let Some(rabs) = value.get("rabs") {
        let table = rabs
            .as_table()
            .ok_or_else(|| "[rabs] must be a table".to_string())?;
        for (key, entry) in table {
            match key.as_str() {
                "socket_path" => {
                    config.socket_path = entry
                        .as_str()
                        .ok_or_else(|| "rabs.socket_path must be a string".to_string())?
                        .to_string();
                }
                "log_level" => {
                    config.log_level = entry
                        .as_str()
                        .ok_or_else(|| "rabs.log_level must be a string".to_string())?
                        .to_string();
                }
                unknown => {
                    return Err(format!(
                        "unknown [rabs] config key {unknown:?} — refusing (config drift \
                         must be loud); known keys: socket_path, log_level"
                    ));
                }
            }
        }
    }
    Ok(config)
}

fn load_config() -> Result<RabsConfig, String> {
    let path = std::env::var("RABS_CONFIG")
        .unwrap_or_else(|_| default_under_home(".config/rch/config.toml"));
    let mut config = match std::fs::read_to_string(&path) {
        Ok(text) => parse_config(&text)?,
        Err(_) => RabsConfig::default(), // absent config = defaults (fail-open)
    };
    if let Ok(socket) = std::env::var("RABS_SOCKET_PATH") {
        config.socket_path = socket;
    }
    if let Ok(level) = std::env::var("RABS_LOG_LEVEL") {
        config.log_level = level;
    }
    Ok(config)
}

fn log_line(kind: &str, fields: &[(&str, &str)]) {
    let mut line = format!("{{\"v\":1,\"kind\":\"{kind}\"");
    for (key, value) in fields {
        line.push_str(&format!(",\"{}\":\"{}\"", key, value.replace('"', "'")));
    }
    line.push('}');
    eprintln!("{line}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("rabsd {VERSION}");
            return;
        }
        Some("--help") => {
            println!(
                "rabsd {VERSION} — RABS edge+coordinator daemon\n\
                 \n\
                 USAGE: rabsd [--version|--help|--check-config|--run-for-ms N]\n\
                 \n\
                 Runs until SIGTERM/SIGINT; prints the obligation-accounted\n\
                 shutdown receipt (JSON) as its final stdout line.\n\
                 Config: [rabs] table ($RABS_CONFIG or ~/.config/rch/config.toml);\n\
                 env: RABS_SOCKET_PATH, RABS_LOG_LEVEL."
            );
            return;
        }
        Some("--coord-status") => {
            // Live query over the real socket: connect, hello, status.
            use std::io::{BufRead, BufReader, Write};
            let config = load_config().unwrap_or_default();
            let stream = std::os::unix::net::UnixStream::connect(&config.socket_path);
            let Ok(mut stream) = stream else {
                eprintln!("rabsd: no daemon at {}", config.socket_path);
                std::process::exit(1);
            };
            let hello = "{\"kind\":\"hello\",\
                \"transport\":{\"minimum_compatible\":1,\"current\":1},\
                \"application\":{\"minimum_compatible\":1,\"current\":1}}";
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            let ok = stream.write_all(hello.as_bytes()).is_ok()
                && stream.write_all(b"\n").is_ok()
                && reader.read_line(&mut line).is_ok()
                && line.contains("hello-ok")
                && stream.write_all(b"{\"kind\":\"status\"}\n").is_ok();
            line.clear();
            if !ok || reader.read_line(&mut line).is_err() {
                eprintln!("rabsd: status query failed");
                std::process::exit(1);
            }
            print!("{line}");
            return;
        }
        Some("--shadow-report") => {
            let state_dir = std::env::var("RABS_STATE_DIR")
                .unwrap_or_else(|_| default_under_home(".cache/rch/rabs-state"));
            match rabsd::edge::shadow::shadow_report(std::path::Path::new(&state_dir)) {
                Ok(report) => {
                    println!("{report}");
                    return;
                }
                Err(error) => {
                    eprintln!("rabsd: shadow report: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("--check-config") => match load_config() {
            Ok(config) => {
                println!(
                    "{{\"v\":1,\"kind\":\"rabsd-config\",\"socket_path\":\"{}\",\"log_level\":\"{}\"}}",
                    config.socket_path, config.log_level
                );
                return;
            }
            Err(error) => {
                eprintln!("rabsd: config error: {error}");
                std::process::exit(1);
            }
        },
        _ => {}
    }

    let run_for = match args.first().map(String::as_str) {
        Some("--run-for-ms") => match args.get(1).and_then(|n| n.parse::<u64>().ok()) {
            Some(ms) => Some(Duration::from_millis(ms)),
            None => {
                eprintln!("rabsd: --run-for-ms requires a millisecond count");
                std::process::exit(2);
            }
        },
        Some(other) => {
            eprintln!("rabsd: unknown argument {other:?} (see --help)");
            std::process::exit(2);
        }
        None => None,
    };

    let config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("rabsd: config error: {error}");
            std::process::exit(1);
        }
    };
    log_line(
        "rabsd-boot",
        &[
            ("version", VERSION),
            ("socket_path", &config.socket_path),
            ("log_level", &config.log_level),
        ],
    );

    let marker = std::env::var("RABS_BOOT_MARKER")
        .unwrap_or_else(|_| default_under_home(".cache/rch/rabsd.boot"));
    // The live coordinator (S6): shared edge<->coord in-process, with
    // the structural authority split intact — the coord region owns its
    // availability; the edge only consults it.
    let coord = std::sync::Arc::new(rabsd::coord::live::CoordLive::new());
    let coord_for_region = std::sync::Arc::clone(&coord);
    let coord_work: rabs_asupersync::daemon_runtime::SubsystemWork =
        Box::new(move |cx, mut shutdown| {
            Box::pin(async move {
                if std::env::var("RABS_LAB_COORD_DOWN").is_ok() {
                    // Lab fault injection: the coord region dies at boot;
                    // edge consults must survive in degraded mode and the
                    // receipt must show this region abandoned.
                    return Err("lab: coord region down (RABS_LAB_COORD_DOWN)".to_string());
                }
                coord_for_region.mark_up();
                cx.trace("coord region up: leases + arbiter + singleflight mounted");
                shutdown.wait().await;
                coord_for_region.mark_down();
                Ok(())
            })
        });
    let options = DaemonRunOptions {
        run_for,
        boot_marker: Some(std::path::PathBuf::from(marker)),
        edge_work: Some(rabsd::edge::server::edge_work(
            rabsd::edge::server::EdgeServerConfig {
                socket_path: std::path::PathBuf::from(&config.socket_path),
                state_dir: std::path::PathBuf::from(
                    std::env::var("RABS_STATE_DIR")
                        .unwrap_or_else(|_| default_under_home(".cache/rch/rabs-state")),
                ),
                coord,
            },
        )),
        coord_work: Some(coord_work),
        ..DaemonRunOptions::default()
    };
    match run_daemon(options) {
        Ok(receipt) => {
            if receipt.recovered_from_unclean {
                log_line(
                    "rabsd-recovery",
                    &[("prior_incarnation", "died-unclean (boot marker present)")],
                );
            }
            println!("{}", receipt.to_json_line());
            std::process::exit(i32::from(!receipt.clean()));
        }
        Err(error) => {
            eprintln!("rabsd: {error}");
            std::process::exit(1);
        }
    }
}
