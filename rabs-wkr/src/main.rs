//! `rabs-wkr` — the RABS trusted worker daemon binary (bead S5).
//!
//! Boots the asupersync runtime (same island machinery as `rabsd`),
//! connects to the coordinator over asupersync TCP, authenticates, and
//! serves `canonical-exec` requests through the proven rabs-sandbox
//! launcher. The worker OFFERS results; it never commits (R50 — no
//! commit type exists in this binary).
//!
//! CLI:
//!   rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]
//!   rabs-wkr --version | --help
//!
//! `--once` serves exactly one request then exits (acceptance harness).

use rabs_asupersync::asupersync::cx::Cx;
use rabs_asupersync::asupersync::io::{AsyncReadExt, AsyncWriteExt};
use rabs_asupersync::asupersync::net::TcpStream;
use rabs_asupersync::asupersync::runtime::RuntimeBuilder;
use rabs_wkr::session::{
    CanonicalExecRequest, execute_canonical, probe_capability, sample_pressure,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("rabs-wkr {VERSION}");
            return;
        }
        Some("--help") => {
            println!(
                "rabs-wkr {VERSION} — RABS trusted worker daemon\n\
                 USAGE: rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]\n\
                 Serves canonical-exec requests through the sandbox launcher; \
                 offers results, never commits (R50)."
            );
            return;
        }
        _ => {}
    }

    let mut coordinator = None;
    let mut worker_id = std::env::var("RABS_WORKER_ID").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .arg("-s")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "worker".to_string())
    });
    let mut once = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--coordinator" => coordinator = iter.next().cloned(),
            "--worker-id" => {
                if let Some(id) = iter.next() {
                    worker_id = id.clone();
                }
            }
            "--once" => once = true,
            other => {
                eprintln!("rabs-wkr: unknown argument {other:?} (see --help)");
                std::process::exit(2);
            }
        }
    }
    let Some(coordinator) = coordinator else {
        eprintln!("rabs-wkr: --coordinator <host:port> is required");
        std::process::exit(2);
    };

    let report = probe_capability(&worker_id);
    eprintln!(
        "{{\"v\":1,\"kind\":\"rabs-wkr-boot\",\"worker_id\":\"{}\",\"canonical\":{},\"slots\":{}}}",
        report.worker_id, report.canonical_namespace, report.slots
    );

    let runtime = match RuntimeBuilder::current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rabs-wkr: runtime build failed: {error:?}");
            std::process::exit(1);
        }
    };

    let handle = runtime.handle();
    let exit_code: i32 = runtime.block_on(async move {
        handle
            .spawn(async move {
                let cx = Cx::current().expect("runtime task Cx");
                match session_loop(&cx, &coordinator, &report, once).await {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("rabs-wkr: session ended: {error}");
                        1
                    }
                }
            })
            .await
    });
    std::process::exit(exit_code);
}

async fn read_frame(stream: &mut TcpStream) -> Option<String> {
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Some(String::from_utf8_lossy(&frame).into_owned());
                }
                frame.push(byte[0]);
                if frame.len() > 1 << 20 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

async fn write_frame(stream: &mut TcpStream, line: &str) -> bool {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.is_ok()
}

async fn session_loop(
    cx: &Cx,
    coordinator: &str,
    report: &rabs_wkr::session::CapabilityReport,
    once: bool,
) -> Result<(), String> {
    let addr = coordinator.to_string();
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {coordinator}: {e}"))?;
    cx.trace("rabs-wkr connected to coordinator");

    // Handshake: worker-hello with capability report.
    let hello = format!(
        "{{\"kind\":\"worker-hello\",\"worker_id\":{},\"canonical\":{},\"slots\":{},\"token_id\":1}}",
        json_string(&report.worker_id),
        report.canonical_namespace,
        report.slots,
    );
    if !write_frame(&mut stream, &hello).await {
        return Err("hello write failed".to_string());
    }
    let ack = read_frame(&mut stream)
        .await
        .ok_or_else(|| "no session-ok".to_string())?;
    if !ack.contains("session-ok") {
        return Err(format!("handshake refused: {ack}"));
    }

    let cargo_home = std::env::temp_dir().join(format!("rabs-wkr-ch-{}", std::process::id()));
    let home = std::env::temp_dir().join(format!("rabs-wkr-home-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&cargo_home);
    let _ = std::fs::create_dir_all(&home);

    // Steady state: exec requests, pings, and periodic heartbeats.
    loop {
        let _ = cx.checkpoint();
        let Some(frame) = read_frame(&mut stream).await else {
            return Ok(()); // coordinator closed: clean session end
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&frame) else {
            let _ = write_frame(&mut stream, "{\"kind\":\"error\",\"reason\":\"malformed\"}").await;
            continue;
        };
        match value.get("kind").and_then(|k| k.as_str()) {
            Some("ping") => {
                let pressure = sample_pressure(&cargo_home);
                let heartbeat = format!(
                    "{{\"kind\":\"heartbeat\",\"worker_id\":{},\"load_x100\":{},\"free_disk_mib\":{}}}",
                    json_string(&report.worker_id),
                    pressure.load_x100,
                    pressure.free_disk_mib,
                );
                if !write_frame(&mut stream, &heartbeat).await {
                    return Ok(());
                }
            }
            Some("canonical-exec") => {
                let request = parse_exec_request(&value)?;
                let result = execute_canonical(&request, &cargo_home, &home);
                let reply = format!(
                    "{{\"kind\":\"exec-result\",\"request_id\":{},\"exit_code\":{},\
                     \"stdout_sha256\":{},\"stderr_sha256\":{},\"executed\":{}}}",
                    result.request_id,
                    result.exit_code,
                    json_string(&result.stdout_sha256),
                    json_string(&result.stderr_sha256),
                    result.executed,
                );
                if !write_frame(&mut stream, &reply).await {
                    return Ok(());
                }
                if once {
                    return Ok(());
                }
            }
            _ => {
                let _ =
                    write_frame(&mut stream, "{\"kind\":\"error\",\"reason\":\"unknown-frame\"}")
                        .await;
            }
        }
    }
}

fn parse_exec_request(value: &serde_json::Value) -> Result<CanonicalExecRequest, String> {
    Ok(CanonicalExecRequest {
        request_id: value
            .get("request_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or("exec request missing request_id")?,
        program: value
            .get("program")
            .and_then(|p| p.as_str())
            .ok_or("exec request missing program")?
            .to_string(),
        args: value
            .get("args")
            .and_then(|a| a.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        toolchain_backing: value
            .get("toolchain_backing")
            .and_then(|t| t.as_str())
            .ok_or("exec request missing toolchain_backing")?
            .to_string(),
        workspace_backing: value
            .get("workspace_backing")
            .and_then(|w| w.as_str())
            .ok_or("exec request missing workspace_backing")?
            .to_string(),
    })
}
