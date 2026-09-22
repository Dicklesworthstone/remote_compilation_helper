//! Explicit archival/recovery operator path. Never launches a worker/compiler.
use rabsd::coord::delivery_archive::{archive_delivery, parse_archive_key, restore_delivery};
use rabsd::coord::delivery_recovery::{DeliveryTrust, install_delivery_outputs};
use rabsd::coord::worker_delivery::{MAX_FRAME_BYTES, validate_request};
use rabsd::janitor::store::mount_and_reconcile;
use std::io::Read;
use std::path::Path;

const USAGE: &str = "rabs-delivery-cas archive CAS_ROOT REQUEST_JSON WORKER DELIVERY_DIR TRUST\n\
    rabs-delivery-cas restore CAS_ROOT ROOT_OBJECT REQUEST_JSON WORKER NEW_DIR TRUST\n\
    rabs-delivery-cas install REQUEST_JSON WORKER DELIVERY_DIR NEW_OUTPUT_DIR TRUST\n\
    TRUST is loopback or spki:<64 lowercase hex digits>.\n\
    Archive/restore use exclusive CAS ownership; stop the daemon or choose a separate store.\n\
    Install copies verified artifacts without a worker connection or CAS mount.\n\
    Complete matching restores/installs are verified and reused, never overwritten. Archive pins do not expire.\n\
    This does not publish an action, authorize reuse, or rerun compilation.";

fn trust(text: &str) -> Result<DeliveryTrust, String> {
    if text == "loopback" { return Ok(DeliveryTrust::Loopback); }
    let pin = text.strip_prefix("spki:").ok_or("TRUST must be loopback or spki:<digest>")?;
    let key = format!("{}:{pin}", rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN);
    let pin = parse_archive_key(&key)?.bytes;
    if pin == [0;32] { return Err("worker SPKI pin cannot be zero".to_owned()); }
    Ok(DeliveryTrust::PinnedWorker(pin))
}
fn request(path: &Path) -> Result<serde_json::Value, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_FRAME_BYTES as u64 {
        return Err("request must be a bounded regular JSON file".to_owned());
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_FRAME_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FRAME_BYTES { return Err("request exceeds its size limit".to_owned()); }
    let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    validate_request(&value).map_err(|e| e.to_string())?;
    Ok(value)
}
fn run(args: &[String]) -> Result<serde_json::Value, String> {
    match args.first().map(String::as_str) {
        Some("install") if args.len() == 6 => {
            let request = request(Path::new(&args[1]))?;
            let trust = trust(&args[5])?;
            Ok(install_delivery_outputs(&request, &args[2], Path::new(&args[3]),
                Path::new(&args[4]), trust)?.to_json())
        }
        Some("archive") if args.len() == 6 => {
            let request = request(Path::new(&args[2]))?;
            let trust = trust(&args[5])?;
            let cas = mount_and_reconcile(Path::new(&args[1]))?;
            Ok(archive_delivery(&cas,&request,&args[3],Path::new(&args[4]),trust)?.to_json())
        }
        Some("restore") if args.len() == 7 => {
            parse_archive_key(&args[2])?;
            let request = request(Path::new(&args[3]))?;
            let trust = trust(&args[6])?;
            let cas = mount_and_reconcile(Path::new(&args[1]))?;
            Ok(restore_delivery(&cas,&args[2],&request,&args[4],Path::new(&args[5]),trust)?.to_json())
        }
        _ => Err(USAGE.to_owned()),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}"); return;
    }
    match run(&args) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{}",serde_json::json!({"kind":"delivery-archive-error","reason":error,
                "reexecute":false,"publication_authorized":false}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trust_is_explicit_and_cannot_silently_downgrade() {
        assert!(matches!(trust("loopback"),Ok(DeliveryTrust::Loopback)));
        assert!(matches!(trust(&format!("spki:{}","01".repeat(32))),Ok(DeliveryTrust::PinnedWorker(_))));
        for bad in ["", "auto", "spki:", "spki:ABC", &format!("spki:{}","00".repeat(32))] {
            assert!(trust(bad).is_err());
        }
    }
}
