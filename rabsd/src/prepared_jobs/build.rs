//! Capture once, submit one durable daemon operation, and replay its verified
//! completion. The client owns no worker reservation and never retries submit or
//! dispatch after a lost response. Leaving this client does not cancel the job.

use super::{exchange, invalid, wait};
use rabsd::coord::prepared_operation::{PreparedOperationSpec, PreparedPoolOperationSpec};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

const USAGE: &str = "usage: rabsd --job-build --prepare-from <source-root> <spec.json> <id32hex> (<listen-IP:port> <worker> <pin> | --worker-pool <pool.json>) <bundle> <delivery> <outputs>";
const MAX_POOL_FILE_BYTES: u64 = 16 * 1024;

enum Submission {
    Single(PreparedOperationSpec),
    Pool(PreparedPoolOperationSpec),
}

impl Submission {
    /// Preparation does not embed a worker identity or contact a worker. A
    /// validated pool member supplies only the existing local path/trust checks;
    /// the daemon selects and retains actual placement at admission.
    fn preparation(&self) -> PreparedOperationSpec {
        match self {
            Self::Single(spec) => spec.clone(),
            Self::Pool(spec) => PreparedOperationSpec {
                id: spec.id.clone(),
                address: spec.workers[0].address.clone(),
                worker: spec.workers[0].worker.clone(),
                worker_spki_sha256: spec.workers[0].worker_spki_sha256.clone(),
                bundle: spec.bundle.clone(),
                delivery: spec.delivery.clone(),
                output: spec.output.clone(),
            },
        }
    }

    fn request(&self) -> Value {
        match self {
            Self::Single(spec) => json!({"kind":"prepared-submit-allocated", "operation":spec}),
            Self::Pool(spec) => json!({"kind":"prepared-submit-pool", "operation":spec}),
        }
    }

    fn admits(&self, status: &Value) -> bool {
        let prepared = self.preparation();
        let placement = match self {
            Self::Single(spec) => {
                status["address"] == spec.address
                    && status["worker"] == spec.worker
                    && status["worker_spki_sha256"] == spec.worker_spki_sha256
            }
            Self::Pool(spec) => spec.workers.iter().any(|worker| {
                status["address"] == worker.address
                    && status["worker"] == worker.worker
                    && status["worker_spki_sha256"] == worker.worker_spki_sha256
            }),
        };
        placement
            && status["bundle"] == json!(prepared.bundle)
            && status["delivery"] == json!(prepared.delivery)
            && status["output"] == json!(prepared.output)
    }
}

fn pool_file(path: &Path) -> io::Result<Vec<rabsd::coord::prepared_operation::PreparedWorker>> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "worker pool must be an absolute file without traversal",
        ));
    }
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open, openat};
        let directories = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = File::from(open("/", directories, Mode::empty())?);
        let mut parts = path.components().skip(1).peekable();
        loop {
            let name = parts
                .next()
                .ok_or_else(|| invalid("worker pool path lacks a file name"))?;
            if parts.peek().is_none() {
                break File::from(openat(
                    &directory,
                    name.as_os_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
            directory = File::from(openat(
                &directory,
                name.as_os_str(),
                directories,
                Mode::empty(),
            )?);
        }
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_POOL_FILE_BYTES {
        return Err(invalid("worker pool must be a bounded ordinary JSON file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_POOL_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POOL_FILE_BYTES {
        return Err(invalid("worker pool exceeds its byte limit"));
    }
    serde_json::from_slice(&bytes).map_err(Into::into)
}

pub(super) fn pool_request(args: &[String]) -> io::Result<Value> {
    let [command, id, path, bundle, delivery, output] = args else {
        return Err(invalid(
            "usage: --job-submit-pool <id32hex> <pool.json> <bundle> <delivery> <outputs>",
        ));
    };
    if command != "--job-submit-pool"
        || [id, path, bundle, delivery, output]
            .into_iter()
            .any(|value| value.is_empty() || value.starts_with("--"))
    {
        return Err(invalid("invalid worker pool submission arguments"));
    }
    let spec = PreparedPoolOperationSpec {
        id: id.clone(),
        workers: pool_file(Path::new(path))?,
        bundle: bundle.into(),
        delivery: delivery.into(),
        output: output.into(),
    };
    spec.validate()?;
    Ok(Submission::Pool(spec).request())
}

fn arguments(args: &[String]) -> io::Result<(&str, &str, Submission)> {
    if args.first().map(String::as_str) != Some("--job-build")
        || args.get(1).map(String::as_str) != Some("--prepare-from")
    {
        return Err(invalid(USAGE));
    }
    let (source, specification, submission) = match args {
        [
            _,
            _,
            source,
            specification,
            id,
            flag,
            path,
            bundle,
            delivery,
            output,
        ] if flag == "--worker-pool" => {
            let request = pool_request(&[
                "--job-submit-pool".into(),
                id.clone(),
                path.clone(),
                bundle.clone(),
                delivery.clone(),
                output.clone(),
            ])?;
            (
                source,
                specification,
                Submission::Pool(serde_json::from_value(request["operation"].clone())?),
            )
        }
        [_, _, source, specification, _, _, _, _, _, _, _] => {
            if args[4..]
                .iter()
                .any(|value| value.is_empty() || value.starts_with("--"))
            {
                return Err(invalid(USAGE));
            }
            // Reuse the ordinary client's exact job-ID and positional contract.
            let mut submit = vec!["--job-submit".to_owned()];
            submit.extend_from_slice(&args[4..]);
            let request = super::request(&submit).map_err(invalid)?;
            (
                source,
                specification,
                Submission::Single(serde_json::from_value(request["operation"].clone())?),
            )
        }
        _ => return Err(invalid(USAGE)),
    };
    if [source, specification]
        .into_iter()
        .any(|value| value.is_empty() || value.starts_with("--"))
    {
        return Err(invalid(USAGE));
    }
    Ok((source, specification, submission))
}

fn admission_reply(reply: &Value, submission: &Submission) -> io::Result<()> {
    let id = &submission.preparation().id;
    if reply["kind"] != "prepared-operation"
        || reply["operation"]["id"] != *id
        || reply["publication_authorized"] != false
        || reply["reexecute"] != false
        || !submission.admits(&reply["operation"])
    {
        return Err(invalid(format!(
            "daemon did not admit the selected job: {reply}"
        )));
    }
    wait::fingerprint(&reply["operation"], id)?;
    Ok(())
}

pub(super) fn run(args: &[String], socket: &str) -> i32 {
    let (source, specification, submission) = match arguments(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("rabsd: {error}");
            return 2;
        }
    };
    let spec = submission.preparation();
    let mut submitted = false;
    let result = (|| -> io::Result<()> {
        // Fail before a potentially large capture when the configured daemon is
        // unavailable. An existing ID is inspection/recovery intent, never a
        // request to recapture inputs or silently start another operation.
        let status = exchange(
            socket,
            &json!({"kind":"prepared-status", "operation_id":spec.id}),
        )?;
        if status["kind"] != "prepared-operation-error" {
            return Err(invalid(
                "job ID already exists; use --job-status or --job-wait without recapturing",
            ));
        }
        let prepared = crate::worker_exec::prepare_daemon_build(&spec, source, specification)?;
        if prepared["kind"] != "prepared-source-template" || prepared["request_id"] != "allocate" {
            return Err(invalid(
                "source preparation did not retain allocation intent",
            ));
        }
        // Output the inspectable identity BEFORE admission. A closed console
        // cannot leave the caller unaware of the ID of work it just submitted.
        writeln!(
            io::stderr().lock(),
            "{}",
            json!({
                "kind":"prepared-build-ready", "operation_id":spec.id, "bundle":spec.bundle,
                "request_id":null, "execution_may_have_run":false,
                "publication_authorized":false, "reexecute":false,
            })
        )?;
        submitted = true; // From this point a lost reply is an unknown admission.
        let reply = exchange(socket, &submission.request())?;
        admission_reply(&reply, &submission)?;
        writeln!(io::stderr().lock(), "{reply}")?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = writeln!(
            io::stderr().lock(),
            "{}",
            json!({
                "kind":"prepared-client-error", "operation_id":spec.id,
                "detail":error.to_string(), "outcome_unconfirmed":submitted,
                "diagnostics_may_have_been_exposed":false, "reexecute":false,
            })
        );
        return 1;
    }
    // This existing native path verifies both complete retained streams before
    // emitting either, preserves the worker's exit status, and never reconnects
    // to a worker or repeats a compiler execution.
    wait::run(&["--job-wait".to_owned(), spec.id], socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        [
            "--job-build",
            "--prepare-from",
            "/source",
            "/spec.json",
            "0123456789abcdef0123456789abcdef",
            "127.0.0.1:7091",
            "worker",
            "pin",
            "/bundle",
            "/delivery",
            "/output",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn combined_build_requires_explicit_new_preparation_and_retained_job_identity() {
        let values = args();
        let (source, specification, submission) = arguments(&values).unwrap();
        assert_eq!((source, specification), ("/source", "/spec.json"));
        assert_eq!(submission.preparation().id, values[4]);
        for at in [0, 1, 4] {
            let mut changed = values.clone();
            changed[at] = "invalid".into();
            assert!(arguments(&changed).is_err());
        }
        assert!(arguments(&values[..10]).is_err());
        let mut recovery = values;
        recovery[1] = "--resume".into();
        assert!(arguments(&recovery).is_err());
    }

    #[test]
    fn admission_is_bound_to_the_original_job_and_has_no_publication_authority() {
        let values = args();
        let (_, _, submission) = arguments(&values).unwrap();
        let id = &values[4];
        let good = json!({"kind":"prepared-operation", "operation":{
            "id":id, "request_id":null, "request_sha256":"ab".repeat(32),
            "address":values[5], "worker":values[6], "worker_spki_sha256":values[7],
            "bundle":values[8], "delivery":values[9], "output":values[10]},
            "publication_authorized":false, "reexecute":false});
        admission_reply(&good, &submission).unwrap();
        for field in ["publication_authorized", "reexecute"] {
            let mut wrong = good.clone();
            wrong[field] = json!(true);
            assert!(admission_reply(&wrong, &submission).is_err());
        }
        let mut wrong = good;
        wrong["operation"]["id"] = json!("00".repeat(16));
        assert!(admission_reply(&wrong, &submission).is_err());
    }

    fn pool_values(root: &Path) -> (Vec<String>, Value) {
        let workers = json!([
            {"address":"127.0.0.1:7091", "worker":"one", "worker_spki_sha256":"11".repeat(32)},
            {"address":"127.0.0.1:7092", "worker":"two", "worker_spki_sha256":"22".repeat(32)}
        ]);
        let path = root.join("pool.json");
        std::fs::write(&path, serde_json::to_vec(&workers).unwrap()).unwrap();
        let values = [
            "--job-build".to_owned(),
            "--prepare-from".to_owned(),
            "/source".to_owned(),
            "/spec.json".to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
            "--worker-pool".to_owned(),
            path.to_str().unwrap().to_owned(),
            "/bundle".to_owned(),
            "/delivery".to_owned(),
            "/output".to_owned(),
        ]
        .into_iter()
        .collect();
        (values, workers)
    }

    #[test]
    fn pool_build_and_explicit_retry_carry_the_same_ordered_placement_intent() {
        let root = tempfile::tempdir().unwrap();
        let (values, workers) = pool_values(root.path());
        let (source, specification, submission) = arguments(&values).unwrap();
        assert_eq!((source, specification), ("/source", "/spec.json"));
        let request = submission.request();
        assert_eq!(request["kind"], "prepared-submit-pool");
        assert_eq!(request["operation"]["workers"], workers);
        let retry = vec![
            "--job-submit-pool".into(),
            values[4].clone(),
            values[6].clone(),
            values[7].clone(),
            values[8].clone(),
            values[9].clone(),
        ];
        assert_eq!(pool_request(&retry).unwrap(), request);
        assert!(pool_request(&retry[..5]).is_err());
        let mut wrong = values.clone();
        wrong[5] = "--resume".into();
        assert!(arguments(&wrong).is_err());

        // Preparation may inspect the first candidate, but the daemon can
        // legitimately select another one. Bind every retained path and all
        // three selected-worker fields; partial matches are insufficient.
        let mut status = workers[1].clone();
        for key in ["id", "bundle", "delivery", "output"] {
            status[key] = request["operation"][key].clone();
        }
        status["request_sha256"] = json!("ab".repeat(32));
        let reply = json!({"kind":"prepared-operation", "operation":status,
            "publication_authorized":false, "reexecute":false});
        admission_reply(&reply, &submission).unwrap();
        for key in [
            "worker",
            "worker_spki_sha256",
            "address",
            "bundle",
            "delivery",
            "output",
        ] {
            let mut wrong = reply.clone();
            wrong["operation"][key] = json!("other");
            assert!(admission_reply(&wrong, &submission).is_err(), "{key}");
        }
    }

    #[test]
    fn pool_files_and_candidate_sets_are_bounded_before_capture_or_admission() {
        let root = tempfile::tempdir().unwrap();
        let (values, workers) = pool_values(root.path());
        for malformed in [
            json!([]),
            json!([workers[0].clone(), workers[0].clone()]),
            json!({"workers":workers}),
        ] {
            std::fs::write(&values[6], serde_json::to_vec(&malformed).unwrap()).unwrap();
            assert!(arguments(&values).is_err());
        }
        std::fs::write(&values[6], vec![b' '; MAX_POOL_FILE_BYTES as usize + 1]).unwrap();
        assert!(arguments(&values).is_err());
        let mut relative = values;
        relative[6] = "pool.json".into();
        assert!(arguments(&relative).is_err());
        assert!(pool_file(root.path()).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn pool_file_rejects_links_and_special_files_without_waiting_for_a_writer() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let (values, _) = pool_values(root.path());
        let linked = root.path().join("linked.json");
        symlink(&values[6], &linked).unwrap();
        assert!(pool_file(&linked).is_err());
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        assert!(pool_file(&alias.join("pool.json")).is_err());
        let fifo = root.path().join("fifo.json");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        assert!(pool_file(&fifo).is_err());
    }
}
