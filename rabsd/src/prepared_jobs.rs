//! Running-daemon prepared builds: a bounded execution driver and its UDS client.
//! The coordinator region owns every blocking executor through shutdown. A
//! client disconnect never drops a queued job or authorizes another execution.

mod wait;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::UnixStream;
use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabsd::coord::live::CoordLive;
use rabsd::coord::prepared_operation::PreparedOperationStore;
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const EXECUTORS: usize = 4;
const IDLE_WAIT: Duration = Duration::from_millis(100);
const CLIENT_BUDGET: Duration = Duration::from_secs(20);

struct Drivers {
    store: Arc<PreparedOperationStore>,
    stopped: Arc<AtomicBool>,
    threads: Vec<JoinHandle<Result<(), String>>>,
}

impl Drivers {
    fn start(store: Arc<PreparedOperationStore>, coord: Arc<CoordLive>) -> io::Result<Self> {
        let mut drivers = Self {
            store,
            stopped: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        };
        for index in 0..EXECUTORS {
            let store = Arc::clone(&drivers.store);
            let coord = Arc::clone(&coord);
            let stopped = Arc::clone(&drivers.stopped);
            let handle = std::thread::Builder::new()
                .name(format!("rabs-prepared-{index}"))
                .spawn(move || {
                    while !stopped.load(Ordering::Acquire) {
                        // The execution-only service belongs to this live
                        // coordinator, even though it grants no cache authority.
                        if !coord.available() || coord.authority().is_none() {
                            store.wait_for_work(IDLE_WAIT);
                            continue;
                        }
                        let claim = match store.claim_next() {
                            Ok(claim) => claim,
                            Err(error) => {
                                stopped.store(true, Ordering::Release);
                                let _ = store.stop();
                                return Err(format!("prepared job claim: {error}"));
                            }
                        };
                        let Some(claim) = claim else {
                            store.wait_for_work(IDLE_WAIT);
                            continue;
                        };
                        let outcome = crate::worker_exec::execute_prepared_operation(&claim);
                        if let Err(error) = claim.finish(outcome) {
                            stopped.store(true, Ordering::Release);
                            let _ = store.stop();
                            return Err(format!("prepared job completion: {error}"));
                        }
                    }
                    Ok(())
                })?;
            drivers.threads.push(handle);
        }
        Ok(drivers)
    }

    fn stop(&self) -> Option<String> {
        self.stopped.store(true, Ordering::Release);
        self.store.stop().err().map(|error| error.to_string())
    }

    fn join(&mut self, mut failure: Option<String>) -> Result<(), String> {
        // No executor is detached. Cancellation interrupts accept/admission or
        // sends the exact in-flight request's cancel and drains its result.
        for handle in self.threads.drain(..) {
            let result = handle
                .join()
                .unwrap_or_else(|_| Err("prepared executor panicked".into()));
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn finish(&mut self) -> Result<(), String> {
        let failure = self.stop();
        while self.threads.iter().any(|thread| !thread.is_finished()) {
            let mut wait = pin!(asupersync::time::sleep(
                asupersync::time::wall_now(),
                Duration::from_millis(10),
            ));
            poll_fn(|task| {
                // Shutdown has already cancelled this region. Mask only each
                // timer poll so Sleep parks instead of immediately completing
                // and spinning; siblings remain free to drain their resources.
                match asupersync::cx::Cx::current() {
                    Some(cx) => cx.masked(|| wait.as_mut().poll(task)),
                    None => wait.as_mut().poll(task),
                }
            })
            .await;
        }
        self.join(failure)
    }
}

impl Drop for Drivers {
    fn drop(&mut self) {
        if self.threads.is_empty() {
            return;
        }
        // Forced future drop still owns every executor. The ordinary shutdown
        // path awaits above; RAII cannot leave live OS threads detached.
        let failure = self.stop();
        if let Err(error) = self.join(failure) {
            eprintln!(
                "{}",
                json!({"kind":"prepared-executor-shutdown-error", "detail":error})
            );
        }
    }
}

pub(crate) fn coord_work(
    coord: Arc<CoordLive>,
    operations: Option<Arc<PreparedOperationStore>>,
) -> SubsystemWork {
    let authority_work = rabsd::coord::live::coord_work(Arc::clone(&coord));
    Box::new(move |cx, shutdown| {
        Box::pin(async move {
            let mut drivers = operations
                .map(|store| Drivers::start(store, coord))
                .transpose()
                .map_err(|error| format!("start prepared executors: {error}"))?;
            let result = authority_work(cx, shutdown).await;
            let stopped = match drivers.as_mut() {
                Some(drivers) => drivers.finish().await,
                None => Ok(()),
            };
            result.and(stopped)
        })
    })
}

fn invalid(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

fn request(args: &[String]) -> Result<Value, &'static str> {
    let id = args.get(1).ok_or("missing job ID")?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("job ID must be exactly 32 lowercase hexadecimal digits");
    }
    match args.first().map(String::as_str) {
        Some("--job-submit") if args.len() == 8 => Ok(json!({
            "kind":"prepared-submit", "operation":{
                "id":id, "address":args[2], "worker":args[3],
                "worker_spki_sha256":args[4], "bundle":args[5],
                "delivery":args[6], "output":args[7],
            },
        })),
        Some("--job-status") if args.len() == 2 => Ok(json!({
            "kind":"prepared-status", "operation_id":id,
        })),
        Some("--job-cancel") if args.len() == 2 => Ok(json!({
            "kind":"prepared-cancel", "operation_id":id,
        })),
        Some("--job-resume") if matches!(args.len(), 3 | 4) => Ok(json!({
            "kind":"prepared-resume", "operation_id":id,
            "delivery":args[2], "resume_from":args.get(3),
        })),
        Some("--job-acknowledge") if args.len() == 3 => Ok(json!({
            "kind":"prepared-acknowledge", "operation_id":id, "delivery":args[2],
        })),
        _ => Err("invalid prepared job arguments"),
    }
}

fn remaining(until: Instant) -> io::Result<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|budget| !budget.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "daemon job exchange deadline"))
}

async fn write_frame(stream: &mut UnixStream, value: &Value, until: Instant) -> io::Result<()> {
    remaining(until)?;
    let mut frame = serde_json::to_vec(value)?;
    if frame.len() > rabsd::edge::server::MAX_FRAME_BYTES {
        return Err(invalid("job request exceeds daemon frame limit"));
    }
    frame.push(b'\n');
    AsyncWriteExt::write_all(stream, &frame).await?;
    remaining(until)?;
    Ok(())
}

async fn read_frame(stream: &mut UnixStream, until: Instant) -> io::Result<Value> {
    let mut frame = Vec::new();
    let mut byte = [0];
    loop {
        remaining(until)?;
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            remaining(until)?;
            return serde_json::from_slice(&frame).map_err(Into::into);
        }
        if frame.len() == rabsd::edge::server::MAX_FRAME_BYTES {
            return Err(invalid("job response exceeds daemon frame limit"));
        }
        frame.push(byte[0]);
    }
}

fn exchange(socket: &str, request: &Value) -> io::Result<Value> {
    let until = Instant::now() + CLIENT_BUDGET;
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| io::Error::other(format!("job client runtime: {error:?}")))?;
    runtime.block_on(exchange_until(UnixStream::connect(socket), request, until))
}

async fn exchange_until(
    connect: impl Future<Output = io::Result<UnixStream>>,
    request: &Value,
    until: Instant,
) -> io::Result<Value> {
    // The connection itself is nonblocking and lives inside the same timeout
    // as the handshake and reply. A full daemon backlog cannot evade the bound.
    asupersync::time::timeout(asupersync::time::wall_now(), remaining(until)?, async {
        let mut stream = connect.await?;
        exchange_frames(&mut stream, request, until).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "daemon job exchange deadline"))?
}

async fn exchange_frames(
    stream: &mut UnixStream,
    request: &Value,
    until: Instant,
) -> io::Result<Value> {
    write_frame(
        stream,
        &json!({
            "kind":"hello", "transport":{"minimum_compatible":1,"current":1},
            "application":{"minimum_compatible":1,"current":1},
        }),
        until,
    )
    .await?;
    let hello = read_frame(stream, until).await?;
    if hello["kind"] != "hello-ok" || hello["transport"] != 1 || hello["application"] != 1 {
        return Err(invalid(format!("daemon job handshake refused: {hello}")));
    }
    write_frame(stream, request, until).await?;
    let reply = read_frame(stream, until).await?;
    if !matches!(
        reply["kind"].as_str(),
        Some("prepared-operation" | "prepared-operation-error" | "prepared-completion")
    ) {
        return Err(invalid(
            "unexpected daemon job reply; inspect the same job ID",
        ));
    }
    if reply["kind"] == "prepared-operation" {
        let expected_id = request.get("operation_id").or_else(|| {
            request
                .get("operation")
                .and_then(|operation| operation.get("id"))
        });
        if reply["operation"].get("id") != expected_id {
            return Err(invalid(
                "daemon job reply has a different operation identity",
            ));
        }
    }
    if reply["kind"] == "prepared-completion" {
        let expected_id = request.get("operation_id");
        if request["kind"] != "prepared-completion"
            || expected_id.is_none()
            || reply.get("operation_id") != expected_id
            || reply["completion"].get("operation_id") != expected_id
            || reply["completion"].get("request_sha256") != request.get("request_sha256")
            || reply["publication_authorized"] != false
            || reply["reexecute"] != false
        {
            return Err(invalid("daemon completion differs from the selected read-only request"));
        }
    } else if request["kind"] == "prepared-completion"
        && reply["kind"] != "prepared-operation-error"
    {
        return Err(invalid("daemon returned status instead of a verified completion"));
    }
    remaining(until)?;
    Ok(reply)
}

pub(crate) fn run(args: &[String], socket: &str) -> i32 {
    if args.first().is_some_and(|arg| arg == "--job-wait") {
        return wait::run(args, socket);
    }
    let request = match request(args) {
        Ok(request) => request,
        Err(detail) => {
            eprintln!(
                "rabsd: {detail}\n\
                --job-submit <id32hex> <listen-IP:port> <worker> <pin> <bundle> <delivery> <output>\n\
                --job-status <id32hex>\n\
                --job-wait <id32hex> [timeout-seconds]\n\
                --job-cancel <id32hex>\n\
                --job-resume <id32hex> <new-delivery> [old-prefix-directory]\n\
                --job-acknowledge <id32hex> <owned-delivery>\n\
                Paths must be absolute; reuse the same job ID to inspect an uncertain response."
            );
            return 2;
        }
    };
    match exchange(socket, &request) {
        Ok(reply) => {
            let code = i32::from(reply["kind"] == "prepared-operation-error");
            let result = writeln!(io::stdout().lock(), "{reply}");
            if let Err(error) = result {
                eprintln!(
                    "rabsd: job reply could not be written: {error}; inspect job {}",
                    args[1]
                );
                return 1;
            }
            code
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({
                    "kind":"prepared-client-error", "operation_id":args[1],
                    "detail":error.to_string(), "outcome_unconfirmed":true, "reexecute":false,
                })
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_deadline_covers_a_pending_connection_and_drops_it() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        struct PendingConnect(Arc<AtomicBool>);
        impl Future for PendingConnect {
            type Output = io::Result<UnixStream>;
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Pending
            }
        }
        impl Drop for PendingConnect {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let result = runtime.block_on(exchange_until(
            PendingConnect(Arc::clone(&dropped)),
            &json!({"kind":"prepared-status"}),
            Instant::now() + Duration::from_millis(10),
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn normal_executor_shutdown_yields_while_owned_threads_finish() {
        use std::task::Poll;
        let root = tempfile::tempdir().unwrap();
        let store = PreparedOperationStore::open(&root.path().join("operations")).unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            wait.recv_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())
        });
        let mut drivers = Drivers {
            store,
            stopped: Arc::new(AtomicBool::new(false)),
            threads: vec![thread],
        };
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let mut released = false;
        runtime
            .block_on(async {
                let mut finishing = pin!(drivers.finish());
                poll_fn(|cx| match finishing.as_mut().poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => {
                        if !released {
                            // This sibling work can release the executor only if
                            // shutdown has yielded instead of joining synchronously.
                            release.send(()).unwrap();
                            released = true;
                        }
                        Poll::Pending
                    }
                })
                .await
            })
            .unwrap();
        assert!(released);
        assert!(drivers.threads.is_empty());
    }

    #[test]
    fn job_client_requires_stable_identity_and_explicit_resume() {
        let id = "0123456789abcdef0123456789abcdef";
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>()
        };
        let resume = request(&args(&["--job-resume", id, "/new", "/old"])).unwrap();
        assert_eq!(resume["kind"], "prepared-resume");
        assert_eq!(resume["operation_id"], id);
        assert_eq!(resume["resume_from"], "/old");
        let acknowledge = request(&args(&["--job-acknowledge", id, "/old"])).unwrap();
        assert_eq!(acknowledge["kind"], "prepared-acknowledge");
        assert_eq!(acknowledge["delivery"], "/old");
        for malformed in [
            args(&["--job-status", "1"]),
            args(&["--job-submit", id]),
            args(&["--job-resume", id]),
            args(&["--job-cancel", id, "/extra"]),
            args(&["--job-acknowledge", id]),
        ] {
            assert!(request(&malformed).is_err());
        }
    }
}
