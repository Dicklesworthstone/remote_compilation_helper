//! Running-daemon prepared builds: a bounded execution driver and its UDS client.
//! The coordinator region owns every blocking executor through shutdown. A
//! client disconnect never drops a queued job or authorizes another execution.

mod build;
mod follow;
pub(crate) mod live;
mod wait;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::UnixStream;
use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabsd::coord::live::CoordLive;
use rabsd::coord::prepared_operation::PreparedOperationStore;
use serde_json::{Value, json};
use std::cell::Cell;
use std::fmt::Display;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const IDLE_WAIT: Duration = Duration::from_millis(100);
const CLIENT_BUDGET: Duration = Duration::from_secs(20);
const COMPLETION_BUDGET: Duration = Duration::from_secs(300);
#[cfg(target_os = "linux")]
const ERROR_REPORT_BUDGET: Duration = Duration::from_millis(100);

/// A waiting client's own deadline, separate from the durable job's lifetime.
/// Completion shortens both subsequent verification and already-open writers;
/// neither a slow console nor a final replay starts a fresh wait budget.
pub(crate) struct ClientDeadline {
    until: Cell<Instant>,
    #[cfg(target_os = "linux")]
    pub(crate) output: rabsd::OutputDeadline,
}

impl ClientDeadline {
    pub(crate) fn new(until: Instant) -> Self {
        Self {
            until: Cell::new(until),
            #[cfg(target_os = "linux")]
            output: rabsd::OutputDeadline::new(until),
        }
    }

    pub(crate) fn get(&self) -> Instant {
        let until = self.until.get();
        #[cfg(target_os = "linux")]
        let until = until.min(self.output.get());
        until
    }

    fn limit(&self, until: Instant) {
        let until = self.get().min(until);
        self.until.set(until);
        #[cfg(target_os = "linux")]
        self.output.limit(until);
    }

    pub(crate) fn complete(&self) -> Instant {
        self.limit(Instant::now() + COMPLETION_BUDGET);
        self.get()
    }
}

/// Own only this reader's console descriptions. The ordinary process signal
/// dispositions remain intact; no job cancellation, result recovery or retry
/// is attached to either writer's lifetime.
fn with_client_console<T>(
    deadline: &ClientDeadline,
    work: impl FnOnce(&mut dyn Write, &mut dyn Write) -> io::Result<T>,
) -> io::Result<T> {
    with_stopped_client_console(deadline, &AtomicBool::new(false), work)
}

/// Direct clients share the same bounded console path while their operation's
/// signal bridge may revoke a stalled write. This flag never proves completion.
pub(crate) fn with_stopped_client_console<T>(
    deadline: &ClientDeadline,
    stopped: &AtomicBool,
    work: impl FnOnce(&mut dyn Write, &mut dyn Write) -> io::Result<T>,
) -> io::Result<T> {
    #[cfg(target_os = "linux")]
    {
        client_console_to(&io::stdout(), &io::stderr(), deadline, stopped, work)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "console cancelled",
            ));
        }
        remaining(deadline.get())?;
        work(&mut io::stdout().lock(), &mut io::stderr().lock())
    }
}

/// NDJSON follow has only a stdout sink. Its error reporter owns stderr
/// separately, so an unused closed or read-only stderr cannot reject a reader.
fn with_client_stdout<T>(
    deadline: &ClientDeadline,
    work: impl FnOnce(&mut dyn Write) -> io::Result<T>,
) -> io::Result<T> {
    #[cfg(target_os = "linux")]
    {
        let stopped = AtomicBool::new(false);
        let mut stdout = rabsd::ControlledOutput::with_deadline(
            &io::stdout(),
            &stopped,
            deadline.output.clone(),
        )?;
        work(&mut stdout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        remaining(deadline.get())?;
        work(&mut io::stdout().lock())
    }
}

pub(crate) fn write_client_status(message: impl Display) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        write_client_record_to(&io::stderr(), message, CLIENT_BUDGET)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut stderr = io::stderr().lock();
        writeln!(stderr, "{message}")?;
        stderr.flush()
    }
}

fn write_client_reply(message: impl Display) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        write_client_record_to(&io::stdout(), message, CLIENT_BUDGET)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{message}")?;
        stdout.flush()
    }
}

#[cfg(target_os = "linux")]
fn write_client_record_to(
    output: &impl std::os::fd::AsFd,
    message: impl Display,
    budget: Duration,
) -> io::Result<()> {
    let stopped = AtomicBool::new(false);
    let mut output = rabsd::ControlledOutput::new(output, &stopped, Instant::now() + budget)?;
    writeln!(output, "{message}")?;
    output.flush()
}

#[cfg(target_os = "linux")]
fn client_console_to<T>(
    stdout: &impl std::os::fd::AsFd,
    stderr: &impl std::os::fd::AsFd,
    deadline: &ClientDeadline,
    stopped: &AtomicBool,
    work: impl FnOnce(&mut dyn Write, &mut dyn Write) -> io::Result<T>,
) -> io::Result<T> {
    let mut stdout =
        rabsd::ControlledOutput::with_deadline(stdout, stopped, deadline.output.clone())?;
    let mut stderr =
        rabsd::ControlledOutput::with_deadline(stderr, stopped, deadline.output.clone())?;
    work(&mut stdout, &mut stderr)
}

/// Failure reporting gets a small, independent bound. Reusing the failed sink
/// or an unbounded eprintln! here could strand a client after its real timeout.
pub(crate) fn report_client_error(message: impl Display) {
    #[cfg(target_os = "linux")]
    {
        report_client_error_to(&io::stderr(), message);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
}

#[cfg(target_os = "linux")]
fn report_client_error_to(output: &impl std::os::fd::AsFd, message: impl Display) {
    let _ = write_client_record_to(output, message, ERROR_REPORT_BUDGET);
}

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
        for index in 0..drivers.store.concurrency().get() {
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
                        // A lost daemon owner may already have received every
                        // result byte. Recover those bytes on this filesystem
                        // thread before considering another network operation.
                        // No local recovery claim reaches the worker adapter.
                        match store.recover_next_local() {
                            Ok(Some(_)) => continue,
                            Ok(None) => {}
                            Err(error) => {
                                stopped.store(true, Ordering::Release);
                                let _ = store.stop();
                                return Err(format!("prepared local recovery: {error}"));
                            }
                        }
                        let claim = match store.claim_next() {
                            Ok(claim) => claim,
                            Err(error) => {
                                stopped.store(true, Ordering::Release);
                                let _ = store.stop();
                                return Err(format!("prepared job claim: {error}"));
                            }
                        };
                        let Some(mut claim) = claim else {
                            store.wait_for_work(IDLE_WAIT);
                            continue;
                        };
                        let outcome = crate::worker_exec::execute_prepared_operation(&mut claim);
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
        Some("--job-submit" | "--job-submit-allocated") if args.len() == 8 => Ok(json!({
            "kind":if args[0] == "--job-submit-allocated" { "prepared-submit-allocated" } else { "prepared-submit" }, "operation":{
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
        Some("--job-recover-local") if args.len() == 3 => Ok(json!({
            "kind":"prepared-recover-local", "operation_id":id, "delivery":args[2],
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
    // Local verification/installation can read a complete delivery twice. A
    // client timeout does not cancel the joined filesystem owner or retry it.
    let budget = if request["kind"] == "prepared-recover-local" {
        Duration::from_secs(300)
    } else {
        CLIENT_BUDGET
    };
    let until = Instant::now() + budget;
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| io::Error::other(format!("job client runtime: {error:?}")))?;
    rabs_asupersync::daemon_runtime::block_on_top_level(
        &runtime,
        exchange_until(UnixStream::connect(socket), request, until),
    )
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
        Some(
            "prepared-operation"
                | "prepared-operation-error"
                | "prepared-completion"
                | "prepared-preview"
        )
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
            return Err(invalid(
                "daemon completion differs from the selected read-only request",
            ));
        }
    } else if request["kind"] == "prepared-completion"
        && reply["kind"] != "prepared-operation-error"
    {
        return Err(invalid(
            "daemon returned status instead of a verified completion",
        ));
    }
    if reply["kind"] == "prepared-preview" {
        if request["kind"] != "prepared-preview"
            || reply.get("operation_id") != request.get("operation_id")
            || reply.get("request_sha256") != request.get("request_sha256")
            || reply.get("attempt") != request.get("attempt")
            || reply["complete"] != false
            || reply["publication_authorized"] != false
        {
            return Err(invalid(
                "daemon preview differs from the selected read-only attempt",
            ));
        }
    } else if request["kind"] == "prepared-preview" && reply["kind"] != "prepared-operation-error" {
        return Err(invalid(
            "daemon returned another operation instead of a preview",
        ));
    }
    remaining(until)?;
    Ok(reply)
}

pub(crate) fn run(args: &[String], socket: &str) -> i32 {
    if args.first().is_some_and(|arg| arg == "--job-build") {
        return build::run(args, socket);
    }
    if args.first().is_some_and(|arg| arg == "--job-wait") {
        return wait::run(args, socket);
    }
    if args.first().is_some_and(|arg| arg == "--job-follow") {
        return follow::run(args, socket);
    }
    let parsed = if args.first().is_some_and(|arg| arg == "--job-submit-pool") {
        build::pool_request(args)
    } else {
        request(args).map_err(invalid)
    };
    let request = match parsed {
        Ok(request) => request,
        Err(detail) => {
            report_client_error(format_args!(
                "rabsd: {detail}\n\
                --job-submit <id32hex> <listen-IP:port> <worker> <pin> <bundle> <delivery> <output>\n\
                --job-submit-allocated <id32hex> <listen-IP:port> <worker> <pin> <template-bundle> <delivery> <output>\n\
                --job-submit-pool <id32hex> <pool.json> <template-bundle> <delivery> <output>\n\
                --job-status <id32hex>\n\
                --job-wait [--live-stderr] <id32hex> [timeout-seconds]\n\
                --job-follow <id32hex> [timeout-seconds]\n\
                --job-cancel <id32hex>\n\
                --job-resume <id32hex> <new-delivery> [old-prefix-directory]\n\
                --job-acknowledge <id32hex> <owned-delivery>\n\
                --job-recover-local <id32hex> <owned-delivery>\n\
                Paths must be absolute; reuse the same job ID to inspect an uncertain response."
            ));
            return 2;
        }
    };
    match exchange(socket, &request) {
        Ok(reply) => {
            let code = i32::from(reply["kind"] == "prepared-operation-error");
            let result = write_client_reply(reply);
            if let Err(error) = result {
                report_client_error(format_args!(
                    "rabsd: job reply could not be written: {error}; inspect job {}",
                    args[1]
                ));
                return 1;
            }
            code
        }
        Err(error) => {
            report_client_error(json!({
                "kind":"prepared-client-error", "operation_id":args[1],
                "detail":error.to_string(), "outcome_unconfirmed":true, "reexecute":false,
            }));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader stays open without consuming a byte. A regressed blocking
    /// writer is released only after the watchdog has recorded failure, so the
    /// test never leaves a stranded native thread behind.
    #[cfg(target_os = "linux")]
    pub(super) fn with_full_pipe<T: Send + 'static>(
        case: impl FnOnce(std::fs::File) -> T + Send + 'static,
    ) -> T {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        use rustix::io::Errno;
        use rustix::pipe::{PipeFlags, pipe_with};
        use std::sync::mpsc;

        let (reader, writer) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC).unwrap();
        loop {
            match rustix::io::write(&writer, &[0x5a; 4096]) {
                Ok(count) => assert!(count > 0),
                Err(Errno::AGAIN) => break,
                result => panic!("unexpected output-pipe fill: {result:?}"),
            }
        }
        assert_eq!(rustix::io::write(&writer, b"x"), Err(Errno::AGAIN));
        let flags = fcntl_getfl(&writer).unwrap() & !OFlags::NONBLOCK;
        fcntl_setfl(&writer, flags).unwrap();
        let writer = std::fs::File::from(writer);
        let observed = writer.try_clone().unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let _ = sender.send(case(writer));
        });
        let result = receiver.recv_timeout(Duration::from_secs(5));
        drop(reader);
        thread.join().unwrap();
        assert_eq!(fcntl_getfl(&observed).unwrap(), flags);
        result.expect("prepared client stayed blocked after its output deadline")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn both_console_streams_observe_the_shortened_completion_bound() {
        for stdout_stalls in [false, true] {
            with_full_pipe(move |pipe| {
                let ordinary = tempfile::tempfile().unwrap();
                let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(30));
                let (stdout, stderr) = if stdout_stalls {
                    (&pipe, &ordinary)
                } else {
                    (&ordinary, &pipe)
                };
                let error = client_console_to(
                    stdout,
                    stderr,
                    &deadline,
                    &AtomicBool::new(false),
                    |stdout, stderr| {
                        deadline.limit(Instant::now() + Duration::from_millis(50));
                        let retained = deadline.get();
                        deadline.complete();
                        assert_eq!(
                            deadline.get(),
                            retained,
                            "completion must never renew a bound"
                        );
                        if stdout_stalls {
                            stdout.write_all(b"verified final stdout")
                        } else {
                            stderr.write_all(b"live stderr")
                        }
                    },
                )
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(ordinary.metadata().unwrap().len(), 0);
            });
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_client_can_report_to_the_same_full_stderr_without_hanging_again() {
        with_full_pipe(|pipe| {
            report_client_error_to(
                &pipe,
                json!({"kind":"prepared-client-error", "reexecute":false}),
            );
        });
    }

    #[test]
    fn allocated_submit_reuses_the_exact_job_and_paths_under_a_distinct_intent_api() {
        let mut values: Vec<String> = [
            "--job-submit-allocated",
            "0123456789abcdef0123456789abcdef",
            "127.0.0.1:7091",
            "worker",
            "ab",
            "/bundle",
            "/delivery",
            "/output",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let allocated = request(&values).unwrap();
        assert_eq!(allocated["kind"], "prepared-submit-allocated");
        values[0] = "--job-submit".into();
        let numeric = request(&values).unwrap();
        assert_eq!(numeric["kind"], "prepared-submit");
        assert_eq!(allocated["operation"], numeric["operation"]);
        assert!(request(&values[..7]).is_err());
    }

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
        let result = rabs_asupersync::daemon_runtime::block_on_top_level(
            &runtime,
            exchange_until(
                PendingConnect(Arc::clone(&dropped)),
                &json!({"kind":"prepared-status"}),
                Instant::now() + Duration::from_millis(10),
            ),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn configured_driver_pool_owns_and_joins_every_executor() {
        use rabsd::coord::prepared_operation::PreparedConcurrency;
        for width in [1, 8] {
            let root = tempfile::tempdir().unwrap();
            let store = PreparedOperationStore::open_with_concurrency(
                &root.path().join("operations"),
                PreparedConcurrency::new(width).unwrap(),
            )
            .unwrap();
            // An unavailable coordinator cannot dispatch; the real drivers
            // still exist and must all be stopped and joined by their owner.
            let mut drivers =
                Drivers::start(Arc::clone(&store), Arc::new(CoordLive::new())).unwrap();
            assert_eq!(drivers.threads.len(), width);
            let failure = drivers.stop();
            drivers.join(failure).unwrap();
            assert!(drivers.threads.is_empty());
            assert!(!store.capacity_status().unwrap().accepting);
        }
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
        rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async {
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
        let local = request(&args(&["--job-recover-local", id, "/old"])).unwrap();
        assert_eq!(
            local,
            json!({"kind":"prepared-recover-local", "operation_id":id, "delivery":"/old"})
        );
        assert!(request(&args(&["--job-recover-local", id, "/old", "/extra"])).is_err());
        for malformed in [
            args(&["--job-status", "1"]),
            args(&["--job-submit", id]),
            args(&["--job-resume", id]),
            args(&["--job-cancel", id, "/extra"]),
            args(&["--job-acknowledge", id]),
            args(&["--job-recover-local", id]),
        ] {
            assert!(request(&malformed).is_err());
        }
    }
}
