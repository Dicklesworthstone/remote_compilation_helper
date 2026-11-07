//! Authenticated S5 worker transport on native Asupersync TLS and ATP frames.
//!
//! The execution driver continues to consume bounded JSON records. On the
//! network, each record is an ATP Control frame inside a mutually authenticated
//! TLS connection; the JSON newline is an in-process adapter boundary only.
//! This adapter deliberately does not grant execution or publication authority.
//! Its peer identity is derived from the public key TLS actually authenticated,
//! never from the worker label or a self-asserted hello field.
//!
//! Edges use a separate canonical-operation ALPN and explicit Edge/Coordinator
//! key enrollment. Both planes share bounded ATP records and TLS machinery;
//! worker-session admission never grants access to the edge/coordinator plane.
//!
//! Partial read/write state AND deadlines belong to the connection, not a
//! disposable future. Trickled progress cannot renew an incomplete record's
//! budget. Cancellation and timeout return errors through the session driver's
//! ordinary process-drain/journal path; they never retransmit execution.

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, PrivateKey, RootCertStore, TlsAcceptor,
    TlsConnector, TlsConnectorBuilder, TlsStream,
};
use rabs_protocol::identity_store::{IdentityStore, TransportIdentity, TrustScope, VerifyVerdict};
use std::future::{Future, poll_fn};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};
use std::time::Duration;

/// Injectable runtime clock for transport deadlines (bead J011).
///
/// By default, [`runtime_transport_now`] queries the active Asupersync task
/// context (`Cx::current().map(|cx| cx.now())`), which automatically uses the
/// virtualized clock inside `LabRuntime`, and falls back to the runtime clock
/// only when polled outside a task context.
pub type TransportClock = fn() -> asupersync::types::Time;

/// Monotonic transport timestamp in nanoseconds on the active [`TransportClock`] (bead J011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransportInstant(pub u64);

impl TransportInstant {
    /// Nanoseconds since the transport clock epoch.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Saturating duration elapsed since `earlier`.
    #[must_use]
    pub const fn duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// Read the current Asupersync runtime time from the active [`Cx`](asupersync::cx::Cx)
/// when inside a task/lab context (bead J011).
#[must_use]
pub fn runtime_transport_now() -> asupersync::types::Time {
    asupersync::cx::Cx::current().map_or_else(asupersync::time::wall_now, |cx| cx.now())
}

/// Both endpoints must negotiate this exact protocol. There is no downgrade.
pub const WORKER_ALPN: &[u8] = b"rabs-worker-atp/1";
/// Canonical operations submitted by explicitly enrolled edges. Worker control
/// messages cannot negotiate this protocol, or vice versa.
pub const EDGE_COORDINATOR_ALPN: &[u8] = b"rabs-edge-coordinator-atp/1";

#[derive(Clone, Copy)]
enum PeerProtocol {
    Worker,
    EdgeCoordinator,
}

impl PeerProtocol {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Worker => WORKER_ALPN,
            Self::EdgeCoordinator => EDGE_COORDINATOR_ALPN,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::EdgeCoordinator => "edge/coordinator",
        }
    }
}

/// Includes ATP header bytes, not just the JSON payload.
pub const MAX_WIRE_FRAME: usize = 1024 * 1024;
/// Reserve more than the extension-free ATP header's maximum encoded length.
pub const MAX_JSON_RECORD: usize = MAX_WIRE_FRAME - 64;
const TLS_FILE_LIMIT: u64 = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(10);
// A quiet compiler is not a partial protocol frame. Allow the worker's maximum
// 30-minute execution plus transfer grace before recycling an idle connection.
// This does not renew an execution lease or replace the executor's own budget.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(35 * 60);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn check_task_cancellation() -> io::Result<()> {
    if asupersync::cx::Cx::current().is_some_and(|cx| cx.is_cancel_requested()) {
        // Interrupted can be retried by write_all. Cancellation is terminal for
        // this session and must instead unwind into its explicit cleanup path.
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "worker session cancelled",
        ))
    } else {
        Ok(())
    }
}

/// A native timer supplies wakeups; the monotonic runtime timestamp also rejects a late
/// poll even when bytes are immediately available. Construct the timeout NOW,
/// not inside the boxed async body, so its first poll cannot restart the clock (bead J011).
struct FrameDeadline {
    until: TransportInstant,
    wake: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl FrameDeadline {
    fn wake_after(budget: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let timer = asupersync::time::timeout(
            runtime_transport_now(),
            budget,
            std::future::pending::<()>(),
        );
        Box::pin(async move {
            let _ = timer.await;
        })
    }

    fn new_with_clock(budget: Duration, clock: TransportClock) -> Self {
        let now = clock();
        let budget_nanos = u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX);
        let until = TransportInstant(now.as_nanos().saturating_add(budget_nanos));
        Self {
            until,
            wake: Some(Self::wake_after(budget)),
        }
    }

    fn expired(&mut self, cx: &mut Context<'_>, clock: TransportClock) -> bool {
        let now = TransportInstant(clock().as_nanos());
        if now >= self.until {
            return true;
        }
        // The runtime timer wakes this task; only the selected clock can
        // establish expiry. An injected clock may have a different epoch or
        // advance more slowly. Re-arm its remaining budget, never its deadline.
        if self
            .wake
            .as_mut()
            .is_none_or(|wake| wake.as_mut().poll(cx).is_ready())
        {
            // A completed async timer must never be polled a second time,
            // including another check_live call in this same stream poll.
            self.wake = None;
            let now = TransportInstant(clock().as_nanos());
            if now >= self.until {
                return true;
            }
            let mut wake = Self::wake_after(self.until.duration_since(now));
            if wake.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            } else {
                self.wake = Some(wake);
            }
        }
        false
    }
}

/// Translate the existing record-oriented driver to the native ATP codec.
///
/// `new` does not authenticate its input. Production callers use `accept_peer`
/// or `connect_worker`, which complete TLS before constructing this adapter.
/// At most one outbound record is buffered; flush-before-read avoids the
/// request/reply deadlock that a buffering byte-stream adapter could introduce.
pub struct JsonAtpStream<S> {
    io: S,
    decoder: AtpFrameCodec,
    input: BytesMut,
    boundary_bytes: usize,
    ready: Vec<u8>,
    ready_offset: usize,
    line: Vec<u8>,
    output: Vec<u8>,
    output_offset: usize,
    failed: bool,
    clock: TransportClock,
    read_deadline: Option<FrameDeadline>,
    idle_deadline: Option<FrameDeadline>,
    write_deadline: Option<FrameDeadline>,
}

impl<S> JsonAtpStream<S> {
    /// Wrap a stream using [`runtime_transport_now`]. Authentication is the enclosing transport's responsibility.
    pub fn new(io: S) -> Self {
        Self::with_clock(io, runtime_transport_now)
    }

    /// Wrap a stream with an explicitly injected [`TransportClock`] (bead J011).
    pub fn with_clock(io: S, clock: TransportClock) -> Self {
        Self {
            io,
            decoder: AtpFrameCodec::with_max_frame_size(MAX_WIRE_FRAME as u64),
            input: BytesMut::new(),
            boundary_bytes: 0,
            ready: Vec::new(),
            ready_offset: 0,
            line: Vec::new(),
            output: Vec::new(),
            output_offset: 0,
            failed: false,
            clock,
            read_deadline: None,
            idle_deadline: None,
            write_deadline: None,
        }
    }

    fn poison(&mut self, error: io::Error) -> io::Error {
        self.failed = true;
        self.read_deadline = None;
        self.idle_deadline = None;
        self.write_deadline = None;
        error
    }

    fn check_live(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.failed {
            return Err(invalid("worker ATP connection is unusable"));
        }
        if let Err(error) = check_task_cancellation() {
            return Err(self.poison(error));
        }
        let clock = self.clock;
        let expired = if self
            .read_deadline
            .as_mut()
            .is_some_and(|timer| timer.expired(cx, clock))
        {
            Some("worker ATP partial-frame deadline exceeded")
        } else if self
            .write_deadline
            .as_mut()
            .is_some_and(|timer| timer.expired(cx, clock))
        {
            Some("worker ATP write/flush deadline exceeded")
        } else if self
            .idle_deadline
            .as_mut()
            .is_some_and(|timer| timer.expired(cx, clock))
        {
            Some("worker ATP idle-read deadline exceeded")
        } else {
            None
        };
        match expired {
            Some(message) => Err(self.poison(io::Error::new(io::ErrorKind::TimedOut, message))),
            None => Ok(()),
        }
    }

    fn begin_write(&mut self) {
        let clock = self.clock;
        self.write_deadline
            .get_or_insert_with(|| FrameDeadline::new_with_clock(FRAME_IO_TIMEOUT, clock));
    }
}

impl<S: AsyncWrite + Unpin> JsonAtpStream<S> {
    fn drain_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Even an always-ready writer yields so shutdown/control can be polled.
        for _ in 0..32 {
            self.check_live(cx)?;
            if self.output_offset == self.output.len() {
                self.output.clear();
                self.output_offset = 0;
                return Poll::Ready(Ok(()));
            }
            let n = match ready!(
                Pin::new(&mut self.io).poll_write(cx, &self.output[self.output_offset..],)
            ) {
                Ok(0) => {
                    return Poll::Ready(Err(self.poison(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "worker ATP frame write made no progress",
                    ))));
                }
                Ok(n) => n,
                Err(error) => return Poll::Ready(Err(self.poison(error))),
            };
            self.output_offset += n;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn flush_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_live(cx)?;
        ready!(self.drain_output(cx))?;
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Pending => {
                // The driver requests one decoded byte at a time. An empty,
                // ready flush must not allocate a fresh timer for EVERY byte.
                // Actual writes already own a deadline; an idle flush starts
                // one only when it would otherwise wait indefinitely.
                self.begin_write();
                self.check_live(cx)?;
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                // Flushing an unfinished JSON prefix is not completion of its
                // record and must not grant that prefix a fresh write budget.
                if self.line.is_empty() {
                    self.write_deadline = None;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.poison(error))),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for JsonAtpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_live(cx)?;
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        ready!(this.flush_output(cx))?;
        for _ in 0..32 {
            this.check_live(cx)?;
            if this.ready_offset < this.ready.len() {
                let count = destination
                    .remaining()
                    .min(this.ready.len() - this.ready_offset);
                destination.put_slice(&this.ready[this.ready_offset..this.ready_offset + count]);
                this.ready_offset += count;
                if this.ready_offset == this.ready.len() {
                    this.ready.clear();
                    this.ready_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.decoder.decode(&mut this.input) {
                Ok(Some(frame)) => {
                    if frame.version() != ProtocolVersion::CURRENT
                        || frame.frame_type() != FrameType::Control
                        || !frame.header.extensions.is_empty()
                        || frame.payload.len() > MAX_JSON_RECORD
                        || frame.payload.contains(&b'\n')
                    {
                        return Poll::Ready(Err(
                            this.poison(invalid("unsupported worker ATP record"))
                        ));
                    }
                    this.boundary_bytes = this.input.len();
                    this.read_deadline = None;
                    this.idle_deadline = None;
                    this.ready = frame.payload;
                    this.ready.push(b'\n');
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    return Poll::Ready(Err(
                        this.poison(invalid(format!("worker ATP decode: {error}",)))
                    ));
                }
            }
            let clock = this.clock;
            this.idle_deadline
                .get_or_insert_with(|| FrameDeadline::new_with_clock(IDLE_READ_TIMEOUT, clock));
            if this.boundary_bytes != 0 {
                this.read_deadline
                    .get_or_insert_with(|| FrameDeadline::new_with_clock(FRAME_IO_TIMEOUT, clock));
            }
            this.check_live(cx)?;
            // The codec may consume a header while waiting for its payload.
            // boundary_bytes, unlike input.is_empty(), still records that an
            // EOF here would truncate a frame.
            if this.boundary_bytes >= MAX_WIRE_FRAME {
                return Poll::Ready(Err(this.poison(invalid("worker ATP frame too large"))));
            }
            let mut bytes = [0u8; 4096];
            let capacity = bytes.len().min(MAX_WIRE_FRAME - this.boundary_bytes);
            let mut read = ReadBuf::new(&mut bytes[..capacity]);
            match ready!(Pin::new(&mut this.io).poll_read(cx, &mut read)) {
                Ok(()) if read.filled().is_empty() => {
                    if this.boundary_bytes != 0 {
                        return Poll::Ready(Err(this.poison(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated worker ATP frame",
                        ))));
                    }
                    this.idle_deadline = None;
                    return Poll::Ready(Ok(()));
                }
                Ok(()) => {
                    this.boundary_bytes += read.filled().len();
                    this.input.extend_from_slice(read.filled());
                    let clock = this.clock;
                    this.read_deadline.get_or_insert_with(|| {
                        FrameDeadline::new_with_clock(FRAME_IO_TIMEOUT, clock)
                    });
                }
                Err(error) => return Poll::Ready(Err(this.poison(error))),
            }
        }
        // Large, immediately-ready streams must yield to cancellation/control.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for JsonAtpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_live(cx)?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.begin_write();
        ready!(this.drain_output(cx))?;
        let newline = bytes.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(bytes.len(), |index| index + 1);
        let payload_count = count - usize::from(newline.is_some());
        if payload_count > MAX_JSON_RECORD.saturating_sub(this.line.len()) {
            return Poll::Ready(Err(this.poison(invalid("worker JSON record too large"))));
        }
        this.line.extend_from_slice(&bytes[..payload_count]);
        if newline.is_some() {
            let frame = match Frame::new(
                ProtocolVersion::CURRENT,
                FrameType::Control,
                std::mem::take(&mut this.line),
            ) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(this.poison(invalid(error.to_string())))),
            };
            let mut encoded = BytesMut::new();
            if let Err(error) = AtpFrameCodec::with_max_frame_size(MAX_WIRE_FRAME as u64)
                .encode(frame, &mut encoded)
            {
                return Poll::Ready(Err(this.poison(invalid(error.to_string()))));
            }
            this.output = encoded.to_vec();
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_live(cx)?;
        this.flush_output(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_live(cx)?;
        if !this.line.is_empty() {
            return Poll::Ready(Err(this.poison(invalid("unfinished worker ATP record"))));
        }
        this.begin_write();
        ready!(this.drain_output(cx))?;
        match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            Ok(()) => {
                this.write_deadline = None;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(this.poison(error))),
        }
    }
}

/// Explicit TLS material; ambient system roots are never loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

fn read_pem(path: &Path) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("TLS file {}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("TLS material must be a regular file".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(TLS_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > TLS_FILE_LIMIT {
        return Err("TLS material exceeds the file-size limit".to_owned());
    }
    Ok(bytes)
}

/// Public-key identity, including after a certificate renewal with the same key.
/// The caller supplies the certificate returned by a successful TLS handshake.
pub fn certificate_identity(certificate: &Certificate) -> Result<TransportIdentity, String> {
    let pin = CertificatePin::compute_spki_sha256(certificate).map_err(|e| e.to_string())?;
    let fingerprint: [u8; 32] = pin
        .hash_bytes()
        .try_into()
        .map_err(|_| "TLS public-key fingerprint has the wrong length".to_owned())?;
    Ok(TransportIdentity {
        peer_id: fingerprint,
        fingerprint,
    })
}

impl TlsFiles {
    pub fn local_identity(&self) -> Result<TransportIdentity, String> {
        let certificates =
            Certificate::from_pem(&read_pem(&self.certificate)?).map_err(|e| e.to_string())?;
        certificate_identity(
            certificates
                .first()
                .ok_or("TLS certificate chain is empty")?,
        )
    }

    pub fn connector(&self) -> Result<TlsConnector, String> {
        self.connector_for(PeerProtocol::Worker)
    }

    fn connector_for(&self, protocol: PeerProtocol) -> Result<TlsConnector, String> {
        let roots = Certificate::from_pem(&read_pem(&self.ca)?).map_err(|e| e.to_string())?;
        let chain =
            CertificateChain::from_pem(&read_pem(&self.certificate)?).map_err(|e| e.to_string())?;
        let key = PrivateKey::from_pem(&read_pem(&self.private_key)?).map_err(|e| e.to_string())?;
        TlsConnectorBuilder::new()
            .with_strict_ca_validation()
            .add_root_certificates(roots)
            .identity(chain, key)
            .alpn_protocols_required(vec![protocol.alpn().to_vec()])
            .handshake_timeout(HANDSHAKE_TIMEOUT)
            .build()
            .map_err(|e| format!("{} TLS client configuration: {e}", protocol.name()))
    }

    pub fn acceptor(&self) -> Result<TlsAcceptor, String> {
        self.acceptor_for(PeerProtocol::Worker)
    }

    /// Require mutual TLS and the dedicated canonical-operation protocol.
    /// The listener must still call [`accept_edge_peer`] to apply its explicit
    /// edge enrollment before exposing an application stream.
    pub fn edge_coordinator_acceptor(&self) -> Result<TlsAcceptor, String> {
        self.acceptor_for(PeerProtocol::EdgeCoordinator)
    }

    fn acceptor_for(&self, protocol: PeerProtocol) -> Result<TlsAcceptor, String> {
        let mut roots = RootCertStore::empty();
        for cert in Certificate::from_pem(&read_pem(&self.ca)?).map_err(|e| e.to_string())? {
            roots
                .add(&cert)
                .map_err(|e| format!("{} CA: {e}", protocol.name()))?;
        }
        let chain =
            CertificateChain::from_pem(&read_pem(&self.certificate)?).map_err(|e| e.to_string())?;
        let key = PrivateKey::from_pem(&read_pem(&self.private_key)?).map_err(|e| e.to_string())?;
        // The pinned acceptor selects ring for ServerConfig, but its required
        // WebPkiClientVerifier still uses the process default. Combined RCH/RABS
        // builds also enable AWS-LC via reqwest, so inference would panic.
        // Preserve an application-selected provider. A concurrent installer may
        // win the OnceLock; that is the only install_default error and is safe.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap_or(());
        }
        TlsAcceptor::builder(chain, key)
            .require_client_auth(roots)
            .alpn_protocols_required(vec![protocol.alpn().to_vec()])
            .handshake_timeout(HANDSHAKE_TIMEOUT)
            .build()
            .map_err(|e| format!("{} TLS server configuration: {e}", protocol.name()))
    }
}

pub type SecureWorkerStream = JsonAtpStream<TlsStream<TcpStream>>;

/// A successful mutual-TLS connection and the key it actually authenticated.
/// This identity is evidence, not an execution/publication grant.
pub struct AuthenticatedPeer {
    pub stream: SecureWorkerStream,
    pub identity: TransportIdentity,
}

fn established(
    stream: TlsStream<TcpStream>,
    protocol: PeerProtocol,
) -> Result<AuthenticatedPeer, String> {
    if stream.alpn_protocol() != Some(protocol.alpn()) {
        return Err(format!("{} ALPN was not negotiated", protocol.name()));
    }
    let certificate = stream
        .peer_leaf_certificate_der()
        .ok_or_else(|| format!("{} TLS peer did not provide a certificate", protocol.name()))?;
    let identity = certificate_identity(&Certificate::from_der(certificate))?;
    Ok(AuthenticatedPeer {
        stream: JsonAtpStream::new(stream),
        identity,
    })
}

/// Authenticate an accepted socket before reading a single application record.
pub async fn accept_peer(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> Result<AuthenticatedPeer, String> {
    accept_peer_for(acceptor, stream, PeerProtocol::Worker).await
}

async fn accept_peer_for(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    protocol: PeerProtocol,
) -> Result<AuthenticatedPeer, String> {
    // ATP exchanges bounded control records and per-chunk acknowledgments.
    // Do not hold those records behind Nagle while the peer waits for credit.
    stream
        .set_nodelay(true)
        .map_err(|e| format!("{} TCP no-delay configuration: {e}", protocol.name()))?;
    established(
        acceptor
            .accept(stream)
            .await
            .map_err(|e| format!("{} TLS accept: {e}", protocol.name()))?,
        protocol,
    )
}

/// Client connection with no plaintext fallback, even on a TLS configuration error.
pub async fn connect_peer(
    address: &str,
    server_name: &str,
    files: &TlsFiles,
) -> Result<AuthenticatedPeer, String> {
    connect_peer_for(address, server_name, files, PeerProtocol::Worker).await
}

async fn connect_peer_for(
    address: &str,
    server_name: &str,
    files: &TlsFiles,
    protocol: PeerProtocol,
) -> Result<AuthenticatedPeer, String> {
    let connector = files.connector_for(protocol)?;
    let connect = async {
        let stream = TcpStream::connect(address.to_owned())
            .await
            .map_err(|e| format!("{} connect: {e}", protocol.name()))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("{} TCP no-delay configuration: {e}", protocol.name()))?;
        established(
            connector
                .connect(server_name, stream)
                .await
                .map_err(|e| format!("coordinator TLS handshake: {e}"))?,
            protocol,
        )
    };
    asupersync::time::timeout(runtime_transport_now(), CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| format!("{} connection deadline exceeded", protocol.name()))?
}

fn validate_enrollment(pins: &[[u8; 32]], role: TrustScope) -> Result<(), String> {
    if pins.is_empty() || pins.contains(&[0; 32]) {
        return Err(format!("{role:?} enrollment requires nonzero SPKI pins"));
    }
    Ok(())
}

fn admit_enrolled_peer(
    peer: AuthenticatedPeer,
    pins: &[[u8; 32]],
    role: TrustScope,
) -> Result<AuthenticatedPeer, String> {
    let pin = pins
        .iter()
        .find(|pin| **pin == peer.identity.peer_id)
        .ok_or_else(|| format!("authenticated peer is not enrolled for {role:?} role"))?;
    // The listener/client configuration grants this role, never a peer's hello
    // or the mere presence of a CA-valid certificate. This immutable pin
    // enrollment is not a credential-rotation or execution-session grant.
    let mut identities = IdentityStore::default();
    identities
        .create(*pin, *pin, role, 1)
        .map_err(|error| format!("{role:?} identity enrollment: {error:?}"))?;
    match identities.verify(&peer.identity.peer_id, &peer.identity.fingerprint) {
        VerifyVerdict::Valid { scope, .. } if scope == role => Ok(peer),
        _ => Err(format!(
            "authenticated peer does not prove its {role:?} enrollment"
        )),
    }
}

/// Authenticate one explicitly enrolled edge on the canonical-operation plane.
/// The allowlist grants only the Edge role; worker enrollment and self-claimed
/// roles never satisfy it. No application record is read before this returns.
pub async fn accept_edge_peer(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    allowed_edge_pins: &[[u8; 32]],
) -> Result<AuthenticatedPeer, String> {
    validate_enrollment(allowed_edge_pins, TrustScope::Edge)?;
    let peer = accept_peer_for(acceptor, stream, PeerProtocol::EdgeCoordinator).await?;
    admit_enrolled_peer(peer, allowed_edge_pins, TrustScope::Edge)
}

/// Connect an edge to its explicitly pinned coordinator, with mutual TLS and
/// the dedicated ALPN. CA validation, server-name validation and the configured
/// coordinator key must all agree; there is no worker or plaintext fallback.
pub async fn connect_coordinator_peer(
    address: &str,
    server_name: &str,
    files: &TlsFiles,
    coordinator_pin: [u8; 32],
) -> Result<AuthenticatedPeer, String> {
    validate_enrollment(&[coordinator_pin], TrustScope::Coordinator)?;
    let peer = connect_peer_for(address, server_name, files, PeerProtocol::EdgeCoordinator).await?;
    admit_enrolled_peer(peer, &[coordinator_pin], TrustScope::Coordinator)
}

/// The historical plaintext fixture transport is restricted to literal loopback.
/// It cannot accidentally become a fleet transport through DNS or host aliases.
pub fn is_loopback_fixture(address: &str) -> bool {
    address
        .parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback())
}

/// The worker's actual transport, with its authenticated mode visible to hello.
pub enum WorkerConnection {
    Authenticated {
        peer: Box<AuthenticatedPeer>,
        local: TransportIdentity,
    },
    LoopbackFixture(TcpStream),
}

impl WorkerConnection {
    pub fn local_identity(&self) -> Option<TransportIdentity> {
        match self {
            Self::Authenticated { local, .. } => Some(*local),
            Self::LoopbackFixture(_) => None,
        }
    }
}

impl AsyncRead for WorkerConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        check_task_cancellation()?;
        match self.get_mut() {
            Self::Authenticated { peer, .. } => Pin::new(&mut peer.stream).poll_read(cx, buf),
            Self::LoopbackFixture(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WorkerConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        check_task_cancellation()?;
        match self.get_mut() {
            Self::Authenticated { peer, .. } => Pin::new(&mut peer.stream).poll_write(cx, bytes),
            Self::LoopbackFixture(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        check_task_cancellation()?;
        match self.get_mut() {
            Self::Authenticated { peer, .. } => Pin::new(&mut peer.stream).poll_flush(cx),
            Self::LoopbackFixture(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        check_task_cancellation()?;
        match self.get_mut() {
            Self::Authenticated { peer, .. } => Pin::new(&mut peer.stream).poll_shutdown(cx),
            Self::LoopbackFixture(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Load only explicit worker TLS settings. Partial configuration fails closed.
/// A supervisor cancelling the owning Cx can interrupt connection establishment
/// before execution is admitted, as well as reads/writes on an established peer.
pub async fn connect_worker(address: &str) -> Result<WorkerConnection, String> {
    let mut connection = pin!(connect_worker_inner(address));
    poll_fn(|cx| {
        if let Err(error) = check_task_cancellation() {
            return Poll::Ready(Err(error.to_string()));
        }
        connection.as_mut().poll(cx)
    })
    .await
}

async fn connect_worker_inner(address: &str) -> Result<WorkerConnection, String> {
    let ca = std::env::var_os("RABS_WORKER_TLS_CA");
    let certificate = std::env::var_os("RABS_WORKER_TLS_CERT");
    let private_key = std::env::var_os("RABS_WORKER_TLS_KEY");
    let server_name = std::env::var_os("RABS_WORKER_TLS_SERVER_NAME");
    if ca.is_none() && certificate.is_none() && private_key.is_none() && server_name.is_none() {
        if !is_loopback_fixture(address) {
            return Err(
                "fleet connections require RABS_WORKER_TLS_CA/CERT/KEY/SERVER_NAME".to_owned(),
            );
        }
        let stream = asupersync::time::timeout(
            runtime_transport_now(),
            CONNECT_TIMEOUT,
            TcpStream::connect(address.to_owned()),
        )
        .await
        .map_err(|_| "loopback fixture connection timed out".to_owned())?
        .map_err(|e| format!("loopback fixture connection: {e}"))?;
        return Ok(WorkerConnection::LoopbackFixture(stream));
    }
    let files = TlsFiles {
        ca: PathBuf::from(ca.ok_or("missing RABS_WORKER_TLS_CA")?),
        certificate: PathBuf::from(certificate.ok_or("missing RABS_WORKER_TLS_CERT")?),
        private_key: PathBuf::from(private_key.ok_or("missing RABS_WORKER_TLS_KEY")?),
    };
    let server_name = server_name
        .ok_or("missing RABS_WORKER_TLS_SERVER_NAME")?
        .into_string()
        .map_err(|_| "TLS server name must be UTF-8".to_owned())?;
    if server_name.is_empty() {
        return Err("TLS server name must not be empty".to_owned());
    }
    let local = files.local_identity()?;
    let peer = connect_peer(address, &server_name, &files).await?;
    Ok(WorkerConnection::Authenticated {
        peer: Box::new(peer),
        local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::Waker;

    #[cfg(unix)]
    fn openssl(root: &Path, args: &[&str]) {
        let output = std::process::Command::new("openssl")
            .current_dir(root)
            .args(args)
            .output()
            .expect("OpenSSL is required for the native TLS regressions");
        assert!(
            output.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn test_ca(root: &Path, name: &str) {
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RABS transport test CA",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.pem"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
    }

    #[cfg(unix)]
    fn test_identity(root: &Path, ca: &str, name: &str, usage: &str, serial: &str) -> TlsFiles {
        openssl(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-sha256",
                "-subj",
                "/CN=localhost",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
            ],
        );
        std::fs::write(
            root.join(format!("{name}.ext")),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n"
            ),
        )
        .unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-set_serial",
                serial,
                "-days",
                "1",
                "-sha256",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        );
        TlsFiles {
            ca: root.join(format!("{ca}.pem")),
            certificate: root.join(format!("{name}.pem")),
            private_key: root.join(format!("{name}.key")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn mutual_tls_factories_handle_both_crypto_backends_in_fresh_processes() {
        const CASE: &str = "worker_transport::tests::mutual_tls_factories_handle_both_crypto_backends_in_fresh_processes";
        const CHILD: &str = "RABS_TLS_PROVIDER_REGRESSION_CHILD";
        let Some(mode) = std::env::var_os(CHILD) else {
            for mode in ["unset", "aws"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CASE, "--nocapture", "--test-threads=1"])
                    .env(CHILD, mode)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode}: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("1 passed; 0 failed; 0 ignored;"),
                    "fresh provider probe must execute its exact case"
                );
            }
            return;
        };
        // Both symbols must compile: a ring-only test build cannot certify the
        // real RCH/reqwest + RABS feature-unification regression.
        let ring = rustls::crypto::ring::default_provider();
        let aws = rustls::crypto::aws_lc_rs::default_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        if mode == "aws" {
            aws.install_default().unwrap();
        } else {
            assert_eq!(mode, "unset");
        }
        drop(ring);
        let previous = rustls::crypto::CryptoProvider::get_default().cloned();
        let root = tempfile::tempdir().unwrap();
        test_ca(root.path(), "ca");
        let files = test_identity(root.path(), "ca", "peer", "serverAuth,clientAuth", "2");
        for _ in 0..2 {
            for protocol in [PeerProtocol::Worker, PeerProtocol::EdgeCoordinator] {
                let (acceptor, connector) = match protocol {
                    PeerProtocol::Worker => (files.acceptor().unwrap(), files.connector().unwrap()),
                    PeerProtocol::EdgeCoordinator => (
                        files.edge_coordinator_acceptor().unwrap(),
                        files.connector_for(protocol).unwrap(),
                    ),
                };
                assert_eq!(acceptor.handshake_timeout(), Some(HANDSHAKE_TIMEOUT));
                assert_eq!(connector.handshake_timeout(), Some(HANDSHAKE_TIMEOUT));
                assert_eq!(
                    acceptor.config().alpn_protocols,
                    vec![protocol.alpn().to_vec()]
                );
                assert_eq!(
                    connector.config().alpn_protocols,
                    vec![protocol.alpn().to_vec()]
                );
            }
        }
        let selected = rustls::crypto::CryptoProvider::get_default().unwrap();
        if let Some(previous) = previous {
            assert!(std::sync::Arc::ptr_eq(&previous, selected));
        }
    }

    #[cfg(unix)]
    fn tls_exchange(
        server: &TlsFiles,
        client: &TlsFiles,
        allowed_edges: &[[u8; 32]],
        coordinator_pin: [u8; 32],
        server_protocol: PeerProtocol,
        client_protocol: PeerProtocol,
    ) -> (
        Result<TransportIdentity, String>,
        Result<TransportIdentity, String>,
    ) {
        use asupersync::io::{AsyncReadExt, AsyncWriteExt};
        use asupersync::runtime::RuntimeBuilder;
        const REQUEST: &[u8] = b"{\"kind\":\"canonical-transport-test\"}\n";
        const RESPONSE: &[u8] = b"{\"kind\":\"canonical-transport-received\"}\n";
        let run = |future| {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            crate::daemon_runtime::block_on_top_level(&runtime, async {
                asupersync::time::timeout(runtime_transport_now(), Duration::from_secs(15), future)
                    .await
                    .expect("native transport exchange exceeded its deadline")
            })
        };
        std::thread::scope(|scope| {
            let (address_sender, address_receiver) = std::sync::mpsc::sync_channel(1);
            let accepted = scope.spawn(move || {
                let runtime = RuntimeBuilder::current_thread().build().unwrap();
                crate::daemon_runtime::block_on_top_level(&runtime, async {
                    asupersync::time::timeout(
                        runtime_transport_now(),
                        Duration::from_secs(15),
                        async {
                            let acceptor = match server_protocol {
                                PeerProtocol::Worker => server.acceptor()?,
                                PeerProtocol::EdgeCoordinator => {
                                    server.edge_coordinator_acceptor()?
                                }
                            };
                            let listener = asupersync::net::TcpListener::bind("127.0.0.1:0")
                                .await
                                .map_err(|error| error.to_string())?;
                            address_sender
                                .send(listener.local_addr().unwrap().to_string())
                                .unwrap();
                            let (stream, _) =
                                listener.accept().await.map_err(|error| error.to_string())?;
                            let mut peer = match server_protocol {
                                PeerProtocol::Worker => accept_peer(&acceptor, stream).await?,
                                PeerProtocol::EdgeCoordinator => {
                                    accept_edge_peer(&acceptor, stream, allowed_edges).await?
                                }
                            };
                            let mut bytes = [0; REQUEST.len()];
                            peer.stream
                                .read_exact(&mut bytes)
                                .await
                                .map_err(|error| error.to_string())?;
                            if bytes.as_slice() != REQUEST {
                                return Err("server received changed application bytes".to_owned());
                            }
                            peer.stream
                                .write_all(RESPONSE)
                                .await
                                .map_err(|error| error.to_string())?;
                            peer.stream
                                .flush()
                                .await
                                .map_err(|error| error.to_string())?;
                            Ok(peer.identity)
                        },
                    )
                    .await
                    .expect("native TLS server exceeded its deadline")
                })
            });
            let address = address_receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            let connected = run(async move {
                let mut peer = match client_protocol {
                    PeerProtocol::Worker => connect_peer(&address, "localhost", client).await?,
                    PeerProtocol::EdgeCoordinator => {
                        connect_coordinator_peer(&address, "localhost", client, coordinator_pin)
                            .await?
                    }
                };
                peer.stream
                    .write_all(REQUEST)
                    .await
                    .map_err(|error| error.to_string())?;
                peer.stream
                    .flush()
                    .await
                    .map_err(|error| error.to_string())?;
                let mut bytes = [0; RESPONSE.len()];
                peer.stream
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|error| error.to_string())?;
                if bytes.as_slice() != RESPONSE {
                    return Err("client received changed application bytes".to_owned());
                }
                Ok(peer.identity)
            });
            (accepted.join().unwrap(), connected)
        })
    }

    #[cfg(unix)]
    #[test]
    fn edge_coordinator_mutual_tls_requires_both_enrolled_role_pins() {
        let root = tempfile::tempdir().unwrap();
        test_ca(root.path(), "ca");
        let coordinator = test_identity(root.path(), "ca", "coordinator", "serverAuth", "2");
        let edge = test_identity(root.path(), "ca", "edge", "clientAuth", "3");
        let other = test_identity(root.path(), "ca", "other", "serverAuth,clientAuth", "4");
        let coordinator_id = coordinator.local_identity().unwrap();
        let edge_id = edge.local_identity().unwrap();
        let other_id = other.local_identity().unwrap();
        let (accepted, connected) = tls_exchange(
            &coordinator,
            &edge,
            &[other_id.fingerprint, edge_id.fingerprint],
            coordinator_id.fingerprint,
            PeerProtocol::EdgeCoordinator,
            PeerProtocol::EdgeCoordinator,
        );
        assert_eq!(accepted.unwrap(), edge_id);
        assert_eq!(connected.unwrap(), coordinator_id);

        // A CA-valid certificate is not permission to assume the Edge role.
        let (accepted, connected) = tls_exchange(
            &coordinator,
            &other,
            &[edge_id.fingerprint],
            coordinator_id.fingerprint,
            PeerProtocol::EdgeCoordinator,
            PeerProtocol::EdgeCoordinator,
        );
        assert!(accepted.unwrap_err().contains("not enrolled for Edge role"));
        assert!(
            connected.is_err(),
            "unlisted edge exchanged application bytes"
        );

        // The configured coordinator pin is required in addition to CA and
        // server-name validation. This other server has a fully valid chain.
        let (accepted, connected) = tls_exchange(
            &other,
            &edge,
            &[edge_id.fingerprint],
            coordinator_id.fingerprint,
            PeerProtocol::EdgeCoordinator,
            PeerProtocol::EdgeCoordinator,
        );
        assert!(
            connected
                .unwrap_err()
                .contains("not enrolled for Coordinator role")
        );
        assert!(
            accepted.is_err(),
            "wrong coordinator received application bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn edge_coordinator_mutual_tls_rejects_worker_alpn_in_both_directions() {
        let root = tempfile::tempdir().unwrap();
        test_ca(root.path(), "ca");
        let coordinator = test_identity(root.path(), "ca", "coordinator", "serverAuth", "2");
        let edge = test_identity(root.path(), "ca", "edge", "clientAuth", "3");
        let coordinator_id = coordinator.local_identity().unwrap();
        let edge_id = edge.local_identity().unwrap();
        // The old worker API still negotiates and exchanges the original ATP
        // records; adding another plane must not change its default protocol.
        let (accepted, connected) = tls_exchange(
            &coordinator,
            &edge,
            &[edge_id.fingerprint],
            coordinator_id.fingerprint,
            PeerProtocol::Worker,
            PeerProtocol::Worker,
        );
        assert_eq!(accepted.unwrap(), edge_id);
        assert_eq!(connected.unwrap(), coordinator_id);
        for (server, client) in [
            (PeerProtocol::EdgeCoordinator, PeerProtocol::Worker),
            (PeerProtocol::Worker, PeerProtocol::EdgeCoordinator),
        ] {
            let (accepted, connected) = tls_exchange(
                &coordinator,
                &edge,
                &[edge_id.fingerprint],
                coordinator_id.fingerprint,
                server,
                client,
            );
            assert!(
                accepted.is_err(),
                "cross-ALPN server admitted application bytes"
            );
            assert!(
                connected.is_err(),
                "cross-ALPN client admitted application bytes"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn edge_coordinator_mutual_tls_rejects_an_enrolled_but_untrusted_certificate() {
        let root = tempfile::tempdir().unwrap();
        test_ca(root.path(), "ca");
        test_ca(root.path(), "untrusted-ca");
        let coordinator = test_identity(root.path(), "ca", "coordinator", "serverAuth", "2");
        let mut edge = test_identity(root.path(), "untrusted-ca", "edge", "clientAuth", "3");
        // The client trusts the server correctly, but its own presented
        // certificate was issued by a CA the server has never configured.
        edge.ca = coordinator.ca.clone();
        let (accepted, connected) = tls_exchange(
            &coordinator,
            &edge,
            &[edge.local_identity().unwrap().fingerprint],
            coordinator.local_identity().unwrap().fingerprint,
            PeerProtocol::EdgeCoordinator,
            PeerProtocol::EdgeCoordinator,
        );
        assert!(
            accepted.is_err(),
            "pin enrollment bypassed certificate validation"
        );
        assert!(
            connected.is_err(),
            "untrusted certificate exchanged application bytes"
        );
    }

    #[test]
    fn edge_coordinator_empty_or_zero_enrollment_never_connects() {
        assert!(validate_enrollment(&[], TrustScope::Edge).is_err());
        assert!(validate_enrollment(&[[1; 32], [0; 32]], TrustScope::Edge).is_err());
        let files = TlsFiles {
            ca: PathBuf::from("/nonexistent-rabs-ca"),
            certificate: PathBuf::from("/nonexistent-rabs-certificate"),
            private_key: PathBuf::from("/nonexistent-rabs-key"),
        };
        let mut connect = pin!(connect_coordinator_peer(
            "invalid-address",
            "",
            &files,
            [0; 32]
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            connect.as_mut().poll(&mut context),
            Poll::Ready(Err(error)) if error.contains("Coordinator enrollment requires nonzero SPKI pins")
        ));
    }

    static VIRTUAL_CLOCK_NANOS: AtomicU64 = AtomicU64::new(1_000_000_000);

    fn virtual_clock_now() -> asupersync::types::Time {
        asupersync::types::Time::from_nanos(VIRTUAL_CLOCK_NANOS.load(Ordering::SeqCst))
    }

    struct Wire {
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
        blocked: bool,
        quantum: usize,
    }

    impl Default for Wire {
        fn default() -> Self {
            Self {
                input: VecDeque::new(),
                output: Vec::new(),
                eof: false,
                blocked: false,
                quantum: 3,
            }
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.input.is_empty() {
                return if this.eof {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            }
            for _ in 0..this.quantum.min(buf.remaining()).min(this.input.len()) {
                buf.put_slice(&[this.input.pop_front().unwrap()]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.blocked {
                return Poll::Pending;
            }
            let count = this.quantum.min(bytes.len());
            this.output.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.blocked {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn encoded(payload: &[u8], kind: FrameType) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        AtpFrameCodec::new()
            .encode(
                Frame::new(ProtocolVersion::CURRENT, kind, payload.to_vec()).unwrap(),
                &mut bytes,
            )
            .unwrap();
        bytes.to_vec()
    }

    fn read_once(stream: &mut JsonAtpStream<Wire>) -> Poll<io::Result<Vec<u8>>> {
        let mut bytes = [0u8; 128];
        let mut destination = ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream)
            .poll_read(&mut cx, &mut destination)
            .map(|result| result.map(|()| destination.filled().to_vec()))
    }

    #[test]
    fn fragmented_native_frames_return_exact_driver_records() {
        let mut stream = JsonAtpStream::new(Wire::default());
        stream
            .io
            .input
            .extend(encoded(br#"{"kind":"ping"}"#, FrameType::Control));
        stream.io.input.extend(encoded(
            br#"{"kind":"cancel","request_id":7}"#,
            FrameType::Control,
        ));
        assert!(
            matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"ping\"}\n")
        );
        assert!(
            matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"cancel\",\"request_id\":7}\n")
        );
        stream.io.eof = true;
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes.is_empty()));
    }

    #[test]
    fn cancelled_partial_read_resumes_the_same_atp_frame() {
        let wire = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        let mut stream = JsonAtpStream::new(Wire::default());
        stream.io.input.extend(&wire[..6]);
        assert!(read_once(&mut stream).is_pending());
        // Simulates the read future losing a race to execution completion.
        // Its next poll is a different call; the connection owns the prefix.
        stream.io.input.extend(&wire[6..]);
        assert!(
            matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"ping\"}\n")
        );
    }

    #[test]
    fn truncated_header_and_payload_fail_instead_of_clean_eof() {
        let wire = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        for length in 1..wire.len() {
            let mut stream = JsonAtpStream::new(Wire::default());
            stream.io.input.extend(&wire[..length]);
            stream.io.eof = true;
            assert!(
                matches!(read_once(&mut stream), Poll::Ready(Err(_))),
                "prefix {length}"
            );
            assert!(
                matches!(read_once(&mut stream), Poll::Ready(Err(_))),
                "poison {length}"
            );
        }
    }

    #[test]
    fn no_non_control_or_record_injection_frames_are_accepted() {
        for (payload, kind) in [
            (&b"{}"[..], FrameType::Capabilities),
            (&b"{}\n{}"[..], FrameType::Control),
        ] {
            let mut stream = JsonAtpStream::new(Wire::default());
            stream.io.input.extend(encoded(payload, kind));
            assert!(matches!(read_once(&mut stream), Poll::Ready(Err(_))));
        }
    }

    #[test]
    fn partial_write_is_sent_once_and_flushed_before_waiting_for_reply() {
        let mut stream = JsonAtpStream::new(Wire::default());
        let mut cx = Context::from_waker(Waker::noop());
        let first = b"{\"kind\":";
        assert!(
            matches!(Pin::new(&mut stream).poll_write(&mut cx, first), Poll::Ready(Ok(n)) if n == first.len())
        );
        assert!(stream.io.output.is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"\"ping\"}\n"),
            Poll::Ready(Ok(8))
        ));
        stream.io.blocked = true;
        assert!(read_once(&mut stream).is_pending());
        assert!(stream.io.output.is_empty());
        stream.io.blocked = false;
        assert!(read_once(&mut stream).is_pending());
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&stream.io.output);
        let frame = AtpFrameCodec::new().decode(&mut wire).unwrap().unwrap();
        assert_eq!(frame.frame_type(), FrameType::Control);
        assert_eq!(frame.payload, br#"{"kind":"ping"}"#);
        assert!(wire.is_empty());
        let sent = stream.io.output.len();
        assert!(read_once(&mut stream).is_pending());
        assert_eq!(stream.io.output.len(), sent);
    }

    #[test]
    fn oversize_outgoing_record_and_partial_shutdown_refuse() {
        let mut stream = JsonAtpStream::new(Wire::default());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &vec![b'a'; MAX_JSON_RECORD + 1]),
            Poll::Ready(Err(_))
        ));
        let mut stream = JsonAtpStream::new(Wire::default());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"{"),
            Poll::Ready(Ok(1))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn plaintext_fixture_cannot_be_selected_by_hostname_or_remote_address() {
        assert!(is_loopback_fixture("127.0.0.1:1234"));
        assert!(is_loopback_fixture("[::1]:1234"));
        for address in [
            "localhost:1234",
            "worker:1234",
            "10.0.0.2:1234",
            "0.0.0.0:1234",
            "[::]:1234",
        ] {
            assert!(!is_loopback_fixture(address), "{address}");
        }
    }

    #[test]
    fn trickled_frame_and_replaced_read_future_cannot_renew_deadline() {
        let bytes = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        let mut stream = JsonAtpStream::new(Wire::default());
        stream.io.input.extend(&bytes[..1]);
        assert!(read_once(&mut stream).is_pending());
        let until = stream.read_deadline.as_ref().unwrap().until;
        for byte in &bytes[1..6] {
            stream.io.input.push_back(*byte);
            assert!(read_once(&mut stream).is_pending());
            assert_eq!(stream.read_deadline.as_ref().unwrap().until, until);
        }
        stream.read_deadline.as_mut().unwrap().until =
            TransportInstant(runtime_transport_now().as_nanos());
        stream.io.input.extend(&bytes[6..]);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
        assert!(stream.failed);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(_))));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"{}\n"),
            Poll::Ready(Err(_))
        ));
        assert!(stream.io.output.is_empty());
    }

    #[test]
    fn write_prefix_and_stalled_flush_share_one_terminal_deadline() {
        let mut stream = JsonAtpStream::new(Wire::default());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"{"),
            Poll::Ready(Ok(1))
        ));
        let until = stream.write_deadline.as_ref().unwrap().until;
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(stream.write_deadline.as_ref().unwrap().until, until);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"}\n"),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(stream.write_deadline.as_ref().unwrap().until, until);
        stream.io.blocked = true;
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        stream.write_deadline.as_mut().unwrap().until =
            TransportInstant(runtime_transport_now().as_nanos());
        stream.io.blocked = false;
        assert!(
            matches!(Pin::new(&mut stream).poll_flush(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(
            stream.io.output.is_empty(),
            "late flush must not write expired bytes"
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn healthy_idle_and_partial_record_budgets_are_distinct() {
        let mut stream = JsonAtpStream::new(Wire::default());
        assert!(read_once(&mut stream).is_pending());
        assert!(stream.read_deadline.is_none());
        let idle = stream.idle_deadline.as_ref().unwrap().until;
        let now_instant = TransportInstant(runtime_transport_now().as_nanos());
        assert!(idle.duration_since(now_instant) > Duration::from_secs(30 * 60));
        let bytes = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        stream.io.input.extend(&bytes[..6]);
        assert!(read_once(&mut stream).is_pending());
        assert!(stream.read_deadline.as_ref().unwrap().until < idle);
        stream.io.input.extend(&bytes[6..]);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(_))));
        assert!(stream.read_deadline.is_none());
        assert!(stream.idle_deadline.is_none());
        assert!(read_once(&mut stream).is_pending());
        stream.idle_deadline.as_mut().unwrap().until =
            TransportInstant(runtime_transport_now().as_nanos());
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
    }

    #[test]
    fn native_deadlines_wake_stalled_io_without_another_peer_event() {
        use asupersync::io::{AsyncReadExt, AsyncWriteExt};
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle();
        crate::daemon_runtime::block_on_top_level(&runtime, async move {
            handle
                .spawn(async move {
                    for writing in [false, true] {
                        let mut stream = JsonAtpStream::new(Wire::default());
                        if writing {
                            let mut cx = Context::from_waker(Waker::noop());
                            assert!(matches!(
                                Pin::new(&mut stream).poll_write(&mut cx, b"{}\n"),
                                Poll::Ready(Ok(3))
                            ));
                            stream.io.blocked = true;
                            stream.write_deadline = Some(FrameDeadline::new_with_clock(
                                Duration::from_millis(30),
                                runtime_transport_now,
                            ));
                        } else {
                            let bytes = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
                            stream.io.input.push_back(bytes[0]);
                            assert!(read_once(&mut stream).is_pending());
                            stream.read_deadline = Some(FrameDeadline::new_with_clock(
                                Duration::from_millis(30),
                                runtime_transport_now,
                            ));
                        }
                        // This wire sends no more bytes and supplies no wakeups.
                        // The adapter's native timer must wake its own blocked IO;
                        // a separately expiring watchdog is a FAILURE, not a pass.
                        let operation = async {
                            if writing {
                                stream.flush().await
                            } else {
                                let mut byte = [0];
                                stream.read(&mut byte).await.map(|_| ())
                            }
                        };
                        let error = asupersync::time::timeout(
                            runtime_transport_now(),
                            Duration::from_secs(1),
                            operation,
                        )
                        .await
                        .expect("connection timer did not wake stalled IO")
                        .unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                        assert!(stream.failed);
                    }
                })
                .await
        });
    }

    #[test]
    fn j011_lab_virtualizes_transport_time_and_no_direct_clock_reads_in_core_paths() {
        // 1. Virtualized clock test: without sleeping a single wall-clock millisecond,
        //    advancing the injected virtual clock expires partial-frame and idle deadlines
        //    at the exact nanosecond boundary.
        VIRTUAL_CLOCK_NANOS.store(1_000_000_000, Ordering::SeqCst);
        let mut stream = JsonAtpStream::with_clock(Wire::default(), virtual_clock_now);
        let bytes = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        stream.io.input.extend(&bytes[..4]);
        assert!(read_once(&mut stream).is_pending());

        // A native wake is not authority to expire an injected clock. Keep
        // the original absolute boundary even when its wake has already fired.
        stream.read_deadline.as_mut().unwrap().wake = Some(Box::pin(std::future::ready(())));

        // Advance virtual time to 1ns before FRAME_IO_TIMEOUT (10s): still live!
        VIRTUAL_CLOCK_NANOS.store(
            1_000_000_000 + u64::try_from(FRAME_IO_TIMEOUT.as_nanos()).unwrap() - 1,
            Ordering::SeqCst,
        );
        assert!(read_once(&mut stream).is_pending());
        assert!(!stream.failed);
        assert!(read_once(&mut stream).is_pending());

        // Advance virtual time by 1ns to cross FRAME_IO_TIMEOUT: expires deterministically!
        VIRTUAL_CLOCK_NANOS.fetch_add(1, Ordering::SeqCst);
        assert!(
            matches!(read_once(&mut stream), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::TimedOut)
        );
        assert!(stream.failed);

        // A clock crossing the boundary while its wake is polled must refuse
        // in this same IO poll, before any further stream work can proceed.
        VIRTUAL_CLOCK_NANOS.store(1_000_000_000, Ordering::SeqCst);
        let mut raced = JsonAtpStream::with_clock(Wire::default(), virtual_clock_now);
        raced.io.input.extend(&bytes[..4]);
        assert!(read_once(&mut raced).is_pending());
        let until = raced.read_deadline.as_ref().unwrap().until.as_nanos();
        raced.read_deadline.as_mut().unwrap().wake = Some(Box::pin(poll_fn(move |_| {
            VIRTUAL_CLOCK_NANOS.store(until, Ordering::SeqCst);
            Poll::Ready(())
        })));
        assert!(
            matches!(read_once(&mut raced), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::TimedOut)
        );
        assert!(raced.failed);

        // 2. Lint gate (J011 acceptance): verify no direct `Instant::now(` or `SystemTime::now(`
        //    clock reads appear in the production (non-`#[cfg(test)]`) code of transport modules.
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for rel_path in [
            "rabs-asupersync/src/worker_transport.rs",
            "rabs-protocol/src/object_transfer.rs",
            "rabs-protocol/src/wire_time.rs",
            "rabs-protocol/src/reconnect.rs",
        ] {
            let source =
                std::fs::read_to_string(workspace.join(rel_path)).expect("read transport source");
            let prod_source = source.split("#[cfg(test)]").next().unwrap_or(&source);
            for forbidden in ["Instant::now(", "SystemTime::now("] {
                assert!(
                    !prod_source.contains(forbidden),
                    "J011 lint failure: direct clock read `{forbidden}` found in production path of {rel_path}"
                );
            }
        }
    }
}
