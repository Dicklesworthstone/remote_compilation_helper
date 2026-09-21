//! Authenticated S5 worker transport on native Asupersync TLS and ATP frames.
//!
//! The execution driver continues to consume bounded JSON records. On the
//! network, each record is an ATP Control frame inside a mutually authenticated
//! TLS connection; the JSON newline is an in-process adapter boundary only.
//! This adapter deliberately does not grant execution or publication authority.
//! Its peer identity is derived from the public key TLS actually authenticated,
//! never from the worker label or a self-asserted hello field.
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
use rabs_protocol::identity_store::TransportIdentity;
use std::future::{Future, poll_fn};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

/// Both endpoints must negotiate this exact protocol. There is no downgrade.
pub const WORKER_ALPN: &[u8] = b"rabs-worker-atp/1";
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
        Err(io::Error::new(io::ErrorKind::ConnectionAborted, "worker session cancelled"))
    } else {
        Ok(())
    }
}

/// A native timer supplies wakeups; the monotonic instant also rejects a late
/// poll even when bytes are immediately available. Construct the timeout NOW,
/// not inside the boxed async body, so its first poll cannot restart the clock.
struct FrameDeadline {
    until: Instant,
    wake: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl FrameDeadline {
    fn new(budget: Duration) -> Self {
        let timer = asupersync::time::timeout(
            asupersync::time::wall_now(), budget, std::future::pending::<()>(),
        );
        Self {
            until: Instant::now() + budget,
            wake: Box::pin(async move { let _ = timer.await; }),
        }
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.until || self.wake.as_mut().poll(cx).is_ready()
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
    read_deadline: Option<FrameDeadline>,
    idle_deadline: Option<FrameDeadline>,
    write_deadline: Option<FrameDeadline>,
}

impl<S> JsonAtpStream<S> {
    /// Wrap a stream. Authentication is the enclosing transport's responsibility.
    pub fn new(io: S) -> Self {
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
        let expired = if self.read_deadline.as_mut().is_some_and(|timer| timer.expired(cx)) {
            Some("worker ATP partial-frame deadline exceeded")
        } else if self.write_deadline.as_mut().is_some_and(|timer| timer.expired(cx)) {
            Some("worker ATP write/flush deadline exceeded")
        } else if self.idle_deadline.as_mut().is_some_and(|timer| timer.expired(cx)) {
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
        self.write_deadline.get_or_insert_with(|| FrameDeadline::new(FRAME_IO_TIMEOUT));
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
            let n = match ready!(Pin::new(&mut self.io).poll_write(
                cx,
                &self.output[self.output_offset..],
            )) {
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
        self.begin_write();
        self.check_live(cx)?;
        ready!(self.drain_output(cx))?;
        match ready!(Pin::new(&mut self.io).poll_flush(cx)) {
            Ok(()) => {
                // Flushing an unfinished JSON prefix is not completion of its
                // record and must not grant that prefix a fresh write budget.
                if self.line.is_empty() { self.write_deadline = None; }
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(self.poison(error))),
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
                let count = destination.remaining().min(this.ready.len() - this.ready_offset);
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
                        return Poll::Ready(Err(this.poison(invalid(
                            "unsupported worker ATP record",
                        ))));
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
                    return Poll::Ready(Err(this.poison(invalid(format!(
                        "worker ATP decode: {error}",
                    )))));
                }
            }
            this.idle_deadline.get_or_insert_with(|| FrameDeadline::new(IDLE_READ_TIMEOUT));
            if this.boundary_bytes != 0 {
                this.read_deadline.get_or_insert_with(|| FrameDeadline::new(FRAME_IO_TIMEOUT));
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
                    this.read_deadline.get_or_insert_with(|| FrameDeadline::new(FRAME_IO_TIMEOUT));
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
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
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
            Ok(()) => { this.write_deadline = None; Poll::Ready(Ok(())) }
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
    let file = std::fs::File::open(path).map_err(|e| format!("TLS file {}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("TLS material must be a regular file".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(TLS_FILE_LIMIT + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > TLS_FILE_LIMIT {
        return Err("TLS material exceeds the file-size limit".to_owned());
    }
    Ok(bytes)
}

/// Public-key identity, including after a certificate renewal with the same key.
/// The caller supplies the certificate returned by a successful TLS handshake.
pub fn certificate_identity(certificate: &Certificate) -> Result<TransportIdentity, String> {
    let pin = CertificatePin::compute_spki_sha256(certificate).map_err(|e| e.to_string())?;
    let fingerprint: [u8; 32] = pin.hash_bytes().try_into()
        .map_err(|_| "TLS public-key fingerprint has the wrong length".to_owned())?;
    Ok(TransportIdentity { peer_id: fingerprint, fingerprint })
}

impl TlsFiles {
    pub fn local_identity(&self) -> Result<TransportIdentity, String> {
        let certificates = Certificate::from_pem(&read_pem(&self.certificate)?)
            .map_err(|e| e.to_string())?;
        certificate_identity(certificates.first().ok_or("TLS certificate chain is empty")?)
    }

    pub fn connector(&self) -> Result<TlsConnector, String> {
        let roots = Certificate::from_pem(&read_pem(&self.ca)?).map_err(|e| e.to_string())?;
        let chain = CertificateChain::from_pem(&read_pem(&self.certificate)?)
            .map_err(|e| e.to_string())?;
        let key = PrivateKey::from_pem(&read_pem(&self.private_key)?)
            .map_err(|e| e.to_string())?;
        TlsConnectorBuilder::new()
            .with_strict_ca_validation()
            .add_root_certificates(roots)
            .identity(chain, key)
            .alpn_protocols_required(vec![WORKER_ALPN.to_vec()])
            .handshake_timeout(HANDSHAKE_TIMEOUT)
            .build()
            .map_err(|e| format!("worker TLS client configuration: {e}"))
    }

    pub fn acceptor(&self) -> Result<TlsAcceptor, String> {
        let mut roots = RootCertStore::empty();
        for cert in Certificate::from_pem(&read_pem(&self.ca)?).map_err(|e| e.to_string())? {
            roots.add(&cert).map_err(|e| format!("worker CA: {e}"))?;
        }
        let chain = CertificateChain::from_pem(&read_pem(&self.certificate)?)
            .map_err(|e| e.to_string())?;
        let key = PrivateKey::from_pem(&read_pem(&self.private_key)?)
            .map_err(|e| e.to_string())?;
        TlsAcceptor::builder(chain, key)
            .require_client_auth(roots)
            .alpn_protocols_required(vec![WORKER_ALPN.to_vec()])
            .handshake_timeout(HANDSHAKE_TIMEOUT)
            .build()
            .map_err(|e| format!("worker TLS server configuration: {e}"))
    }
}

pub type SecureWorkerStream = JsonAtpStream<TlsStream<TcpStream>>;

/// A successful mutual-TLS connection and the key it actually authenticated.
/// This identity is evidence, not an execution/publication grant.
pub struct AuthenticatedPeer {
    pub stream: SecureWorkerStream,
    pub identity: TransportIdentity,
}

fn established(stream: TlsStream<TcpStream>) -> Result<AuthenticatedPeer, String> {
    if stream.alpn_protocol() != Some(WORKER_ALPN) {
        return Err("worker ALPN was not negotiated".to_owned());
    }
    let certificate = stream.peer_leaf_certificate_der()
        .ok_or("worker TLS peer did not provide a certificate")?;
    let identity = certificate_identity(&Certificate::from_der(certificate))?;
    Ok(AuthenticatedPeer { stream: JsonAtpStream::new(stream), identity })
}

/// Authenticate an accepted socket before reading a single application record.
pub async fn accept_peer(acceptor: &TlsAcceptor, stream: TcpStream) -> Result<AuthenticatedPeer, String> {
    established(acceptor.accept(stream).await.map_err(|e| format!("worker TLS accept: {e}"))?)
}

/// Client connection with no plaintext fallback, even on a TLS configuration error.
pub async fn connect_peer(
    address: &str,
    server_name: &str,
    files: &TlsFiles,
) -> Result<AuthenticatedPeer, String> {
    let connector = files.connector()?;
    let connect = async {
        let stream = TcpStream::connect(address.to_owned()).await
            .map_err(|e| format!("worker connect: {e}"))?;
        established(connector.connect(server_name, stream).await
            .map_err(|e| format!("coordinator TLS handshake: {e}"))?)
    };
    asupersync::time::timeout(asupersync::time::wall_now(), CONNECT_TIMEOUT, connect)
        .await.map_err(|_| "worker connection deadline exceeded".to_owned())?
}

/// The historical plaintext fixture transport is restricted to literal loopback.
/// It cannot accidentally become a fleet transport through DNS or host aliases.
pub fn is_loopback_fixture(address: &str) -> bool {
    address.parse::<SocketAddr>().is_ok_and(|address| address.ip().is_loopback())
}

/// The worker's actual transport, with its authenticated mode visible to hello.
pub enum WorkerConnection {
    Authenticated { peer: Box<AuthenticatedPeer>, local: TransportIdentity },
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
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        check_task_cancellation()?;
        match self.get_mut() {
            Self::Authenticated { peer, .. } => Pin::new(&mut peer.stream).poll_read(cx, buf),
            Self::LoopbackFixture(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WorkerConnection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
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
    }).await
}

async fn connect_worker_inner(address: &str) -> Result<WorkerConnection, String> {
    let ca = std::env::var_os("RABS_WORKER_TLS_CA");
    let certificate = std::env::var_os("RABS_WORKER_TLS_CERT");
    let private_key = std::env::var_os("RABS_WORKER_TLS_KEY");
    let server_name = std::env::var_os("RABS_WORKER_TLS_SERVER_NAME");
    if ca.is_none() && certificate.is_none() && private_key.is_none() && server_name.is_none() {
        if !is_loopback_fixture(address) {
            return Err("fleet connections require RABS_WORKER_TLS_CA/CERT/KEY/SERVER_NAME".to_owned());
        }
        let stream = asupersync::time::timeout(
            asupersync::time::wall_now(), CONNECT_TIMEOUT, TcpStream::connect(address.to_owned()),
        ).await.map_err(|_| "loopback fixture connection timed out".to_owned())?
            .map_err(|e| format!("loopback fixture connection: {e}"))?;
        return Ok(WorkerConnection::LoopbackFixture(stream));
    }
    let files = TlsFiles {
        ca: PathBuf::from(ca.ok_or("missing RABS_WORKER_TLS_CA")?),
        certificate: PathBuf::from(certificate.ok_or("missing RABS_WORKER_TLS_CERT")?),
        private_key: PathBuf::from(private_key.ok_or("missing RABS_WORKER_TLS_KEY")?),
    };
    let server_name = server_name.ok_or("missing RABS_WORKER_TLS_SERVER_NAME")?
        .into_string().map_err(|_| "TLS server name must be UTF-8".to_owned())?;
    if server_name.is_empty() {
        return Err("TLS server name must not be empty".to_owned());
    }
    let local = files.local_identity()?;
    let peer = connect_peer(address, &server_name, &files).await?;
    Ok(WorkerConnection::Authenticated { peer: Box::new(peer), local })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::task::Waker;

    struct Wire {
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
        blocked: bool,
        quantum: usize,
    }

    impl Default for Wire {
        fn default() -> Self {
            Self { input: VecDeque::new(), output: Vec::new(), eof: false, blocked: false, quantum: 3 }
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.input.is_empty() {
                return if this.eof { Poll::Ready(Ok(())) } else { Poll::Pending };
            }
            for _ in 0..this.quantum.min(buf.remaining()).min(this.input.len()) {
                buf.put_slice(&[this.input.pop_front().unwrap()]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.blocked { return Poll::Pending }
            let count = this.quantum.min(bytes.len());
            this.output.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.blocked { Poll::Pending } else { Poll::Ready(Ok(())) }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn encoded(payload: &[u8], kind: FrameType) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        AtpFrameCodec::new().encode(Frame::new(ProtocolVersion::CURRENT, kind, payload.to_vec()).unwrap(), &mut bytes).unwrap();
        bytes.to_vec()
    }

    fn read_once(stream: &mut JsonAtpStream<Wire>) -> Poll<io::Result<Vec<u8>>> {
        let mut bytes = [0u8; 128];
        let mut destination = ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream).poll_read(&mut cx, &mut destination)
            .map(|result| result.map(|()| destination.filled().to_vec()))
    }

    #[test]
    fn fragmented_native_frames_return_exact_driver_records() {
        let mut stream = JsonAtpStream::new(Wire::default());
        stream.io.input.extend(encoded(br#"{"kind":"ping"}"#, FrameType::Control));
        stream.io.input.extend(encoded(br#"{"kind":"cancel","request_id":7}"#, FrameType::Control));
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"ping\"}\n"));
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"cancel\",\"request_id\":7}\n"));
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
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(bytes)) if bytes == b"{\"kind\":\"ping\"}\n"));
    }

    #[test]
    fn truncated_header_and_payload_fail_instead_of_clean_eof() {
        let wire = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        for length in 1..wire.len() {
            let mut stream = JsonAtpStream::new(Wire::default());
            stream.io.input.extend(&wire[..length]);
            stream.io.eof = true;
            assert!(matches!(read_once(&mut stream), Poll::Ready(Err(_))), "prefix {length}");
            assert!(matches!(read_once(&mut stream), Poll::Ready(Err(_))), "poison {length}");
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
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, first), Poll::Ready(Ok(n)) if n == first.len()));
        assert!(stream.io.output.is_empty());
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"\"ping\"}\n"), Poll::Ready(Ok(8))));
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
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, &vec![b'a'; MAX_JSON_RECORD + 1]), Poll::Ready(Err(_))));
        let mut stream = JsonAtpStream::new(Wire::default());
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"{"), Poll::Ready(Ok(1))));
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Err(_))));
    }

    #[test]
    fn plaintext_fixture_cannot_be_selected_by_hostname_or_remote_address() {
        assert!(is_loopback_fixture("127.0.0.1:1234"));
        assert!(is_loopback_fixture("[::1]:1234"));
        for address in ["localhost:1234", "worker:1234", "10.0.0.2:1234", "0.0.0.0:1234", "[::]:1234"] {
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
        stream.read_deadline.as_mut().unwrap().until = Instant::now();
        stream.io.input.extend(&bytes[6..]);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
        assert!(stream.failed);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(_))));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"{}\n"), Poll::Ready(Err(_))));
        assert!(stream.io.output.is_empty());
    }

    #[test]
    fn write_prefix_and_stalled_flush_share_one_terminal_deadline() {
        let mut stream = JsonAtpStream::new(Wire::default());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"{"), Poll::Ready(Ok(1))));
        let until = stream.write_deadline.as_ref().unwrap().until;
        assert!(matches!(Pin::new(&mut stream).poll_flush(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(stream.write_deadline.as_ref().unwrap().until, until);
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"}\n"), Poll::Ready(Ok(2))));
        assert_eq!(stream.write_deadline.as_ref().unwrap().until, until);
        stream.io.blocked = true;
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        stream.write_deadline.as_mut().unwrap().until = Instant::now();
        stream.io.blocked = false;
        assert!(matches!(Pin::new(&mut stream).poll_flush(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
        assert!(stream.io.output.is_empty(), "late flush must not write expired bytes");
        assert!(matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Err(_))));
    }

    #[test]
    fn healthy_idle_and_partial_record_budgets_are_distinct() {
        let mut stream = JsonAtpStream::new(Wire::default());
        assert!(read_once(&mut stream).is_pending());
        assert!(stream.read_deadline.is_none());
        let idle = stream.idle_deadline.as_ref().unwrap().until;
        assert!(idle.duration_since(Instant::now()) > Duration::from_secs(30 * 60));
        let bytes = encoded(br#"{"kind":"ping"}"#, FrameType::Control);
        stream.io.input.extend(&bytes[..6]);
        assert!(read_once(&mut stream).is_pending());
        assert!(stream.read_deadline.as_ref().unwrap().until < idle);
        stream.io.input.extend(&bytes[6..]);
        assert!(matches!(read_once(&mut stream), Poll::Ready(Ok(_))));
        assert!(stream.read_deadline.is_none());
        assert!(stream.idle_deadline.is_none());
        assert!(read_once(&mut stream).is_pending());
        stream.idle_deadline.as_mut().unwrap().until = Instant::now();
        assert!(matches!(read_once(&mut stream), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::TimedOut));
    }
}
