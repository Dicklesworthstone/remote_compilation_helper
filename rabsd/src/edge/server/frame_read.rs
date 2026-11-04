//! Bounded newline framing over one connection-owned read buffer.
//!
//! The caller keeps this buffer across hello, requests, compiler completion,
//! capture acknowledgment and subsequent requests. Never wrap each frame in a
//! fresh buffer or read directly from its inner socket: prefetched bytes belong
//! to the next phase. Writes may use the inner socket without disturbing them.
//!
//! The caller supplies one absolute timeout around this future. On cancellation,
//! malformed/oversized input or EOF the connection is terminal; consumed partial
//! bytes must not be retried as the beginning of a new protocol frame.

use asupersync::io::AsyncBufRead;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

/// The delimiter does not count toward the existing frame payload limit.
/// Copy chunks rather than issuing a socket read and async poll per byte.
pub(super) async fn read_frame(
    reader: &mut (impl AsyncBufRead + Unpin),
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let mut frame = Vec::new();
    poll_fn(|cx| {
        loop {
            let available = match Pin::new(&mut *reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Ready(Ok(available)) => available,
            };
            if available.is_empty() {
                return Poll::Ready(None);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.unwrap_or(available.len());
            if count > max_bytes.saturating_sub(frame.len()) {
                return Poll::Ready(None);
            }
            frame.extend_from_slice(&available[..count]);
            Pin::new(&mut *reader).consume(count + usize::from(newline.is_some()));
            if newline.is_some() {
                return Poll::Ready(Some(std::mem::take(&mut frame)));
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::{AsyncRead, BufReader, ReadBuf};
    use std::future::Future;
    use std::io;
    use std::task::{Context, Waker};

    struct Source {
        bytes: Vec<u8>,
        offset: usize,
        chunk: usize,
        reads: usize,
        pending: bool,
        alternate_pending: bool,
        error_at_end: bool,
    }

    impl Source {
        fn new(bytes: Vec<u8>, chunk: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                chunk,
                reads: 0,
                pending: false,
                alternate_pending: false,
                error_at_end: false,
            }
        }
    }

    impl AsyncRead for Source {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let source = self.get_mut();
            if source.pending {
                source.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            source.reads += 1;
            if source.offset == source.bytes.len() && source.error_at_end {
                return Poll::Ready(Err(io::Error::other("injected read failure")));
            }
            let count = output
                .remaining()
                .min(source.chunk)
                .min(source.bytes.len() - source.offset);
            output.put_slice(&source.bytes[source.offset..source.offset + count]);
            source.offset += count;
            source.pending = source.alternate_pending;
            Poll::Ready(Ok(()))
        }
    }

    // Deterministic source readiness needs no nested runtime or wall-clock wait.
    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
        panic!("deterministic frame reader did not settle");
    }

    #[test]
    fn coalesced_protocol_phases_retain_prefetched_bytes() {
        let phases: [&[u8]; 5] = [
            b"hello",
            b"rustc-request",
            b"rustc-complete",
            b"rustc-capture-ack",
            b"next-rustc-request",
        ];
        let mut wire = Vec::new();
        for frame in phases {
            wire.extend_from_slice(frame);
            wire.push(b'\n');
        }
        let mut reader = BufReader::with_capacity(16 * 1024, Source::new(wire, usize::MAX));
        for expected in phases {
            assert_eq!(ready(read_frame(&mut reader, 64 * 1024)).unwrap(), expected);
        }
        assert_eq!(reader.get_ref().reads, 1);
        assert_eq!(ready(read_frame(&mut reader, 64 * 1024)), None);
    }

    #[test]
    fn large_completion_uses_block_reads_not_one_read_per_byte() {
        let size = 2 * 1024 * 1024 + 64 * 1024;
        let mut wire = vec![b'x'; size];
        wire.push(b'\n');
        wire.extend_from_slice(b"ack\n");
        let mut reader = BufReader::with_capacity(16 * 1024, Source::new(wire, usize::MAX));
        let frame = ready(read_frame(&mut reader, size)).unwrap();
        assert_eq!(frame.len(), size);
        assert!(frame.iter().all(|byte| *byte == b'x'));
        let reads = reader.get_ref().reads;
        assert_eq!(reads, (size + 1).div_ceil(16 * 1024));
        assert_eq!(ready(read_frame(&mut reader, 3)).unwrap(), b"ack");
        assert_eq!(reader.get_ref().reads, reads);
    }

    #[test]
    fn fragmented_and_pending_reads_preserve_exact_binary_frame_bytes() {
        let payload = b"quotes\"\\\r\0\xff bytes";
        for chunk in [1, 2, 7, 16, 4096] {
            let mut wire = payload.to_vec();
            wire.extend_from_slice(b"\nnext\n");
            let mut source = Source::new(wire, chunk);
            source.alternate_pending = true;
            let mut reader = BufReader::with_capacity(8, source);
            assert_eq!(
                ready(read_frame(&mut reader, payload.len())).unwrap(),
                payload
            );
            assert_eq!(ready(read_frame(&mut reader, 4)).unwrap(), b"next");
            assert_eq!(ready(read_frame(&mut reader, 4)), None);
        }
    }

    #[test]
    fn exact_payload_limits_include_neither_delimiter_nor_next_frame() {
        for chunk in [1, 2, 3, 4, 64] {
            let mut reader =
                BufReader::with_capacity(8, Source::new(b"abc\nnext\n".to_vec(), chunk));
            assert_eq!(ready(read_frame(&mut reader, 3)).unwrap(), b"abc");
            assert_eq!(ready(read_frame(&mut reader, 4)).unwrap(), b"next");
            let mut oversized = BufReader::with_capacity(8, Source::new(b"abcd\n".to_vec(), chunk));
            assert_eq!(ready(read_frame(&mut oversized, 3)), None);
        }
        let mut empty = BufReader::new(Source::new(b"\nx\n".to_vec(), 8));
        assert_eq!(ready(read_frame(&mut empty, 0)), Some(Vec::new()));
        assert_eq!(ready(read_frame(&mut empty, 0)), None);
    }

    #[test]
    fn eof_and_errors_never_return_an_unterminated_frame() {
        for bytes in [b"".as_slice(), b"partial", b"exact"] {
            for error_at_end in [false, true] {
                let mut source = Source::new(bytes.to_vec(), 2);
                source.error_at_end = error_at_end;
                let mut reader = BufReader::with_capacity(4, source);
                assert_eq!(ready(read_frame(&mut reader, bytes.len())), None);
            }
        }
    }

    #[test]
    fn dropping_a_pending_frame_does_not_read_or_create_protocol_authority() {
        let mut source = Source::new(b"partial".to_vec(), 2);
        source.alternate_pending = true;
        let mut reader = BufReader::with_capacity(4, source);
        {
            let mut future = std::pin::pin!(read_frame(&mut reader, 64));
            let mut context = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut context).is_pending());
        }
        assert_eq!(reader.get_ref().reads, 1);
        assert_eq!(reader.get_ref().offset, 2);
        // The caller closes this connection, as with timeout in the old reader.
        // There is intentionally no attempt to reinterpret the consumed prefix.
    }
}
