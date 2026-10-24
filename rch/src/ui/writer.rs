//! Thread-safe output writers for stdout and stderr.
//!
//! Provides synchronized access to output streams to prevent interleaving
//! when multiple tasks output concurrently.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// Thread-safe writer that wraps an output stream.
#[derive(Clone)]
pub struct OutputWriter {
    inner: Arc<Mutex<Box<dyn Write + Send>>>,
    is_tty: bool,
}

impl std::fmt::Debug for OutputWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputWriter")
            .field("is_tty", &self.is_tty)
            .finish()
    }
}

impl OutputWriter {
    /// Create a new output writer wrapping the given stream.
    pub fn new<W: Write + Send + 'static>(writer: W, is_tty: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(writer))),
            is_tty,
        }
    }

    /// Create a writer for stdout.
    pub fn stdout() -> Self {
        let is_tty = is_terminal::is_terminal(io::stdout());
        Self::new(io::stdout(), is_tty)
    }

    /// Create a writer for stderr.
    pub fn stderr() -> Self {
        let is_tty = is_terminal::is_terminal(io::stderr());
        Self::new(io::stderr(), is_tty)
    }

    /// Check if this writer is connected to a TTY.
    pub fn is_tty(&self) -> bool {
        self.is_tty
    }

    /// Write a line to the output (with newline).
    pub fn write_line(&self, line: &str) {
        if let Ok(mut writer) = self.inner.lock() {
            let _ = writeln!(writer, "{line}");
            let _ = writer.flush();
        }
    }

    /// Write and flush a line, reporting delivery or poisoned-lock failures.
    pub fn write_line_checked(&self, line: &str) -> io::Result<()> {
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("output writer lock poisoned"))?;
        writeln!(writer, "{line}")?;
        writer.flush()
    }

    /// Write text without a trailing newline.
    pub fn write(&self, text: &str) {
        if let Ok(mut writer) = self.inner.lock() {
            let _ = write!(writer, "{text}");
            let _ = writer.flush();
        }
    }

    /// Write raw bytes.
    pub fn write_bytes(&self, bytes: &[u8]) {
        if let Ok(mut writer) = self.inner.lock() {
            let _ = writer.write_all(bytes);
            let _ = writer.flush();
        }
    }

    /// Flush the output buffer.
    pub fn flush(&self) {
        if let Ok(mut writer) = self.inner.lock() {
            let _ = writer.flush();
        }
    }
}

/// Buffer for capturing output in tests.
#[derive(Clone, Default)]
pub struct OutputBuffer {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl std::fmt::Debug for OutputBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputBuffer").finish()
    }
}

impl OutputBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the contents as a string.
    pub fn to_string_lossy(&self) -> String {
        let guard = self.inner.lock().unwrap();
        String::from_utf8_lossy(&guard).to_string()
    }

    /// Get the contents as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let guard = self.inner.lock().unwrap();
        guard.clone()
    }

    /// Clear the buffer.
    pub fn clear(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.clear();
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        let guard = self.inner.lock().unwrap();
        guard.is_empty()
    }

    /// Get the length of the buffer.
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().unwrap();
        guard.len()
    }
}

impl Write for OutputBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.inner.lock().unwrap();
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A clonable version of OutputBuffer that implements Write by wrapping a clone.
#[derive(Clone, Default, Debug)]
pub struct SharedOutputBuffer {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl SharedOutputBuffer {
    /// Create a new empty shared buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the contents as a string.
    pub fn to_string_lossy(&self) -> String {
        let guard = self.inner.lock().unwrap();
        String::from_utf8_lossy(&guard).to_string()
    }

    /// Create an OutputWriter using this buffer.
    pub fn as_writer(&self, is_tty: bool) -> OutputWriter {
        OutputWriter {
            inner: Arc::new(Mutex::new(Box::new(BufferWriter(self.inner.clone())))),
            is_tty,
        }
    }
}

/// Internal writer that writes to a shared buffer.
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().unwrap();
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    #[test]
    fn test_output_buffer_write_and_read() {
        log_test_start("test_output_buffer_write_and_read");
        let mut buffer = OutputBuffer::new();
        write!(buffer, "Hello, ").unwrap();
        write!(buffer, "World!").unwrap();
        assert_eq!(buffer.to_string_lossy(), "Hello, World!");
    }

    #[test]
    fn test_output_buffer_clear() {
        log_test_start("test_output_buffer_clear");
        let mut buffer = OutputBuffer::new();
        write!(buffer, "test").unwrap();
        assert!(!buffer.is_empty());
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_output_writer_line() {
        log_test_start("test_output_writer_line");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write_line("test line");
        assert_eq!(buffer.to_string_lossy(), "test line\n");
        writer.write_line_checked("checked line").unwrap();
        assert_eq!(buffer.to_string_lossy(), "test line\nchecked line\n");
    }

    #[test]
    fn checked_line_reports_a_poisoned_lock_without_writing() {
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        let poisoned = writer.clone();
        assert!(
            thread::spawn(move || {
                let _guard = poisoned.inner.lock().unwrap();
                panic!("intentional output writer lock poisoning");
            })
            .join()
            .is_err()
        );
        let error = writer.write_line_checked("undelivered").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("output writer lock poisoned"));
        assert!(buffer.to_string_lossy().is_empty());
    }

    #[test]
    fn test_output_writer_thread_safe() {
        log_test_start("test_output_writer_thread_safe");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let w = writer.clone();
                thread::spawn(move || {
                    w.write_line(&format!("line {i}"));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let output = buffer.to_string_lossy();
        // All 10 lines should be present (thread-safe means no data loss)
        for i in 0..10 {
            assert!(
                output.contains(&format!("line {i}")),
                "Missing line {i} in output"
            );
        }
    }

    // ========================
    // OutputWriter tests
    // ========================

    #[test]
    fn test_output_writer_write_without_newline() {
        log_test_start("test_output_writer_write_without_newline");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write("hello");
        writer.write(" world");
        assert_eq!(buffer.to_string_lossy(), "hello world");
    }

    #[test]
    fn test_output_writer_write_bytes() {
        log_test_start("test_output_writer_write_bytes");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write_bytes(b"raw bytes");
        assert_eq!(buffer.to_string_lossy(), "raw bytes");
    }

    #[test]
    fn test_output_writer_write_bytes_binary() {
        log_test_start("test_output_writer_write_bytes_binary");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        let binary = vec![0x00, 0x01, 0x02, 0xFF];
        writer.write_bytes(&binary);
        let output = buffer.inner.lock().unwrap();
        assert_eq!(output.as_slice(), &[0x00, 0x01, 0x02, 0xFF]);
    }

    #[test]
    fn test_output_writer_flush() {
        log_test_start("test_output_writer_flush");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write("data");
        writer.flush();
        assert_eq!(buffer.to_string_lossy(), "data");
    }

    #[test]
    fn test_output_writer_is_tty_false() {
        log_test_start("test_output_writer_is_tty_false");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        assert!(!writer.is_tty());
    }

    #[test]
    fn test_output_writer_is_tty_true() {
        log_test_start("test_output_writer_is_tty_true");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(true);
        assert!(writer.is_tty());
    }

    #[test]
    fn test_output_writer_debug() {
        log_test_start("test_output_writer_debug");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(true);
        let debug = format!("{:?}", writer);
        assert!(debug.contains("OutputWriter"));
        assert!(debug.contains("is_tty"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn test_output_writer_clone() {
        log_test_start("test_output_writer_clone");
        let buffer = SharedOutputBuffer::new();
        let writer1 = buffer.as_writer(false);
        let writer2 = writer1.clone();

        writer1.write("from writer1 ");
        writer2.write("from writer2");

        assert_eq!(buffer.to_string_lossy(), "from writer1 from writer2");
    }

    #[test]
    fn test_output_writer_multiple_lines() {
        log_test_start("test_output_writer_multiple_lines");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write_line("line 1");
        writer.write_line("line 2");
        writer.write_line("line 3");
        assert_eq!(buffer.to_string_lossy(), "line 1\nline 2\nline 3\n");
    }

    #[test]
    fn test_output_writer_mixed_operations() {
        log_test_start("test_output_writer_mixed_operations");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write("prefix: ");
        writer.write_line("with newline");
        writer.write_bytes(b"raw");
        assert_eq!(buffer.to_string_lossy(), "prefix: with newline\nraw");
    }

    // ========================
    // OutputBuffer tests
    // ========================

    #[test]
    fn test_output_buffer_to_bytes() {
        log_test_start("test_output_buffer_to_bytes");
        let mut buffer = OutputBuffer::new();
        write!(buffer, "test").unwrap();
        let bytes = buffer.to_bytes();
        assert_eq!(bytes, b"test");
    }

    #[test]
    fn test_output_buffer_len() {
        log_test_start("test_output_buffer_len");
        let mut buffer = OutputBuffer::new();
        assert_eq!(buffer.len(), 0);
        write!(buffer, "12345").unwrap();
        assert_eq!(buffer.len(), 5);
    }

    #[test]
    fn test_output_buffer_is_empty() {
        log_test_start("test_output_buffer_is_empty");
        let buffer = OutputBuffer::new();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_output_buffer_default() {
        log_test_start("test_output_buffer_default");
        let buffer: OutputBuffer = Default::default();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_output_buffer_debug() {
        log_test_start("test_output_buffer_debug");
        let buffer = OutputBuffer::new();
        let debug = format!("{:?}", buffer);
        assert!(debug.contains("OutputBuffer"));
    }

    #[test]
    fn test_output_buffer_clone() {
        log_test_start("test_output_buffer_clone");
        let mut buffer = OutputBuffer::new();
        write!(buffer, "original").unwrap();

        let cloned = buffer.clone();
        // Both share the same data (Arc)
        assert_eq!(cloned.to_string_lossy(), "original");
    }

    #[test]
    fn test_output_buffer_write_trait_flush() {
        log_test_start("test_output_buffer_write_trait_flush");
        let mut buffer = OutputBuffer::new();
        buffer.flush().unwrap();
        assert!(buffer.is_empty());
    }

    // ========================
    // SharedOutputBuffer tests
    // ========================

    #[test]
    fn test_shared_output_buffer_new() {
        log_test_start("test_shared_output_buffer_new");
        let buffer = SharedOutputBuffer::new();
        assert_eq!(buffer.to_string_lossy(), "");
    }

    #[test]
    fn test_shared_output_buffer_default() {
        log_test_start("test_shared_output_buffer_default");
        let buffer: SharedOutputBuffer = Default::default();
        assert_eq!(buffer.to_string_lossy(), "");
    }

    #[test]
    fn test_shared_output_buffer_clone() {
        log_test_start("test_shared_output_buffer_clone");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write("test");

        let cloned = buffer.clone();
        assert_eq!(cloned.to_string_lossy(), "test");
    }

    #[test]
    fn test_shared_output_buffer_debug() {
        log_test_start("test_shared_output_buffer_debug");
        let buffer = SharedOutputBuffer::new();
        let debug = format!("{:?}", buffer);
        assert!(debug.contains("SharedOutputBuffer"));
    }

    #[test]
    fn test_shared_output_buffer_as_writer_tty_setting() {
        log_test_start("test_shared_output_buffer_as_writer_tty_setting");
        let buffer = SharedOutputBuffer::new();
        let writer_tty = buffer.as_writer(true);
        let writer_no_tty = buffer.as_writer(false);

        assert!(writer_tty.is_tty());
        assert!(!writer_no_tty.is_tty());
    }

    #[test]
    fn test_shared_output_buffer_concurrent_writes() {
        log_test_start("test_shared_output_buffer_concurrent_writes");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let w = writer.clone();
                thread::spawn(move || {
                    w.write(&format!("{}", i));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All digits should be present (order may vary)
        let output = buffer.to_string_lossy();
        assert_eq!(output.len(), 5);
        for i in 0..5 {
            assert!(output.contains(&i.to_string()));
        }
    }

    // ========================
    // Edge case tests
    // ========================

    #[test]
    fn test_output_writer_empty_string() {
        log_test_start("test_output_writer_empty_string");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write("");
        writer.write_line("");
        assert_eq!(buffer.to_string_lossy(), "\n");
    }

    #[test]
    fn test_output_writer_unicode() {
        log_test_start("test_output_writer_unicode");
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write_line("Hello, 世界! 🌍");
        assert!(buffer.to_string_lossy().contains("世界"));
        assert!(buffer.to_string_lossy().contains("🌍"));
    }

    #[test]
    fn test_output_buffer_binary_data() {
        log_test_start("test_output_buffer_binary_data");
        let mut buffer = OutputBuffer::new();
        let data = vec![0x00, 0xFF, 0x80, 0x7F];
        buffer.write_all(&data).unwrap();
        assert_eq!(buffer.to_bytes(), data);
    }
}
