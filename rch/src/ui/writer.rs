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

    #[test]
    fn test_output_buffer_write_and_read() {
        let mut buffer = OutputBuffer::new();
        write!(buffer, "Hello, ").unwrap();
        write!(buffer, "World!").unwrap();
        assert_eq!(buffer.to_string_lossy(), "Hello, World!");
    }

    #[test]
    fn test_output_buffer_clear() {
        let mut buffer = OutputBuffer::new();
        write!(buffer, "test").unwrap();
        assert!(!buffer.is_empty());
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_output_writer_line() {
        let buffer = SharedOutputBuffer::new();
        let writer = buffer.as_writer(false);
        writer.write_line("test line");
        assert_eq!(buffer.to_string_lossy(), "test line\n");
    }

    #[test]
    fn test_output_writer_thread_safe() {
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
}
