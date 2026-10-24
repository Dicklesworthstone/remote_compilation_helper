//! Streaming, same-invocation release download recovery.
//!
//! Retry only a contiguous prefix tied to a strong HTTP validator. The release
//! metadata bounds disk use; neither its length nor the ETag authenticates the
//! archive. The caller must still verify its checksum and pinned-key signature.
//! See RFC 9110 sections 13.1.5, 14.4 and 15.3.7.3.

use super::{UpdateError, classify_http_status, write_downloaded_bytes};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use std::io::SeekFrom;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncSeekExt;

/// Own one file and validator for the complete retry loop. Never recover an
/// arbitrary pre-existing file or trust an offset supplied by a caller.
pub(super) struct AssetDownload {
    client: Client,
    url: String,
    file: tokio::fs::File,
    expected_size: u64,
    offset: u64,
    etag: Option<HeaderValue>,
}

fn local(error: std::io::Error) -> UpdateError {
    UpdateError::DownloadFailed(format!("Cannot store release download: {error}"))
}

fn invalid(detail: &str) -> UpdateError {
    UpdateError::DownloadFailed(format!("Invalid release download response: {detail}"))
}

fn network(error: reqwest::Error) -> UpdateError {
    // Redirect URLs may contain temporary signed credentials.
    UpdateError::NetworkError(error.without_url().to_string())
}

impl AssetDownload {
    pub(super) async fn new(
        url: &str,
        dest: &Path,
        expected_size: u64,
    ) -> Result<Self, UpdateError> {
        let client = client_builder().build().map_err(network)?;
        Self::with_client(client, url, dest, expected_size).await
    }

    async fn with_client(
        client: Client,
        url: &str,
        dest: &Path,
        expected_size: u64,
    ) -> Result<Self, UpdateError> {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .await
            .map_err(local)?;
        Ok(Self {
            client,
            url: url.to_owned(),
            file,
            expected_size,
            offset: 0,
            etag: None,
        })
    }

    fn resumable(&self) -> Option<&HeaderValue> {
        // Reaching the declared length without a valid HTTP end-of-message is
        // not completion. Re-fetch rather than interpreting a 416 as success.
        (self.offset > 0 && self.offset < self.expected_size)
            .then_some(self.etag.as_ref())
            .flatten()
    }

    pub(super) async fn attempt(&mut self) -> Result<(), UpdateError> {
        let previous_etag = self.resumable().cloned();
        let start = if previous_etag.is_some() {
            self.offset
        } else {
            0
        };
        let mut request = self
            .client
            .get(&self.url)
            .header("Accept-Encoding", "identity");
        if let Some(etag) = &previous_etag {
            request = request
                .header("Range", format!("bytes={start}-"))
                .header("If-Range", etag.clone());
        }
        let mut response = request.send().await.map_err(network)?;
        let status = response.status();
        if previous_etag.is_some()
            && matches!(
                status,
                StatusCode::RANGE_NOT_SATISFIABLE | StatusCode::PRECONDITION_FAILED
            )
        {
            // Some CDNs refuse ranges instead of sending a full 200. Consume
            // an ordinary retry attempt, and make the next request a full GET.
            // Do not authorize a completed download from a 416's length alone.
            self.etag = None;
            return Err(UpdateError::NetworkError(
                "Release server refused resumption; retrying a full download".to_owned(),
            ));
        }
        let plan = plan_response(
            status,
            response.headers(),
            start,
            previous_etag.as_ref(),
            self.expected_size,
        )?;
        if plan.restart {
            self.file.set_len(0).await.map_err(local)?;
            self.file.seek(SeekFrom::Start(0)).await.map_err(local)?;
            self.offset = 0;
        }
        self.etag = plan.etag;
        tracing::debug!(
            resumed = !plan.restart,
            offset = self.offset,
            expected_bytes = self.expected_size,
            "Receiving release asset"
        );

        while let Some(chunk) = response.chunk().await.map_err(network)? {
            let next = self
                .offset
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| invalid("byte count overflow"))?;
            if next > plan.end {
                return Err(invalid(
                    "body exceeds its declared range or release asset size",
                ));
            }
            // Each accepted prefix has completed local I/O before it becomes
            // eligible for resumption. This also preserves the signature-read
            // completion barrier and makes delayed local errors non-retryable.
            write_downloaded_bytes(&mut self.file, &chunk).await?;
            self.offset = next;
        }
        if self.offset != plan.end {
            return Err(UpdateError::NetworkError(
                "Release response ended before the expected byte count".to_owned(),
            ));
        }
        if self.offset != self.expected_size {
            // A server may return a shorter contiguous range. The next normal
            // retry continues from that exact prefix; the retry budget holds.
            return Err(UpdateError::NetworkError(
                "Release response delivered only part of the requested range".to_owned(),
            ));
        }
        Ok(())
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(Duration::from_secs(300))
        .connect_timeout(Duration::from_secs(30))
        .user_agent(concat!("rch/", env!("CARGO_PKG_VERSION")))
        // Byte offsets refer to the signed representation, never transparently
        // decoded bytes. These opt-outs work even under feature unification.
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        // The outer loop owns the request budget, including range resets.
        .retry(reqwest::retry::never())
}

#[derive(Debug)]
struct BodyPlan {
    restart: bool,
    /// Exclusive end position in the entire release asset.
    end: u64,
    etag: Option<HeaderValue>,
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, UpdateError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid("duplicate representation header"));
    }
    Ok(first)
}

fn decimal(value: &str) -> Result<u64, UpdateError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("invalid byte count"));
    }
    value.parse().map_err(|_| invalid("byte count overflow"))
}

fn header_text(value: &HeaderValue) -> Result<&str, UpdateError> {
    value
        .to_str()
        .map_err(|_| invalid("non-ASCII representation header"))
}

fn strong_etag(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && bytes[0] == b'"'
        && bytes[bytes.len() - 1] == b'"'
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
}

fn plan_response(
    status: StatusCode,
    headers: &HeaderMap,
    start: u64,
    previous_etag: Option<&HeaderValue>,
    expected_size: u64,
) -> Result<BodyPlan, UpdateError> {
    if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
        return Err(classify_http_status(status));
    }
    if let Some(encoding) = unique_header(headers, "content-encoding")?
        && !header_text(encoding)?.eq_ignore_ascii_case("identity")
    {
        return Err(invalid(
            "encoded representation cannot be resumed or verified as an archive",
        ));
    }
    let length = unique_header(headers, "content-length")?
        .map(|value| decimal(header_text(value)?))
        .transpose()?;
    let etag = unique_header(headers, "etag")?
        .filter(|value| strong_etag(value))
        .cloned();
    let range = unique_header(headers, "content-range")?;
    if status == StatusCode::OK {
        if range.is_some() || length.is_some_and(|length| length != expected_size) {
            return Err(invalid("full response does not match release asset size"));
        }
        // The representation changed, the validator was absent/weak, or the
        // server ignored Range. Never concatenate a full body with old bytes.
        return Ok(BodyPlan {
            restart: true,
            end: expected_size,
            etag,
        });
    }
    if start == 0
        || start >= expected_size
        || previous_etag.is_none()
        || etag.as_ref() != previous_etag
    {
        return Err(invalid("partial response lacks the exact strong validator"));
    }
    let range = header_text(range.ok_or_else(|| invalid("partial response lacks Content-Range"))?)?;
    let (positions, total) = range
        .strip_prefix("bytes ")
        .and_then(|value| value.split_once('/'))
        .ok_or_else(|| invalid("invalid Content-Range"))?;
    let (first, last) = positions
        .split_once('-')
        .ok_or_else(|| invalid("invalid Content-Range"))?;
    let first = decimal(first)?;
    let last = decimal(last)?;
    let total = decimal(total)?;
    if first != start || last < first || last >= total || total != expected_size {
        return Err(invalid(
            "partial response range does not match retained bytes",
        ));
    }
    let end = last
        .checked_add(1)
        .ok_or_else(|| invalid("range end overflow"))?;
    if length.is_some_and(|length| length != end - start) {
        return Err(invalid("partial response length does not match its range"));
    }
    if let Some(content_type) = unique_header(headers, "content-type")?
        && header_text(content_type)?
            .to_ascii_lowercase()
            .starts_with("multipart/")
    {
        return Err(invalid("multipart ranges are not supported"));
    }
    Ok(BodyPlan {
        restart: false,
        end,
        etag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn only_strong_literal_entity_tags_authorize_resumption() {
        for value in ["\"\"", "\"asset-v1\"", "\"with\\backslash\""] {
            assert!(strong_etag(&HeaderValue::from_str(value).unwrap()));
        }
        for value in [
            "",
            "asset-v1",
            "W/\"asset-v1\"",
            "\"a\", \"b\"",
            "\"a b\"",
            "\"a\"junk",
        ] {
            assert!(
                !strong_etag(&HeaderValue::from_str(value).unwrap()),
                "{value}"
            );
        }
    }

    #[test]
    fn full_responses_restart_and_ranges_require_exact_identity_and_offsets() {
        let etag = HeaderValue::from_static("\"v1\"");
        let full = headers(&[("content-length", "10"), ("etag", "\"v2\"")]);
        assert!(
            plan_response(StatusCode::OK, &full, 4, Some(&etag), 10)
                .unwrap()
                .restart
        );
        let partial = headers(&[
            ("content-range", "bytes 4-9/10"),
            ("content-length", "6"),
            ("etag", "\"v1\""),
        ]);
        let plan =
            plan_response(StatusCode::PARTIAL_CONTENT, &partial, 4, Some(&etag), 10).unwrap();
        assert!(!plan.restart);
        assert_eq!(plan.end, 10);
        for (start, previous, size) in [
            (0, Some(&etag), 10),
            (3, Some(&etag), 10),
            (4, None, 10),
            (4, Some(&etag), 11),
        ] {
            assert!(
                plan_response(StatusCode::PARTIAL_CONTENT, &partial, start, previous, size)
                    .is_err()
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_ranges_never_authorize_append() {
        let etag = HeaderValue::from_static("\"v1\"");
        for range in [
            "bytes 3-9/10",
            "bytes 5-9/10",
            "bytes 4-3/10",
            "bytes 4-10/10",
            "bytes 4-9/*",
            "bytes 4-9/11",
            "bytes +4-9/10",
            "bytes 4-18446744073709551615/10",
            "items 4-9/10",
            "bytes 4-9/10, 4-9/10",
        ] {
            let mut input = headers(&[("etag", "\"v1\"")]);
            input.insert("content-range", HeaderValue::from_str(range).unwrap());
            assert!(
                plan_response(StatusCode::PARTIAL_CONTENT, &input, 4, Some(&etag), 10).is_err(),
                "{range}"
            );
        }
        for extra in [
            ("etag", "\"v2\""),
            ("etag", "W/\"v1\""),
            ("content-range", "bytes 4-9/10"),
            ("content-length", "7"),
            ("content-encoding", "gzip"),
            ("content-type", "multipart/byteranges; boundary=x"),
        ] {
            let mut input = headers(&[("etag", "\"v1\""), ("content-range", "bytes 4-9/10")]);
            input.append(extra.0, HeaderValue::from_static(extra.1));
            assert!(
                plan_response(StatusCode::PARTIAL_CONTENT, &input, 4, Some(&etag), 10).is_err(),
                "{extra:?}"
            );
        }
    }

    #[test]
    fn unknown_body_length_is_bounded_by_release_metadata_not_treated_as_empty() {
        let plan = plan_response(StatusCode::OK, &HeaderMap::new(), 0, None, 123).unwrap();
        assert_eq!(plan.end, 123);
        for value in ["122", "124", "+123", "18446744073709551616"] {
            let mut input = HeaderMap::new();
            input.insert("content-length", HeaderValue::from_str(value).unwrap());
            assert!(plan_response(StatusCode::OK, &input, 0, None, 123).is_err());
        }
        assert!(plan_response(StatusCode::NO_CONTENT, &HeaderMap::new(), 0, None, 0).is_err());
        assert!(plan_response(StatusCode::PARTIAL_CONTENT, &HeaderMap::new(), 0, None, 0).is_err());
    }
}

#[cfg(test)]
mod wire_tests;
