//! Real loopback HTTP and filesystem tests. No public network, worker access,
//! global environment changes, or substituted downloader/verification logic.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const BOUND: Duration = Duration::from_secs(5);

struct Reply {
    wire: Vec<u8>,
    hold: Option<oneshot::Receiver<()>>,
}

impl From<Vec<u8>> for Reply {
    fn from(wire: Vec<u8>) -> Self {
        Self { wire, hold: None }
    }
}

struct Peer {
    url: String,
    task: Option<JoinHandle<Vec<String>>>,
}

impl Peer {
    async fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/release", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut socket, _) = tokio::time::timeout(BOUND, listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let request = tokio::time::timeout(BOUND, async {
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        assert!(bytes.len() < 16 * 1024, "request exceeded fixture limit");
                        bytes.push(socket.read_u8().await.unwrap());
                    }
                    String::from_utf8(bytes).unwrap()
                })
                .await
                .unwrap();
                requests.push(request);
                // A deliberately invalid response may make the client close
                // early. The client verdict and retained bytes are asserted.
                let _ = tokio::time::timeout(BOUND, socket.write_all(&reply.wire))
                    .await
                    .unwrap();
                if let Some(hold) = reply.hold {
                    let _ = tokio::time::timeout(BOUND, hold).await.unwrap();
                }
                let _ = socket.shutdown().await;
            }
            requests
        });
        Self {
            url,
            task: Some(task),
        }
    }

    async fn finish(mut self) -> Vec<String> {
        tokio::time::timeout(BOUND, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n").into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn full(size: usize, etag: &str, body: &[u8]) -> Vec<u8> {
    response("200 OK", &format!("Content-Length: {size}\r\n{etag}"), body)
}

fn partial(start: usize, end: usize, total: usize, body: &[u8]) -> Vec<u8> {
    response(
        "206 Partial Content",
        &format!(
            "ETag: \"v1\"\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\n",
            end - start + 1,
        ),
        body,
    )
}

async fn transfer(peer: &Peer, path: &Path, size: usize) -> AssetDownload {
    let client = client_builder().no_proxy().timeout(BOUND).build().unwrap();
    AssetDownload::with_client(client, &peer.url, path, size as u64)
        .await
        .unwrap()
}

fn request_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

#[tokio::test]
async fn flushed_prefix_is_visible_before_eof_and_resumes_only_the_suffix() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let body: Vec<u8> = (0..131_073).map(|i| (i % 251) as u8).collect();
    let split = 65_537;
    let (release, hold) = oneshot::channel();
    let peer = Peer::new(vec![
        Reply {
            wire: full(body.len(), "ETag: \"v1\"\r\n", &body[..split]),
            hold: Some(hold),
        },
        partial(split, body.len() - 1, body.len(), &body[split..]).into(),
    ])
    .await;
    let mut download = transfer(&peer, &path, body.len()).await;
    let attempt = tokio::spawn(async move {
        let result = download.attempt().await;
        (download, result)
    });
    // The first response has not ended. Buffering the entire response before
    // writing (the old path) cannot meet this assertion, regardless of speed.
    let observed = tokio::time::timeout(BOUND, async {
        loop {
            if std::fs::metadata(&path).unwrap().len() == split as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let before_eof = std::fs::read(&path).unwrap();
    let _ = release.send(());
    let (mut download, result) = tokio::time::timeout(BOUND, attempt).await.unwrap().unwrap();
    observed.expect("response chunks must reach disk before HTTP EOF");
    assert_eq!(before_eof, body[..split]);
    assert!(super::super::is_transient_error(&result.unwrap_err()));
    assert_eq!(download.offset, split as u64);
    download.attempt().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), body);
    let requests = peer.finish().await;
    assert_eq!(request_header(&requests[0], "Range"), None);
    assert_eq!(request_header(&requests[1], "Range"), Some("bytes=65537-"));
    assert_eq!(request_header(&requests[1], "If-Range"), Some("\"v1\""));
    assert!(
        requests
            .iter()
            .all(|r| request_header(r, "Accept-Encoding") == Some("identity"))
    );
}

#[tokio::test]
async fn ignored_ranges_or_changed_representations_replace_instead_of_concatenating() {
    for etag in ["ETag: \"v1\"\r\n", "ETag: \"v2\"\r\n", ""] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let peer = Peer::new(vec![
            full(10, "ETag: \"v1\"\r\n", b"OLD!").into(),
            full(10, etag, b"0123456789").into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, 10).await;
        assert!(download.attempt().await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"OLD!");
        download.attempt().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
        let requests = peer.finish().await;
        assert_eq!(request_header(&requests[1], "Range"), Some("bytes=4-"));
    }
}

#[tokio::test]
async fn absent_or_weak_validators_force_a_fresh_request() {
    for etag in ["", "ETag: W/\"v1\"\r\n"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let peer = Peer::new(vec![
            full(10, etag, b"OLD!").into(),
            full(10, "ETag: \"v2\"\r\n", b"0123456789").into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, 10).await;
        assert!(download.attempt().await.is_err());
        download.attempt().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
        let requests = peer.finish().await;
        assert_eq!(request_header(&requests[1], "Range"), None);
        assert_eq!(request_header(&requests[1], "If-Range"), None);
    }
}

#[tokio::test]
async fn mismatched_or_duplicate_partial_headers_preserve_the_existing_prefix() {
    for headers in [
        "ETag: \"v2\"\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 6\r\n",
        "ETag: \"v1\"\r\nContent-Range: bytes 3-8/10\r\nContent-Length: 6\r\n",
        "ETag: \"v1\"\r\nContent-Range: bytes 4-9/11\r\nContent-Length: 6\r\n",
        "ETag: \"v1\"\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 7\r\n",
        "ETag: \"v1\"\r\nETag: \"v1\"\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 6\r\n",
        "ETag: \"v1\"\r\nContent-Length: 6\r\n",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let peer = Peer::new(vec![
            full(10, "ETag: \"v1\"\r\n", b"0123").into(),
            response("206 Partial Content", headers, b"ATTACK!").into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, 10).await;
        assert!(download.attempt().await.is_err());
        let error = download.attempt().await.unwrap_err();
        assert!(matches!(error, UpdateError::DownloadFailed(_)), "{error}");
        assert!(!super::super::is_transient_error(&error));
        assert_eq!(std::fs::read(&path).unwrap(), b"0123");
        assert_eq!(peer.finish().await.len(), 2);
    }
}

#[tokio::test]
async fn refused_ranges_require_a_new_full_response_never_infer_completion() {
    for status in ["412 Precondition Failed", "416 Range Not Satisfiable"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let peer = Peer::new(vec![
            full(10, "ETag: \"v1\"\r\n", b"0123").into(),
            response(
                status,
                "Content-Range: bytes */4\r\nContent-Length: 0\r\n",
                b"",
            )
            .into(),
            full(10, "ETag: \"v2\"\r\n", b"9876543210").into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, 10).await;
        assert!(download.attempt().await.is_err());
        let error = download.attempt().await.unwrap_err();
        assert!(super::super::is_transient_error(&error));
        assert_eq!(std::fs::read(&path).unwrap(), b"0123");
        download.attempt().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"9876543210");
        let requests = peer.finish().await;
        assert_eq!(request_header(&requests[1], "Range"), Some("bytes=4-"));
        assert_eq!(request_header(&requests[2], "Range"), None);
    }
}

#[tokio::test]
async fn transient_status_keeps_the_prefix_and_short_contiguous_ranges_progress() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let peer = Peer::new(vec![
        full(10, "ETag: \"v1\"\r\n", b"0123").into(),
        response("503 Service Unavailable", "Content-Length: 0\r\n", b"").into(),
        partial(4, 6, 10, b"456").into(),
        partial(7, 9, 10, b"789").into(),
    ])
    .await;
    let mut download = transfer(&peer, &path, 10).await;
    for expected in [4, 4, 7] {
        let error = download.attempt().await.unwrap_err();
        assert!(super::super::is_transient_error(&error), "{error}");
        assert_eq!(download.offset, expected);
    }
    download.attempt().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
    let requests = peer.finish().await;
    assert_eq!(request_header(&requests[2], "Range"), Some("bytes=4-"));
    assert_eq!(request_header(&requests[3], "Range"), Some("bytes=7-"));
}

#[tokio::test]
async fn chunked_bodies_obey_metadata_size_without_content_length() {
    for length in [9, 10, 11] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let body = format!("{length:x}\r\n{}\r\n0\r\n\r\n", "x".repeat(length));
        let peer = Peer::new(vec![
            response("200 OK", "Transfer-Encoding: chunked\r\n", body.as_bytes()).into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, 10).await;
        let result = download.attempt().await;
        if length == 10 {
            result.unwrap();
        } else if length < 10 {
            assert!(super::super::is_transient_error(&result.unwrap_err()));
        } else {
            assert!(matches!(result, Err(UpdateError::DownloadFailed(_))));
        }
        assert!(std::fs::metadata(&path).unwrap().len() <= 10);
        peer.finish().await;
    }
}

#[tokio::test]
async fn complete_range_bytes_still_require_a_valid_signature() {
    // The independently signed fixture already used by update::verify tests.
    let payload = b"rch minisign test payload v1\n";
    let signature = "untrusted comment: signature from minisign secret key\n\
RUTZPaZ0gaEhqDSXunnChY49+8G9WeMdP7wwnCG9s382LwYf7h09hfwypAG0pKwYrhcX+N1Ujyzv1r4ZpRClO4To6jTL1DR1ewo=\n\
trusted comment: rch test fixture\n\
xfmvGjlaWGXfdNKtFwBNm45V0V6VPZ3lLFhIzfLmQ7xUjPzacD1iHPC0MO2oczUBCt2gAZtoGnuQMxpswMpMCw==\n";
    let key = minisign_verify::PublicKey::from_base64(
        "RWTZPaZ0gaEhqMa/pPZEdaALWkxxAm/EtQzB6egPldD4Uh1cCRlw/b0w",
    )
    .unwrap();
    for tamper in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        let mut body = payload.to_vec();
        if tamper {
            body[8] ^= 1;
        }
        let split = 7;
        let peer = Peer::new(vec![
            full(body.len(), "ETag: \"v1\"\r\n", &body[..split]).into(),
            partial(split, body.len() - 1, body.len(), &body[split..]).into(),
        ])
        .await;
        let mut download = transfer(&peer, &path, body.len()).await;
        assert!(download.attempt().await.is_err());
        download.attempt().await.unwrap();
        let downloaded = std::fs::read(&path).unwrap();
        let signature = minisign_verify::Signature::decode(signature).unwrap();
        assert_eq!(key.verify(&downloaded, &signature, false).is_ok(), !tamper);
        peer.finish().await;
    }
}

#[tokio::test]
async fn existing_files_and_zero_attempts_are_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keep");
    std::fs::write(&path, b"caller bytes").unwrap();
    assert!(
        AssetDownload::new("http://127.0.0.1:1/unused", &path, 12)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"caller bytes");
    let never_created = directory.path().join("absent");
    let result = super::super::download_with_retry(
        "http://127.0.0.1:1/unused",
        &never_created,
        "unused",
        12,
        0,
    )
    .await;
    assert!(matches!(result, Err(UpdateError::DownloadFailed(_))));
    assert!(!never_created.exists());
}
