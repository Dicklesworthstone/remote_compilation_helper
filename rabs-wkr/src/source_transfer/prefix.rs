//! Sender-selected input prefixes within the existing source upload owner.
//! Offers own frozen bytes, selection imports them once, and the unchanged
//! receiver still verifies the complete file and complete source manifest.

use super::*;
use rabs_sandbox::source_cache::{SourcePrefix, SourcePrefixSnapshots};
use rabs_sandbox::source_transfer::{MAX_SOURCE_PREFIX_HINT_BYTES, SOURCE_PREFIX_REUSE_VERSION};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(all(test, unix))]
mod tests;

pub(super) fn selected(frame: &Value, allow_cached_files: bool) -> Result<bool, String> {
    match frame.get("source_prefix_reuse") {
        None => Ok(false),
        Some(version) if version == SOURCE_PREFIX_REUSE_VERSION && allow_cached_files => Ok(true),
        Some(_) => Err(invalid(
            "source prefix reuse requires its supported version and cached files",
        )),
    }
}

pub(super) struct PrefixTransfer {
    snapshots: Option<SourcePrefixSnapshots>,
    missing: BTreeSet<String>,
    offers: BTreeMap<String, SourcePrefix>,
    rows: Vec<Value>,
    selections: BTreeMap<String, Selection>,
    sealed: bool,
}

struct Selection {
    prefix: SourcePrefix,
    first_bytes: usize,
    first_sha256: [u8; 32],
}

impl PrefixTransfer {
    pub(super) fn new(cache: Option<SourceCache>, manifest: &SourceManifest) -> Self {
        let snapshots = cache.and_then(|cache| match SourcePrefixSnapshots::new(cache, manifest) {
            Ok(snapshots) => Some(snapshots),
            Err(error) => {
                eprintln!("rabs-wkr: optional source prefix snapshots unavailable: {error}");
                None
            }
        });
        Self {
            snapshots,
            missing: BTreeSet::new(),
            offers: BTreeMap::new(),
            rows: Vec::new(),
            selections: BTreeMap::new(),
            sealed: false,
        }
    }

    pub(super) fn capture(&mut self, expected: &SourceFile) {
        self.missing.insert(expected.path.clone());
        if let Some(snapshots) = &mut self.snapshots {
            match snapshots.capture(expected) {
                Ok(Some(prefix)) => {
                    self.offers.insert(expected.path.clone(), prefix);
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("rabs-wkr: optional source prefix snapshots unavailable: {error}");
                    self.snapshots = None;
                    self.offers.clear();
                }
            }
        }
    }

    pub(super) fn seal(&mut self, base_reply: &Value) -> Result<(), String> {
        if let Some(snapshots) = &mut self.snapshots
            && let Err(error) = snapshots.seal()
        {
            eprintln!("rabs-wkr: optional source prefix snapshots unavailable: {error}");
            self.snapshots = None;
            self.offers.clear();
        }
        let mut empty_reply = base_reply.clone();
        empty_reply["source_prefix_reuse"] = json!(SOURCE_PREFIX_REUSE_VERSION);
        empty_reply["prefixes"] = json!([]);
        let base_bytes = serde_json::to_vec(&empty_reply)
            .map_err(|error| error.to_string())?
            .len();
        let reply_budget = (rabs_protocol::framing::DEFAULT_MAX_FRAME_BYTES as usize)
            .checked_sub(base_bytes)
            .ok_or("source prefix readiness exceeds frame bound")?
            // The frozen offers are echoed at final seal too. Leave room for
            // a bounded filesystem diagnostic appearing after the initial ACK.
            .saturating_sub(8 * 1024);
        let mut added = 0;
        let mut retained = BTreeMap::new();
        for (path, prefix) in &self.offers {
            let row = json!({"path":path, "offset":prefix.offset, "sha256":hex(&prefix.sha256)});
            let cost = serde_json::to_vec(&row)
                .map_err(|error| error.to_string())?
                .len()
                + usize::from(!self.rows.is_empty());
            if added + cost > reply_budget || added + cost + 2 > MAX_SOURCE_PREFIX_HINT_BYTES {
                continue;
            }
            added += cost;
            self.rows.push(row);
            retained.insert(path.clone(), *prefix);
        }
        self.offers = retained;
        self.sealed = true;
        Ok(())
    }

    pub(super) fn add_ready_fields(&self, reply: &mut Value) -> Result<(), String> {
        if !self.sealed {
            return Err(invalid("source prefix offers are not frozen"));
        }
        reply["source_prefix_reuse"] = json!(SOURCE_PREFIX_REUSE_VERSION);
        reply["prefixes"] = json!(self.rows);
        Ok(())
    }

    fn parse_selection(value: &Value) -> Result<SourcePrefix, String> {
        if !value.as_object().is_some_and(|fields| {
            fields.len() == 2 && fields.contains_key("offset") && fields.contains_key("sha256")
        }) {
            return Err(invalid(
                "source prefix selection requires an offset and digest",
            ));
        }
        Ok(SourcePrefix {
            offset: value["offset"]
                .as_u64()
                .ok_or("source prefix offset must be unsigned")?,
            sha256: digest(&value["sha256"])?,
        })
    }

    pub(super) fn select(
        &mut self,
        receiver: &mut SourceReceiver,
        frame: &Value,
        path: &str,
        offset: u64,
        chunk_bytes: usize,
        chunk_sha256: [u8; 32],
    ) -> Result<Option<SourcePrefix>, String> {
        if !self.sealed || !self.missing.contains(path) {
            return Err(invalid(
                "source prefix selection is outside the frozen missing files",
            ));
        }
        if let Some(previous) = self.selections.get(path) {
            if let Some(value) = frame.get("resume") {
                let repeated = Self::parse_selection(value)?;
                if repeated != previous.prefix
                    || offset != previous.prefix.offset
                    || chunk_bytes != previous.first_bytes
                    || chunk_sha256 != previous.first_sha256
                {
                    return Err(invalid(
                        "source prefix selection changed after the first chunk",
                    ));
                }
            }
            return Ok(None);
        }
        let selected = Self::parse_selection(
            frame
                .get("resume")
                .ok_or("first source chunk requires prefix selection")?,
        )?;
        if offset != selected.offset {
            return Err(invalid(
                "source chunk does not start at its selected prefix",
            ));
        }
        if selected.offset == 0 {
            if selected.sha256 != <[u8; 32]>::from(Sha256::digest([])) {
                return Err(invalid("zero source prefix requires the empty digest"));
            }
        } else {
            if self.offers.get(path) != Some(&selected) {
                return Err(invalid(
                    "source prefix selection differs from its owned offer",
                ));
            }
            let mut hash = Sha256::new();
            let mut imported = 0;
            while imported < selected.offset {
                let bytes = self
                    .read_chunk(path, imported, MAX_SOURCE_CHUNK)
                    .map_err(|error| error.to_string())?;
                hash.update(&bytes);
                receiver
                    .write_chunk(path, imported, &bytes, Sha256::digest(&bytes).into())
                    .map_err(|error| error.to_string())?;
                imported += bytes.len() as u64;
            }
            if imported != selected.offset || <[u8; 32]>::from(hash.finalize()) != selected.sha256 {
                return Err(invalid("source prefix snapshot differs from selection"));
            }
        }
        self.selections.insert(
            path.to_owned(),
            Selection {
                prefix: selected,
                first_bytes: chunk_bytes,
                first_sha256: chunk_sha256,
            },
        );
        Ok(Some(selected))
    }

    pub(super) fn read_chunk(
        &mut self,
        path: &str,
        offset: u64,
        count: usize,
    ) -> io::Result<Vec<u8>> {
        self.snapshots
            .as_mut()
            .ok_or_else(|| io::Error::other("source prefix snapshot owner unavailable"))?
            .read_chunk(path, offset, count)
    }
}
