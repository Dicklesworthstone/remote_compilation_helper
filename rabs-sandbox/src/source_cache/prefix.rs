//! Optional incomplete input bytes. A prefix is a transport hint until the
//! sender agrees with its hash; it never substitutes for a complete-file or
//! complete-source seal. The existing cache lock and quotas also cover prefixes.

use super::*;
use std::io::SeekFrom;

#[cfg(all(test, unix))]
mod tests;

/// The actual bytes copied from an incomplete cache object, not a saved cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePrefix {
    pub offset: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Copy)]
struct Range {
    start: u64,
    prefix: SourcePrefix,
}

/// One private spool bounds descriptor use independently of the file count.
/// All offered ranges are frozen before any execution receiver may read them.
pub struct SourcePrefixSnapshots {
    cache: SourceCache,
    spool: File,
    max_bytes: u64,
    bytes: u64,
    ranges: BTreeMap<String, Range>,
    frozen: Option<Metadata>,
}

impl SourcePrefixSnapshots {
    pub fn new(cache: SourceCache, manifest: &SourceManifest) -> io::Result<Self> {
        cache.control.check()?;
        private_directory(&cache.root)?;
        let spool = tempfile::tempfile_in(&cache.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            spool.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        if !private_snapshot(&spool.metadata()?, 0) {
            return Err(invalid("source prefix spool is not private and anonymous"));
        }
        Ok(Self {
            max_bytes: cache.max_bytes.min(manifest.total_bytes()),
            cache,
            spool,
            bytes: 0,
            ranges: BTreeMap::new(),
            frozen: None,
        })
    }

    /// Cache errors are misses. Cancellation is still returned independently,
    /// and no partially copied range is ever offered to the sender.
    pub fn capture(&mut self, expected: &SourceFile) -> io::Result<Option<SourcePrefix>> {
        self.cache.control.check()?;
        if self.frozen.is_some() || self.ranges.contains_key(&expected.path) {
            return Err(invalid("source prefix snapshot phase or member repeated"));
        }
        if expected.len == 0 || expected.len > MAX_FILE_BYTES || self.ranges.len() >= MAX_FILES {
            return Ok(None);
        }
        self.spool.seek(SeekFrom::Start(self.bytes))?;
        let copied = (|| -> io::Result<SourcePrefix> {
            private_directory(&self.cache.root)?;
            let path = self.cache.object_path(&expected.sha256);
            let length = fs::symlink_metadata(&path)?.len();
            if length == 0 || length >= expected.len || length > self.max_bytes - self.bytes {
                return Err(invalid("source prefix length is outside its bound"));
            }
            let partial = SourceFile {
                len: length,
                ..expected.clone()
            };
            let (mut input, before) =
                open_source_object(&path, &partial, &self.cache.control).map_err(source_error)?;
            let mut remaining = length;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
            while remaining != 0 {
                self.cache.control.check()?;
                let count = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                self.spool.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            self.cache.control.check()?;
            if input.read(&mut buffer[..1])? != 0 {
                return Err(invalid("source prefix has an unexpected tail"));
            }
            verify_source_generation(&path, &input, &before).map_err(source_error)?;
            Ok(SourcePrefix {
                offset: length,
                sha256: hash.finalize().into(),
            })
        })();
        self.cache.control.check()?;
        let prefix = match copied {
            Ok(prefix) => prefix,
            Err(_) => {
                self.spool.set_len(self.bytes)?;
                self.spool.seek(SeekFrom::Start(self.bytes))?;
                return Ok(None);
            }
        };
        self.ranges.insert(
            expected.path.clone(),
            Range {
                start: self.bytes,
                prefix,
            },
        );
        self.bytes += prefix.offset;
        Ok(Some(prefix))
    }

    pub fn seal(&mut self) -> io::Result<()> {
        self.cache.control.check()?;
        if self.frozen.is_some() {
            return Err(invalid("source prefix snapshots already sealed"));
        }
        self.spool.set_len(self.bytes)?;
        let mut permissions = self.spool.metadata()?.permissions();
        permissions.set_readonly(true);
        self.spool.set_permissions(permissions)?;
        let metadata = self.spool.metadata()?;
        if !private_snapshot(&metadata, self.bytes) {
            return Err(invalid("source prefix spool identity changed"));
        }
        self.frozen = Some(metadata);
        self.cache.control.check()
    }

    /// Reads remain bounded and bound to the original frozen spool generation.
    /// The caller must still hash the entire selected range before accepting it.
    pub fn read_chunk(&mut self, path: &str, offset: u64, count: usize) -> io::Result<Vec<u8>> {
        self.cache.control.check()?;
        let frozen = self
            .frozen
            .as_ref()
            .ok_or_else(|| invalid("source prefix snapshots are not sealed"))?;
        let range = self
            .ranges
            .get(path)
            .ok_or_else(|| invalid("source prefix was never snapshotted"))?;
        if count == 0
            || count > MAX_SOURCE_CHUNK
            || offset >= range.prefix.offset
            || !same_state(frozen, &self.spool.metadata()?)
        {
            return Err(invalid(
                "source prefix snapshot range or generation changed",
            ));
        }
        let count = (range.prefix.offset - offset).min(count as u64) as usize;
        self.spool.seek(SeekFrom::Start(range.start + offset))?;
        let mut bytes = vec![0_u8; count];
        self.spool.read_exact(&mut bytes)?;
        self.cache.control.check()?;
        if !same_state(frozen, &self.spool.metadata()?) {
            return Err(invalid("source prefix spool changed during reading"));
        }
        Ok(bytes)
    }
}

fn source_error(error: RememberError) -> io::Error {
    match error {
        RememberError::Cache(error) | RememberError::Source(error) => error,
    }
}

pub(super) struct PrefixWriter {
    expected: SourceFile,
    file: File,
    metadata: Metadata,
    offset: u64,
    writable: bool,
}

impl SourceCheckpoints {
    fn expected_prefix_file(
        &self,
        receiver: &SourceReceiver,
        path: &str,
    ) -> Result<SourceFile, RememberError> {
        if receiver.manifest().digest() != self.manifest_digest {
            return Err(RememberError::Source(invalid(
                "source prefix manifest changed",
            )));
        }
        let files = receiver.manifest().files();
        files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .map(|index| files[index].clone())
            .map_err(|_| RememberError::Source(invalid("undeclared source prefix member")))
    }

    pub(super) fn replacement_generation(&self, path: &Path) -> io::Result<Option<Metadata>> {
        self.check_owner()?;
        match self.entries.get(path) {
            Some(entry) => {
                let metadata = fs::symlink_metadata(path)?;
                if !ordinary(&metadata) || metadata.len() != entry.bytes {
                    return Err(invalid("source cache replacement inventory changed"));
                }
                Ok(Some(metadata))
            }
            None => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
                Ok(_) => Err(invalid("untracked source cache replacement destination")),
            },
        }
    }

    pub(super) fn reserve_replacement(&mut self, path: &Path, bytes: u64) -> io::Result<bool> {
        if bytes > self.cache.max_bytes {
            return Ok(false);
        }
        let previous = self
            .entries
            .get(path)
            .map(|entry| (entry.bytes, entry.used));
        if let Some((_, used)) = previous {
            self.evictable.remove(&(used, path.to_path_buf()));
        }
        let growth = bytes.saturating_sub(previous.map_or(0, |(bytes, _)| bytes));
        let result = (|| {
            while self.total > self.cache.max_bytes - growth
                || self.entries.len() + usize::from(previous.is_none()) > self.cache.max_files
            {
                let Some((_, victim)) = self.evictable.first().cloned() else {
                    return Ok(false);
                };
                self.remove(&victim)?;
            }
            Ok(true)
        })();
        if let Some((_, used)) = previous
            && !self.protected.contains_key(path)
        {
            self.evictable.insert((used, path.to_path_buf()));
        }
        result
    }

    pub(super) fn publish_replacement(
        &mut self,
        path: &Path,
        file: &File,
        bytes: u64,
        previous: Option<&Metadata>,
    ) -> io::Result<Metadata> {
        self.check_owner()?;
        let scratch = self.cache.root.join(INCOMING);
        let staged = file.metadata()?;
        if !ordinary(&staged)
            || staged.len() != bytes
            || !same_state(&staged, &fs::symlink_metadata(&scratch)?)
        {
            return Err(invalid("source cache staged replacement changed"));
        }
        match previous {
            Some(previous) if !same_state(previous, &fs::symlink_metadata(path)?) => {
                return Err(invalid("source cache object changed before replacement"));
            }
            Some(_) => {}
            None => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(invalid("source cache replacement destination appeared")),
            },
        }
        let old_bytes = self.entries.get(path).map_or(0, |entry| entry.bytes);
        let total = self
            .total
            .checked_sub(old_bytes)
            .and_then(|total| total.checked_add(bytes))
            .filter(|total| *total <= self.cache.max_bytes)
            .ok_or_else(|| invalid("source cache replacement exceeds its budget"))?;
        if self.entries.len() + usize::from(!self.entries.contains_key(path)) > self.cache.max_files
        {
            return Err(invalid("source cache replacement exceeds its file bound"));
        }
        fs::rename(&scratch, path)?;
        let metadata = file.metadata()?;
        if !same_state(&metadata, &fs::symlink_metadata(path)?) {
            return Err(invalid("source cache published replacement changed"));
        }
        let used = metadata.modified()?;
        if let Some(entry) = self.entries.remove(path) {
            self.evictable.remove(&(entry.used, entry.path));
        }
        self.total = total;
        self.entries.insert(
            path.to_path_buf(),
            Entry {
                path: path.to_path_buf(),
                bytes,
                used,
            },
        );
        self.evictable.insert((used, path.to_path_buf()));
        Ok(metadata)
    }

    /// Start this file's optional partial checkpoint after the sender's exact
    /// prefix selection. Only a verified independent snapshot supplies a seed.
    /// Switching interleaved files releases the earlier writer but keeps its
    /// bounded prefix; there is never one open writer per manifest member.
    pub fn begin_prefix(
        &mut self,
        receiver: &SourceReceiver,
        path: &str,
        selected: SourcePrefix,
        mut read: impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    ) -> Result<(), RememberError> {
        self.check_owner()?;
        let expected = self.expected_prefix_file(receiver, path)?;
        if expected.len == 0 || selected.offset >= expected.len {
            return Err(RememberError::Source(invalid(
                "source prefix requires an unfinished file",
            )));
        }
        if let Some(previous) = &self.active_prefix {
            let previous_path = previous.expected.path.clone();
            self.finish_prefix(&previous_path)?;
        }
        let destination = self.cache.object_path(&expected.sha256);
        if self.protected.contains_key(&destination) || selected.offset > self.cache.max_bytes {
            return Ok(());
        }
        let previous = self.replacement_generation(&destination)?;
        if !self.reserve_replacement(&destination, selected.offset)? {
            return Ok(());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.cache.root.join(INCOMING))?;
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < selected.offset {
            self.check_owner()?;
            let count = (selected.offset - offset).min(MAX_SOURCE_CHUNK as u64) as usize;
            let bytes = read(offset, count)?;
            if bytes.len() != count {
                return Err(invalid("source prefix seed returned an unexpected range").into());
            }
            hash.update(&bytes);
            file.write_all(&bytes)?;
            offset += bytes.len() as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) != selected.sha256 {
            return Err(invalid("source prefix seed differs from sender selection").into());
        }
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        let metadata =
            self.publish_replacement(&destination, &file, selected.offset, previous.as_ref())?;
        self.evictable.remove(&(metadata.modified()?, destination));
        self.active_prefix = Some(PrefixWriter {
            expected,
            file,
            metadata,
            offset: selected.offset,
            writable: true,
        });
        self.check_owner().map_err(RememberError::Cache)
    }

    /// Called only after the receiver accepts the same bytes. A short write or
    /// disconnect leaves a hint whose actual length and hash must be checked
    /// again by both sides. Capacity pressure stops growth, retaining progress.
    pub fn append_prefix(&mut self, path: &str, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.check_owner()?;
        let Some(active) = &self.active_prefix else {
            return Ok(());
        };
        if active.expected.path != path || !active.writable {
            return Ok(());
        }
        let next = offset
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= active.expected.len)
            .ok_or_else(|| invalid("source prefix checkpoint exceeds its file"))?;
        // The receiver has already verified an exact retransmission. It must
        // not duplicate bytes or consume cache capacity a second time.
        if offset < active.offset && next <= active.offset {
            return Ok(());
        }
        let destination = self.cache.object_path(&active.expected.sha256);
        if offset != active.offset
            || bytes.is_empty()
            || bytes.len() > MAX_SOURCE_CHUNK
            || !same_state(&active.metadata, &active.file.metadata()?)
            || !same_state(&active.metadata, &fs::symlink_metadata(&destination)?)
        {
            return Err(invalid(
                "source prefix checkpoint generation or offset changed",
            ));
        }
        if !self.reserve_replacement(&destination, next)? {
            self.active_prefix.as_mut().unwrap().writable = false;
            return Ok(());
        }
        // reserve_replacement restores ordinary eviction membership; the
        // active object remains protected for the rest of its stream.
        let active = self.active_prefix.as_mut().unwrap();
        let used = active.metadata.modified()?;
        self.evictable.remove(&(used, destination.clone()));
        if active.file.stream_position()? != offset {
            return Err(invalid("source prefix writer cursor changed"));
        }
        active.file.write_all(bytes)?;
        let metadata = active.file.metadata()?;
        if !ordinary(&metadata)
            || metadata.len() != next
            || !same_state(&metadata, &fs::symlink_metadata(&destination)?)
        {
            return Err(invalid("source prefix changed during append"));
        }
        let used = metadata.modified()?;
        active.metadata = metadata;
        active.offset = next;
        self.total += bytes.len() as u64;
        self.entries.insert(
            destination.clone(),
            Entry {
                path: destination,
                bytes: next,
                used,
            },
        );
        self.check_owner()
    }

    pub fn finish_prefix(&mut self, path: &str) -> io::Result<()> {
        self.check_owner()?;
        if !self
            .active_prefix
            .as_ref()
            .is_some_and(|active| active.expected.path == path)
        {
            return Ok(());
        }
        let active = self.active_prefix.take().unwrap();
        let destination = self.cache.object_path(&active.expected.sha256);
        if !same_state(&active.metadata, &active.file.metadata()?)
            || !same_state(&active.metadata, &fs::symlink_metadata(&destination)?)
        {
            return Err(invalid("completed source prefix generation changed"));
        }
        self.evictable
            .insert((active.metadata.modified()?, destination));
        Ok(())
    }
}
