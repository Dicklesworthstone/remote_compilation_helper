//! Subscriber presentation for Cargo's outward JSON stream, never rustc's
//! internal artifact protocol. The caller must validate to a private sink before
//! replaying to stdout. Translation is presentation only: package identities,
//! message text, source snippets, suggestions, build-script values and runtime
//! bytes retain their meaning. Source links name the original captured roots;
//! they do not assert that a live checkout still contains the captured bytes.

use super::{SubscriberMapping, canonical_path};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Read, Write};

const OUTPUT_ROOT: &str = "/__rabs/out/cargo";
const READ_BYTES: usize = 64 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_TRANSLATED_BYTES: usize = 4 * MAX_JSON_BYTES;

/// A bounded refusal contains no source text or subscriber filesystem paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoPresentationBypass {
    /// A declared path has no corresponding subscriber root.
    UnmappedPath,
    /// A returned output path is absent from the verified installed tree.
    UnavailableOutput,
    /// A recognized Cargo event does not have the supported structured shape.
    InvalidRecord,
    /// A JSON-shaped line exceeds the finite parsing bound.
    OversizedRecord,
    /// Substituting subscriber roots would exceed the finite output-line bound.
    OversizedTranslation,
    /// The complete presented stream would exceed its caller-owned byte budget.
    OutputLimit,
    /// A canonical rendered location cannot be corroborated by diagnostic spans.
    UnsupportedRenderedLocation,
}

impl CargoPresentationBypass {
    /// Stable, content-free reason for the client's diagnostic status record.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnmappedPath => "unmapped-canonical-path",
            Self::UnavailableOutput => "output-path-not-installed",
            Self::InvalidRecord => "unsupported-cargo-record",
            Self::OversizedRecord => "cargo-json-line-limit",
            Self::OversizedTranslation => "translated-cargo-json-line-limit",
            Self::OutputLimit => "translated-cargo-output-limit",
            Self::UnsupportedRenderedLocation => "unsupported-rendered-location",
        }
    }
}

/// Validation must finish successfully before a translated stream is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoPresentationOutcome {
    /// All recognized path fields are translatable under this presentation.
    Complete,
    /// Discard any private translated prefix and replay the original stream.
    Bypass(CargoPresentationBypass),
}

/// Explicit outward-Cargo presentation, with custody of verified output names.
///
/// `installed_files` contains source-transfer-manifest relative names only after
/// the corresponding target has been installed and verified. An absent target
/// still permits source-only error diagnostics; an actual output reference then
/// refuses the whole translated presentation. No Cargo JSON record authorizes
/// installation or creates a missing file or directory.
pub struct CargoJsonPresentation {
    mapping: SubscriberMapping,
    installed_files: Option<BTreeSet<String>>,
    source_paths_only: bool,
}

impl CargoJsonPresentation {
    /// Construct local presentation state. It never enters remote build identity.
    #[must_use]
    pub fn new(mapping: SubscriberMapping, installed_files: Option<BTreeSet<String>>) -> Self {
        Self {
            mapping,
            installed_files,
            source_paths_only: false,
        }
    }

    /// Translate source locations while preserving every artifact/build-script
    /// output path. This explicit variant works for failed builds that never
    /// install a target tree; unchanged output fields remain canonical paths.
    #[must_use]
    pub fn source_paths(mapping: SubscriberMapping) -> Self {
        Self {
            mapping,
            installed_files: None,
            source_paths_only: true,
        }
    }

    /// Copy a bounded presentation. Call first with a private sink, rewind the
    /// retained raw input, verify installed output custody, and only then call
    /// with the subscriber's stdout. A refusal may follow a private prefix.
    ///
    /// Unrecognized/non-JSON bytes are copied exactly. A valid `build-finished`
    /// ends interpretation permanently, including for JSON-looking, non-UTF-8,
    /// oversized or unterminated runtime output. Only JSON-shaped compilation
    /// lines are buffered; arbitrary long plain output is copied in chunks.
    /// Every emitted byte, including opaque output and runtime tails, is charged
    /// against `maximum_output_bytes` on both validation and publication passes.
    pub fn copy(
        &self,
        reader: impl Read,
        writer: &mut impl Write,
        maximum_output_bytes: u64,
        mut checkpoint: impl FnMut() -> io::Result<()>,
    ) -> io::Result<CargoPresentationOutcome> {
        let mut reader = BufReader::with_capacity(READ_BYTES, reader);
        let mut line = Vec::new();
        let mut finished = false;
        let mut remaining_output_bytes = maximum_output_bytes;
        loop {
            checkpoint()?;
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(CargoPresentationOutcome::Complete);
            }
            if finished {
                let count = available.len();
                if !write_within_budget(writer, available, &mut remaining_output_bytes)? {
                    return Ok(CargoPresentationOutcome::Bypass(
                        CargoPresentationBypass::OutputLimit,
                    ));
                }
                reader.consume(count);
                continue;
            }
            let json = available.first() == Some(&b'{');
            line.clear();
            loop {
                checkpoint()?;
                let available = reader.fill_buf()?;
                if available.is_empty() {
                    break;
                }
                let newline = available.iter().position(|byte| *byte == b'\n');
                let count = newline.map_or(available.len(), |index| index + 1);
                if json {
                    if line.len().saturating_add(count) > MAX_JSON_BYTES {
                        return Ok(CargoPresentationOutcome::Bypass(
                            CargoPresentationBypass::OversizedRecord,
                        ));
                    }
                    line.extend_from_slice(&available[..count]);
                } else {
                    if !write_within_budget(
                        writer,
                        &available[..count],
                        &mut remaining_output_bytes,
                    )? {
                        return Ok(CargoPresentationOutcome::Bypass(
                            CargoPresentationBypass::OutputLimit,
                        ));
                    }
                }
                reader.consume(count);
                if newline.is_some() {
                    break;
                }
            }
            if json {
                match self.record(&line) {
                    Ok(record) => {
                        if !write_within_budget(
                            writer,
                            record.bytes.as_deref().unwrap_or(&line),
                            &mut remaining_output_bytes,
                        )? {
                            return Ok(CargoPresentationOutcome::Bypass(
                                CargoPresentationBypass::OutputLimit,
                            ));
                        }
                        finished = record.finished;
                    }
                    Err(reason) => return Ok(CargoPresentationOutcome::Bypass(reason)),
                }
            }
        }
    }

    fn record(&self, line: &[u8]) -> Result<Record, CargoPresentationBypass> {
        let Ok(mut value) = serde_json::from_slice::<Value>(line) else {
            // Procedural macros can print arbitrary bytes before Cargo finishes.
            // Invalid JSON is not a structured event and is never repaired.
            return Ok(Record::unchanged(false));
        };
        let Some(reason) = value.get("reason").and_then(Value::as_str) else {
            // This also preserves rustc's internal artifact notifications.
            return Ok(Record::unchanged(false));
        };
        if !matches!(
            reason,
            "compiler-artifact" | "compiler-message" | "build-script-executed" | "build-finished"
        ) {
            return Ok(Record::unchanged(false));
        }
        if line.last() != Some(&b'\n') {
            return Err(CargoPresentationBypass::InvalidRecord);
        }
        if reason == "build-finished" {
            if value.get("success").and_then(Value::as_bool).is_none() {
                return Err(CargoPresentationBypass::InvalidRecord);
            }
            return Ok(Record::unchanged(true));
        }
        if self.source_paths_only && reason == "build-script-executed" {
            return Ok(Record::unchanged(false));
        }
        let mut budget = Budget(MAX_TRANSLATED_BYTES.saturating_sub(line.len()));
        // package_id is Cargo's package identity, not a filesystem field. In
        // particular, do not rebuild opaque/path+file URI encodings here.
        string_field(&value, "package_id")?;
        let changed = match reason {
            "compiler-artifact" => {
                let mut changed = self.source_fields(&mut value, &mut budget)?;
                if !value.get("profile").is_some_and(Value::is_object)
                    || !value.get("fresh").is_some_and(Value::is_boolean)
                {
                    return Err(CargoPresentationBypass::InvalidRecord);
                }
                if !self.source_paths_only {
                    let files = value
                        .get_mut("filenames")
                        .and_then(Value::as_array_mut)
                        .filter(|files| !files.is_empty())
                        .ok_or(CargoPresentationBypass::InvalidRecord)?;
                    for file in files {
                        changed |= self.path_value(file, PathKind::File, &mut budget)?;
                    }
                    let executable = value
                        .get_mut("executable")
                        .ok_or(CargoPresentationBypass::InvalidRecord)?;
                    if !executable.is_null() {
                        changed |= self.path_value(executable, PathKind::File, &mut budget)?;
                    }
                }
                changed
            }
            "compiler-message" => {
                let mut changed = self.source_fields(&mut value, &mut budget)?;
                let message = value
                    .get_mut("message")
                    .ok_or(CargoPresentationBypass::InvalidRecord)?;
                let mut locations = BTreeMap::new();
                let mut literals = BTreeSet::new();
                changed |=
                    self.diagnostic_paths(message, &mut budget, &mut locations, &mut literals)?;
                changed |= rendered_diagnostics(message, &locations, &literals, &mut budget)?;
                changed
            }
            "build-script-executed" => {
                let mut changed =
                    self.path_field(&mut value, "out_dir", PathKind::Directory, &mut budget)?;
                let paths = value
                    .get_mut("linked_paths")
                    .and_then(Value::as_array_mut)
                    .ok_or(CargoPresentationBypass::InvalidRecord)?;
                for path in paths {
                    let text = path
                        .as_str()
                        .ok_or(CargoPresentationBypass::InvalidRecord)?;
                    let (kind, original) = match text.split_once('=') {
                        Some((kind, path))
                            if matches!(
                                kind,
                                "dependency" | "crate" | "native" | "framework" | "all"
                            ) =>
                        {
                            (Some(kind), path)
                        }
                        Some((_, path)) if canonical_path(path) => {
                            return Err(CargoPresentationBypass::InvalidRecord);
                        }
                        _ => (None, text),
                    };
                    if let Some(mapped) = self.path(original, PathKind::Directory, &mut budget)? {
                        *path = Value::String(
                            kind.map_or(mapped.clone(), |kind| format!("{kind}={mapped}")),
                        );
                        changed = true;
                    }
                }
                changed
            }
            _ => unreachable!("recognized Cargo record"),
        };
        if !changed {
            return Ok(Record::unchanged(false));
        }
        let mut bytes =
            serde_json::to_vec(&value).map_err(|_| CargoPresentationBypass::InvalidRecord)?;
        bytes.extend_from_slice(if line.ends_with(b"\r\n") {
            b"\r\n"
        } else {
            b"\n"
        });
        if bytes.len() > MAX_TRANSLATED_BYTES {
            return Err(CargoPresentationBypass::OversizedTranslation);
        }
        Ok(Record {
            bytes: Some(bytes),
            finished: false,
        })
    }

    fn source_fields(
        &self,
        value: &mut Value,
        budget: &mut Budget,
    ) -> Result<bool, CargoPresentationBypass> {
        let mut changed = self.path_field(value, "manifest_path", PathKind::File, budget)?;
        let target = value
            .get_mut("target")
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        changed |= self.path_field(target, "src_path", PathKind::File, budget)?;
        Ok(changed)
    }

    fn path_field(
        &self,
        value: &mut Value,
        field: &str,
        kind: PathKind,
        budget: &mut Budget,
    ) -> Result<bool, CargoPresentationBypass> {
        let value = value
            .get_mut(field)
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        self.path_value(value, kind, budget)
    }

    fn path_value(
        &self,
        value: &mut Value,
        kind: PathKind,
        budget: &mut Budget,
    ) -> Result<bool, CargoPresentationBypass> {
        let text = value
            .as_str()
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        if let Some(mapped) = self.path(text, kind, budget)? {
            *value = Value::String(mapped);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn path(
        &self,
        path: &str,
        kind: PathKind,
        budget: &mut Budget,
    ) -> Result<Option<String>, CargoPresentationBypass> {
        if !canonical_path(path) {
            return Ok(None);
        }
        if path.chars().any(char::is_control)
            || path
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(CargoPresentationBypass::InvalidRecord);
        }
        if let Some(relative) = path.strip_prefix(OUTPUT_ROOT)
            && (relative.is_empty() || relative.starts_with('/'))
        {
            let files = self
                .installed_files
                .as_ref()
                .ok_or(CargoPresentationBypass::UnavailableOutput)?;
            let relative = relative.strip_prefix('/').unwrap_or(relative);
            let available = match kind {
                PathKind::File => files.contains(relative),
                PathKind::Directory => {
                    relative.is_empty()
                        || files
                            .range(format!("{relative}/")..)
                            .next()
                            .is_some_and(|file| {
                                file.strip_prefix(relative)
                                    .is_some_and(|rest| rest.starts_with('/'))
                            })
                }
            };
            if !available {
                return Err(CargoPresentationBypass::UnavailableOutput);
            }
        }
        let entry = self
            .mapping
            .entries
            .iter()
            .find(|entry| {
                path.strip_prefix(&entry.canonical)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
            .ok_or(CargoPresentationBypass::UnmappedPath)?;
        let suffix = &path[entry.canonical.len()..];
        let length = entry
            .worktree
            .len()
            .checked_add(suffix.len())
            .ok_or(CargoPresentationBypass::OversizedTranslation)?;
        budget.growth(path.len(), length)?;
        let mapped = format!("{}{suffix}", entry.worktree);
        Ok((mapped != path).then_some(mapped))
    }

    fn diagnostic_paths(
        &self,
        value: &mut Value,
        budget: &mut Budget,
        locations: &mut BTreeMap<String, Location>,
        literals: &mut BTreeSet<String>,
    ) -> Result<bool, CargoPresentationBypass> {
        for line in string_field(value, "message")?.lines() {
            // Compare the same visible text as rendered-header recognition.
            // Otherwise a colored user message could impersonate a location
            // after its SGR sequences are stripped only on the rendered side.
            let (visible, _) = visible_line(line)?;
            literals.insert(visible.trim().to_owned());
        }
        string_field(value, "level")?;
        let spans = value
            .get_mut("spans")
            .and_then(Value::as_array_mut)
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        let mut changed = false;
        for span in spans {
            changed |= self.span(span, budget, locations)?;
        }
        let children = value
            .get_mut("children")
            .and_then(Value::as_array_mut)
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        for child in children {
            changed |= self.diagnostic_paths(child, budget, locations, literals)?;
        }
        Ok(changed)
    }

    fn span(
        &self,
        span: &mut Value,
        budget: &mut Budget,
        locations: &mut BTreeMap<String, Location>,
    ) -> Result<bool, CargoPresentationBypass> {
        let original = string_field(span, "file_name")?;
        let mut changed = false;
        if let Some(mapped) = self.path(original, PathKind::File, budget)? {
            if let (Some(line), Some(column)) = (
                span.get("line_start").and_then(Value::as_u64),
                span.get("column_start").and_then(Value::as_u64),
            ) {
                locations.insert(
                    format!("{original}:{line}:{column}"),
                    Location {
                        original_len: original.len(),
                        mapped: mapped.clone(),
                    },
                );
            }
            span["file_name"] = Value::String(mapped);
            changed = true;
        }
        if let Some(expansion) = span.get_mut("expansion").filter(|value| !value.is_null()) {
            let location = expansion
                .get_mut("span")
                .ok_or(CargoPresentationBypass::InvalidRecord)?;
            changed |= self.span(location, budget, locations)?;
            if let Some(definition) = expansion
                .get_mut("def_site_span")
                .filter(|value| !value.is_null())
            {
                changed |= self.span(definition, budget, locations)?;
            }
        }
        Ok(changed)
    }
}

fn write_within_budget(
    writer: &mut impl Write,
    bytes: &[u8],
    remaining: &mut u64,
) -> io::Result<bool> {
    let Some(next) = remaining.checked_sub(bytes.len() as u64) else {
        return Ok(false);
    };
    writer.write_all(bytes)?;
    *remaining = next;
    Ok(true)
}

struct Record {
    bytes: Option<Vec<u8>>,
    finished: bool,
}

impl Record {
    fn unchanged(finished: bool) -> Self {
        Self {
            bytes: None,
            finished,
        }
    }
}

#[derive(Clone, Copy)]
enum PathKind {
    File,
    Directory,
}

struct Budget(usize);

impl Budget {
    fn growth(&mut self, before: usize, after: usize) -> Result<(), CargoPresentationBypass> {
        // Every added byte can need at most six bytes in a JSON string. The
        // original record already fits; this conservative bound also limits
        // intermediate allocations before serde serializes the translated value.
        let added = after
            .saturating_sub(before)
            .checked_mul(6)
            .ok_or(CargoPresentationBypass::OversizedTranslation)?;
        self.0 = self
            .0
            .checked_sub(added)
            .ok_or(CargoPresentationBypass::OversizedTranslation)?;
        Ok(())
    }
}

struct Location {
    original_len: usize,
    mapped: String,
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, CargoPresentationBypass> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(CargoPresentationBypass::InvalidRecord)
}

fn rendered_diagnostics(
    value: &mut Value,
    locations: &BTreeMap<String, Location>,
    literals: &BTreeSet<String>,
    budget: &mut Budget,
) -> Result<bool, CargoPresentationBypass> {
    let mut changed = false;
    if let Some(rendered) = value.get_mut("rendered").filter(|value| !value.is_null()) {
        let text = rendered
            .as_str()
            .ok_or(CargoPresentationBypass::InvalidRecord)?;
        if let Some(mapped) = rendered_locations(text, locations, literals, budget)? {
            *rendered = Value::String(mapped);
            changed = true;
        }
    }
    let children = value
        .get_mut("children")
        .and_then(Value::as_array_mut)
        .ok_or(CargoPresentationBypass::InvalidRecord)?;
    for child in children {
        changed |= rendered_diagnostics(child, locations, literals, budget)?;
    }
    Ok(changed)
}

fn rendered_locations(
    text: &str,
    locations: &BTreeMap<String, Location>,
    literals: &BTreeSet<String>,
    budget: &mut Budget,
) -> Result<Option<String>, CargoPresentationBypass> {
    let mut out = String::new();
    let mut copied = 0;
    let mut line_offset = 0;
    for line in text.split_inclusive('\n') {
        let (visible, positions) = visible_line(line)?;
        let trimmed = visible.trim_start_matches([' ', '\t']);
        let Some(location) = trimmed
            .strip_prefix("--> ")
            .or_else(|| trimmed.strip_prefix("::: "))
        else {
            line_offset += line.len();
            continue;
        };
        let location = location.trim_end_matches(['\r', '\n']);
        if !canonical_path(location) {
            line_offset += line.len();
            continue;
        }
        // A user-supplied diagnostic message can contain a fake location line.
        // Its bytes are evidence, not an instruction to rewrite the message.
        if literals.contains(trimmed.trim_end_matches(['\r', '\n'])) {
            return Err(CargoPresentationBypass::UnsupportedRenderedLocation);
        }
        let mapped = locations
            .get(location)
            .ok_or(CargoPresentationBypass::UnsupportedRenderedLocation)?;
        if mapped.mapped.chars().any(char::is_control) {
            // JSON can represent such a real filename, but inserting it into a
            // rendered header could introduce lines or terminal controls. No
            // renderer-specific escaping contract is guessed here.
            return Err(CargoPresentationBypass::UnsupportedRenderedLocation);
        }
        let start = visible.len() - trimmed.len() + 4;
        let first = *positions
            .get(start)
            .ok_or(CargoPresentationBypass::UnsupportedRenderedLocation)?;
        let end = positions
            .get(start + mapped.original_len - 1)
            .copied()
            .ok_or(CargoPresentationBypass::UnsupportedRenderedLocation)?
            + 1;
        if line.as_bytes()[first..end].contains(&0x1b) {
            return Err(CargoPresentationBypass::UnsupportedRenderedLocation);
        }
        budget.growth(mapped.original_len, mapped.mapped.len())?;
        out.push_str(&text[copied..line_offset + first]);
        out.push_str(&mapped.mapped);
        copied = line_offset + end;
        line_offset += line.len();
    }
    if copied == 0 {
        return Ok(None);
    }
    out.push_str(&text[copied..]);
    Ok(Some(out))
}

/// Strip only SGR color sequences for recognizing a location header. Retain the
/// original byte positions so color before/after the filename survives exactly.
fn visible_line(line: &str) -> Result<(String, Vec<usize>), CargoPresentationBypass> {
    let bytes = line.as_bytes();
    let mut visible = Vec::with_capacity(bytes.len());
    let mut positions = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b {
            if bytes.get(index + 1) != Some(&b'[') {
                return Err(CargoPresentationBypass::UnsupportedRenderedLocation);
            }
            let mut end = index + 2;
            while bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_digit() || matches!(byte, b';' | b':'))
            {
                end += 1;
            }
            if bytes.get(end) != Some(&b'm') {
                return Err(CargoPresentationBypass::UnsupportedRenderedLocation);
            }
            index = end + 1;
        } else {
            visible.push(bytes[index]);
            positions.push(index);
            index += 1;
        }
    }
    let visible = String::from_utf8(visible)
        .map_err(|_| CargoPresentationBypass::UnsupportedRenderedLocation)?;
    Ok((visible, positions))
}

#[cfg(test)]
mod tests;
