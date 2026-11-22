//! Shared contract for preparing fresh, explicitly declared job outputs.
//!
//! The worker retains old output directories beside the source tree before it
//! creates empty replacements. This request is an exact, bounded plan: neither
//! side may normalize a different path or accept another attempt's receipt.
//! Filesystem identity, source authority and no-replace publication remain the
//! worker's responsibility; these checks do not confer filesystem ownership.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_RESULT_DIRS: usize = 64;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PATH_COMPONENTS: usize = 64;
pub const MAX_REQUEST_BYTES: usize = 65_536;

/// Rsync protects exactly the sibling namespace created by this protocol.
/// Each of the eight groups below matches four lowercase hexadecimal digits.
pub const RETENTION_EXCLUDE_PATTERN: &str = concat!(
    "?*.rch-job-results-",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
    "[0-9a-f][0-9a-f][0-9a-f][0-9a-f]",
);

/// Recognize a retained-results sibling without claiming lookalike directories.
pub fn is_retention_basename(name: &str) -> bool {
    name.rsplit_once(".rch-job-results-")
        .is_some_and(|(source_basename, plan_id)| {
            !source_basename.is_empty() && !source_basename.contains('/') && valid_plan_id(plan_id)
        })
}

fn valid_plan_id(plan_id: &str) -> bool {
    plan_id.len() == 32
        && plan_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResultsPreparationRequest {
    pub schema_version: u32,
    pub plan_id: String,
    pub source_root: String,
    pub retention_root: String,
    pub result_dirs: Vec<String>,
}

impl JobResultsPreparationRequest {
    /// Check the complete immutable plan before worker filesystem mutation.
    ///
    /// # Errors
    /// Rejects unsupported versions, malformed identities, unsafe/overlapping
    /// output paths, unrelated retention destinations and oversized requests.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported fresh job results schema version".to_string());
        }
        let expected_retention = retention_root_for(&self.source_root, &self.plan_id)?;
        if self.retention_root != expected_retention {
            return Err("retention_root must be the exact plan-bound source sibling".to_string());
        }
        validate_result_dirs(&self.result_dirs)?;
        for result_dir in &self.result_dirs {
            if self.source_root.len() + 1 + result_dir.len() > MAX_PATH_BYTES
                || self.retention_root.len() + "/old/".len() + result_dir.len() > MAX_PATH_BYTES
            {
                return Err(
                    "fresh result directory exceeds the materialized path limit".to_string()
                );
            }
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("encode fresh job results plan: {error}"))?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("fresh job results plan exceeds its byte limit".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviousResultDirectory {
    Absent,
    Retained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResultsPreparationResult {
    pub result_dir: String,
    pub previous: PreviousResultDirectory,
    pub retained_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResultsPreparationResponse {
    pub schema_version: u32,
    pub request: JobResultsPreparationRequest,
    pub results: Vec<JobResultsPreparationResult>,
}

impl JobResultsPreparationResponse {
    /// Accept only a complete receipt for the caller's exact preparation plan.
    ///
    /// # Errors
    /// Rejects another attempt/root, missing/duplicate/reordered results, and
    /// retained paths not bound to the corresponding declared directory.
    pub fn validate_for(&self, request: &JobResultsPreparationRequest) -> Result<(), String> {
        request.validate()?;
        if self.schema_version != SCHEMA_VERSION || &self.request != request {
            return Err("fresh job results receipt does not match the requested plan".to_string());
        }
        if self.results.len() != request.result_dirs.len() {
            return Err("fresh job results receipt has an incomplete result inventory".to_string());
        }
        for (result, expected) in self.results.iter().zip(&request.result_dirs) {
            if &result.result_dir != expected {
                return Err(
                    "fresh job results receipt has a different result order or path".to_string(),
                );
            }
            match result.previous {
                PreviousResultDirectory::Absent if result.retained_path.is_none() => {}
                PreviousResultDirectory::Retained
                    if result.retained_path.as_deref()
                        == Some(format!("{}/old/{expected}", request.retention_root).as_str()) => {}
                _ => {
                    return Err(
                        "fresh job results receipt has an invalid retained path".to_string()
                    );
                }
            }
        }
        Ok(())
    }
}

/// Derive the only retention destination accepted for this source and attempt.
///
/// # Errors
/// Rejects an unnormalized/nonabsolute Unix root, malformed attempt identity,
/// or a destination exceeding the path bound.
pub fn retention_root_for(source_root: &str, plan_id: &str) -> Result<String, String> {
    if !valid_plan_id(plan_id) {
        return Err(
            "fresh result plan_id must contain 32 lowercase hexadecimal digits".to_string(),
        );
    }
    if source_root.len() > MAX_PATH_BYTES
        || !source_root.starts_with('/')
        || source_root.contains('\\')
        || source_root.chars().any(char::is_control)
        || source_root.split('/').skip(1).count() > MAX_PATH_COMPONENTS
        || source_root[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(
            "fresh results source_root must be a normalized absolute Unix directory".to_string(),
        );
    }
    let retention = format!("{source_root}.rch-job-results-{plan_id}");
    if retention.len() > MAX_PATH_BYTES {
        return Err("fresh results retention_root exceeds the path limit".to_string());
    }
    Ok(retention)
}

/// Validate already-normalized output paths shared by the CLI, rules and worker.
///
/// # Errors
/// Rejects empty, unbounded, aliased, overlapping or metadata directory roots.
pub fn validate_result_dirs(result_dirs: &[String]) -> Result<(), String> {
    if result_dirs.is_empty() || result_dirs.len() > MAX_RESULT_DIRS {
        return Err(format!(
            "fresh result directories require 1..={MAX_RESULT_DIRS} declared roots"
        ));
    }
    for (index, path) in result_dirs.iter().enumerate() {
        if path.len() > MAX_PATH_BYTES
            || !path.is_ascii()
            || path.contains(['\\', ':'])
            || path.chars().any(char::is_control)
            || path.split('/').count() > MAX_PATH_COMPONENTS
            || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(
                "fresh result directories must be normalized relative ASCII paths".to_string(),
            );
        }
        if path.split('/').any(|part| {
            let lower = part.to_ascii_lowercase();
            matches!(lower.as_str(), ".git" | ".rch" | ".beads")
                || lower.starts_with(".rch-")
                || is_retention_basename(part)
        }) {
            return Err(
                "fresh result directories may not contain repository or RCH metadata".to_string(),
            );
        }
        if result_dirs[..index]
            .iter()
            .any(|prior| contains_root(path, prior) || contains_root(prior, path))
        {
            return Err("fresh result directories must not duplicate or overlap".to_string());
        }
    }
    Ok(())
}

fn contains_root(path: &str, root: &str) -> bool {
    path.eq_ignore_ascii_case(root)
        || (path
            .get(..root.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root))
            && path.as_bytes().get(root.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> JobResultsPreparationRequest {
        let source_root = "/worker/source with 'quotes'".to_string();
        let plan_id = "0123456789abcdef0123456789abcdef".to_string();
        JobResultsPreparationRequest {
            schema_version: SCHEMA_VERSION,
            retention_root: retention_root_for(&source_root, &plan_id).unwrap(),
            plan_id,
            source_root,
            result_dirs: vec!["out".to_string(), "reports/gate run".to_string()],
        }
    }

    fn response(request: &JobResultsPreparationRequest) -> JobResultsPreparationResponse {
        JobResultsPreparationResponse {
            schema_version: SCHEMA_VERSION,
            request: request.clone(),
            results: vec![
                JobResultsPreparationResult {
                    result_dir: "out".to_string(),
                    previous: PreviousResultDirectory::Retained,
                    retained_path: Some(format!("{}/old/out", request.retention_root)),
                },
                JobResultsPreparationResult {
                    result_dir: "reports/gate run".to_string(),
                    previous: PreviousResultDirectory::Absent,
                    retained_path: None,
                },
            ],
        }
    }

    #[test]
    fn preparation_round_trips_exact_plan_and_complete_outcome() {
        let request = request();
        request.validate().unwrap();
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: JobResultsPreparationRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
        let response = response(&request);
        response.validate_for(&request).unwrap();
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded: JobResultsPreparationResponse = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, response);
        decoded.validate_for(&request).unwrap();
    }

    #[test]
    fn retention_location_is_bound_to_one_source_and_attempt() {
        for root in [
            "",
            "/",
            "relative",
            "/worker/../source",
            "/worker/./source",
            "/worker//source",
            "/worker/source/",
            "/worker/so\\urce",
            "/worker/so\nurce",
        ] {
            assert!(
                retention_root_for(root, &request().plan_id).is_err(),
                "{root:?}"
            );
        }
        for plan in [
            "",
            "x",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(
                retention_root_for("/worker/source", plan).is_err(),
                "{plan:?}"
            );
        }
        let mut invalid = request();
        invalid.retention_root = "/elsewhere/unrelated".to_string();
        assert!(invalid.validate().is_err());
        invalid.retention_root = format!("{}/retained", invalid.source_root);
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.schema_version += 1;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn result_roots_cannot_escape_alias_overlap_or_consume_metadata() {
        for path in [
            "",
            ".",
            "./out",
            "/out",
            "out/",
            "out//nested",
            "out/./nested",
            "out/../src",
            "C:/out",
            "out\\nested",
            "out\nnext",
            "résults",
            ".git",
            ".Git/hooks",
            "out/.rch",
            ".beads",
            "out/.BEADS/recovery",
            ".rch-target-cache",
            "out/.RCH-work",
            "source.rch-job-results-0123456789abcdef0123456789abcdef",
            "out/project.rch-job-results-0123456789abcdef0123456789abcdef/old",
        ] {
            assert!(
                validate_result_dirs(&[path.to_string()]).is_err(),
                "{path:?}"
            );
        }
        for dirs in [
            ["out", "out"],
            ["out", "out/nested"],
            ["out/nested", "out"],
            ["out", "OUT"],
            ["out", "Out/nested"],
        ] {
            assert!(
                validate_result_dirs(&dirs.map(str::to_string)).is_err(),
                "{dirs:?}"
            );
        }
        validate_result_dirs(&[
            "out".into(),
            "outputs".into(),
            "result.json".into(),
            "reports/.cache".into(),
            "source.rch-job-results-not-an-attempt".into(),
        ])
        .unwrap();
        assert!(validate_result_dirs(&[]).is_err());
        assert!(validate_result_dirs(&vec!["out".to_string(); MAX_RESULT_DIRS + 1]).is_err());
        assert!(validate_result_dirs(&["x".repeat(MAX_PATH_BYTES + 1)]).is_err());
        let too_deep = vec!["nested"; MAX_PATH_COMPONENTS + 1].join("/");
        assert!(validate_result_dirs(std::slice::from_ref(&too_deep)).is_err());
        assert!(retention_root_for(&format!("/{too_deep}"), &request().plan_id).is_err());
    }

    #[test]
    fn request_bounds_cover_materialized_paths_and_serialized_size() {
        let mut oversized = request();
        oversized.result_dirs = vec!["x".repeat(MAX_PATH_BYTES)];
        assert!(
            oversized
                .validate()
                .unwrap_err()
                .contains("materialized path")
        );
        oversized.result_dirs = (0..MAX_RESULT_DIRS)
            .map(|index| format!("output{index}/{}", "x".repeat(1100)))
            .collect();
        assert!(oversized.validate().unwrap_err().contains("byte limit"));
    }

    #[test]
    fn outcome_requires_exact_identity_inventory_and_retention_paths() {
        let request = request();
        for mutation in 0..8 {
            let mut altered = response(&request);
            match mutation {
                0 => altered.schema_version += 1,
                1 => altered.request.plan_id = "ffffffffffffffffffffffffffffffff".to_string(),
                2 => altered.request.source_root.push_str("-other"),
                3 => {
                    altered.results.pop();
                }
                4 => altered.results.swap(0, 1),
                5 => altered.results[1].result_dir = "out".to_string(),
                6 => altered.results[0].retained_path = Some("/unrelated/out".to_string()),
                7 => {
                    altered.results[1].retained_path =
                        Some(format!("{}/old/reports/gate run", request.retention_root))
                }
                _ => unreachable!(),
            }
            assert!(
                altered.validate_for(&request).is_err(),
                "mutation {mutation}"
            );
        }
        let mut missing = response(&request);
        missing.results[0].retained_path = None;
        assert!(missing.validate_for(&request).is_err());
    }

    #[test]
    fn schema_rejects_unknown_fields_in_plan_outcome_and_entries() {
        let mut request_value = serde_json::to_value(request()).unwrap();
        request_value["delete_previous"] = true.into();
        assert!(serde_json::from_value::<JobResultsPreparationRequest>(request_value).is_err());
        let mut response_value = serde_json::to_value(response(&request())).unwrap();
        response_value["success"] = true.into();
        assert!(serde_json::from_value::<JobResultsPreparationResponse>(response_value).is_err());
        let mut response_value = serde_json::to_value(response(&request())).unwrap();
        response_value["results"][0]["deleted"] = true.into();
        assert!(serde_json::from_value::<JobResultsPreparationResponse>(response_value).is_err());
    }
}
