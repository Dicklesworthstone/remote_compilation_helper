//! Daemon selection-response wire deserialization for the hook.
//!
//! This submodule owns the wire-format DTOs for the daemon's worker-selection
//! response and their conversion into the domain types `run_hook` / `run_exec`
//! consume, extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`:
//!
//! - [`SelectionResponseWire`] / `SelectionReasonWire` / `UnitSelectionReasonWire`
//!   mirror the JSON the daemon emits over the selection socket, with `From`
//!   conversions into `rch_common`'s `SelectionResponse` / `SelectionReason` so the
//!   rest of the hook never touches the wire shape. The hand-rolled
//!   `Deserialize for SelectionReasonWire` tolerates both the tagged-object and
//!   bare-string reason encodings and degrades unknown variants to
//!   `Unknown`/`SelectionError` rather than failing the parse.
//! - [`parse_selection_response`] is the single entry point: it parses the body,
//!   enforces the selection protocol-version ceiling
//!   (`validate_selection_response_protocol`), and returns the domain
//!   `SelectionResponse`.
//!
//! It reaches its support layer from the parent via `use super::*`: `serde`'s
//! `Deserialize`, the `rch_common` types (`SelectedWorker`, `SelectionResponse`,
//! `SelectionReason`, `SelectionDiagnostics`,
//! `SELECTION_RESPONSE_PROTOCOL_VERSION`), and `serde_json`/`anyhow`. Only
//! `parse_selection_response` is `pub(super)` (re-exported into `hook` because
//! `run_hook` / `run_exec` call it, and reached by the test suite through that
//! re-export); every wire type and validation helper stays private and is reached
//! through it.

use super::*;

#[derive(Debug, Deserialize)]
struct SelectionResponseWire {
    worker: Option<SelectedWorker>,
    reason: SelectionReasonWire,
    #[serde(default)]
    build_id: Option<u64>,
    #[serde(default)]
    diagnostics: Option<rch_common::SelectionDiagnostics>,
}

impl From<SelectionResponseWire> for SelectionResponse {
    fn from(value: SelectionResponseWire) -> Self {
        Self {
            worker: value.worker,
            reason: value.reason.into(),
            build_id: value.build_id,
            diagnostics: value.diagnostics,
        }
    }
}

#[derive(Debug)]
enum SelectionReasonWire {
    NoAdmissibleWorkers { no_admissible_workers: String },
    NoWorkersWithRuntime { no_workers_with_runtime: String },
    SelectionError { selection_error: String },
    Unit(UnitSelectionReasonWire),
    Unknown(serde_json::Value),
}

impl<'de> Deserialize<'de> for SelectionReasonWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        match &value {
            serde_json::Value::Object(object) if object.len() == 1 => {
                if let Some(reason) = object
                    .get("no_admissible_workers")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::NoAdmissibleWorkers {
                        no_admissible_workers: reason.to_string(),
                    });
                }
                if let Some(runtime) = object
                    .get("no_workers_with_runtime")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::NoWorkersWithRuntime {
                        no_workers_with_runtime: runtime.to_string(),
                    });
                }
                if let Some(error) = object
                    .get("selection_error")
                    .and_then(serde_json::Value::as_str)
                {
                    return Ok(Self::SelectionError {
                        selection_error: error.to_string(),
                    });
                }
            }
            serde_json::Value::String(_) => {
                let unit = serde_json::from_value::<UnitSelectionReasonWire>(value.clone())
                    .map_err(serde::de::Error::custom)?;
                return Ok(match unit {
                    UnitSelectionReasonWire::Unknown => Self::Unknown(value),
                    unit => Self::Unit(unit),
                });
            }
            _ => {}
        }

        Ok(Self::Unknown(value))
    }
}

impl From<SelectionReasonWire> for SelectionReason {
    fn from(value: SelectionReasonWire) -> Self {
        match value {
            SelectionReasonWire::NoAdmissibleWorkers {
                no_admissible_workers,
            } => Self::NoAdmissibleWorkers(no_admissible_workers),
            SelectionReasonWire::NoWorkersWithRuntime {
                no_workers_with_runtime,
            } => Self::NoWorkersWithRuntime(no_workers_with_runtime),
            SelectionReasonWire::SelectionError { selection_error } => {
                Self::SelectionError(selection_error)
            }
            SelectionReasonWire::Unit(unit) => unit.into(),
            SelectionReasonWire::Unknown(value) => Self::SelectionError(format!(
                "unknown daemon selection reason: {}",
                selection_reason_wire_detail(&value)
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UnitSelectionReasonWire {
    Success,
    NoWorkersConfigured,
    AllWorkersUnreachable,
    AllCircuitsOpen,
    AllWorkersBusy,
    NoWorkersPassedHealth,
    AllWorkersFailedPreflight,
    AllWorkersFailedConvergence,
    NoMatchingWorkers,
    AffinityPinned,
    AffinityFallback,
    #[serde(other)]
    Unknown,
}

impl From<UnitSelectionReasonWire> for SelectionReason {
    fn from(value: UnitSelectionReasonWire) -> Self {
        match value {
            UnitSelectionReasonWire::Success => Self::Success,
            UnitSelectionReasonWire::NoWorkersConfigured => Self::NoWorkersConfigured,
            UnitSelectionReasonWire::AllWorkersUnreachable => Self::AllWorkersUnreachable,
            UnitSelectionReasonWire::AllCircuitsOpen => Self::AllCircuitsOpen,
            UnitSelectionReasonWire::AllWorkersBusy => Self::AllWorkersBusy,
            UnitSelectionReasonWire::NoWorkersPassedHealth => Self::NoWorkersPassedHealth,
            UnitSelectionReasonWire::AllWorkersFailedPreflight => Self::AllWorkersFailedPreflight,
            UnitSelectionReasonWire::AllWorkersFailedConvergence => {
                Self::AllWorkersFailedConvergence
            }
            UnitSelectionReasonWire::NoMatchingWorkers => Self::NoMatchingWorkers,
            UnitSelectionReasonWire::AffinityPinned => Self::AffinityPinned,
            UnitSelectionReasonWire::AffinityFallback => Self::AffinityFallback,
            UnitSelectionReasonWire::Unknown => {
                Self::SelectionError("unknown daemon selection reason".to_string())
            }
        }
    }
}

pub(super) fn parse_selection_response(body: &str) -> anyhow::Result<SelectionResponse> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("Failed to parse daemon response JSON: {}", e))?;
    validate_selection_response_protocol(&value)?;
    let wire: SelectionResponseWire = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("Failed to parse daemon selection response: {}", e))?;
    Ok(wire.into())
}

fn validate_selection_response_protocol(value: &serde_json::Value) -> anyhow::Result<()> {
    let Some(version_value) = value
        .get("selection_protocol_version")
        .or_else(|| value.get("protocol_version"))
    else {
        return Ok(());
    };

    let version = selection_protocol_version_value(version_value).ok_or_else(|| {
        anyhow::anyhow!(
            "Daemon selection protocol version must be an integer or integer string, got {}",
            version_value
        )
    })?;
    let supported = rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION;
    if version > supported {
        return Err(anyhow::anyhow!(
            "Daemon selection protocol version {} exceeds client support {}; reinstall matching rch/rchd binaries",
            version,
            supported
        ));
    }

    Ok(())
}

fn selection_protocol_version_value(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn selection_reason_wire_detail(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(reason) => reason.clone(),
        _ => value.to_string(),
    }
}
