//! Live inspection and scoped reset of the daemon's learned disk estimates.

use anyhow::{Context, Result, anyhow, ensure};
use clap::Subcommand;
use rch_common::ApiResponse;
use rch_common::footprints::{
    FootprintReset, FootprintSnapshot, FootprintSource, validate_selection,
};
use serde::de::DeserializeOwned;
use std::io::{self, Write};

use super::helpers::urlencoding_encode;
use super::send_daemon_command;
use crate::status_types::extract_json_body;
use crate::ui::context::OutputContext;

#[derive(Debug, Subcommand)]
pub enum FootprintAction {
    /// Show retained observations, freshness, and a command's cold allowance
    Show {
        /// Exact project ID from queue/history output
        project: String,
        /// Inspect one exact command and its shared family contributors
        #[arg(long, value_name = "COMMAND")]
        command: Option<String>,
    },
    /// Forget selected estimates for future builds, preserving active reservations
    Forget {
        /// Exact project ID; no wildcard or implicit all-project reset
        project: String,
        /// Forget only this exact command and its endpoint-specific warm proofs
        #[arg(long, value_name = "COMMAND")]
        command: Option<String>,
    },
}

fn request_line(project: &str, command: Option<&str>, forget: bool) -> Result<String> {
    validate_selection(project, command).map_err(|reason| anyhow!(reason))?;
    let (method, path) = if forget {
        ("POST", "/footprints/forget")
    } else {
        ("GET", "/footprints")
    };
    let mut request = format!("{method} {path}?project={}", urlencoding_encode(project));
    if let Some(command) = command {
        request.push_str("&command=");
        request.push_str(&urlencoding_encode(command.trim()));
    }
    request.push('\n');
    Ok(request)
}

fn response_data<T: DeserializeOwned>(response: &str, command: &str) -> Result<T> {
    let body = extract_json_body(response)
        .ok_or_else(|| anyhow!("daemon returned no footprint response body"))?;
    let value: serde_json::Value =
        serde_json::from_str(body).context("invalid daemon footprint response")?;
    ensure!(
        value["api_version"] == rch_common::api::API_VERSION && value["command"] == command,
        "daemon does not support the requested footprint operation; update rchd"
    );
    ensure!(
        value["success"] == true,
        "{}",
        value["error"]["details"]
            .as_str()
            .or_else(|| value["error"]["message"].as_str())
            .unwrap_or("daemon refused the footprint operation")
    );
    serde_json::from_value(value["data"].clone()).context("invalid footprint response data")
}

fn render_snapshot(snapshot: &FootprintSnapshot, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Disk footprint evidence: {}",
        snapshot.project.escape_debug()
    )?;
    if let Some(command) = &snapshot.command {
        writeln!(out, "Command: {}", command.escape_debug())?;
        if let (Some(cold), Some(budget)) = (snapshot.cold_prior_gib, snapshot.growth_budget_gib) {
            writeln!(
                out,
                "Cold prior: {cold:.2} GiB; cold admission growth budget: {budget} GiB"
            )?;
            if let Some(learned) = snapshot.learned_gib {
                writeln!(out, "Applied learned footprint: {learned:.2} GiB")?;
            }
            writeln!(
                out,
                "The worker reserve floor is additional; qualified warm placement is separate."
            )?;
        }
    }
    if snapshot.records.is_empty() {
        writeln!(
            out,
            "No recognized retained evidence matches this selection."
        )?;
    }
    for record in &snapshot.records {
        let source = match record.source {
            FootprintSource::Exact => "exact command",
            FootprintSource::Family => "command family",
            FootprintSource::Legacy => "legacy observation",
            FootprintSource::Warm => "conditional warm pool",
        };
        let name = record
            .command
            .as_deref()
            .or(record.kind.as_deref())
            .unwrap_or("unknown");
        let high_water = record.high_water_gib.map_or_else(
            || "no fresh measurement".into(),
            |gib| format!("{gib:.2} GiB"),
        );
        writeln!(out, "  {source}: {} — {high_water}", name.escape_debug())?;
        writeln!(
            out,
            "    samples: {} fresh / {} retained, {} complete; schema v{}",
            record.valid_sample_count,
            record.sample_count,
            record.complete_sample_count,
            record.version
        )?;
        if record.retired {
            writeln!(out, "    retired schema: excluded from current estimates")?;
        } else if record.source == FootprintSource::Family && matches!(record.version, 2 | 4) {
            writeln!(
                out,
                "    historical family: used only for wide commands; old scope labels are not authoritative"
            )?;
        }
        if let Some(scope) = record.scope {
            writeln!(out, "    scope: {scope:?}")?;
        }
        if let Some(host) = &record.endpoint_host {
            writeln!(
                out,
                "    worker: {}; qualified pools: {} / {}",
                host.escape_debug(),
                record.qualified_pool_count,
                record.pool_count
            )?;
        }
    }
    Ok(())
}

fn render_reset(reset: &FootprintReset, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Forgot disk footprint evidence for {}",
        reset.project.escape_debug()
    )?;
    if let Some(command) = &reset.command {
        writeln!(out, "Exact command: {}", command.escape_debug())?;
        writeln!(out, "Shared family and legacy observations are retained.")?;
    }
    writeln!(
        out,
        "Removed {} entries, {} warm pools, and {} samples; persisted: {}",
        reset.removed_entries, reset.removed_pools, reset.removed_samples, reset.persisted
    )?;
    writeln!(
        out,
        "Active reservations remain in force. Future builds use remaining evidence and cold defaults."
    )
}

pub async fn run(action: FootprintAction, ctx: &OutputContext) -> Result<()> {
    let (project, command, forget) = match action {
        FootprintAction::Show { project, command } => (project, command, false),
        FootprintAction::Forget { project, command } => (project, command, true),
    };
    let request = request_line(&project, command.as_deref(), forget)?;
    let response = send_daemon_command(&request).await?;
    if forget {
        let reset: FootprintReset = response_data(&response, "footprints forget")?;
        if ctx.is_json() {
            ctx.json(&ApiResponse::ok("footprints forget", reset))?;
        } else {
            render_reset(&reset, &mut io::stdout().lock())?;
        }
    } else {
        let snapshot: FootprintSnapshot = response_data(&response, "footprints show")?;
        if ctx.is_json() {
            ctx.json(&ApiResponse::ok("footprints show", snapshot))?;
        } else {
            render_snapshot(&snapshot, &mut io::stdout().lock())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footprint_request_preserves_exact_id_and_command_without_query_injection() {
        assert_eq!(
            request_line("project+&α", Some(" cargo test --filter=x&y "), true).unwrap(),
            "POST /footprints/forget?project=project%2B%26%CE%B1&command=cargo%20test%20--filter%3Dx%26y\n"
        );
        assert_eq!(
            request_line("project", None, false).unwrap(),
            "GET /footprints?project=project\n"
        );
        for (project, command) in [
            ("", None),
            ("project\nGET /shutdown", None),
            ("project", Some("")),
            ("project", Some("cargo test\n")),
        ] {
            assert!(request_line(project, command, true).is_err());
        }
    }

    #[test]
    fn footprint_reply_requires_successful_matching_operation_and_typed_data() {
        let reset = FootprintReset {
            project: "project".into(),
            command: Some("cargo test".into()),
            removed_entries: 1,
            removed_pools: 2,
            removed_samples: 3,
            persisted: true,
        };
        let value = serde_json::to_value(ApiResponse::ok("footprints forget", &reset)).unwrap();
        for mutation in ["none", "command", "success", "data", "api_version"] {
            let mut changed = value.clone();
            match mutation {
                "none" => {}
                "command" => changed["command"] = "footprints show".into(),
                "success" => changed["success"] = false.into(),
                "data" => changed["data"] = serde_json::Value::Null,
                "api_version" => changed["api_version"] = "future".into(),
                _ => unreachable!(),
            }
            let wire = format!("HTTP/1.0 200 OK\r\n\r\n{changed}");
            let actual = response_data::<FootprintReset>(&wire, "footprints forget");
            if mutation == "none" {
                assert_eq!(actual.unwrap(), reset);
            } else {
                assert!(actual.is_err(), "{mutation}");
            }
        }
    }

    #[test]
    fn footprint_display_distinguishes_cold_budget_and_conditional_warm_evidence() {
        let snapshot = FootprintSnapshot {
            project: "project".into(),
            command: Some("cargo test".into()),
            observed_unix: 1_800_000_000,
            persistence_enabled: true,
            cold_prior_gib: Some(24.0),
            learned_gib: Some(24.0),
            growth_budget_gib: Some(30),
            records: vec![],
        };
        let mut bytes = Vec::new();
        render_snapshot(&snapshot, &mut bytes).unwrap();
        let rendered = String::from_utf8(bytes).unwrap();
        assert!(rendered.contains("cold admission growth budget: 30 GiB"));
        assert!(rendered.contains("qualified warm placement is separate"));
        assert!(rendered.contains("No recognized retained evidence"));
    }
}
