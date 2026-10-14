//! Separate the selected output set from allocation needed by a resumed pull.
//!
//! Only a successful, checksum-aware dry run may credit files already staged.
//! Rsync still creates a FULL replacement for each changed regular file, even
//! when its network delta is tiny. Never use protocol or literal-data bytes as
//! the disk budget. Selection, timeout, manifest and publication checks remain
//! independent of this advisory allocation estimate.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RsyncStoragePlan {
    pub(super) selected_bytes: u64,
    pub(super) replacement_bytes: u64,
    replacement_files: u64,
}

/// An exact integer, with optional rsync-style thousands separators. Do not
/// repair malformed, rounded, signed or overflowing counters into evidence.
fn count(value: &str) -> Option<u64> {
    let value = value.trim();
    let grouped = value.contains(',');
    for (index, part) in value.split(',').enumerate() {
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (grouped
                && if index == 0 {
                    part.len() > 3
                } else {
                    part.len() != 3
                })
        {
            return None;
        }
    }
    value
        .bytes()
        .filter(|byte| *byte != b',')
        .try_fold(0_u64, |total, byte| {
            total.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })
}

fn set_once(slot: &mut Option<u64>, value: Option<u64>) -> Option<()> {
    let value = value?;
    if slot.replace(value).is_some() {
        return None;
    }
    Some(())
}

impl RsyncStoragePlan {
    /// Failure to recognize a complete unambiguous report grants NO reuse
    /// credit. Callers retain the existing full-selected-size storage check.
    pub(super) fn parse(stdout: &[u8]) -> Option<Self> {
        if !stdout.ends_with(b"\n") {
            return None;
        }
        let output = std::str::from_utf8(stdout).ok()?;
        let mut selected = None;
        let mut replacements = None;
        let mut files = None;
        let mut sent = None;
        let mut received = None;
        for line in output.lines() {
            if let Some(value) = line.strip_prefix("Total file size:") {
                set_once(&mut selected, count(value.trim().strip_suffix(" bytes")?))?;
            } else if let Some(value) = line.strip_prefix("Total transferred file size:") {
                set_once(
                    &mut replacements,
                    count(value.trim().strip_suffix(" bytes")?),
                )?;
            } else if let Some(value) = line
                .strip_prefix("Number of regular files transferred:")
                .or_else(|| line.strip_prefix("Number of files transferred:"))
            {
                set_once(&mut files, count(value))?;
            } else if let Some(value) = line.strip_prefix("Total bytes sent:") {
                set_once(&mut sent, count(value))?;
            } else if let Some(value) = line.strip_prefix("Total bytes received:") {
                set_once(&mut received, count(value))?;
            }
        }
        // Require the counters at the end of the stats block as well. A
        // partial captured block or missing field cannot imply zero allocation.
        sent?;
        received?;
        let plan = Self {
            selected_bytes: selected?,
            replacement_bytes: replacements?,
            replacement_files: files?,
        };
        if plan.replacement_bytes > plan.selected_bytes
            || (plan.replacement_files == 0 && plan.replacement_bytes != 0)
        {
            return None;
        }
        Some(plan)
    }

    /// Conservative payload allocation including up to one allocation unit
    /// of padding per replaced file. Metadata, quotas and concurrent writers
    /// can still cause failure; the configured reserve is added separately.
    #[cfg(any(unix, test))]
    pub(super) fn additional_bytes(self, allocation_unit: u64) -> Option<u64> {
        if self.replacement_files == 0 {
            return Some(0);
        }
        let padding = allocation_unit.checked_sub(1)?;
        self.replacement_bytes
            .checked_add(self.replacement_files.checked_mul(padding)?)
    }
}

/// The legacy full allocation remains the fallback. A different selected set
/// cannot borrow a plan, and every route still adds the configured reserve.
#[cfg(any(unix, test))]
pub(super) fn required_bytes(
    selected_bytes: u64,
    plan: Option<RsyncStoragePlan>,
    allocation_unit: u64,
    reserve: u64,
) -> Option<u64> {
    let payload = match plan.filter(|plan| plan.selected_bytes == selected_bytes) {
        Some(plan) => plan.additional_bytes(allocation_unit)?,
        None => selected_bytes,
    };
    payload.checked_add(reserve)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(selected: &str, replacements: &str, files: &str) -> String {
        format!(
            "Number of regular files transferred: {files}\n\
             Total file size: {selected} bytes\n\
             Total transferred file size: {replacements} bytes\n\
             Literal data: 0 bytes\nMatched data: 0 bytes\n\
             Total bytes sent: 61\nTotal bytes received: 119\n"
        )
    }

    #[test]
    fn modern_and_legacy_reports_keep_selection_separate_from_replacement_bytes() {
        let modern = report("649,047,958", "1,048,576", "2");
        let expected = RsyncStoragePlan {
            selected_bytes: 649_047_958,
            replacement_bytes: 1_048_576,
            replacement_files: 2,
        };
        assert_eq!(RsyncStoragePlan::parse(modern.as_bytes()), Some(expected));
        let legacy = modern.replace(
            "Number of regular files transferred:",
            "Number of files transferred:",
        );
        assert_eq!(RsyncStoragePlan::parse(legacy.as_bytes()), Some(expected));
        assert_eq!(expected.additional_bytes(4096), Some(1_056_766));
        assert_eq!(expected.selected_bytes, 649_047_958);
    }

    #[test]
    fn no_op_and_empty_outputs_do_not_require_a_second_full_payload() {
        let no_op = RsyncStoragePlan::parse(report("649047958", "0", "0").as_bytes()).unwrap();
        assert_eq!(no_op.additional_bytes(4096), Some(0));
        let empty = RsyncStoragePlan::parse(report("0", "0", "2").as_bytes()).unwrap();
        assert_eq!(empty.additional_bytes(4096), Some(8190));
        assert_eq!(empty.additional_bytes(0), None);
    }

    #[test]
    fn network_delta_cannot_reduce_a_changed_files_full_replacement_budget() {
        let text = report("1048576", "1048576", "1")
            .replace("Literal data: 0", "Literal data: 1")
            .replace("Matched data: 0", "Matched data: 1048575");
        let plan = RsyncStoragePlan::parse(text.as_bytes()).unwrap();
        assert_eq!(plan.replacement_bytes, 1_048_576);
        assert_eq!(plan.additional_bytes(4096), Some(1_052_671));
    }

    #[test]
    fn absent_partial_duplicate_or_contradictory_stats_never_grant_reuse_credit() {
        let valid = report("100", "10", "1");
        for bad in [
            String::new(),
            valid.trim_end().to_owned(),
            valid.replace("Total bytes received: 119\n", ""),
            valid.replace("Total transferred file size: 10 bytes\n", ""),
            format!("{valid}Total transferred file size: 0 bytes\n"),
            format!("{valid}Number of files transferred: 0\n"),
            format!("{valid}Total file size: 100 bytes\n"),
            report("10", "11", "1"),
            report("100", "1", "0"),
        ] {
            assert!(RsyncStoragePlan::parse(bad.as_bytes()).is_none(), "{bad:?}");
        }
        let mut invalid_utf8 = valid.into_bytes();
        invalid_utf8.splice(0..0, [0xff, b'\n']);
        assert!(RsyncStoragePlan::parse(&invalid_utf8).is_none());
    }

    #[test]
    fn malformed_numbers_and_allocation_overflow_fail_closed() {
        for bad in [
            "",
            "1,00",
            "1000,000",
            "1,,000",
            "+1",
            "-1",
            "1.0",
            "1K",
            "１",
            "18446744073709551616",
        ] {
            assert!(
                RsyncStoragePlan::parse(report(bad, "0", "0").as_bytes()).is_none(),
                "{bad}"
            );
            assert!(
                RsyncStoragePlan::parse(report("100", bad, "1").as_bytes()).is_none(),
                "{bad}"
            );
            assert!(
                RsyncStoragePlan::parse(report("100", "10", bad).as_bytes()).is_none(),
                "{bad}"
            );
        }
        let huge = RsyncStoragePlan::parse(
            report(&u64::MAX.to_string(), &u64::MAX.to_string(), "1").as_bytes(),
        )
        .unwrap();
        assert_eq!(huge.additional_bytes(4096), None);
        let many =
            RsyncStoragePlan::parse(report("0", "0", &u64::MAX.to_string()).as_bytes()).unwrap();
        assert_eq!(many.additional_bytes(4096), None);
    }

    #[test]
    fn itemized_filenames_are_not_statistics() {
        let text = format!(
            ">f+++++++++ Total transferred file size: 0 bytes\n\
             >f+++++++++ Number of files transferred: 0\n{}",
            report("100", "100", "2")
        );
        let plan = RsyncStoragePlan::parse(text.as_bytes()).unwrap();
        assert_eq!(plan.replacement_bytes, 100);
        assert_eq!(plan.replacement_files, 2);
    }

    #[test]
    fn full_fallback_reserve_and_selected_set_binding_are_preserved() {
        let plan = RsyncStoragePlan::parse(report("649047958", "1024", "1").as_bytes()).unwrap();
        let reserve = 64 * 1024 * 1024;
        let available = reserve + 1024 * 1024;
        let resumed = required_bytes(plan.selected_bytes, Some(plan), 4096, reserve).unwrap();
        let cold = required_bytes(plan.selected_bytes, None, 4096, reserve).unwrap();
        assert!(resumed <= available);
        assert!(cold > available);
        assert_eq!(resumed, 5119 + reserve);
        assert_eq!(required_bytes(99, Some(plan), 4096, 10), Some(109));
        assert_eq!(required_bytes(u64::MAX, None, 4096, 1), None);
        assert_eq!(
            required_bytes(plan.selected_bytes, Some(plan), 4096, u64::MAX),
            None
        );
    }
}
