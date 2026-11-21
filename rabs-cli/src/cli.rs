//! Small, exact CLI parser: no abbreviated options and no implicit operation.

use std::ffi::{OsStr, OsString};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobControl {
    Wait,
    Status,
    Cancel,
}

#[derive(Debug, Default)]
pub(crate) struct Options {
    pub directory: OsString,
    pub job_control: Option<JobControl>,
    pub resume_to: Option<OsString>,
    pub delivery: Option<OsString>,
    pub acknowledge: Option<OsString>,
    pub no_prefix: bool,
    pub prefix_from: Option<OsString>,
    pub daemon: Option<OsString>,
    pub canonical_state: Option<OsString>,
}

pub(crate) enum Invocation {
    Help,
    Recover(Options),
}

pub(crate) fn parse(arguments: &[OsString]) -> Result<Invocation, &'static str> {
    let mut options = Options::default();
    let mut positional = None;
    let mut flags = true;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if flags && argument == "--" {
            flags = false;
            continue;
        }
        if flags && (argument == "--help" || argument == "-h") {
            return Ok(Invocation::Help);
        }
        if flags
            && let Some(control) = match argument.to_str() {
                Some("--wait") => Some(JobControl::Wait),
                Some("--status") => Some(JobControl::Status),
                Some("--cancel") => Some(JobControl::Cancel),
                _ => None,
            }
        {
            if options.job_control.replace(control).is_some() {
                return Err("select exactly one job control");
            }
            continue;
        }
        if flags && argument == "--no-prefix" {
            if options.no_prefix {
                return Err("--no-prefix may be selected only once");
            }
            options.no_prefix = true;
            continue;
        }
        if flags && argument.as_encoded_bytes().starts_with(b"-") {
            let (name, inline) = argument
                .to_str()
                .and_then(|value| value.split_once('='))
                .map_or((argument.as_os_str(), None), |(name, value)| {
                    (OsStr::new(name), Some(OsString::from(value)))
                });
            let destination = match name.to_str() {
                Some("--resume-to") => &mut options.resume_to,
                Some("--delivery") => &mut options.delivery,
                Some("--acknowledge") => &mut options.acknowledge,
                Some("--prefix-from") => &mut options.prefix_from,
                Some("--rabsd") => &mut options.daemon,
                Some("--canonical-state-dir") => &mut options.canonical_state,
                _ => return Err("unrecognized argument; use --help"),
            };
            if destination.is_some() {
                return Err("options may be selected only once");
            }
            let value = inline.or_else(|| arguments.next().cloned());
            let value = value.ok_or("option requires a value")?;
            if value.as_encoded_bytes().starts_with(b"-") && inline_is_absent(argument) {
                return Err("option requires a value");
            }
            *destination = Some(value);
        } else if positional.replace(argument.clone()).is_some() {
            return Err("exactly one recovery directory is required");
        }
    }
    options.directory = positional.ok_or("a recovery directory is required; use --help")?;
    let destinations = [&options.resume_to, &options.delivery, &options.acknowledge]
        .iter()
        .filter(|value| value.is_some())
        .count();
    if destinations > 1 || (options.job_control.is_some() && destinations != 0) {
        return Err("select one job control or result destination");
    }
    if options.no_prefix && options.prefix_from.is_some() {
        return Err("--no-prefix and --prefix-from are mutually exclusive");
    }
    if (options.no_prefix || options.prefix_from.is_some()) && options.resume_to.is_none() {
        return Err("prefix selection requires --resume-to");
    }
    Ok(Invocation::Recover(options))
}

fn inline_is_absent(argument: &OsStr) -> bool {
    !argument.as_encoded_bytes().contains(&b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn options_can_follow_directory_and_use_equals() {
        let Invocation::Recover(options) = parse(&arguments(&[
            "/state/result",
            "--resume-to=/new/result",
            "--rabsd",
            "/tools/daemon",
            "--no-prefix",
        ]))
        .unwrap() else {
            panic!("expected recovery");
        };
        assert_eq!(options.resume_to, Some("/new/result".into()));
        assert_eq!(options.daemon, Some("/tools/daemon".into()));
        assert!(options.no_prefix);
    }

    #[test]
    fn daemon_job_controls_and_delivery_are_explicit() {
        for (flag, control) in [
            ("--wait", JobControl::Wait),
            ("--status", JobControl::Status),
            ("--cancel", JobControl::Cancel),
        ] {
            let Invocation::Recover(options) = parse(&arguments(&[flag, "/operation"])).unwrap()
            else {
                panic!("expected job control");
            };
            assert_eq!(options.job_control, Some(control));
        }
        let Invocation::Recover(options) =
            parse(&arguments(&["/operation", "--delivery=/retained"])).unwrap()
        else {
            panic!("expected local delivery recovery");
        };
        assert_eq!(options.delivery, Some("/retained".into()));
        assert_eq!(options.job_control, None);
    }

    #[test]
    fn ambiguous_or_incomplete_invocations_are_refused() {
        for values in [
            vec!["/result", "--res", "/new"],
            vec!["/result", "--resume-to"],
            vec!["/result", "--resume-to", "--no-prefix"],
            vec!["/result", "--no-prefix"],
            vec!["/result", "--prefix-from", "/old"],
            vec!["/result", "--resume-to=/new", "--acknowledge=/done"],
            vec![
                "/result",
                "--resume-to=/new",
                "--no-prefix",
                "--prefix-from=/old",
            ],
            vec!["/result", "/another"],
            vec!["/result", "--wait", "--cancel"],
            vec!["/result", "--status", "--status"],
            vec!["/result", "--wait=true"],
            vec!["/result", "--wait", "--resume-to=/new"],
            vec!["/result", "--status", "--acknowledge=/done"],
            vec!["/result", "--cancel", "--delivery=/done"],
            vec!["/result", "--delivery=/done", "--resume-to=/new"],
            vec!["/result", "--delivery=/done", "--acknowledge=/done"],
            vec!["/result", "--delivery=/done", "--prefix-from=/old"],
            vec!["/result", "--delivery=/one", "--delivery=/two"],
            vec!["/result", "--rabsd=/one", "--rabsd=/two"],
            vec!["/result", "--resume-to=/new", "--no-prefix", "--no-prefix"],
        ] {
            assert!(parse(&arguments(&values)).is_err(), "{values:?}");
        }
    }
}
