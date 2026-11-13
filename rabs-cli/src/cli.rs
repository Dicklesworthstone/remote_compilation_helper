//! Small, exact CLI parser: no abbreviated options and no implicit operation.

use std::ffi::{OsStr, OsString};

#[derive(Debug, Default)]
pub(crate) struct Options {
    pub directory: OsString,
    pub resume_to: Option<OsString>,
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
        if flags && argument == "--no-prefix" {
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
                Some("--acknowledge") => &mut options.acknowledge,
                Some("--prefix-from") => &mut options.prefix_from,
                Some("--rabsd") => &mut options.daemon,
                Some("--canonical-state-dir") => &mut options.canonical_state,
                _ => return Err("unrecognized argument; use --help"),
            };
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
    if options.resume_to.is_some() && options.acknowledge.is_some() {
        return Err("--resume-to and --acknowledge are mutually exclusive");
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
        ] {
            assert!(parse(&arguments(&values)).is_err(), "{values:?}");
        }
    }
}
