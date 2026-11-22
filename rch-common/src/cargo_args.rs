//! Literal Cargo manifest selection shared by planning and command consumers.
//!
//! Callers resolve shell/wrapper syntax before supplying the arguments after
//! the Cargo executable. This parser does not evaluate a shell, validate a
//! manifest on disk, or decide whether an unknown Cargo option is supported.
//! Its spans let source relocation preserve the original argument spelling.

/// One manifest selector in the supplied Cargo argument slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSelector {
    pub option_index: usize,
    pub value_index: usize,
    /// Byte offset in `args[value_index]`; zero for a separate operand.
    pub value_offset: usize,
    pub value: String,
}

/// The selected manifest and any actual Cargo working-directory override.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestSelection {
    pub manifest: Option<ManifestSelector>,
    pub changes_directory: bool,
}

/// Find the first value-taking short option after known valueless flags.
///
/// An attached value consumes the remainder of its word: the `m` in
/// `-Fsome-feature` or `-Zsomething` is never a manifest option. `None` as the
/// returned offset means the operand belongs to the following word. An empty
/// attached operand, as in `-m=`, has an offset equal to the word's length.
#[must_use]
pub fn short_value_option(word: &str) -> Option<(char, Option<usize>)> {
    if !word.starts_with('-') || word.starts_with("--") {
        return None;
    }
    for (index, option) in word.char_indices().skip(1) {
        match option {
            'q' | 'v' | 'r' | 'n' | 'l' | 'h' | 'V' => {}
            'm' | 'p' | 'F' | 'j' | 'Z' | 'C' | 'o' | 'E' | 'P' => {
                let mut offset = index + option.len_utf8();
                if offset == word.len() {
                    return Some((option, None));
                }
                if word.as_bytes()[offset] == b'=' {
                    offset += 1;
                }
                return Some((option, Some(offset)));
            }
            _ => return None,
        }
    }
    None
}

/// Whether a known Cargo or nextest option consumes the following argument
/// verbatim. Attached operands are already contained by their own word.
#[must_use]
pub fn takes_separate_value(word: &str) -> bool {
    matches!(
        word,
        "--manifest-path"
            | "--config"
            | "--target"
            | "--target-dir"
            | "--build-dir"
            | "--lockfile-path"
            | "--package"
            | "--exclude"
            | "--features"
            | "--bin"
            | "--example"
            | "--test"
            | "--bench"
            | "--profile"
            | "--color"
            | "--message-format"
            | "--jobs"
            | "--artifact-dir"
            | "--out-dir"
            | "--crate-type"
            | "--index"
            | "--registry"
            | "--token"
            | "--filter-expr"
            | "--filterset"
            | "--partition"
            | "--status-level"
            | "--final-status-level"
            | "--failure-output"
            | "--success-output"
            | "--archive-file"
            | "--workspace-remap"
            | "--test-threads"
    ) || matches!(short_value_option(word), Some((_, None)))
}

/// Cheap syntax-only prefilter; a full scan still distinguishes option values
/// and arguments after Cargo's `--` from real selectors.
#[must_use]
pub fn is_manifest_selector_candidate(word: &str) -> bool {
    word == "--manifest-path"
        || word.starts_with("--manifest-path=")
        || matches!(short_value_option(word), Some(('m', _)))
}

/// Resolve one literal manifest selector without changing the argument slice.
///
/// Supports `--manifest-path`, `-m`, attached/equal operands, and grouped short
/// flags such as `-qvm`. Consuming option values remain opaque and Cargo's
/// `--` ends inspection. Working-directory changes are reported separately so
/// source planners can retain their existing refusal or mapping contract.
///
/// # Errors
/// Rejects duplicate manifest selectors, missing option operands, and empty
/// or control-bearing manifest values instead of choosing a different root.
pub fn parse_manifest_selection(args: &[String]) -> Result<ManifestSelection, String> {
    let mut selection = ManifestSelection::default();
    let mut index = 0;
    while let Some(word) = args.get(index) {
        if word == "--" {
            break;
        }
        let short = short_value_option(word);
        if matches!(short, Some(('C', _))) {
            selection.changes_directory = true;
        }
        let operand = if word == "--manifest-path" {
            Some((index + 1, 0))
        } else if word.starts_with("--manifest-path=") {
            Some((index, "--manifest-path=".len()))
        } else if let Some(('m', offset)) = short {
            Some(offset.map_or((index + 1, 0), |offset| (index, offset)))
        } else {
            None
        };
        if let Some((value_index, value_offset)) = operand {
            if selection.manifest.is_some() {
                return Err("multiple Cargo manifest selectors are unsupported".into());
            }
            let value = args
                .get(value_index)
                .and_then(|word| word.get(value_offset..))
                .filter(|value| {
                    !value.is_empty() && *value != "--" && !value.chars().any(char::is_control)
                })
                .ok_or_else(|| format!("missing or invalid value for Cargo option {word}"))?;
            selection.manifest = Some(ManifestSelector {
                option_index: index,
                value_index,
                value_offset,
                value: value.to_owned(),
            });
            index = value_index + 1;
        } else if takes_separate_value(word) {
            if args.get(index + 1).is_none() {
                return Err(format!("missing value for Cargo option {word}"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(selection)
}

/// Canonicalize a short manifest selector for read-only option consumers.
///
/// Split its preceding valueless short flags into their equivalent individual
/// arguments, then emit the long selector and literal operand. All other words
/// remain unchanged. Execution/source relocation can instead use the original
/// spans from [`parse_manifest_selection`] to preserve caller spelling.
///
/// # Errors
/// Returns the same ambiguity and operand errors as [`parse_manifest_selection`].
pub fn normalize_manifest_options(args: &[String]) -> Result<Vec<String>, String> {
    let Some(selector) = parse_manifest_selection(args)?.manifest else {
        return Ok(args.to_vec());
    };
    let option = &args[selector.option_index];
    if option.starts_with("--") {
        return Ok(args.to_vec());
    }
    // The parsed descriptor proves that m is the first value-taking option;
    // every earlier character is a valueless flag, never operand data.
    let manifest_flag = option
        .find('m')
        .ok_or("short Cargo manifest selector lost its option")?;
    let mut normalized = args[..selector.option_index].to_vec();
    normalized.extend(
        option[1..manifest_flag]
            .chars()
            .map(|flag| format!("-{flag}")),
    );
    normalized.push("--manifest-path".into());
    normalized.push(selector.value);
    normalized.extend_from_slice(&args[selector.value_index + 1..]);
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn every_manifest_spelling_preserves_the_exact_operand_and_span() {
        let path = "crates/it's a café/Cargo.toml";
        for flags in ["", "q", "vv", "qvr"] {
            for (option, separate) in [
                (format!("-{flags}m"), true),
                (format!("-{flags}m{path}"), false),
                (format!("-{flags}m={path}"), false),
            ] {
                let mut args = words(&["+nightly", "check"]);
                args.push(option);
                if separate {
                    args.push(path.into());
                }
                args.push("--locked".into());
                let selected = parse_manifest_selection(&args).unwrap();
                let manifest = selected.manifest.unwrap();
                assert_eq!(manifest.value, path);
                assert_eq!(manifest.option_index, 2);
                assert_eq!(manifest.value_index, if separate { 3 } else { 2 });
                assert_eq!(&args[manifest.value_index][manifest.value_offset..], path);
                assert!(!selected.changes_directory);
                let mut expected = words(&["+nightly", "check"]);
                expected.extend(flags.chars().map(|flag| format!("-{flag}")));
                expected.extend(words(&["--manifest-path", path, "--locked"]));
                let normalized = normalize_manifest_options(&args).unwrap();
                assert_eq!(normalized, expected);
                assert_eq!(normalize_manifest_options(&normalized).unwrap(), normalized);
            }
        }
        for args in [
            words(&["check", "--manifest-path", path]),
            vec!["check".into(), format!("--manifest-path={path}")],
        ] {
            assert_eq!(
                parse_manifest_selection(&args)
                    .unwrap()
                    .manifest
                    .unwrap()
                    .value,
                path
            );
            assert_eq!(normalize_manifest_options(&args).unwrap(), args);
        }
    }

    #[test]
    fn option_values_and_program_arguments_cannot_select_a_manifest() {
        for args in [
            words(&["check", "--config", "-mdecoy", "--target", "native"]),
            words(&["check", "--config", "--manifest-path=decoy"]),
            words(&["check", "--config=-mdecoy"]),
            words(&["check", "-qF", "-mdecoy"]),
            words(&["check", "-qFfeature-m", "-pm-package", "-Zm-setting"]),
            words(&["test", "--", "-qm", "decoy", "--manifest-path=decoy"]),
            words(&["check", "--config", "--", "--target", "native"]),
            words(&["nextest", "run", "-E", "-mdecoy"]),
            words(&["nextest", "run", "-qE", "-mdecoy"]),
            words(&["nextest", "run", "--filterset", "-mdecoy"]),
            words(&["nextest", "run", "-P", "-mdecoy"]),
            words(&["nextest", "run", "--archive-file", "-mdecoy"]),
        ] {
            assert!(
                parse_manifest_selection(&args).unwrap().manifest.is_none(),
                "{args:?}"
            );
            assert_eq!(normalize_manifest_options(&args).unwrap(), args);
        }
        let args = words(&["check", "-qF", "-mdecoy", "-m", "actual/Cargo.toml"]);
        assert_eq!(
            parse_manifest_selection(&args)
                .unwrap()
                .manifest
                .unwrap()
                .value,
            "actual/Cargo.toml"
        );
        let args = words(&["test", "-m", "actual/Cargo.toml", "--", "-m", "payload"]);
        assert_eq!(
            parse_manifest_selection(&args)
                .unwrap()
                .manifest
                .unwrap()
                .value,
            "actual/Cargo.toml"
        );
        let args = words(&[
            "nextest",
            "run",
            "--filter-expr",
            "-mdecoy",
            "-P",
            "-qmdecoy",
            "-m",
            "actual/Cargo.toml",
        ]);
        assert_eq!(
            parse_manifest_selection(&args)
                .unwrap()
                .manifest
                .unwrap()
                .value,
            "actual/Cargo.toml"
        );
    }

    #[test]
    fn ambiguous_or_incomplete_selectors_refuse_without_mutation() {
        for args in [
            words(&["check", "-m"]),
            words(&["check", "-qm"]),
            words(&["check", "-m="]),
            words(&["check", "-qvm="]),
            words(&["check", "--manifest-path="]),
            words(&["check", "-m", "--"]),
            words(&["check", "-m", "bad\n/Cargo.toml"]),
            words(&[
                "check",
                "-mone/Cargo.toml",
                "--manifest-path=two/Cargo.toml",
            ]),
            words(&["check", "-mone/Cargo.toml", "-qvmtwo/Cargo.toml"]),
        ] {
            let original = args.clone();
            assert!(parse_manifest_selection(&args).is_err(), "{args:?}");
            assert!(normalize_manifest_options(&args).is_err(), "{args:?}");
            assert_eq!(args, original);
        }
    }

    #[test]
    fn working_directory_changes_are_actual_options_not_argument_data() {
        for args in [
            words(&["-C", "parent", "check", "-m", "Cargo.toml"]),
            words(&["check", "-qCparent", "-mCargo.toml"]),
            words(&["check", "-qC=parent"]),
        ] {
            assert!(
                parse_manifest_selection(&args).unwrap().changes_directory,
                "{args:?}"
            );
        }
        for args in [
            words(&["check", "--config", "-Cparent", "-mCargo.toml"]),
            words(&["check", "-qF", "-Cparent"]),
            words(&["test", "--", "-qCparent"]),
        ] {
            assert!(
                !parse_manifest_selection(&args).unwrap().changes_directory,
                "{args:?}"
            );
        }
    }
}
