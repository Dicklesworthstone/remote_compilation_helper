//! Exact Ninja graph outputs for direct Ninja and Ninja-backed CMake/Meson.
//!
//! A build directory can contain source files, and its graph may write outputs
//! in a sibling directory. Neither -C nor --build authorizes recursive copies.
//! Query the settled graph after a successful build and add its real output
//! paths to the existing project retrieval policy. That policy still returns
//! undeclared sidecars from known build roots. Backend regeneration rules
//! retain worker paths and must not replace a caller's local build graph.
//! Some targets may not have been selected, so the new paths are optional
//! files, not a required-file contract. Existing runtime and source-integrity
//! filters still apply.

use super::direct_compiler::{compiler_arguments, literal_file_pattern};
use rch_common::CompilationKind;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Bound the actual worker query and parser together. A large graph never
/// becomes an unbounded SSH reply or publication-pattern list.
pub(in crate::hook) const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TARGETS: usize = 16_384;
const MAX_PATH_BYTES: usize = 4096;
const OUTPUT_HEADER: &str = "RCH_NINJA_OUTPUTS_V1";

pub(in crate::hook) struct BuildSystemOutputDiscovery {
    directory: PathBuf,
    query: String,
}

impl BuildSystemOutputDiscovery {
    pub(in crate::hook) fn for_command(
        kind: Option<CompilationKind>,
        command: &str,
    ) -> Option<Self> {
        let executable = match kind? {
            CompilationKind::CmakeBuild => "cmake",
            CompilationKind::Ninja => "ninja",
            CompilationKind::Meson => "meson",
            _ => return None,
        };
        let arguments = compiler_arguments(command, &[executable])?;
        let (directory, manifest, configuration) = match executable {
            "cmake" => {
                let (directory, configuration) = cmake_directory(&arguments)?;
                (directory, "build.ninja".into(), configuration)
            }
            "ninja" => {
                let (directory, manifest) = changed_directory(&arguments, false)?;
                (directory, manifest, None)
            }
            "meson" => {
                if arguments.first()?.as_str() != "compile" {
                    return None;
                }
                let (directory, manifest) = changed_directory(&arguments[1..], true)?;
                (directory, manifest, None)
            }
            _ => return None,
        };
        let directory = selected_directory(&directory)?;
        // compiler_arguments already validated the literal shell grammar.
        // Preserve environment and other transparent wrapper operands.
        let mut words = shell_words::split(command).ok()?;
        let executable_index = words.len().checked_sub(arguments.len() + 1)?;
        words.truncate(executable_index + 1);
        if executable != "ninja" {
            words[executable_index] = "ninja".into();
        }
        let fallback = manifest_query(&directory, &manifest, &words)?;
        let query = if let Some(configuration) = configuration {
            // Ninja Multi-Config executes build-<config>.ninja. Ordinary
            // single-config CMake ignores --config and still uses build.ninja.
            // An existing non-regular candidate must fail its guards rather
            // than silently choose a different configuration's graph.
            let manifest = format!("build-{configuration}.ninja");
            let selected = manifest_query(&directory, &manifest, &words)?;
            let path = relative_output(&directory, &manifest)?;
            let path = shell_words::quote(path.to_str()?);
            format!("if test -e {path} || test -L {path}; then {selected}; else {fallback}; fi")
        } else {
            fallback
        };
        Some(Self { directory, query })
    }

    pub(in crate::hook) fn query(&self) -> &str {
        &self.query
    }

    /// Every returned include names a file that the actual graph declares as
    /// an output. Regeneration files receive exact exclusions. Phony aliases,
    /// source inputs and the selected directory itself never acquire new
    /// publication authority from this query.
    pub(in crate::hook) fn resolve(&self, stdout: &[u8]) -> anyhow::Result<Vec<String>> {
        use anyhow::Context;
        anyhow::ensure!(
            stdout.len() <= MAX_OUTPUT_BYTES && (stdout.is_empty() || stdout.ends_with(b"\n")),
            "incomplete or oversized Ninja output listing"
        );
        let text = std::str::from_utf8(stdout).context("non-UTF-8 Ninja output listing")?;
        let mut lines = text.split_terminator('\n');
        anyhow::ensure!(
            lines.next() == Some(OUTPUT_HEADER),
            "missing Ninja output-root header"
        );
        let logical_root = lines
            .next()
            .and_then(absolute_root)
            .context("invalid Ninja logical output root")?;
        let physical_root = lines
            .next()
            .and_then(absolute_root)
            .context("invalid Ninja physical output root")?;
        let mut outputs = BTreeSet::new();
        let mut excluded = BTreeSet::new();
        for (index, line) in lines.enumerate() {
            anyhow::ensure!(
                index < MAX_TARGETS,
                "Ninja output listing exceeds target limit"
            );
            let (path, rule) = line
                .rsplit_once(": ")
                .context("malformed Ninja output listing")?;
            anyhow::ensure!(
                !rule.is_empty()
                    && !rule.chars().any(|ch| ch.is_whitespace() || ch.is_control())
                    && !line.chars().any(char::is_control),
                "invalid Ninja output rule"
            );
            // CMake/Meson's regeneration rules write worker-specific Ninja
            // manifests and install scripts, not transferable build outputs.
            // Match the rule rather than a suffix: a real custom command may
            // legitimately generate a .cmake or .ninja user asset.
            if rule == "phony" {
                continue;
            }
            let regeneration = matches!(rule, "RERUN_CMAKE" | "REGENERATE_BUILD");
            let path = if Path::new(path).is_absolute() {
                // These roots were captured by the very query which listed
                // the graph, after entering the source-granted project cwd.
                // Strip complete path components, never a textual prefix.
                let relative = Path::new(path)
                    .strip_prefix(&logical_root)
                    .or_else(|_| Path::new(path).strip_prefix(&physical_root));
                if regeneration && relative.is_err() {
                    // An external backend file cannot be reached by the
                    // project policy, and never receives new authority here.
                    continue;
                }
                relative
                    .ok()
                    .and_then(Path::to_str)
                    .and_then(|relative| relative_output(Path::new(""), relative))
            } else {
                relative_output(&self.directory, path)
            }
            .context("Ninja output leaves the project or has an ambiguous path")?;
            let pattern = literal_file_pattern(path.to_str().context("non-UTF-8 Ninja output")?)
                .context("invalid Ninja output filename")?;
            if regeneration {
                // Root-anchor exclusions too: a root build.ninja must not
                // hide an unrelated generated asset with the same basename.
                excluded.insert(format!("- /{pattern}"));
            } else {
                outputs.insert(pattern);
            }
        }
        let mut patterns: Vec<_> = excluded.into_iter().chain(outputs).collect();
        if !patterns.is_empty() {
            super::clean_overlay::exclude_source_archive(&mut patterns);
        }
        Ok(patterns)
    }
}

fn manifest_query(directory: &Path, manifest: &str, executable: &[String]) -> Option<String> {
    let manifest_path = relative_output(directory, manifest)?;
    let mut words = executable.to_vec();
    words.extend([
        "-C".into(),
        directory
            .to_str()
            .filter(|text| !text.is_empty())
            .unwrap_or(".")
            .into(),
        "-f".into(),
        manifest.into(),
        "-t".into(),
        "targets".into(),
        "all".into(),
    ]);
    // A symlink in the selected working-directory chain would make leading
    // ../ outputs refer to a different physical ancestor. Prove the lexical
    // mapping before asking Ninja to interpret its graph.
    let mut directories = BTreeSet::new();
    for path in [directory, manifest_path.parent()?] {
        for parent in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(parent.to_str()?.to_owned());
        }
    }
    let mut guards = Vec::new();
    for directory in directories {
        let directory = shell_words::quote(&directory);
        guards.push(format!("test -d {directory} && test ! -L {directory}"));
    }
    let manifest = shell_words::quote(manifest_path.to_str()?);
    guards.push(format!("test -f {manifest} && test ! -L {manifest}"));
    // CMake emits absolute outputs even for ordinary generated files. Bind
    // both spellings of this invocation root before listing them: worker
    // mirrors may expose the physical tree through a logical path.
    Some(format!(
        "if {}; then printf '%s\\n' '{OUTPUT_HEADER}' && pwd -L && pwd -P && {}; else exit 3; fi",
        guards.join(" && "),
        super::super::join_exec_command(&words),
    ))
}

/// Extend the established project policy without losing undeclared compiler
/// sidecars already covered by its known build roots. Backend metadata and
/// source-transport exclusions precede every ordinary include.
pub(in crate::hook) fn merge_patterns(existing: &[String], discovered: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for exclusion in [true, false] {
        for pattern in existing.iter().chain(discovered) {
            if pattern.starts_with("- ") == exclusion && seen.insert(pattern.clone()) {
                merged.push(pattern.clone());
            }
        }
    }
    if !merged.is_empty() {
        super::clean_overlay::exclude_source_archive(&mut merged);
    }
    merged
}

fn absolute_root(root: &str) -> Option<PathBuf> {
    if root.is_empty()
        || root.len() > MAX_PATH_BYTES
        || root.chars().any(char::is_control)
        || root.contains('\\')
        || !Path::new(root).is_absolute()
        || !Path::new(root)
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return None;
    }
    Some(PathBuf::from(root))
}

fn ordinary_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && !path.chars().any(char::is_control)
        && !path.contains('\\')
        && path.as_bytes().get(1) != Some(&b':')
        && !Path::new(path).is_absolute()
}

fn selected_directory(directory: &str) -> Option<PathBuf> {
    if !ordinary_relative(directory) {
        return None;
    }
    let mut path = PathBuf::new();
    for component in Path::new(directory).components() {
        match component {
            Component::Normal(name) => path.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn relative_output(directory: &Path, output: &str) -> Option<PathBuf> {
    if !ordinary_relative(output) || output.ends_with('/') {
        return None;
    }
    let mut path = directory.to_owned();
    let mut saw_name = false;
    for component in Path::new(output).components() {
        match component {
            Component::Normal(name) => {
                saw_name = true;
                path.push(name);
            }
            Component::CurDir => {}
            Component::ParentDir if !saw_name && path.pop() => {}
            // A later parent traversal could cross a symlink inside the
            // output path. Leading parents alone use the proven build-root
            // ancestry and may safely reach another project directory.
            _ => return None,
        }
    }
    (saw_name && !path.as_os_str().is_empty()).then_some(path)
}

fn cmake_directory(arguments: &[String]) -> Option<(String, Option<String>)> {
    let (directory, rest) = if arguments.first()?.as_str() == "--build" {
        (arguments.get(1)?.as_str(), &arguments[2..])
    } else {
        (
            arguments.first()?.strip_prefix("--build=")?,
            &arguments[1..],
        )
    };
    if directory.is_empty() || directory.starts_with('-') {
        return None;
    }
    let mut configuration = None;
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        if argument == "--" {
            let backend = &rest[index + 1..];
            // Forwarded graph/tool/dry-run switches do not execute the graph
            // inferred from CMake's root/configuration. Keep only ordinary
            // target, scheduling and verbosity arguments for this discovery.
            if backend.iter().any(|argument| {
                ["-C", "-f", "-t", "-n", "-d", "-w"]
                    .iter()
                    .any(|prefix| argument.starts_with(*prefix))
            }) {
                return None;
            }
            changed_directory(backend, false)?;
            break;
        }
        let selected = if argument == "--config" {
            index += 1;
            Some(rest.get(index)?.as_str())
        } else {
            argument.strip_prefix("--config=")
        };
        if let Some(selected) = selected {
            if !ordinary_relative(selected)
                || selected.starts_with('-')
                || selected.contains(['/', '$', '`'])
                || !matches!(
                    Path::new(selected).components().next(),
                    Some(Component::Normal(_))
                )
                || Path::new(selected).components().count() != 1
                || configuration.replace(selected.to_owned()).is_some()
            {
                return None;
            }
        } else if argument == "--build"
            || argument.starts_with("--build=")
            || argument == "--preset"
            || argument.starts_with("--preset=")
            || argument.starts_with("-C")
            || argument == "--directory"
            || argument.starts_with("--directory=")
        {
            return None;
        }
        index += 1;
    }
    Some((directory.to_owned(), configuration))
}

/// Parse a single literal -C selection, consuming option operands so a target,
/// diagnostic setting or backend argument can never masquerade as a directory.
/// Repeated -C has tool-specific semantics and is left to the legacy policy.
fn changed_directory(arguments: &[String], meson: bool) -> Option<(String, String)> {
    let mut directory = None;
    let mut manifest = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            break;
        }
        let selected = if argument == "-C" {
            index += 1;
            Some(arguments.get(index)?.as_str())
        } else {
            argument
                .strip_prefix("-C")
                .filter(|value| !value.is_empty())
        };
        if let Some(selected) = selected {
            if directory.is_some() || selected.is_empty() || selected.starts_with('-') {
                return None;
            }
            directory = Some(selected.to_owned());
        } else if !meson && argument == "-f" {
            index += 1;
            if manifest.replace(arguments.get(index)?.clone()).is_some() {
                return None;
            }
        } else if !meson && let Some(file) = argument.strip_prefix("-f") {
            if manifest.replace(file.to_owned()).is_some() {
                return None;
            }
        } else if argument.starts_with('-') {
            let options_with_value: &[&str] = if meson {
                &["-j", "--jobs", "-l", "--load-average"]
            } else {
                &["-j", "-k", "-l", "-d", "-w"]
            };
            if options_with_value.contains(&argument.as_str()) {
                index += 1;
                arguments.get(index)?;
            } else if options_with_value.iter().any(|option| {
                if option.starts_with("--") {
                    argument
                        .strip_prefix(option)
                        .is_some_and(|suffix| suffix.starts_with('=') && suffix.len() > 1)
                } else {
                    argument.starts_with(option) && argument.len() > option.len()
                }
            }) {
                // Attached option operands do not consume the next token.
            } else if !matches!(argument.as_str(), "-v" | "--verbose" | "--quiet") {
                // Includes dry runs, Ninja tools and arbitrary backend args:
                // they do not declare an ordinary build at this directory.
                return None;
            }
        }
        index += 1;
    }
    Some((
        directory.unwrap_or_else(|| ".".into()),
        manifest.unwrap_or_else(|| "build.ninja".into()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::{TransferPipeline, default_c_cpp_artifact_patterns};
    use rch_common::TransferConfig;
    use std::path::PathBuf;

    fn listing(outputs: &[u8]) -> Vec<u8> {
        let mut framed =
            format!("{OUTPUT_HEADER}\n/worker/project\n/physical/project\n").into_bytes();
        framed.extend_from_slice(outputs);
        framed
    }

    #[test]
    fn explicit_build_locations_select_only_the_named_graph_outputs() {
        for (kind, command, expected) in [
            (
                CompilationKind::CmakeBuild,
                "cmake --build cmake-build-debug --config Debug --parallel 2",
                "cmake-build-debug/app",
            ),
            (
                CompilationKind::CmakeBuild,
                "env MODE=debug /usr/bin/cmake --build './products/debug build/' -- -j2",
                "products/debug build/app",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build=target/native",
                "target/native/app",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build products --config=Release --target app -- -j2 -v",
                "products/app",
            ),
            (
                CompilationKind::Ninja,
                "ninja -v -C obj/debug -j 2 app",
                "obj/debug/app",
            ),
            (
                CompilationKind::Ninja,
                "ninja -C'obj [debug]*?' -f build.ninja -j2",
                "obj [[]debug[]][*][?]/app",
            ),
            (
                CompilationKind::Meson,
                "meson compile -C _build --jobs=2 app",
                "_build/app",
            ),
            (
                CompilationKind::Meson,
                "meson compile --verbose -Ctarget/native -j 2",
                "target/native/app",
            ),
            (CompilationKind::CmakeBuild, "cmake --build .", "app"),
            (CompilationKind::Ninja, "ninja", "app"),
            (CompilationKind::Meson, "meson compile", "app"),
        ] {
            let expected = vec![
                "- .rch-clean-overlay-base.tar".to_owned(),
                expected.to_owned(),
            ];
            let discovery = BuildSystemOutputDiscovery::for_command(Some(kind), command).unwrap();
            assert_eq!(
                discovery
                    .resolve(&listing(b"app: link\nall: phony\n"))
                    .unwrap(),
                expected,
                "{command}"
            );
            assert!(discovery.query().contains("-t targets all"));
        }
    }

    #[test]
    fn ambiguous_build_locations_never_expand_the_artifact_scope() {
        for (kind, commands) in [
            (
                CompilationKind::CmakeBuild,
                vec![
                    "cmake --build",
                    "cmake --build /tmp/build",
                    "cmake --build ../build",
                    "cmake --build obj/../src",
                    "cmake --build '$OUTPUT' --preset p",
                    "cmake --build obj -- -C ../src",
                    "cmake --build obj --build src",
                    "cmake --build --preset dev",
                    "cmake --preset build",
                    "cmake --build C:/build",
                    "cmake --build obj --config",
                    "cmake --build obj --config=",
                    "cmake --build obj --config ''",
                    "cmake --build obj --config .",
                    "cmake --build obj --config ../Release",
                    "cmake --build obj --config=Release/Debug",
                    "cmake --build obj --config '$CONFIG'",
                    "cmake --build obj --config $CONFIG",
                    "cmake --build obj --config Release --config=Debug",
                    "cmake --build obj --config Release --config Release",
                    "cmake --build obj -- -f other.ninja",
                    "cmake --build obj -- -fother.ninja",
                    "cmake --build obj -- -t targets all",
                    "cmake --build obj -- -ttargets",
                    "cmake --build obj -- -n",
                    "cmake --build obj -- -vn",
                    "cmake --build obj -- --dry-run",
                    "cmake --build obj -- -d list",
                    "cmake --build obj -- -w dupbuild=warn",
                ],
            ),
            (
                CompilationKind::Ninja,
                vec![
                    "ninja -C",
                    "ninja -C ../build",
                    "ninja -C obj -C debug",
                    "ninja -C obj -f first.ninja -f second.ninja",
                    "ninja -C obj -t targets",
                    "ninja -C obj --unknown",
                    "ninja -C $OUTPUT",
                    "ninja -C obj*",
                    "sh -c 'ninja -C obj'",
                    "env -C other ninja -C obj",
                ],
            ),
            (
                CompilationKind::Meson,
                vec![
                    "meson setup _build",
                    "meson compile -C obj --ninja-args='-C ../source'",
                    "meson compile -C obj --clean",
                    "meson compile -C obj -C other",
                ],
            ),
            (CompilationKind::Make, vec!["make -C src", "make -C build"]),
        ] {
            for command in commands {
                assert!(
                    BuildSystemOutputDiscovery::for_command(Some(kind), command).is_none(),
                    "{command}"
                );
            }
        }
    }

    #[test]
    fn cmake_configurations_select_a_guarded_manifest_with_single_config_fallback() {
        for command in [
            "cmake --build obj --config Release",
            "cmake --build obj --config=Release --target app -- -j2",
        ] {
            let discovery =
                BuildSystemOutputDiscovery::for_command(Some(CompilationKind::CmakeBuild), command)
                    .unwrap();
            let query = discovery.query();
            assert!(
                query
                    .contains("test -e obj/build-Release.ninja || test -L obj/build-Release.ninja")
            );
            assert!(
                query.contains(
                    "test -f obj/build-Release.ninja && test ! -L obj/build-Release.ninja"
                )
            );
            assert!(query.contains("-f build-Release.ninja -t targets all"));
            assert!(query.contains("test -f obj/build.ninja && test ! -L obj/build.ninja"));
            assert!(query.contains("-f build.ninja -t targets all"));
        }
        let quoted = BuildSystemOutputDiscovery::for_command(
            Some(CompilationKind::CmakeBuild),
            "cmake --build 'obj with spaces' --config 'Release Candidate'",
        )
        .unwrap();
        assert!(
            quoted
                .query()
                .contains("'obj with spaces/build-Release Candidate.ninja'")
        );
        assert!(
            quoted
                .query()
                .contains("-f 'build-Release Candidate.ninja' -t targets all")
        );
    }

    #[test]
    fn custom_build_tree_does_not_authorize_siblings_sources_or_transport_inputs() {
        let root = tempfile::tempdir().unwrap().keep();
        for directory in [
            "packages/native/obj [debug]",
            "packages/native/src",
            "build",
        ] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        std::fs::write(root.join("source.c"), b"caller source").unwrap();
        std::fs::write(
            root.join("packages/native/obj [debug]/main.c"),
            b"in-tree caller source",
        )
        .unwrap();
        let pipeline = TransferPipeline::new(
            root,
            "build-root".into(),
            "build-root-identity".into(),
            TransferConfig::default(),
        );
        let discovery = BuildSystemOutputDiscovery::for_command(
            Some(CompilationKind::Ninja),
            "ninja -C 'packages/native/obj [debug]'",
        )
        .unwrap();
        let patterns = discovery.resolve(&listing(concat!(
            "app: link\nnested/object.o: cc\ngenerated/config.h: generate\n",
            "../bin/sibling: link\nmain.c: phony\n",
            ".rch-clean-overlay-base.tar: generate\nnested/.rch-clean-overlay-base.tar: generate\n",
        ).as_bytes())).unwrap();
        let outputs: Vec<PathBuf> = [
            "packages/native/obj [debug]/app",
            "packages/native/obj [debug]/nested/object.o",
            "packages/native/obj [debug]/generated/config.h",
            "packages/native/bin/sibling",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let excluded: Vec<PathBuf> = [
            "source.c",
            "packages/native/obj [debug]/main.c",
            "packages/native/src/main.c",
            "packages/native/obj d/app",
            "build/stale-app",
            "packages/native/obj [debug]/.rch-clean-overlay-base.tar",
            "packages/native/obj [debug]/nested/.rch-clean-overlay-base.tar",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let mut candidates = outputs.clone();
        candidates.extend(excluded.clone());
        let (admitted, rejected) = pipeline
            .partition_staged_artifact_paths(&candidates, &patterns)
            .unwrap();
        assert_eq!(admitted, outputs);
        assert_eq!(rejected, excluded);
    }

    #[test]
    fn output_listing_is_bounded_and_cannot_expand_into_directory_or_external_authority() {
        let discovery = BuildSystemOutputDiscovery::for_command(
            Some(CompilationKind::Ninja),
            "ninja -C obj/debug",
        )
        .unwrap();
        assert_eq!(
            discovery
                .resolve(&listing(
                    b"../../bin/app: cc\nall: phony\n/foreign/input: phony\n"
                ))
                .unwrap(),
            vec!["- .rch-clean-overlay-base.tar", "bin/app"]
        );
        assert_eq!(
            discovery
                .resolve(&listing(b"name: with spaces[?]*: link\n"))
                .unwrap(),
            vec![
                "- .rch-clean-overlay-base.tar",
                "obj/debug/name: with spaces[[][?][]][*]"
            ]
        );
        assert!(discovery.resolve(&listing(b"")).unwrap().is_empty());
        assert!(
            discovery
                .resolve(&listing(b"all: phony\n"))
                .unwrap()
                .is_empty()
        );
        for output in [
            b"app: cc".as_slice(),
            b"app: cc\r\n",
            b"app: \n",
            b"app\n",
            b"app: rule extra\n",
            b"../../../escape: cc\n",
            b"nested/../app: cc\n",
            b"/external/app: cc\n",
            b"C:/app: cc\n",
            b".: cc\n",
            b"directory/: cc\n",
            b"app\0: cc\n",
            b"app\xff: cc\n",
        ] {
            assert!(discovery.resolve(&listing(output)).is_err(), "{output:?}");
        }
        assert!(
            discovery
                .resolve(&listing(&b"app: link\n".repeat(MAX_TARGETS + 1)))
                .is_err()
        );
        assert!(
            discovery
                .resolve(&vec![b'x'; MAX_OUTPUT_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn absolute_outputs_are_projected_only_from_the_queried_invocation_roots() {
        let discovery = BuildSystemOutputDiscovery::for_command(
            Some(CompilationKind::CmakeBuild),
            "cmake --build 'obj/debug build'",
        )
        .unwrap();
        assert_eq!(
            discovery
                .resolve(&listing(
                    concat!(
                        "/worker/project/bin/app: link\n",
                        "/physical/project/bin/app: link\n",
                        "/physical/project/obj/debug build/cmake_install.cmake: RERUN_CMAKE\n",
                        "object.o: cc\n/foreign/source.c: phony\n",
                    )
                    .as_bytes()
                ))
                .unwrap(),
            vec![
                "- .rch-clean-overlay-base.tar",
                "- /obj/debug build/cmake_install.cmake",
                "bin/app",
                "obj/debug build/object.o",
            ]
        );
        for outputs in [
            "/worker/project-copy/bin/app: link\n",
            "/physical/project-copy/bin/app: link\n",
            "/worker/project/../outside: link\n",
            "/worker/project/nested/../app: link\n",
            "/worker/project: link\n",
            "/unrelated/app: link\n",
        ] {
            assert!(
                discovery.resolve(&listing(outputs.as_bytes())).is_err(),
                "{outputs}"
            );
        }
        for response in [
            "",
            "app: cc\n",
            "RCH_NINJA_OUTPUTS_V1\n",
            "RCH_NINJA_OUTPUTS_V1\n/worker/project\n",
            "RCH_NINJA_OUTPUTS_V1\nrelative\n/physical/project\napp: cc\n",
            "RCH_NINJA_OUTPUTS_V1\n/worker/../project\n/physical/project\napp: cc\n",
            "RCH_NINJA_OUTPUTS_V1\n/worker/project\n/physical/project\r\napp: cc\n",
            "RCH_NINJA_OUTPUTS_V2\n/worker/project\n/physical/project\napp: cc\n",
        ] {
            assert!(
                discovery.resolve(response.as_bytes()).is_err(),
                "{response:?}"
            );
        }
    }

    #[test]
    fn backend_regeneration_outputs_do_not_replace_local_build_graphs() {
        let discovery =
            BuildSystemOutputDiscovery::for_command(Some(CompilationKind::Ninja), "ninja -C build")
                .unwrap();
        assert_eq!(
            discovery
                .resolve(&listing(
                    concat!(
                        "build.ninja: RERUN_CMAKE\n",
                        "/physical/project/build/cmake_install.cmake: RERUN_CMAKE\n",
                        "build.ninja: REGENERATE_BUILD\nreconfigure: REGENERATE_BUILD\n",
                        "/external/cmake_install.cmake: RERUN_CMAKE\n",
                        "generated/asset.cmake: CUSTOM_COMMAND\n",
                        "generated/asset.ninja: CUSTOM_COMMAND\n",
                        "generated/header.h: CUSTOM_COMMAND\n",
                    )
                    .as_bytes()
                ))
                .unwrap(),
            vec![
                "- .rch-clean-overlay-base.tar",
                "- /build/build.ninja",
                "- /build/cmake_install.cmake",
                "- /build/reconfigure",
                "build/generated/asset.cmake",
                "build/generated/asset.ninja",
                "build/generated/header.h",
            ],
        );
    }

    #[test]
    fn merged_policy_retains_legacy_sidecars_without_widening_custom_output_roots() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("obj")).unwrap();
        std::fs::write(root.path().join("source.c"), b"caller source\n").unwrap();
        std::fs::write(root.path().join("obj/source.c"), b"custom-tree source\n").unwrap();
        let pipeline = TransferPipeline::new(
            root.path().to_owned(),
            "build-root".into(),
            "build-root-identity".into(),
            TransferConfig::default(),
        );
        let discovery =
            BuildSystemOutputDiscovery::for_command(Some(CompilationKind::Ninja), "ninja -C build")
                .unwrap();
        let discovered = discovery
            .resolve(&listing(
                concat!(
                    "build.ninja: RERUN_CMAKE\ncmake_install.cmake: RERUN_CMAKE\n",
                    "../obj/generated.cmake: CUSTOM_COMMAND\n",
                    "app: link\n",
                )
                .as_bytes(),
            ))
            .unwrap();
        let existing = default_c_cpp_artifact_patterns();
        let merged = merge_patterns(&existing, &discovered);
        assert_eq!(merge_patterns(&merged, &discovered), merged);
        assert!(existing.iter().all(|pattern| merged.contains(pattern)));
        assert!(merge_patterns(&[], &[]).is_empty());
        let first_include = merged
            .iter()
            .position(|pattern| !pattern.starts_with("- "))
            .unwrap();
        assert!(
            merged[first_include..]
                .iter()
                .all(|pattern| !pattern.starts_with("- "))
        );
        let paths = [
            "build/main.dwo", // Not declared by the graph, retained by the existing build policy.
            "build/generated/header.h",
            "build/nested/cmake_install.cmake", // Only the exact backend output is excluded.
            "obj/generated.cmake",
            "build/build.ninja",
            "build/cmake_install.cmake",
            "obj/source.c",
            "source.c",
        ]
        .map(PathBuf::from);
        let (admitted, rejected) = pipeline
            .partition_staged_artifact_paths(&paths, &merged)
            .unwrap();
        assert_eq!(admitted, paths[..4]);
        assert_eq!(rejected, paths[4..]);
    }

    #[cfg(unix)]
    #[test]
    fn query_requires_a_real_manifest_and_unchanged_lexical_directory_ancestry() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("obj/debug")).unwrap();
        std::fs::create_dir_all(root.path().join("real/debug")).unwrap();
        std::fs::write(root.path().join("real/debug/build.ninja"), b"# fixture\n").unwrap();
        symlink("../real", root.path().join("obj/alias")).unwrap();
        symlink(
            "../../real/debug/build.ninja",
            root.path().join("obj/debug/build.ninja"),
        )
        .unwrap();
        for name in ["config-symlink", "config-dangling", "config-directory"] {
            let directory = root.path().join("obj").join(name);
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("build.ninja"), b"# fallback must not run\n").unwrap();
            if name == "config-directory" {
                std::fs::create_dir(directory.join("build-Release.ninja")).unwrap();
            } else {
                symlink(
                    if name == "config-symlink" {
                        "build.ninja"
                    } else {
                        "absent.ninja"
                    },
                    directory.join("build-Release.ninja"),
                )
                .unwrap();
            }
        }
        for (kind, command) in [
            (CompilationKind::Ninja, "ninja -C missing"),
            (CompilationKind::Ninja, "ninja -C obj/debug"),
            (CompilationKind::Ninja, "ninja -C obj/alias/debug"),
            (
                CompilationKind::CmakeBuild,
                "cmake --build obj/config-symlink --config Release",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build obj/config-dangling --config=Release",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build obj/config-directory --config Release",
            ),
        ] {
            let discovery = BuildSystemOutputDiscovery::for_command(Some(kind), command).unwrap();
            let output = std::process::Command::new("sh")
                .args(["-c", discovery.query()])
                .current_dir(root.path())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(3), "{command}: {output:?}");
            assert!(output.stdout.is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires CMake, Ninja, Meson, a C compiler and rsync"]
    async fn real_build_tools_return_custom_tree_outputs_through_guarded_rsync() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        async fn run(command: &mut Command) -> std::process::Output {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(60), command.output())
                .await
                .expect("owned build-system fixture timed out")
                .expect("CMake, Ninja, Meson, a C compiler and rsync are required");
            assert!(output.status.success(), "{command:?}: {output:?}");
            output
        }

        for (kind, command, build_dir, executable) in [
            (
                CompilationKind::CmakeBuild,
                "cmake --build 'cmake build' --config Release",
                "cmake build",
                "bin/app",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build build",
                "build",
                "bin/app",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build multi-config --config=Release",
                "multi-config",
                "bin/Release/app",
            ),
            (
                CompilationKind::Ninja,
                "ninja -C obj/debug",
                "obj/debug",
                "obj/bin/app",
            ),
            (CompilationKind::Ninja, "ninja -C src", "src", "bin/app"),
            (
                CompilationKind::Ninja,
                "ninja -C src -f graph.ninja",
                "src",
                "bin/app",
            ),
            (
                CompilationKind::Meson,
                "meson compile -C target/meson",
                "target/meson",
                "target/meson/app",
            ),
        ] {
            let root = tempfile::tempdir().unwrap().keep();
            let worker = root.join("worker");
            let local = root.join("caller");
            let stage = root.join("stage");
            for path in [&worker, &local, &stage] {
                std::fs::create_dir_all(path.join(build_dir)).unwrap();
                std::fs::create_dir_all(path.join("build")).unwrap();
            }
            std::fs::write(worker.join("main.c"), b"#include <stdio.h>\nint main(void) { puts(\"build-tree-delivered\"); return 0; }\n").unwrap();
            std::fs::write(local.join("main.c"), b"caller source sentinel\n").unwrap();
            std::fs::write(worker.join(build_dir).join("source.c"), b"#include <stdio.h>\nint main(void) { puts(\"build-tree-delivered\"); return 0; }\n").unwrap();
            std::fs::write(
                local.join(build_dir).join("source.c"),
                b"in-tree caller source sentinel\n",
            )
            .unwrap();
            for metadata in ["build.ninja", "cmake_install.cmake"] {
                std::fs::write(
                    local.join(build_dir).join(metadata),
                    b"caller build graph sentinel\n",
                )
                .unwrap();
            }
            std::fs::create_dir_all(local.join(executable).parent().unwrap()).unwrap();
            std::fs::write(local.join(executable), b"stale local executable\n").unwrap();
            std::fs::write(worker.join("build/stale-app"), b"another build\n").unwrap();
            std::fs::write(
                worker.join("build/main.dwo"),
                b"undeclared split-debug sidecar\n",
            )
            .unwrap();
            match kind {
                CompilationKind::CmakeBuild => {
                    std::fs::write(
                        worker.join("asset.cmake.in"),
                        b"set(RCH_GENERATED_ASSET 37)\n",
                    )
                    .unwrap();
                    std::fs::write(worker.join("CMakeLists.txt"), b"cmake_minimum_required(VERSION 3.20)\nproject(rch_build_tree C)\nset(CMAKE_RUNTIME_OUTPUT_DIRECTORY \"${CMAKE_BINARY_DIR}/../bin\")\nadd_executable(app main.c)\nadd_custom_command(OUTPUT generated_asset.cmake COMMAND ${CMAKE_COMMAND} -E copy \"${CMAKE_SOURCE_DIR}/asset.cmake.in\" generated_asset.cmake DEPENDS asset.cmake.in)\nadd_custom_target(generated_asset ALL DEPENDS generated_asset.cmake)\n").unwrap();
                    let generator = if build_dir == "multi-config" {
                        "Ninja Multi-Config"
                    } else {
                        "Ninja"
                    };
                    run(Command::new("cmake")
                        .current_dir(&worker)
                        .args(["-S", ".", "-B", build_dir, "-G", generator]))
                    .await;
                }
                CompilationKind::Ninja => {
                    let manifest = if command.contains("-f graph.ninja") {
                        "graph.ninja"
                    } else {
                        "build.ninja"
                    };
                    std::fs::write(worker.join(build_dir).join(manifest), b"rule cc\n  command = cc $in -o $out\nbuild ../bin/app: cc source.c\nbuild all: phony ../bin/app\ndefault all\n").unwrap();
                }
                CompilationKind::Meson => {
                    std::fs::write(
                        worker.join("meson.build"),
                        b"project('rch-build-tree', 'c')\nexecutable('app', 'main.c')\n",
                    )
                    .unwrap();
                    run(Command::new("meson")
                        .current_dir(&worker)
                        .args(["setup", build_dir]))
                    .await;
                }
                _ => unreachable!(),
            }
            std::fs::create_dir_all(worker.join(executable).parent().unwrap()).unwrap();
            run(Command::new("sh")
                .current_dir(&worker)
                .args(["-c", command]))
            .await;
            std::fs::write(
                worker.join(build_dir).join(".rch-clean-overlay-base.tar"),
                b"private source transport\n",
            )
            .unwrap();

            let config = rch_common::WorkerConfig {
                id: rch_common::WorkerId::new("build-tree-fixture"),
                ..Default::default()
            };
            let pipeline = TransferPipeline::new(
                local.clone(),
                "build-tree".into(),
                "build-tree-identity".into(),
                TransferConfig::default(),
            )
            .with_local_root(stage.clone());
            let discovery = BuildSystemOutputDiscovery::for_command(Some(kind), command).unwrap();
            let output = run(Command::new("sh")
                .current_dir(&worker)
                .args(["-c", discovery.query()]))
            .await;
            let selected = discovery.resolve(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{command}: {error}: {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            });
            if build_dir == "multi-config" {
                assert!(worker.join(build_dir).join("build-Release.ninja").is_file());
                assert!(selected.iter().any(|pattern| pattern == "bin/Release/app"));
                assert!(!selected.iter().any(|pattern| pattern == "bin/Debug/app"));
            }
            assert!(
                output
                    .stdout
                    .starts_with(format!("{OUTPUT_HEADER}\n").as_bytes()),
                "the worker query must bind its output roots"
            );
            if kind == CompilationKind::CmakeBuild {
                // The graph contains CMake's absolute generated-file names.
                // A worker mirror may enter that same tree through a symlink;
                // both cwd spellings must still select exactly the same files.
                let logical = root.join("logical-worker");
                std::os::unix::fs::symlink(&worker, &logical).unwrap();
                let mirrored_query = format!(
                    "cd {} && {}",
                    shell_words::quote(logical.to_str().unwrap()),
                    discovery.query(),
                );
                let mirrored = run(Command::new("sh")
                    .current_dir(&root)
                    .args(["-c", &mirrored_query]))
                .await;
                assert_eq!(discovery.resolve(&mirrored.stdout).unwrap(), selected);
                let mirrored = std::str::from_utf8(&mirrored.stdout).unwrap();
                let mut roots = mirrored.lines().skip(1);
                assert_eq!(roots.next(), logical.to_str());
                let physical = worker.canonicalize().unwrap();
                assert_eq!(roots.next(), physical.to_str());
            }
            let selected = merge_patterns(&default_c_cpp_artifact_patterns(), &selected);
            let mut retrieval =
                pipeline.local_artifact_retrieval_for_test(&config, &worker, &selected);
            run(&mut retrieval).await;
            assert_eq!(
                std::fs::read(stage.join(executable)).unwrap(),
                std::fs::read(worker.join(executable)).unwrap()
            );
            assert!(!stage.join("main.c").exists());
            if build_dir != "build" {
                assert!(!stage.join(build_dir).join("source.c").exists());
            }
            assert_eq!(
                std::fs::read(stage.join("build/stale-app")).unwrap(),
                b"another build\n"
            );
            assert_eq!(
                std::fs::read(stage.join("build/main.dwo")).unwrap(),
                b"undeclared split-debug sidecar\n"
            );
            for metadata in ["build.ninja", "cmake_install.cmake"] {
                assert!(!stage.join(build_dir).join(metadata).exists());
                assert_eq!(
                    std::fs::read(local.join(build_dir).join(metadata)).unwrap(),
                    b"caller build graph sentinel\n",
                );
            }
            if kind == CompilationKind::CmakeBuild {
                assert_eq!(
                    std::fs::read(stage.join(build_dir).join("generated_asset.cmake")).unwrap(),
                    b"set(RCH_GENERATED_ASSET 37)\n",
                );
            }
            assert!(
                !stage
                    .join(build_dir)
                    .join(".rch-clean-overlay-base.tar")
                    .exists()
            );
            assert_eq!(
                std::fs::read(local.join("main.c")).unwrap(),
                b"caller source sentinel\n"
            );
            assert_eq!(
                std::fs::read(local.join(build_dir).join("source.c")).unwrap(),
                b"in-tree caller source sentinel\n"
            );
            let output = run(&mut Command::new(stage.join(executable))).await;
            assert_eq!(output.stdout, b"build-tree-delivered\n");
        }
    }
}
