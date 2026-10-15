# Reusing dependencies across Cargo build layouts

The live dependency lane already treats the rustc output directory as placement.
Cargo also passes layout settings through its environment. The exact environment
policy keys these values, so separate agent/CI directories can still split
otherwise identical dependency actions.

## Opt in on the daemon

Set `RABS_REUSE_CARGO_LAYOUT=1` (also `true` or `on`) **before starting rabsd**,
in addition to `RABS_LIVE_DEPENDENCY=1`. This projects eligible values of:

- `CARGO_TARGET_DIR`: final artifact directory override.
- `CARGO_BUILD_TARGET_DIR`: environment configuration for `build.target-dir`.
- `CARGO_BUILD_BUILD_DIR`: environment configuration for the intermediate
  `build.build-dir`, including Cargo's path-template spelling.

These are the settings documented in the Cargo configuration reference:
https://doc.rust-lang.org/cargo/reference/config.html#buildtarget-dir and
https://doc.rust-lang.org/cargo/reference/config.html#buildbuild-dir.
Cargo still chooses the real directories; RABS does not reinterpret its config,
precedence, templates or output paths.

The existing `RABS_REUSE_CARGO_TARGET_DIR=1` remains a narrower opt-in: it projects
only `CARGO_TARGET_DIR`. Both settings are off by default and read once per daemon
process. Selecting both is equivalent to selecting the complete layout profile.
The `scripts/cargo-rabs` launcher passes these settings to a new daemon; it does
not reconfigure an already-running shared daemon. For example, with installed
binaries and no existing daemon:

```sh
RABS_REUSE_CARGO_LAYOUT=1 cargo rabs build
```

The profile removes only eligible values from the compiler key. It does not
remove or rewrite variables in rustc's execution environment, alter the
invocation, or change the actual output directory. It composes with
`RABS_REUSE_EMPTY_OUT_DIR=1`: the existing empty generated-tree proof remains
mandatory before that separate projection can apply.

## Why this does not cache an observed build path

The real execution plan retains each selected variable but omits it from
`keyed_env`. The existing post-compilation dep-info closure check consequently
rejects publication after any tracked read, including `env!` and `option_env!`.
Values are not rewritten inside outputs or diagnostics.

The semantic-policy digest binds the exact set of projected, present variable
names. Absent and present-empty are distinct, as are different presence sets.
An invocation with no eligible variables retains its baseline key. Projecting
only `CARGO_TARGET_DIR` preserves the established single-variable policy identity,
regardless of which opt-in selected it.

Original evidence is validated first. Each captured build-script
`cargo::rustc-env=NAME=...` directive still requires exact keying of its value.
If one layout variable cannot be projected, it stays exact while the others may
still be projected. Each trial reconstructs narrower profiles from the original
plan, preserving their policy identities and tracked-read vetoes. Failed trials
cannot leak partially modified execution plans.

Source bytes, generated files, script stdout, compiler/toolchain, dependencies,
flags and all other semantic environment values remain keyed. In particular,
`CARGO_BUILD_TARGET` selects a target platform, not a directory: it is never
projected. The existing comparison, sampling, quarantine, capture and installation
gates are unchanged. There is no remote-execution or build-script-cache authority
here.

## Scope and validation

This is opt-in host-local reuse, not general path-independent compilation.
Dependency-directory membership, path-sensitive generated inputs and other
semantic differences may still prevent a hit. Unsupported compilation classes
still pass through. New policy identities require fresh comparison evidence;
enabling the profile is not a promise of an immediate cache hit.

`cargo_placement_reuse_tests.rs` retains the original target-only regressions and
adds complete-layout coverage: each variable and combination, all presence sets,
tracked value/presence reads, legacy policy identity, independent script-directive
fallback, bounded composition, rejected execution rewrites and semantic misses.
These are action-key/closure tests, not an executed Cargo/fleet speedup claim.
The original empty-OUT_DIR implementation and tests remain in
`empty_out_dir_reuse.rs`.

`rabs-wrap/tests/live_cargo_layout.rs` exercises the actual daemon/wrapper and
offline Cargo with separate final and intermediate directories. It requires a
first publication, two independent comparisons, then a served build with no
dependency compiler admission. Library bytes and executable output must match
stock Cargo in the same test, and the next build must be fresh. Separate real
`env!`/`option_env!` cases must compile and return each layout's actual value,
never replay another layout. The test uses the existing prepared-binary helper;
missing tools or failed builds are failures, not skipped acceptance.

Validation commands on the project's configured build worker:

```sh
rch exec -- cargo test -p rabsd cargo_placement_reuse
rch exec -- cargo test -p rabsd empty_out_dir
rch exec -- cargo test -p rabs-wrap --test live_cargo_layout --locked -- --nocapture
rch exec -- cargo test -p rabs-wrap --bin rabs-wrap singleflight
```
