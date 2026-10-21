# Reusing dependencies across Cargo build layouts

The live dependency lane already treats the rustc output directory as placement.
Cargo also passes layout settings through its environment. The exact environment
policy keys these values, so separate agent/CI directories can still split
otherwise identical dependency actions.

The current live serving class is `--emit=metadata,dep-info`, as used by
`cargo check`. Ordinary `cargo build` codegen still runs with its original
arguments and environment. rustc's dep-info does not report every assembler
input: `global_asm!` can introduce `.incbin` reads outside the captured package.
Repeated identical builds cannot prove that those external bytes will stay
unchanged. Such requests return `LIVE_DEP_CODEGEN_READ_CLOSURE` before toolchain
warming or cache lookup, and the coordinator independently refuses admission,
installation and publication. Older codegen publications remain retained history
and cannot regain serving authority through their accumulated samples.

This restriction applies equally to registry, Git and directory sources, and to
link, object, assembly and LLVM outputs. Re-enabling codegen reuse requires an
enforced complete input view under a distinct policy identity; a source-text scan
or a switch that ignores the missing reads cannot supply that authority.

## Enable reuse through the launcher or daemon

`cargo rabs check` enables the complete layout profile when it starts a new
daemon. Separate agent target/build directories can then reuse eligible
dependency results without an additional setting. The launcher's default is
passed only to the new daemon; it does not introduce a new variable into Cargo's
or rustc's environment. Explicit operator values are preserved, including
`RABS_REUSE_CARGO_LAYOUT=0` to retain exact layout keying.

An already-running shared daemon keeps its existing policy. Attaching a new
`cargo rabs` invocation never restarts or reconfigures it, and readiness alone
does not promise a cache hit. Use an explicitly configured daemon or separate
state/socket paths when a different policy is required.

When starting `rabsd` directly, set `RABS_REUSE_CARGO_LAYOUT=1` (also `true` or
`on`) **before starting the daemon**,
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
only `CARGO_TARGET_DIR`. Both settings are off by default in a directly started
daemon and read once per daemon process. Selecting both is equivalent to
selecting the complete layout profile. To select the narrower profile through
the launcher, explicitly disable its complete-layout default. For example, with
installed binaries and no existing daemon:

```sh
cargo rabs check

# Or select only CARGO_TARGET_DIR reuse for a new daemon:
RABS_REUSE_CARGO_LAYOUT=0 RABS_REUSE_CARGO_TARGET_DIR=1 cargo rabs check
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
