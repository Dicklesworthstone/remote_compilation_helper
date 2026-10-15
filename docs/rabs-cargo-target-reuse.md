# Reusing dependencies across Cargo target directories

The live dependency lane already treats the rustc output directory as placement.
However, Cargo also passes `CARGO_TARGET_DIR` through its environment. The exact
environment policy keys that value, so separate agent/CI target directories can
still split otherwise identical dependency actions.

## Opt in on the daemon

Set `RABS_REUSE_CARGO_TARGET_DIR=1` (also `true` or `on`) **before starting rabsd**,
in addition to `RABS_LIVE_DEPENDENCY=1`. It is off by default and is read once per
daemon process. The `scripts/cargo-rabs` launcher passes this setting to a new
daemon; it deliberately does not reconfigure an already-running shared daemon.

This profile removes only the value of a present `CARGO_TARGET_DIR` from the
compiler key. It does not remove or rewrite the variable in rustc's execution
environment, alter the invocation, or change the actual output directory.
It composes with `RABS_REUSE_EMPTY_OUT_DIR=1`: the existing empty generated-tree
proof remains mandatory before that separate projection can apply.

## Why this does not cache an observed target path

The real execution plan keeps `CARGO_TARGET_DIR`, but omits it from `keyed_env`.
The existing post-compilation dep-info closure check consequently rejects
publication after any tracked read of this variable, including `env!` and
`option_env!`. Values are not rewritten inside outputs or diagnostics.

The profile has its own semantic-policy digest. An invocation with the variable
absent retains the exact baseline key and cannot share the present-variable
profile. This matters for code that observes absence: caching that result under
a key shared with a present value would be unsound.

Original evidence is validated first. A captured build-script
`cargo::rustc-env=CARGO_TARGET_DIR=...` directive still requires exact keying;
projection fails back to the validated baseline without leaking partial plan
changes. Source bytes, generated files, script stdout, compiler/toolchain,
dependencies, flags and other semantic environment values remain keyed.
The existing comparison, sampling, quarantine, capture and installation gates
are unchanged. There is no remote-execution or build-script-cache authority here.

## Scope and validation

This is a narrowly scoped, opt-in host-local reuse profile, not general
path-independent compilation. Other placement-bearing environment variables
(e.g. `CARGO_BUILD_TARGET_DIR`) remain exact. Unsupported compilation classes
still pass through. A new profile must gather fresh comparison evidence before
serving; enabling it is not a promise that the next compile will be a hit.

Regression coverage in `cargo_placement_reuse_tests.rs` exercises real action-key
construction, output-directory relocation, unchanged execution plans, tracked
reads, absent versus present/empty bindings, exact disabled behavior, semantic
input changes, build-script directive fallback, and invalid/ambiguous inputs.
The original empty-OUT_DIR implementation and its tests are retained in
`empty_out_dir_reuse.rs`.

Validation commands on the project's configured build worker:

```sh
rch exec -- cargo test -p rabsd cargo_placement_reuse
rch exec -- cargo test -p rabsd empty_out_dir
rch exec -- cargo test -p rabs-wrap --bin rabs-wrap singleflight
```

