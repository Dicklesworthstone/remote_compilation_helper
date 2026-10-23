# Environment inputs for canonical Cargo

A `canonical-cargo-v1` profile can supply an optional `env` object to
`cargo rabs --rabs-canonical`. This connects application build inputs to the
existing native `env-cwd-v1` context for `build`, `check`, `clippy`, `test`, and
`test --no-run`, in both direct worker and daemon-job modes.

Add this field to an otherwise valid profile:

```json
"env": {
  "APP_VERSION": "2026.10",
  "SOURCE_DATE_EPOCH": "1792530000",
  "SQLX_OFFLINE": "true",
  "RUST_BACKTRACE": "1",
  "OPTIONAL_LABEL": ""
}
```

The values are literal UTF-8 strings. There is no shell expansion, interpolation,
path rewriting, `.env` loading, or lookup in the dispatcher's environment.
An empty string differs from an omitted variable. A profile's `APP_VERSION`
therefore becomes the worker's value even when the dispatcher has a different
one. Variables not explicitly selected remain absent from the request.

The worker's existing environment-clearing namespace launcher applies the
context. Cargo may then supply its own standard variables to build scripts and
tests. An application can consume these inputs with `env!`, `option_env!`, or
ordinary runtime environment access. Use `cargo:rerun-if-env-changed=APP_VERSION`
when a build script depends on that value; Cargo still owns freshness decisions.

## Captured Cargo `[env]` configuration

Canonical preparation also accepts application variables in the approved
workspace's `.cargo/config.toml` or `.cargo/config`. Projects can keep their
existing Cargo configuration instead of duplicating it in the launcher profile:

```toml
[env]
APP_VERSION = "development"
APP_SCHEMA = { value = "schemas/application.json", relative = true }
APP_MODE = { value = "offline", force = true }
OPTIONAL_LABEL = ""
```

The original config bytes are captured and transferred unchanged. Cargo applies
its own configuration layering and resolves `relative = true` inside the
worker's canonical workspace. A relative value is based on the parent of the
`.cargo` directory containing that setting, including settings inherited from a
captured ancestor. It is never expanded into a preparing host's temporary path.
The path must stay inside the approved source anchor; an absolute or escaping
relative path refuses preparation. Empty relative values select the config's
base directory. No additional files outside the anchor are captured.

Ordinary values are defaults: an explicitly supplied profile environment value
wins unless the config sets `force = true`. Empty strings remain present values.
Cargo passes the effective values to build scripts, rustc and tests, so
`include_str!(env!("APP_SCHEMA"))` and build scripts reading the same variable
observe the corresponding captured file. These are Cargo's documented
[`[env]` semantics](https://doc.rust-lang.org/cargo/reference/config.html#env).

Each environment table accepts strings or `{ value, force, relative }` entries
with boolean flags. Names, values, entry counts and aggregate bytes use the
native command-environment bounds below. Worker and build-tool controls remain
reserved even with `force = false`; `GIT_*` variables are additionally reserved
because preparation owns its Git configuration. Unknown fields and malformed
entries fail before a prepared bundle is published. Vendored builds use the
same validation alongside their existing source-replacement checks.

The config remains an exact captured input. Changing its values invalidates the
private target compatibility family, while a new command with identical config
can retain the usual Cargo target state. Supporting `[env]` does not authorize
compiler-result caching or permit ambient host environment capture.

## Ownership and limits

Values are written to private `spec.json` and retained in the prepared request;
they are sent to the selected worker. **This is not a secret-delivery channel.**
Do not place credentials in the profile. The launcher neither copies ambient
credentials into the worker context nor adds profile values to the local native
driver's environment. Source preparation, TLS, daemon selection and recovery
retain their original local configuration.

Names use `[A-Za-z_][A-Za-z0-9_]*` with at most 256 ASCII bytes. Values cannot
contain NUL and must fit the native 64 KiB individual-value bound. The complete
context, including injected controls, is limited to 256 entries and 128 KiB of
`name=value\0` bytes. The existing 64 KiB profile and encoded-request bounds also
apply; JSON escaping can make these the tighter limit. Invalid input refuses
before creating an operation or starting the native driver. Diagnostics do not
print rejected values.

The following remain owned by the worker or frontend: `PATH`, `HOME`, `TMPDIR`,
`LANG`, `LC_ALL`, `TZ`, `MAKEFLAGS`, `MFLAGS`, `NUM_JOBS`, `CARGO`, `RUSTC`,
`RUSTDOC`, `RUSTFLAGS`, `RUSTDOCFLAGS`, and `GLIBC_TUNABLES`. Names beginning with
`CARGO_`, `RUSTUP_`, `RUSTC_`, `RUSTDOC_`, `CLIPPY_`, `RABS_`, `RCH_`, `LD_`, or
`DYLD_` are also reserved. In particular this does not provide a second way to
replace the captured compiler, change output locations, inject a wrapper, alter
Clippy's supported lint contract, or replace the worker's jobserver. Without
`env`, the existing pinned environment is unchanged.

## Identity and recovery

The exact context is part of the saved native request; profile key order is
normalized. The existing worker target-state key already includes the final
execution environment. This feature does not omit inputs from that key, alter
sampling or publication, or grant permission to skip a compiler.

Changing the profile affects only a new operation. `cargo rabs --rabs-recover`
continues to use the saved prepared request or original daemon-owned job, not
fresh values from the profile or current shell. It does not recapture, allocate
another request, or reexecute the build.

Run the frontend regression suite with:

```sh
python3 -I -S scripts/tests/test_cargo_rabs_environment.py -v
```

These tests execute the production Python launcher and real filesystem/process
handoffs with an explicitly labeled native-driver fixture. They are not evidence
of Rust compilation, authenticated worker execution, cache hits, or speedup.

The captured-config tests exercise the native preparer, real offline Cargo,
build scripts, `env!`, and `include_str!` after retiring the original checkout:

```sh
cargo test -p rabsd --lib captured_environment --locked
cargo test -p rabsd --test cargo_vendor_prepare \
  captured_cargo_environment_reaches_real_build_scripts_and_compilers --locked -- --exact
```

On a canonical-capable Linux host with matching built worker and daemon binaries,
the same fixture also verifies the authenticated worker and output-recovery path:

```sh
RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
  cargo test -p rabsd --test cargo_vendor_prepare \
    captured_cargo_environment_resolves_inside_canonical_native_tls_builds \
    --locked -- --ignored --exact
```
