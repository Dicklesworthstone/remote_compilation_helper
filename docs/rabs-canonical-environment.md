# Explicit environment inputs for canonical Cargo

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
