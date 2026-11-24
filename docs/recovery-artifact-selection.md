# Selecting and recovering returned artifacts

## Default Cargo build delivery

Supported full Cargo builds retain a complete output receipt even when no
additional artifact exclusions are configured. This extends output proof to
literal `cargo build` commands with Cargo's default human output, including
plain builds, full workspaces, libraries, broad or mixed target selectors and
examples, and build-only `cargo test --no-run` / `cargo bench --no-run`. It
applies on the durable Unix worker path with a resolved target directory.
Existing named-executable capture keeps its original contract.

Before publishing any files from this complete capture, RCH checks that every
selected Cargo-reported executable, library and sidecar is present in the owned
staging tree. A nonempty transfer cannot replace a missing output, and a stale file
already present in the caller's target directory cannot satisfy the check.
The existing output selection and cache exclusions remain in force; this proof
does not turn compiler intermediates or arbitrary worker-private files into
required deliverables.

The original selection, capture mode and complete producer receipt are retained
with the job. If collection is interrupted or one output is missing, recovery
uses that same completed invocation without rebuilding it. No local output is
published until the complete required set passes validation. A failed Cargo
command keeps its original failure status and diagnostics.

This automatic lane instruments only the default human output with the same
Cargo JSON capture already used for named executable delivery. Explicit
message formats, opaque flags, shell compounds, documentation/package commands,
Zigbuild and transports without durable Unix output evidence keep their
existing behavior. Existing named-executable caller JSON remains unchanged.
Old recovery recipes retain their originally admitted contract; they are not
silently upgraded during collection.

## Cargo target exclusions

Keep worker-private caches out of Cargo artifact return with committed project
configuration in `.rch/config.toml`:

```toml
[transfer]
cargo_retrieval_exclude_dirs = [
  "debug/.wrapper-shims",
  "debug/.kache-build-script-shims",
  "release/.wrapper-shims",
]
```

Each entry names an exact directory relative to the resolved Cargo target root,
including custom `CARGO_TARGET_DIR` roots. Cross-compilation and custom profiles
use their actual directory prefixes, such as
`aarch64-unknown-linux-gnu/ci-fast/.wrapper-shims`. No globbing, traversal,
absolute paths, empty components, trailing slashes, backslashes or colons are
accepted. At most 128 directories of 4096 bytes each are supported. Built-in
`incremental/`, `.fingerprint/`, `build/` and dep-info exclusions remain active.
An exclusion does not match a same-prefix sibling or a same-named tree elsewhere.

This opt-in applies to `cargo build`, ordinary `cargo zigbuild`, and build-only
`cargo test --no-run` / `cargo bench --no-run`. It supports the bounded literal
Cargo build grammar, including full workspaces, libraries, multiple binaries,
profiles and target triples. The Unix durable execution path retains a complete
Cargo JSON receipt and validates every Cargo-reported selected library, binary
and sidecar before publishing anything. Required executables and priority
includes cannot be excluded. Empty, incomplete or malformed output evidence
and out-of-root executables refuse publication; one remaining file cannot stand
in for a complete build. Rust `.rlib`/`.rmeta` and procedural-macro intermediates
in a separate Cargo build directory remain outside target delivery, while every
selected target-root library and executable is still required. Other library
outputs outside that root refuse delivery. This also supports ordinary mirror
builds that retain a configured `build.build-dir`.

For Zigbuild, the accepted forms are `cargo zigbuild`,
`cargo +toolchain zigbuild`, and the literal standalone invocations
`cargo-zigbuild zigbuild`, `cargo-zigbuild build` or `cargo-zigbuild b`.
Zigbuild requires the default message format and literal target triples without
ABI-version suffixes. Select a toolchain through Cargo; standalone
`cargo-zigbuild +toolchain ...` and `rustup run` wrappers are unsupported. An explicit
`--target universal2-apple-darwin` is refused before execution because the
plugin's universal2 mode does not forward a complete Cargo JSON stream. An empty
exclusion list leaves existing Zigbuild behavior unchanged.

The completed receipt must identify every explicitly requested target, including
examples and mixed named/broad selections. Every relevant returning library
format and sidecar must survive the original artifact policy. A named example
requires a deliverable payload; dep-info (`.d`) and metadata (`.rmeta`) alone do
not satisfy it, even when the original policy includes them. Malformed emitted
paths or an invalid saved selection cannot establish a complete receipt. Unknown
Cargo record reasons or target kinds refuse narrowing rather than establishing
an incomplete output set from the remaining known records.

Cargo-reported `.dSYM` debug-symbol bundles are required directories. Their
staged contents must include regular files, and the entire bundle is checked
for symlinks and other unsupported entries before publication. An exclusion
cannot omit a required bundle or one of its subdirectories. Recovery confirms
that bundle contents were published before reporting successful delivery.
Explicit named Cargo JSON retains the bundle directory in `filenames` while
binding its retained contents to the files published by the completed job.

Full builds use their normal human output; explicit caller JSON remains limited
to the existing named-executable contract for ordinary Cargo commands.
Unsupported explicit message formats, opaque flags, documentation/package
commands and transports without durable Cargo evidence refuse before execution.
Streaming check, clippy, ordinary test reports, non-Cargo commands and explicitly
declared job results are unaffected.

Size planning, payload retrieval, staged-file validation and detached recovery
use the same persisted selection. Recovery retains the original exclusions even
when current configuration changes; it never reruns the completed build to
establish output completeness. An exclusion conflicting with an actual emitted
output is reported after completion, before publication, with the attempt retained.

`transfer.exclude_patterns` controls source upload only. Project-root
`.rchignore` is not inherited by the separate Cargo target pull. The target
root's own `.rchignore` keeps its existing guarded directory-only semantics;
unlike the project configuration above, that file is removed by `cargo clean`.

Before publication changes the recovery journal or destination, RCH rechecks the
actual selected staged files against the retained Cargo output contract. A local
`.rchignore` change cannot silently drop a required regular file or a file within
a required bundle: a conflicting selection stops publication while retaining the
stage and Cargo receipt. Correct the conflicting local ignore rule, then resume
the same attempt with `rch jobs recover <wrapper-id>`; the completed build is not
rerun.

## Make outputs that include non-deliverable test fixtures

Make artifact discovery is intentionally broad: a project may produce ordinary
executables, object files, libraries, reports or distribution archives without
an enumerable output contract. RCH cannot infer from a directory name that its
contents are dispensable. In particular, passing negative-control tests may
leave synthetic PATH directories containing symlinks beneath `build/`.

Do not delete those fixtures, dereference their symlinks, disable publication
validation, rerun the successful build, or edit its journal to mark it complete.
The internal `.rch-clean-overlay-base.tar` is always excluded independently.

## Explicit collection-only refinement

An operator can declare exact directories to be non-deliverable for **one
original wrapper** using `RCH_RECOVERY_ARTIFACT_EXCLUSIONS`. The variable contains
a JSON object with `wrapper_id` and `directories`; it is consumed only by
`jobs recover`, after exclusive journal ownership and original-owner absence
have been verified. It does not change new-build selection or run a compiler.

First select a **fresh** durable controller staging base in the configuration
used by this recovery invocation:

```toml
[transfer]
retrieval_staging_dir = "/mnt/controller-storage/refined-retrieval"
retrieval_min_free_bytes = 67108864
max_transfer_time_ms = 900000
```

Use the canonical absolute path, not a symlink alias. The base must be owned by
the current user and not writable by group or others. RCH exclusively creates
the original identity's directory beneath it; an already-existing identity tree
is refused even if empty. The stage must not overlap the caller's output roots
or the job-journal directory. Keep the invocation's original `RCH_STATE_HOME`
and daemon endpoint: changing the staging base does not relocate its journal.

Then supply the **actual** original wrapper ID and the narrow fixture directory
identified in its retained evidence. This example uses a placeholder identity
and directory; do not exclude required build outputs or an entire result tree:

```sh
RCH_RECOVERY_ARTIFACT_EXCLUSIONS='{"wrapper_id":"rchw-example","directories":["build/test-gates/release-fixture/path-without-cosign"]}' \
  rch jobs recover rchw-example --timeout-secs 1200
```

Names are literal, root-relative directory paths. Spaces and Unicode are
supported. Absolute paths, `.`/`..`, empty components, trailing slashes,
control characters, glob syntax, backslashes and colons are rejected. Unknown
JSON fields, duplicate fields/directories, oversized requests and a mismatching
wrapper ID also fail closed. At most 64 directories and 16 KiB of request JSON
are accepted. An anchored directory exclusion does not exclude a same-prefix
sibling, a same-named tree elsewhere, or a regular file bearing that name.

## What is retained and what may change

A new refinement requires a persisted successful command outcome and an
unfinished implicit Make project phase. It cannot alter native or Cargo output
contracts, priority includes, declared result directories, failed results, a
delivered outcome, or released source ownership. It only adds directory-exclusion
rules and pins the fresh staging base. Worker/build identity, source authority,
verification flags, output baselines and original completion remain unchanged.

Previously delivered reports and disjoint partial publication no longer block
refinement of the failed project phase. Every completed phase, published file
fingerprint and pending rename remains in the recipe unchanged. An exclusion
that equals, contains, or lies beneath a pending or published project output is
refused before preparing staging or writing a journal. Declared result-directory
overlap remains forbidden even when its phase is already complete. These checks
compare path components, not text prefixes: `build/tools` does not overlap
`build/tools-extra/app`. Contradictory completed-but-pending phases also refuse.

The collector retrieves into the fresh stage under the original source grant.
It skips completed result phases and resumes the existing publisher: already
published files are not rewritten, and pending renames must still pass their
original fingerprint and ownership checks. This explicit, audited refinement is
different from an ordinary staging-location override, which remains forbidden
after publication starts. It never clears a checkpoint to make a retry succeed.

Before changing the recipe, RCH retains the exact previous journal bytes in an
exclusive, synchronized, private `artifact-policy-<uuid>.before` file beside the
journal. Its name is deliberately not a `.json` job entry. The old staging tree
is neither traversed, moved nor deleted. The new recipe is published through
the existing atomic, descriptor-bound journal writer before collection starts.
Any failed preparation or publication leaves its evidence in place; no cleanup
or permission to adopt an uncertain staging tree is implied.

The normal transfer-size/storage preflight applies to the refined selection.
Publication still rejects any symlink in an admitted output location. No
successful terminal acknowledgment is created by refinement: delivery, output
verification, source retirement/release and daemon reconciliation must complete
through the ordinary recovery path.

Exclusions and the new staging location survive restart without the environment
variable. Repeating an identical request is read-only and may resume partial
publication or read back a terminal job; it cannot reset progress. A *new*
exclusion must be disjoint from every pending and published project output and
cannot modify an already completed project phase. On retries, keep the same
staging configuration or omit the override so the persisted location remains in force.
The overall `--timeout-secs` deadline and transfer budget remain independent.

## Relocating an unfinished collection without changing its artifact policy

A storage failure can occur after a report was delivered or another output
entered pending publication. An ordinary `retrieval_staging_dir` override then
refuses: configuration alone is not authority to reset that progress. Do not
invent an artifact exclusion simply to obtain another staging location.

Instead, select a fresh durable base in the recovery configuration as above,
then authorize relocation for exactly the original wrapper:

```sh
RCH_RECOVERY_RELOCATE_STAGING=rchw-example \
  rch jobs recover rchw-example --timeout-secs 1200
```

The value is the actual wrapper ID, **not** `1` or `true`. This request is
consumed only after exclusive journal ownership and original-owner absence
are verified. Do not combine it with `RCH_RECOVERY_ARTIFACT_EXCLUSIONS`; the
combined request refuses before either operation changes the journal.

Relocation requires a recorded successful execution, at least one unfinished
phase, and outstanding source ownership. It cannot reopen an acknowledged or
returned job, a failed required result, or a completed phase. All existing
phases, baselines, published fingerprints and pending renames are preserved.
No artifact rule is added or removed, including native/Cargo output contracts
and the unconditional internal source-archive exclusion.

The fresh identity tree must not already exist, alias or overlap the old
staging tree, overlap an output/journal directory, or violate the same private
staging-base policy used for refinement. RCH checks available space against the
larger of the stored and requested free-space reserves before publishing the
new location. After source reacquisition, the ordinary filtered transfer-size
preflight still checks the payload allocation. Space checks are advisory:
quotas, metadata allocation and concurrent writers can still fail a transfer.
Neither a RAM-backed caller nor `TMPDIR` selects the durable staging volume.

Relocation records the new staging directory and its private ownership receipt;
the command, artifact policy and delivery checkpoints remain unchanged. The exact prior
journal is retained in an `artifact-policy-<uuid>.before` file using the same
synchronized backup mechanism as refinement. Old staged payloads, source
archives and partial files are not copied, moved, rewritten or deleted.
The subsequent normal recovery config merge may extend the transfer budget
and increase the reserve; it does not reset output progress.

The collector reacquires the original source grant and completion evidence,
then recollects unfinished phases into the new stage. Completed reports are
skipped. The existing publisher verifies and resumes pending renames and never
rewrites a checkpointed published output. Relocation alone creates no terminal
acknowledgment and proves no source release; those boundaries remain mandatory.

An identical request with the same configured base is read-only, even after
collection finishes. The new location survives restart without the environment
variable. Keep the same staging configuration on a retry, or omit the override
and relocation request to use the journal's recorded location. Keep the original
`RCH_STATE_HOME` and daemon endpoint in either case.

A failure after creating the fresh identity directory but before recording its
location leaves that directory retained and the old location authoritative.
Select another unused durable base for the next attempt; no automatic cleanup
or adoption of the uncertain directory is authorized. The original journal
filesystem must still have enough space for its small backup and atomic update.

## Reclaiming completed retrieval payloads

New retrieval stages record their directory identity and a private ownership
marker before the first phase collects any bytes. Once eligible delivery and
source retirement are durable, RCH releases the duplicate phase payloads and
records completion in the recovery journal. Published caller outputs and the
separate retained Cargo receipts remain available.

If a process stops after retirement or during payload release, recovery repeats
the unfinished release before acknowledging the job. The ordinary
`rch jobs recover <wrapper-id>` path also performs this check for an already
retired job. A changed directory identity, substituted path, or damaged ownership
marker refuses cleanup and leaves the job available for recovery and inspection. Removal uses
the held original directory descriptors and does not follow staged symlinks.

A local cleanup failure preserves the original command result and recovery
record. Both `rch exec` and the hook retain the admission for recovery and refuse
automatic command replay. This local failure does not quarantine a worker whose
execution already completed. After the original staging identity is available,
recover that wrapper to finish cleanup and acknowledge its recorded result.

The small identity directory and ownership marker remain after the payloads are
released. A durable completion flag makes later recovery read-only for that
stage, including any new files added afterward. Failed-delivery and pending
publication evidence retains the existing recovery protections.

Older or pre-existing stages without creation-time ownership evidence remain
retained. Recovery does not adopt them for automatic cleanup, scan unrelated
staging jobs, or reclaim the worker's retained source trees. This prevents new
duplicate-output accumulation for owned stages; it does not remove historical
orphaned payloads.
