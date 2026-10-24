# Recovering Make outputs that include non-deliverable test fixtures

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

Only the staging-directory field is changed by relocation. The exact prior
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
