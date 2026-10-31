# Offline worker recovery: issue #128 validation

## Scope and provenance

This records the successful local process-level comparison for
[issue #128](https://github.com/Dicklesworthstone/remote_compilation_helper/issues/128).
The [raw results](offline_worker_issue_128.json) retain the configuration, exact
binary hashes, individual phases, and regression observations.

Both executables ran in **one invocation** of
[`scripts/test_offline_worker_recovery.py`](../../scripts/test_offline_worker_recovery.py),
with real OpenSSH client/server authentication over a local `ProxyCommand` and
inetd-mode `sshd`. The worker command replies are deterministic fixtures. Refusal
and an SSH handshake blackhole simulate an unavailable endpoint and an
unresponsive VPN path. This does not measure real VPN routing traffic or execute
a remote compilation; scheduling is exercised through actual daemon API
reservations and releases.

The baseline checkout was clean at
`a1fe627c25716dc25c752222b678a461d966d5c5`. The measured candidate includes the
offline-worker implementation and the owned-process descendant cleanup fix.
A later final snapshot also preserves the winning worker's pooled admission
when concurrent registrations use the same worker ID, and includes a
behavior-preserving telemetry conditional cleanup. Its complete regression
verification is recorded separately below. The paired resource measurements
remain attributed to the measured candidate; the original raw JSON is unchanged.

| Executable | SHA-256 |
| --- | --- |
| Pristine baseline | `028128d26225a44313b857b7ceeec07fa9150ed84f9486cd3db5f1f2ec22cf7f` |
| Measured candidate | `09bebeec99d7111895fc8d2617b36b3108cf828d8170dec627542419aa1d11c3` |
| Final verified snapshot | `b27beb8be6ed4a54ec6d806bbb940fde9bdaa239ba81dcd47ac280c71a24e3ad` |

Both measured executables used the pinned `nightly-2026-08-31` toolchain and the same unoptimized dev
profile: `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0`, and
`RUSTFLAGS='-Zthreads=1 -Zmir-opt-level=0'`. Builds used `--locked --offline`.

The shared Cargo target initially reused the candidate for the older checkout.
That invalid comparison was detected by identical executable hashes and was
never measured. Updating only the baseline crate-root mtimes forced compilation
of all three local crates; verbose compiler manifests confirmed the baseline
checkout. The supported build-source environment variables stamped its verified
SHA, and `rchd --version` confirmed `a1fe627c2571`. Current crate-root mtimes were
then invalidated and those environment variables unset before compiling the
candidate. Baseline source contents remained unchanged.

## Idle, administrative disablement, and restart

Each daemon had one refused worker, no queued builds, and identical configuration:
a failure threshold of 2, a 30-second healthy check interval, a 300-second recovery
interval, and a 900-second circuit cooldown. The baseline predates the new
recovery-interval setting and ignores it; its built-in 30-second healthy check
interval matches the configured value. The idle observation lasted approximately
65 seconds, followed by 32 seconds after acknowledged administrative disablement
and 2 seconds after restarting with the same durable state.

| Observation | Baseline | Candidate |
| --- | ---: | ---: |
| SSH dials during 65-second idle window | 18 | 2 |
| Physical daemon log lines during idle window | 86 | 31 |
| Daemon CPU time during idle window | 0.08 s | 0.05 s |
| Peak daemon RSS during idle window | 31.92 MiB | 30.88 MiB |
| SSH dials after disable acknowledgement, 32 seconds | 2 | 0 |
| Log lines during disabled observation | 8 | 0 |
| Daemon CPU time during disabled observation | 0.03 s | 0.00 s |
| Peak daemon RSS during disabled observation | 26.61 MiB | 29.33 MiB |
| New SSH dials across disabled restart | 2 | 0 |
| Log lines in the 2-second restart observation | 11 | 0 |

The candidate made the two configured initial health attempts approximately
30 seconds apart. At the end of the idle window its status reported two
consecutive failures and **865 seconds until the next recovery probe**, consistent
with honoring the 900-second cooldown after the second failure at about 30
seconds. The baseline continued dialing despite its open circuit and after
disablement, including after restart.

These are single local observations. CPU time comes from `/proc` accounting and
is quantized; `0.00 s` is not a claim of literally zero CPU work. RSS changes were
mixed, including a higher candidate RSS in the disabled phase. The evidence
establishes fewer SSH attempts and less repeated logging; it does not establish
a general CPU or memory benchmark win. Physical log-line counts include the
logger's multiline formatting and initial failure transitions.

## Recovery, concurrency, and scheduling regressions

The same invocation then exercised the measured candidate with a 1-second healthy check
interval, a failure threshold of 2, a 3-second recovery interval, and a 1-second
total probe deadline. All assertions passed.

| Scenario | Observation |
| --- | --- |
| Sustained refused endpoint | 3 dials in 9.21 seconds; minimum spacing 3.081 seconds; zero repeated daemon log lines |
| Mixed healthy/offline fleet | All 24 concurrent reservations selected the healthy worker; reported sample p95 12.93 ms |
| Concurrent capability refresh | 12 requests caused zero extra offline dials |
| Automatic recovery | Worker became healthy and schedulable in 3.124 seconds after becoming reachable |
| Warm-session disable and restart | Sessions closed; no new dials while disabled or after restart; pinned admission was rejected |
| Explicit enable | Worker recovered and accepted a reservation |
| Loss of an established connection | Failed worker stopped accepting reservations; healthy peer continued; minimum recovery dial spacing 3.079 seconds |
| Handshake blackhole | Minimum dial spacing 4.026 seconds, including the 1-second deadline; sampled peak one live transport |
| Disable during a blackhole probe | In-flight child exited and no further dials occurred |
| Pooling disabled | Two dials in 6.21 seconds, minimum spacing 3.115 seconds; disablement stopped dials |

A further fleet of **14 blackholed workers plus one healthy worker** exercised
the global recovery limit. Its probe deadline was 3 seconds to provide a stable
observation window; other cases retained their 1-second deadline. There were
exactly 12 live blackhole transports both before and after 24 concurrent healthy
admissions, and the sampled blackhole peak remained 12. The healthy worker
completed two further health commands in 2.2 seconds. The physical transport
peak was 13, including healthy sessions; this is reported separately from the
12-permit recovery budget. Selection's reported sample p95 was 14.43 ms.

Process counts validate PID start times to avoid counting or signaling reused
PIDs. Ordinary phases sample every 50 ms; the saturated fleet samples every
10 ms. Consequently a fast refused attempt can have a sampled live-process peak
of zero while its independently logged dial count is nonzero. Selection p95 uses
the lower order statistic at `floor((n - 1) * 0.95)` over 24 requests; this is a
small functional scheduling sample, not a latency benchmark against the baseline.

## Final snapshot verification and validation limits

The final normal daemon executable, SHA-256
`b27beb8be6ed4a54ec6d806bbb940fde9bdaa239ba81dcd47ac280c71a24e3ad`,
built successfully with the same normal build settings in 29.86 seconds. Both
complete regression-only invocations then exited successfully, sequentially,
without concurrent builds. This includes the exact synthetic SSH transport used
by the automated Linux integration-test launcher and real local OpenSSH.

| Final-snapshot observation | Default SSH subprocess fixture | Real local OpenSSH |
| --- | ---: | ---: |
| Healthy worker selected in mixed fleet | 24 / 24 | 24 / 24 |
| Extra offline dials from 12 concurrent capability refreshes | 0 | 0 |
| Recovery latency with 3-second recovery interval | 3.253 s | 3.140 s |
| New dials while administratively disabled | 0 | 0 |
| New dials after disabled daemon restart | 0 | 0 |
| Sampled single-worker blackhole transport peak | 1 | 1 |
| Blackhole transports before and after saturated-fleet admissions | 12 / 12 | 12 / 12 |
| Healthy admissions in saturated fleet | 24 / 24 | 24 / 24 |
| Health commands completed by the healthy peer during the 2.2-second observation | 2 | 2 |

Both final runs also passed established-connection loss, explicit enable,
in-flight probe cancellation, unpooled operation, recovery cadence, and the
14-blackhole fleet's strict 12-transport bound. Raw final results were retained
at `/tmp/rch-128-final-default-e43a/results.json` and
`/tmp/rch-128-final-openssh-e43a/results.json` during validation. These are
regression reruns, not a second before/after resource comparison.

The repository validation status is:

- Final normal daemon build: passed.
- `cargo clippy --locked --offline -p rchd -p rch-common --all-targets -- -D warnings`:
  passed, including typechecking all daemon/common test code.
- Final common unit suite: 2,493 passed, 8 ignored, no failures.
- Formatting check: passed.
- Latest full daemon test harness: execution is **not verified**. The compiler
  was terminated by `SIGKILL` (signal 9) before linking, despite bounded retries.
  An earlier full snapshot had 1,896 passes and three fixture failures. Fixture
  corrections were made without weakening assertions and are typechecked, but
  the blocked final build prevented confirming the complete execution result.
- Full workspace check/Clippy and CLI test compilation: blocked when compilation
  of the preexisting registry dependency `asupersync v0.5.0` was killed. The CLI
  tests did not run. The successful scoped checks and process regressions above
  do not substitute for claiming those broader gates passed.

## Reproduction

Preserve independently verified baseline and candidate executables built with
matching settings, then run:

```sh
python3 scripts/test_offline_worker_recovery.py \
  --binary /path/to/candidate/rchd \
  --before /path/to/baseline/rchd \
  --openssh \
  --measure-seconds 65 \
  --output /tmp/rch-offline-comparison
```

Use a new output directory. Real OpenSSH mode needs `ssh`, `ssh-keygen`, and
`sshd`; root-run tests also need the usual `/run/sshd` privilege-separation
directory. `/proc` must describe the executing PID namespace. Omitting
`--openssh` uses the instrumented SSH subprocess protocol fixture, and omitting
`--before` runs only the regressions. The Linux
`daemon_lifecycle::offline_worker_process_recovery` integration test invokes that
default fixture automatically. No worker credentials, external worker hosts,
live VPN, or queued compilation workload are needed.


## Matched baseline vs final recovery/scheduling comparison

After the final snapshot was published, one additional matched local comparison
was run specifically to quantify recovery latency and scheduling behavior on the
pristine baseline versus the exact final implementation.

Both daemons used the same deterministic local worker fixture and the same
35-second refused-endpoint outage phase. The normal health interval was 30
seconds. The final implementation used a 3-second recovery interval. During the
outage, 24 scheduling requests were issued against a mixed healthy/offline fleet,
and after the endpoint became reachable a pinned reservation was polled every
250 ms until the recovered worker was accepted.

The first attempted comparison, which required the baseline to reach an
`Unreachable` state within 70 seconds, was discarded because the baseline
remained `Degraded`; no timing numbers from that attempt are used below. The
completed comparison instead records the actual state and polls admission
unconditionally.

| Observation | Pristine baseline | Final implementation |
| --- | ---: | ---: |
| Healthy-worker selections during outage | 24 / 24 | 24 / 24 |
| Offline-worker selections during outage | 0 | 0 |
| Selection p95 over the 24-request local sample | 24.97 ms | 15.55 ms |
| First authenticated successful health command after endpoint recovery | 25.083 s | 1.079 s |
| First successful pinned reservation on recovered worker | 25.498 s | 1.596 s |
| Unsuccessful 250 ms pinned-admission polls before success | 100 | 6 |
| Recovery observation censored | no | no |
| Final worker state | Healthy / Closed / 64 slots | Healthy / Closed / 64 slots |

This is a single local deterministic-worker comparison, not a live VPN or remote
compilation benchmark. The 250 ms admission polling cadence limits timing
resolution. The result isolates the practical effect of coordinated recovery:
healthy scheduling remains available during the outage in both versions, while
the final implementation detects endpoint recovery and restores admission much
sooner under the configured recovery policy.

## Current-main follow-up: remaining background recovery paths

This follow-up starts from main at
`4a3fac5fe34db3685bd2ebd4467a5b80dad9e609`, after the earlier implementation and
measurements above. The process measurements used the working candidate based
on `406e982564f58e33c148607ab40bda9cb2fa6bff`. Main was subsequently incorporated
through `c78bd9398918d55c3134831728fa0059d20cde26`. Neither the first two
Git-submodule commits nor the subsequent six RABS/clean-overlay/source-content
commits changed common SSH or daemon production sources; the incorporated CLI
changes require their own validation. The original `a1fe627c` comparison and its
raw JSON remain unchanged. See the
[follow-up raw results](offline_worker_issue_128_followup.json) for the separate
baseline provenance, regression observations, and validation outcomes.

The current-main baseline daemon's SHA-256 is
`8eedeaa98e8e56265e54ced2b4bf5e00be4ab985bc935085086c2331de8e4986`.
Its instrumented SSH subprocess fixture already demonstrated the intended idle
behavior:

| Current-main baseline observation | Result |
| --- | ---: |
| SSH dials during 65.00 seconds with an unavailable worker | 2 |
| Spacing between the initial attempts | 30.006 s |
| Recovery delay reported at the end of that window | 865 s |
| SSH dials during 32.03 seconds after disable acknowledgement | 0 |
| SSH dials during the 2.03-second disabled restart observation | 0 |

The authenticated-session freeze extension also passed on this baseline, using
both the instrumented subprocess fixture and real local OpenSSH. Each run froze
two already authenticated pooled transports, observed one recovery dial in
approximately 6.2 seconds with a peak of one, admitted all 12 concurrent requests
on the healthy peer, and restored the affected worker approximately 0.91 seconds
after unfreezing it. Disablement and disabled restart produced no new dials. The
same active build retained its three-slot reservation through outage, recovery,
disablement, and restart until its explicit release. Toolchain preflight warms
the second pool before freezing; this exercises a stalled authenticated channel,
separately from refusal or a handshake blackhole. These observations are existing
baseline behavior, not improvements attributed to this follow-up.

### Failures reproduced against the current-main baseline

Four focused regressions exposed remaining gaps:

- `offline_worker_benchmark_stops_proxy_on_disable_timeout_and_exit`: revoking
  benchmark network permission left a proxy descendant alive. Killing only the
  immediate SSH child did not establish network silence.
- `removal_while_waiting_for_durable_intent_never_probes_a_retired_endpoint`:
  orphan reconciliation could dial an endpoint removed while the task waited
  for the administrative store, even though its eventual result was rejected.
- `offline_worker_enable_racing_replacement_changes_current_incarnation`:
  enable could acknowledge a transition on an obsolete worker object while the
  replacement remained disabled. The separate disable/replacement regression
  already passed on the baseline.
- `offline_worker_many_owned_cancellations_wait_for_one_health_recovery`:
  automatic cancellation launched an SSH subprocess despite matching
  current-endpoint transport-down evidence. The deterministic transport fixture
  logged a dial and returned a confirmed cancellation receipt; the baseline
  reported `cancelled` and released one slot where the regression requires `deferred`.
  This assertion executes before advancing the virtual outage clock; the
  recorded dial and receipt distinguish the failure from a timer-only artifact.

These cases do not reproduce all traffic or log rates reported for RCH 1.x. They
identify concrete paths that remained outside the coordinated recovery policy
on current main. Per-build cancellation backoff alone is insufficient: many
retained builds can take turns contacting the same unavailable worker.

### Additional existing CLI configuration defect

The first executable CLI regression run passed 206 tests and failed the existing
`config::tests::offline_worker_circuit_settings_load_from_each_source_layer`
test. A user configuration containing `circuit.down_after_failures` failed with
`duplicate field failure_threshold`: the CLI merged that alias into defaults
that already contained the canonical field, without first normalizing the alias.
This prevented an advertised way to configure the consecutive-failure threshold.

The entire CLI configuration source, including the failing test, was
byte-identical at `4a3fac5f` and incorporated main `c78bd939` before this fix. This
is an existing product defect demonstrated by the CLI execution and source
identity; no separate baseline executable run of this test is claimed. The
daemon's direct single-file deserialization already accepted an alias-only
configuration and did not have this layered-merge failure.

The fix canonicalizes the circuit alias separately in each raw file before
merging defaults, user settings, and project settings. A file containing both
names still produces an error with its path. Added regressions cover both
directions of cross-file precedence, resetting a value to its default, source
attribution, partial loading, cache serialization, and duplicate names within
either layer. The initial failure log and exact source hashes are retained in
the follow-up raw results. The final selected CLI suite passed **209 tests with
no failures**, including the previously failing test and both added regressions.

### Recovery and ownership policy

The path audit covered health checks, both connection pools, telemetry,
capability/toolchain probes, self-tests, benchmarking, cache/storage and canary
recovery, orphan reconciliation, automatic cancellation, and dead-client lease
recovery. Pool reuse and background service admission must respect the same
administrative and transport state; a scheduling circuit alone is insufficient.
The existing configurable consecutive-failure threshold and slow health recovery
cadence remain the ordinary route back to service.

Automatic cancellation and lease recovery now defer when their immutable
admitted endpoint matches the current worker's ID, host, user, identity file,
and declared OS and that endpoint is transport-down. A successful health probe
allows recovery to resume. This includes restored journal snapshots without a
process-local worker identity. Different historical endpoints and endpoints
absent from current inventory retain their original recovery authority; today's
unrelated replacement cannot redirect or suppress them. Storage quarantine,
circuit state, and startup readiness alone do not prohibit cleanup of already
owned work.

Administrative disable follows the worker ID across inventory replacement and
restart. Its revocable permit also covers automatic cleanup of historical or
absent endpoints. A failed persistence operation still stops live network work
and survives replacement within that daemon, while reporting failure rather
than claiming restart durability. Enabling a volatile-only disable also requires
a durable clear: the earlier failed save may have renamed the file before its
directory sync failed. Explicit user cancellation and local-only
abandoned-reservation finalization retain their existing behavior. Deferral
preserves active-build history, slots, journals, and source ownership; it does
not manufacture completion receipts or add worker failure debt.

Benchmark completion retains the original worker and a distinct attempt
identity, preventing stale or duplicate replies from releasing another
reservation or publishing into a replacement. Orphan probes validate the
current endpoint before dialing as well as before clearing quarantine. Owned
local process groups cover SSH proxy descendants, with foreground/nonmultiplexed
options and a capability check for older SSH clients. Daemon-managed lease
recovery uses the same policy for direct and rsync transports; parent-pipe EOF
stops its local process group without clearing durable remote ownership.

### Measured follow-up behavior

Both complete process-fixture invocations passed using daemon SHA-256
`7a45c2811ffa8bdeda8297a31c1ce381ddba92b5d1fb18c35de0145e078f9baf`.
The OpenSSH invocation measured baseline and candidate together: each made two
dials in its approximately 65-second idle window and zero dials after disablement
or disabled restart. This preserves behavior already working on current main.
The following table reports the candidate regression phases from the unmodified
result objects embedded in the follow-up JSON.

| Candidate observation | SSH subprocess fixture | Real local OpenSSH |
| --- | ---: | ---: |
| Prolonged-outage dials / observation | 2 / 9.22 s | 3 / 9.20 s |
| Minimum prolonged-outage dial spacing | 3.160 s | 3.066 s |
| Healthy-peer admissions in mixed fleet | 24 / 24 | 24 / 24 |
| Extra offline dials from 12 concurrent capability requests | 0 | 0 |
| Recovery latency with the 3-second recovery interval | 3.315 s | 3.106 s |
| New dials while disabled / after disabled restart | 0 / 0 | 0 / 0 |
| Authenticated pooled transports frozen | 2 | 2 |
| Dials during approximately 6.2 seconds of authenticated freeze | 1 | 1 |
| Recovery latency after unfreezing | 0.912 s | 0.924 s |
| Original reservation retained until explicit release | 3 slots | 3 slots |
| Peak blackhole transports in the 14-worker outage fleet | 12 | 12 |
| Healthy admissions while those recovery lanes were occupied | 24 / 24 | 24 / 24 |

Both modes also passed handshake-blackhole cancellation, established-connection
loss, unpooled operation, explicit enable, and healthy-peer health monitoring
under a saturated recovery fleet. CPU/RSS observations are retained in full,
including higher candidate CPU time during the matched disabled phase; no
general resource-performance improvement is claimed. These local protocols do
not measure Tailscale traffic or reproduce the original RCH 1.x log rates.

The measured daemon predates the final volatile-only-enable persistence
correction described above. That correction is covered by the subsequent full
common-suite rerun, separately from these executable-specific process results.

### Follow-up verification

The complete daemon unit suite passed **1,923 tests, with no failures**. The
common suite passed **2,497 tests, with 8 ignored and no failures**, including a
complete rerun after the final administrative-persistence correction. The
30 focused daemon offline/admin regressions also passed after that correction.
The formatting check passed on the incorporated main revision. All CLI targets
type-check, and strict Clippy passes for every common, daemon, and CLI target
with warnings denied. The final daemon lifecycle integration suite passed
**17 tests** in 121.75 seconds, including `offline_worker_process_recovery` and
maintenance/ownership cases. The job lifecycle suite passed **8 tests** in 6.20
seconds, covering attachment, cancellation receipts, completion races, and
recovery-journal preservation. These suites used the final rebuilt CLI after
the alias correction and the daemon with the common-store durability fix.

The regression coverage includes the 16-build,
900-second virtual outage; 21 lease journals over twelve five-minute scans;
persisted disablement and failed-save replacement; cancellation across
disable/enable ABA; proxy cleanup; endpoint replacement; and healthy-peer
scheduling. Virtual-clock tests keep real subprocess confirmation on a fresh
runtime so an advanced Tokio clock cannot expire a deadline derived from
`std::time::Instant` before the SSH operation starts.

Workspace-wide check and Clippy remain blocked: the compiler for the pinned Git
`asupersync 0.5.0` dependency was terminated by `SIGKILL` before those gates
completed. The initial CLI build also lost its registry `asupersync` compiler to
`SIGKILL`; its allocator-tuned retry was stopped with `SIGTERM` after measured
memory thrashing. The executable-build retry then completed in **7m 03s** with
the package-specific `hint-mostly-unused` code-generation setting for
`asupersync` in the dev and test profiles. This changed no dependency source or
enabled features. The executable rebuilt successfully in **48.63s** after the
CLI alias fix. The selected CLI regression rerun passed all **209 tests**; the
final CLI all-target strict Clippy completed in **1m 33s** without errors.
The earlier daemon lifecycle attempt was incomplete after a nested CLI
dependency build was killed and the harness was subsequently terminated with
`SIGTERM`; the successful final lifecycle runs supersede that incomplete
attempt. The workspace-wide dependency failures remain distinct from these
completed focused gates.

The final integration executables have SHA-256 values
`e2487b83d5aeefcc0dc506c048d96b8be3b3ad31b9c0e569673fb6285e13a340`
for `rch` and
`d92ac5721f892808108c1fb059bcce630131d781b0d5ca113a2ec866963cbe22`
for `rchd`. They are recorded separately from the earlier process-measurement
daemon hash; the original raw measurements are unchanged.

The [follow-up raw results](offline_worker_issue_128_followup.json) retain the
exact completed suite summaries, initial failed attempts and fixture correction,
blocked workspace gates, raw process measurements, and executable identity.
The earlier snapshot's validation limits above remain attributed to that earlier
snapshot.
