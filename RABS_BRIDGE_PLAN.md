# RABS Bridge Plan — From Proven Library to Living System

## Reality check and execution order — updated November 1, 2026

**Initial source assessed:** `7ae3f5fe0cf4a4ca533c235e9e1d89dbfd413ff3`.
**CI/release policy, explicitly confirmed by the user November 1:** DSR only.
Never enable or dispatch GitHub Actions. Historical workflow receipts below
remain unqualified history; the earlier optional enablement question is closed.
**Current status, November 1 at 14:25 UTC:** controlled native RABS is working
for real Cargo archive execution/delivery and five shared-service consumers.
Production source 6a79d453 passes six of seven original canonical cases and
all five overhead/support tests; the overlap case fails final SDK cleanup
under its helper's 250ms escalation policy. A paired real-Cargo diagnostic
confirms that policy interrupts SDK removal, while the unchanged service
exits zero and removes the full SDK in 1.27s under the existing 15s budget.
Test-only correction 404f98a5 wires existing graceful teardown, keeps fast
client cancellation and image checks, and adds passing real-process controls.
Its mandatory workspace check/strict Clippy/fmt pass; dev full-SDK overlap
fails earlier during capture at 121s, so optimized consumer verification
remains pending. DSR/native QA passes 304 checks, cache 94/94 including both
real Rust consumers, relocated roots 16/16, actual diagnostic build and syntax.
Its default full suite stays UNRUN behind the unchanged root-volume guard.
The optimized overlap + 32-case canonical + five-test overhead DSR build is
now active with the verified corrected builder. Four verified runtime-file
repairs are applied to the shared checkout; merged-source checks are queued.
Shared Beads now contains the complete execution history and M6 is in_progress.
M6 remains open;
fleet/QUIC, full package, dependency budgets and broader failures below remain
unqualified. Earlier source-specific observations below are historical
receipts, not statements of the current cut's outcome.
**Completed merged baseline (terminal 101, owner ACK true):**
`e7a94e7c622c11bfa6bcd85c39b6a18c6e8cf40c`.
**Compiled runtime source (17-command verification terminal 101; DSR terminal 6):**
b5b43b3e735b43dfbed3559c46e89cc3f6e16a41
fixes the newly exposed owned-cancellation
settlement, submodule-test constant-borrow warning and worker bootstrap's
inherited-ignored-SIGINT cancellation; the e7 run stays frozen. The last repair
passes its standalone real-process Python suites and rebuilt Rust embedding.
The complete daemon and TLS targets pass; broader native consumers finish with
the explicit retained failures below. The optimized original archive case fails
0/1 in 330.02s: the first canonical Cargo command exceeds its unchanged 300s
bound before a worker execution completes. This path is not working yet.
The portable no-Python verifier fixture also binds the same concrete /bin/sh
as its existing launcher, avoiding an ambient Bash-dependent PATH shim. Its
original thirteen mutation checks and production verifier remain unchanged;
rebuilt native acceptance passes 1/1 with every original mutation assertion.
Three additional positive RCH daemon journal fixtures explicitly create
private canonical files; their production refusal guard is unchanged and their
rebuilt native acceptance passes within all seven API scan cases.
**Private manifest-only follow-up, native validation complete (budget remains red):**
`8e7815b060d2f669ff4154fc127628ef8aa9574a` moves CAS's fixture-only filetime
dependency to dev-dependencies. Existing production timestamps already use
held-file standard-library setters, and all filetime references are cfg(test).
The original budget and every test stay unchanged. Actual Cargo metadata
reports seven normal runtime edges and filetime only as a dev dependency.
Normal production checking, all 408 CAS tests (zero ignored), workspace/all-target
checking, strict Clippy and formatting pass. Original budget probe remains
three passed / one failed for four other crates; overall 101 is preserved.
Final source audit matches all transferred files with the exact prior exclusions,
and supported recovery confirms terminal ACK true. Four genuine result files
are hash-verified under rabs-filetime-8e7815b0-20261101/custody.json. Targeted
UBS also passes (zero critical / zero warnings / twelve info); its skipped Cargo
phases are distinct from the completed native commands above. The b5
source clone, tag, compilation inputs and claimed evidence are unchanged.
**Frozen source with completed full verification (retained red gates):**
`1d081ac45e14048347aea812e97ae59d07e76d00`.
**Previous native cohort (owned cancellation; completed results retained):**
`478a886660d3f92146909e30f159c46e8ba6fe2a`.
**Prior broad native invocation (terminated, results retained):**
`177acee016ee49cb208328e98a05dd020a1f8652`.
**Current runner correction:** `2bad030630d7967c4bc931201222d393fa5bfd40`;
at that correction only the two Python orchestration files differ from source 177.
725bbfd2 corrects the Rustix conversion error found by the actual workspace
check: `Pid::as_raw` is associated, while the pinned 1.1.5 method is
`as_raw_pid`. Its scoped wrapper/all-target check passes in 41.76s;
the full workspace/all-target check exits 0 in 5,773.280s (Cargo reports
96m02s), strict Clippy exits 0 in 2,899.601s and formatting exits 0 in
47.663s. The outer job exits 0 and supported recovery confirms terminal
acknowledgment before source reuse.
177acee0 reserves the existing 8,193-byte proc-stat read buffer up front. It
preserves every liveness check and the original 8,192-byte acceptance limit;
a new boundary case accepts exactly that limit and refuses one extra byte or
the wrong PID. Formatting passes. UBS retains one original shell-fixture
finding, 63 warnings and 52 info, without suppression. There is no measured
latency improvement yet. Source-8d wrapper-release overhead fails below;
its confirmed dev-graph wrapper does not establish shipping qualification.
The full native invocation is admitted at 177acee0: its wrapper/all-target
preflight exits 0 in 98.834s and protocol library passes 499/499, 5.01s libtest
(68.249s command). Adapter units subsequently finish 125/128 in 43.26s
(2,172.514s including compilation), and wrapper units finish 110/112 in 2.90s
(57.283s command). Actual NODELAY/TTL and exact proc-stat byte/PID bounds pass.
The adapter retains two process-group cleanup deadline failures and the J011
injected-clock failure. Both wrapper failures panic inside Rustix's getpgid
conversion because a valid Linux group-zero result cannot become its nonzero
Pid type. A read-only host inventory observes 1,794 group-zero processes among
2,221, not an invented input. This invalidates the typed-query optimization;
there is no speedup claim. The broad job continues to the remaining consumers.
ffd60644 uses bounded PID-checked procfs membership instead and makes timer
wakeups subordinate to the injected transport clock's actual deadline. Its new
early-wake negative preserves exact deadline authority; the original J011 test
and all original timing bounds remain. Local formatting passes. Scoped UBS
retains the original constant `sh -c 'exit 0'` fixture finding, 184 warnings and
68 info, without suppression; that exit 1 is not a scanner pass.
6149261d additionally keeps an immediately elapsed replacement timer wakeable;
its formatting and scoped scanner pass (zero critical, 120 warnings, 21 info).
Its manifest edit only corrects a stale comment, with no dependency change.
The native daemon library finishes 1,326/1,328 in 244.16s. Its two original
planning-process cleanup tests fail at the unchanged 500ms closure proof.
The actual continuation target passes 10/10, 2.80s, and TLS execution target
passes 26/26, 34.30s. Remaining native targets are still running.
TLS interruption then passes 5/5, 8.58s; TLS resume passes 3/3, 8.90s. The
sandbox library passes 458/458 executed, zero ignored, in 100.48s, with only
the declared separate privileged mount case filtered. Worker units finish
337/340 in 898.79s: the same three original real-Cargo persistence/selection
reuse cases fail. Their assertions and metadata-seed refusal policy remain.
The metadata protocol target starts thirteen cases, records six passes and six
failures, then stalls in the remaining case's unbounded fixture accept. Native
thread inspection finds two server threads waiting for a connection, while
the test's existing ten-second stream timeouts do not bound listener.accept.
Only this exact owned invocation is cancelled after its PID/start/cwd/source
match; E504 cancellation is followed by supported recovery, terminal 255 and
ACK true. No final 13-case summary exists. Later declared targets are UNRUN.
An independent post-component audit verifies all 1,199 Rust/TOML/lock files
against the frozen 177 clone, digest
21aba8fe0593a4ee7ed433d3cd82aea5ce283ef9f2c128adcaafd03d814008c8.
This is a post-run audit, not a prelaunch attestation. After terminal ACK the
same Cargo-selected sandbox harness also passes the separate privileged case:
1/1 in 0.13s, command 0.487s, in a new private mount namespace. Its before/after
SHA-256 is 78a5e4434646274537851e9ecd84214960554ff0e71b4113173286f629616a75;
the real bind mount is refused and the parent namespace remains unchanged.
This is 177 component proof, not qualification of the current candidate.
77de3a25 changes their shared process observer to reuse one initially
8,193-byte String across the complete scan and parse its first three fields
without collecting every unrelated field. The reader still consumes every
byte and grows if needed; no PID, field, state, deadline or cleanup assertion
is excluded. Formatting passes; UBS retains two original configured-executable
and process-tree-fixture findings, 177 warnings and 46 info, exit 1 without
suppression. This shared-observer maintenance has no native acceptance yet.
The wrapper's separate procfs membership filter loses in the actual 77 native
invocation: the complete observer takes 0.291299s versus 1.220341s for the
filtered observer, then completion exceeds the unchanged two-second deadline.
Wrapper result is 111/112; the live-member negative passes. Withdraw that
filter at 478a8866, retaining the original full bounded observer, both terminal
sweeps, complete identities, group-zero coverage and all existing bounds.
No replacement dependency is added. Formatting and locked offline metadata
pass; scoped UBS exits 1 with one original constant-shell fixture finding,
62 warnings and 53 info, without suppression. This is not a scanner pass.
3e491a34, included in 478, separately bounds metadata fixture acceptance by its
original ten-second IO budget and restores blocking accepted streams. Every
original protocol assertion remains. Formatting and scoped UBS exit 0 (zero
critical, 164 warnings, 24 info); native protocol verification remains pending.
The old optimized invocation admits at 21:22:59 UTC as build
30088853255618982. After the actual wrapper group-zero panic above, cancel
only this obsolete owner. Cancellation RPC reports E504; supported recovery
then acknowledges terminal 255. The CLI exits 1. Read-only process inventory
finds no remaining writer for its target before any reuse is considered.
Its tool build is interrupted; archive, full-suite and overhead bodies remain
UNRUN. This is not a runtime product failure or a shipping qualification.
These runs use clean frozen clones with strict RCH
and 20-GiB preflight. The optimized run declares the original focused archive
case first, all 30 canonical cases only if that probe passes, then the unchanged
shipping overhead gate; an unrun conditional suite is never counted green.
After the 725 job's acknowledged exit 0, its clean static clone fast-forwards
to 177acee0. Full workspace/all-target check, strict Clippy and formatting at
177 are submitted separately with fresh 20-GiB scratch/tmp preflights. After
the actual native failures above, that obsolete static job is cancelled before
admission: exit 130, zero released slots, null admission and supported recovery
terminal acknowledgment. No 725 pass is inherited by either source change.
Only after acknowledgment does the clean quality clone fast-forward to
ffd60644. Its replacement job declares both unchanged disk preflights, the
complete wrapper unit target, full workspace/all-target check, strict Clippy
and formatting. Two invalid CLI combinations fail before submission (2 and 1);
the plain strict RCH job queues. No compiler or test runs in those CLI errors.
After final wakeup review, cancel this still-unadmitted predecessor too:
130, zero slots released, null admission, recovery ACK true. The next 614
quality job admits as 30088853255618988 but source namespace initialization
refuses an unfinished overlapping owner before compilation. CLI 103 and
terminal daemon exit 1 are retained; supported recovery acknowledges 1.
Its result directory and test bodies never exist. The 614 optimized selection
under rchw-29df727f-4c70-4140-a4a9-51685aa27eea disconnects before a reply;
recovery and exact-identity cancellation retain uncertainty. Do not replay,
manually clear its journal/claims or count a product failure. Preserve that
clone and declared target rather than assigning it to another job.
A fresh independent 77 checkout on the data volume uses command-scoped private
canonical/alias roots through RCH's supported configuration. Its source
is distinct from every active claim; no ownership fence or global config is
modified. A preceding default-root invocation refuses before admission (103)
because that checkout is outside /Users/jemanuel/projects. Its actual storage
guard passes with 824,131,923,968 bytes free, 13.733%. The controller APFS probe
instead fails with 197,134,176,256 bytes free but only 4.933% against 8.061%;
no APFS checkout or build is created. The first data-volume clone attempt
refuses ownership before checkout; retry grants only command-scoped trust to
the known integration repository and its Git directory, with no global edits.
The new job declares 16 commands: unchanged scratch/tmp disk guards, complete
wrapper and adapter units, full workspace/all-target check, strict Clippy,
formatting, complete daemon library, four TLS/continuation targets, real-Cargo
worktrees, feature/direction/budget gates, sandbox library, worker library and
Linux process-tree integration. The original privileged mount case remains
separate. Before Cargo, verify all 1,199 Rust/TOML/lock files against the clean
Git inventory digest f95c905479b6997b681ce978c2d7549661d1593c4fbb17230dbb305657ce02fe,
plus the runner hash. The compact independent inventory avoids placing a full
path list in the selection request. New job submission is not a test pass.
That first isolated job admits as 30088853255618994 but stops in the installed
RCH scoped launcher before the Python body creates a result directory. Initial
SSH outcome is 255; supported recovery acknowledges 102 for missing required
results. A short invocation of a separately retained, hash-checked 5,018-byte
script repeats the same pre-body failure as 30088853255618995 and recovers
102 ACK true. This falsifies command size as the established cause; neither
invocation compiles Rust or adds a test denominator. Its script remains at
`job-current-77de3a25/run.py`, SHA-256
95817f76d3f9deb3f9349476f288b1d9138df2d7517de5f5edd3d934ff99c0a0,
mode 0400 under a new private XFS root, with custody metadata. The later job's
overall build bucket is the original broad-run 10,800s, not a changed RABS
deadline; all product thresholds remain unchanged.
The installed client reports source ff152a046086 (October 15). Its exact source
requires a complete unrelated-thread census before opening the payload gate;
current source already repairs this in 7918a20e/d4fec37a. A same-invocation
read-only control on the busy worker observes the original full `ps -e -L`
timeout at its unchanged 1s bound, 81,920 partial bytes. The leader census
finishes in 0.508845s, 69,316 bytes, 2,236 rows. Load is 66.80 with 5,113 tasks.
This provides a concrete explanation consistent with the pre-body failures;
confirmation through the repaired client remains pending. It is not a RABS
test failure or full performance qualification. Three original native shell
protocol regressions at source 77 pass in 36.266s (36.958s command): live-child
admission without an unrelated census, a required complete observation after
an interrupted post-kill census, and retained uncertainty after admitted census
loss. They use explicit census fault injection with real process identities and
kernel cleanup, without compiling Rust. They do not qualify the installed client
or the pending RABS repairs. Retain all old/new cleanup requirements.
No existing Mac RCH build artifact is present, GitHub lists zero workflow
artifacts, and the repository's Actions permission reports enabled=false.
The queued RABS workflow has no jobs. The existing CSS dispatcher provides a
current client without changing this repository-wide setting; the earlier
optional CI question is closed by the user's explicit DSR-only instruction.
Actions remains disabled; CI and release builds must use DSR.
CSS runs client ca7f1744, containing the unrelated-census admission repair,
and has one configured trj slot. Both new native runs use that slot and one
Cargo job without changing global settings. CSS only holds the immutable
58.6MB source archive: compilation runs on guarded trj XFS, not CSS's low-space
root. The first 77 run correctly refuses before Cargo: only 1,191/1,199 source
files arrive. CSS's global target_*/ pattern drops six target_cache Rust files,
and its .claude exclusion drops two tracked public template TOMLs. A private
capsule config root-anchors /target_*/ and retains reviewed public Git .claude
files; all other exclusions remain. No user/global config changes. The source
digest/count gates remain unchanged. The complete-input 77 run verifies all
1,199 files before Cargo, compiles, and produces the 111/112 wrapper loss above.
Only that obsolete known-red owner is cancelled; supported recovery returns
255 ACK true. Adapter compilation is interrupted; later targets are UNRUN.
The 478 replacement starts at 22:59:52 UTC with all 1,199 files verified before
Cargo, digest 4e6e4f44cfe5190ed443c146550c68ed74402040c82930ddc0f3bee4377902b7.
Its retained script has SHA-256
88fc32d17a0d051a8cd41e7307e0165a45f2b14c8ff7f5e916a4aebf081d0cba.
All three original 20-GiB guards pass. Nineteen declared serial commands cover
protocol, wrapper, metadata protocol, adapter, daemon, TLS/continuation,
real-Cargo worktrees, feature/direction/budget gates, sandbox, worker,
process-tree integration, full workspace/all-target check, strict Clippy and
formatting. Runtime uses the acknowledged native warm target; static checks
use the acknowledged quality target. Neither cache is qualification evidence.
The corrected production-overhead runner's exact bytes are verified too.
Protocol library completes 499/499, zero ignored, in 10.05s (155.296s command).
Wrapper units then pass 112/112, zero ignored, in 8.89s (194.025s command),
including complete native group completion, group-zero, exact byte/PID bounds
and the successful-signal/live-member negative. Metadata protocol completes
10/13, zero ignored, in 32.47s (79.741s command): blocked stderr receives a
deadline diagnostic rather than the required prefix; reported-exposure and
uncertain-tail fixture loops each include a wrapper that never connects. The
new ten-second accept fence makes these failures terminal instead of hanging.
Every original protocol assertion and deadline remains. A bounded syscall
diagnostic against the same wrapper bytes confirms expiry before prefix
delivery; it is not a timing qualification or a suppressed failure. Adapter
units finish 125/129 in 59.46s (199.177s command). Original J011, native
deadline wakeups and NODELAY/TTL pass; both original process-group timing
failures remain, shutdown misses its unchanged 100ms bound at 141ms, and the
new early-wake regression catches a completed Sleep being polled twice.
d6273c0e retires each completed timer before scheduling a fresh clock check;
the exact injected deadline still alone decides expiry. Its negative test
keeps every original assertion, checks a wake was scheduled and repeats early
polls to catch completed-future reuse. Native verification remains pending.
The blocked-prefix trace retains the same wrapper SHA-256
5eb81a6ff4fa242b10a9a07fbbea7eff415d0cbc19db905e3ba07c1d9cd5e707:
consent is sent at 1793488216.055010; the fixture only begins its 2,097,295-byte
send at 1793488216.412302. It spends about 357ms of the original 500ms budget
formatting before sending. No prefix reaches stderr before expiry. The new
fixture prepares those exact wire bytes before wrapper startup, preserving
the 500ms deadline, partial-prefix/closed-pipe assertions, no ACK and no second
compiler. It now excludes fixture-generation time and still gates the real
wire/parser/stderr exchange; it does not qualify producer end-to-end latency.
Before/after lane outcomes must be retained, including all remaining failures.
The same actual native wrapper, given precomputed wire bytes by explicit Unix
socket/compiler-marker fixtures, passes both cached and published-remote
diagnostics: exits 1 in 0.541275s/0.540294s, leaves exactly 65,536 partial x
bytes, sends zero ACK bytes and never runs the compiler. These are two scoped
diagnostic lanes, not the complete Rust target or real Cargo proof. They retain
both outputs/events under `metadata-diagnostic-478a8866/prepared-*` on worker XFS.
Two failed fixture joins additionally retain actual subprocess status, marker
and stderr diagnostics. Formatting and scoped UBS exit 0 (zero critical,
286 warnings, 40 info), with no suppression. No native pass is inherited.
The broad 478 daemon library passes all 1,328 cases, zero ignored, in 163.38s
(542.528s command), including both original planning-process cleanup negatives.
This current component pass does not establish a same-invocation performance
win or repair causality for the separate adapter timing failures. All four
TLS/continuation targets then pass: 10/10 in 2.40s, execution 26/26 in 36.50s,
interruption 5/5 in 5.05s and resume 3/3 in 4.92s; combined command exits 0
in 318.853s including compilation. Real-Cargo worktree preparation and remaining
consumers continue against frozen bytes. The complete source/input
snapshot for d627 is verified independently; its nine-command follow-up is
prepared but never launched. Before submission, the two still-failing native
cleanup cases expose another concrete policy defect: reap_residuals escalates
after ten complete scans, treating scan time as zero, rather than after its
original 100ms half-grace. 1d081ac4 measures elapsed time for escalation while
retaining the original 21 complete polls plus final census and ten-millisecond
poll sleeps. A signal still cannot authorize settlement; only an empty complete
census returns zero. The new real-process regression delays each actual full
census by 120ms, requires native KILL, a later independent empty observation,
reaping and the original two-second bound. Its native acceptance is pending.
Formatting passes. UBS retains the two original configured-executable and
deliberate shell-tree-fixture findings, 184 warnings and 46 info, exit 1 without
suppression; it is not a scanner pass. The new complete 19-command cohort is
prepared at 1d081ac4, not submitted yet. Finish the current real-Cargo consumer,
then retire only its obsolete owned invocation through supported cancellation
and terminal acknowledgment before cache reuse. Preserve its remaining phases
as UNRUN; the successor declares their full original breadth, including the
worker reuse and dependency-budget gates. No test threshold or sample is lowered.
The 478 real-Cargo consumer completes before cancellation: worktrees 11/11
(seven real Cargo, four support), 352.88s; live protocol 8/8, 0.91s; wrapper
units repeat 112/112, 6.24s. Its runner exits 0 in 658.353s and confirms all
prepared hashes unchanged. Feature and direction targets pass 5/5 each;
budget remains 3/4 with the original five excesses. Three tiny timing pairs
include two losses and one win, informational only. Exact selected dev wrapper,
daemon and worktree harness are retained by verified XFS CoW in
`preserved-worktrees-478a8866/custody.json` before target reuse. The wrapper hash
is 5eb81a6ff4fa242b10a9a07fbbea7eff415d0cbc19db905e3ba07c1d9cd5e707;
daemon c1f3b93b8d28d5e3497b92933fce5bbc32eddf0483b3dff531b92b13376b09c0.
Cancellation of that exact owner succeeds. The CLI exits 255; supported
recovery reports 143 ACK true and retains the daemon's earlier 130 separately.
Sandbox compilation races cancellation and begins partial native execution,
then is interrupted without a final denominator. Worker, process-tree and
three static commands are UNRUN. No Cargo/rustc writer remains before reuse.
The complete 1d invocation admits at 23:38:24 UTC as build 30080135327647930 /
`rchw-256bca46-5774-44c4-8a42-889d4cb45cd9`. All 1,199 Rust/TOML/lock files
match c0b89885bce8bf97d5e6bbf9d3943da4b7036490d0b2f36123e7a932dbbc6728
before Cargo; all three unchanged 20-GiB guards pass. Script SHA-256 is
3a771fee1c817a741b537df876e2d2f1dda5e25ac99f08259a74eefddbfbea59.
Actual compiled results: protocol 499/499, 2.58s (9.462s command); wrapper
112/112, 4.90s (10.675s); metadata protocol 13/13, 6.51s (8.830s); adapter
130/130, 8.88s (14.594s), all zero ignored. Both old cleanup timing cases,
the slow-complete-census regression, completed-Sleep regression, original
J011/native wakeups and shutdown bounds pass. The original blocked-prefix
case now reaches the intended pipe behavior in both lanes; the two earlier
no-connect failures do not reproduce, but their cause is not established by
these source changes. This is native component qualification, not a formal
same-invocation performance win. Daemon then passes 1,328/1,328, zero ignored,
in 336.38s (478.253s command). All four TLS/continuation targets pass again:
10/10 in 2.03s, execution 26/26 in 8.21s, interruption 5/5 in 1.55s and resume
3/3 in 1.57s, combined command 404.603s. The corrected real-Cargo runner passes
worktrees 11/11 (seven actual Cargo, four support), 345.32s, live protocol 8/8,
3.84s, and repeats wrapper 112/112; full runner exits 0 in 402.043s. Prepared
dev wrapper, daemon and harness hashes remain unchanged and verified copies are
retained under preserved-worktrees-1d081ac4. Tiny same-invocation timing pairs
include losses; no performance acceptance follows. Feature and direction pass
5/5 each. Budget remains 3/4 with all five original excesses unchanged. Sandbox
passes 458/458 executed, zero ignored, one separate privileged case filtered,
47.50s (135.058s command). Worker units retain exactly the three original real
Cargo reuse failures: 337/340, 207.67s (442.882s command). The fourteen-case
Linux process-tree target finishes 6/14, zero ignored, with no observed SKIP
markers, in 322.09s (360.386s command). All eight failures report private-parent
fixture failures in host-budget creation and runtime retention, before their
original compiler/output assertions. Production refusals remain correct. A follow-up
requests explicit 0700 modes for its real temporary directories; no assertion,
toolchain input or refusal is changed. Formatting passes; compilation and runtime
acceptance of that follow-up are pending. Its scoped UBS exits 1 with the two
retained configured-executable/deliberate shell-tree findings, 566 warnings and
204 info, without suppression. The slow-census fixture is also strengthened to
250ms per complete observation; its original two-second limit remains unchanged
and native execution is pending. Full static, shipping profiles, original archive
and fleet acceptance remain pending. All nineteen declared commands then finish:
full workspace/all-target check exits 0 in 1,064.900s; strict workspace/all-target
Clippy with warnings denied exits 0 in 264.688s; formatting exits 0 in 7.295s.
The first failing gate keeps the full invocation red, exit 101. The CLI also
exits 101; supported recovery confirms completed 101 and terminal acknowledgment
before any successor source/target use. No cancellation is used. Transcript:
`/Volumes/trj-data/rabs-execute-20261031-final-1d081ac4.log`.
The separately preserved current sandbox harness also executes the privileged
mount case 1/1, zero ignored, 0.02s (0.071s command), after a fresh physical-XFS
20-GiB guard passes. It rejects a real bind-mounted source member inside its
own private mount namespace. SHA-256 stays
78a5e4434646274537851e9ecd84214960554ff0e71b4113173286f629616a75 before
and after; the parent mount namespace is unchanged. This independent retained
executable does not touch the active compilation target, so no cache reuse or
cancellation is needed to run it during the static check. Receipt:
`/scratch/rabs-native-a11a6788-20261030/privileged-1d081ac4-20261101/run.json`.
The fixture follow-up is committed as be88af69. Upstream dceec4f3 merges cleanly
at fde87dfb, preserving the frozen active source and original shared checkout;
Beads import reports unchanged JSONL and the active dependency graph has zero
cycles. Reviewed RABS changes cover fresh workspace queue ownership, cancellation
of private target I/O, durable-delivery reconnect and bounded offline pinned
submodule capture. RCH recovery/admin ownership changes and their published
validation limits remain part of the merge; those upstream reports are not
current merged-source execution evidence. Formatting passes after integration.
Review catches a missing parent-helper import in the nested fixture module;
e7a94e7c fixes it before submission. The fde archive and script remain retained
and unsubmitted, superseded. Formatting and fixture-scoped UBS pass after the
import correction (zero critical, 382 warnings, 162 info; no suppression).
The next e7 immutable archive contains 1,729 regular files, SHA-256
5726597f534c03d36ed0c7e58fecd2dcfc8672e8dc67f07bd2d95cd3f8462f1a.
Its 1,199 Rust/TOML/lock-file aggregate is
cf685185e131c51bd412cd00fdb8612af305eacaf7c1765b88d142fe1461d941.
The prepared 23-command successor places all fourteen Linux cases and the full
adapter target first, retains every original broad RABS target and red gate,
adds the other five RABS libraries and complete RCH common/daemon/CLI unit
targets, then runs mandatory full workspace check, strict Clippy and formatting.
It also checks all 1,683 nonexcluded archive files before Cargo, using an
immutable complete manifest; only the same 46 metadata/example paths may be
absent. It admits at 00:42:32 UTC as build 30080135327647937 /
`rchw-da8a4ad3-339c-4af2-87ff-15c516944cc0`, after terminal acknowledgment of
both preceding invocations. Before Cargo, all 1,683 nonexcluded archive files
match content and length; zero differ and exactly the 46 declared exclusions
are absent. All 1,199 Rust/TOML/lock files match their aggregate, and all three
unchanged 20-GiB guards pass. The fourteen-case Linux target compiles first.
No new test pass follows from admission or source verification. Transcript:
`/Volumes/trj-data/rabs-execute-20261101-merged-e7a94e7c.log`.
The repaired Linux target then passes 14/14, zero ignored, filtered or observed
SKIP markers, 833.63s (860.953s including compilation). Every one of its eight
earlier privacy-setup failures now reaches and passes its original namespace,
jobserver, real-compiler, generated/shared input, stock-byte parity or toolchain
ownership assertions. Production privacy refusals remain unchanged. The full
adapter target then passes 130/130, zero ignored or filtered, 46.20s (97.358s
command). The strengthened 250ms census falsifier, original cleanup timing
cases, injected-clock exact boundaries and native timer/socket consumers all
pass. Host contention and profile differences prevent a performance claim.
The same merged source also passes protocol 499/499, 3.08s (15.910s command),
wrapper 112/112, 5.03s (8.535s), and metadata protocol 13/13, 6.30s (8.182s),
all zero ignored or filtered. The daemon target and remaining declared commands
continue; no full-cohort or merged-source static pass is claimed yet.
The merged daemon target finishes 1,342/1,343, zero ignored/filtered, 80.50s
(149.620s command). The one failure is the original newly merged
`cancelling_one_same_key_workspace_waiter_cannot_cancel_or_join_another`:
`try_launch` returns StaleDeferred after its own reaper has removed the cancelled
dormant flight. Its no-worker-probe and independent-second-request assertions
remain unchanged. A follow-up binds launch/finish authority to the originating
supervisor's retained budget slot, then recognizes only its own reaped,
never-started cancelled flight as CancelledBeforeStart. Present replacement
generations, foreign supervisors and consumed capabilities still refuse. A new
regression covers open/closed foreign supervisors, live and cancelled demand,
continued owner completion, no readiness probe and exactly-once cancellation.
Native acceptance of this draft is pending; no failure is reclassified as a pass.
The same compilation reports `const_item_mutation` at Git-submodule test line
1583. The follow-up gives the original MAX_ARCHIVE_MEMBERS value a local mutable
counter, preserving its full-limit refusal assertion and every production bound.
Formatting is checked separately; full check, strict Clippy and targeted/full
daemon/TLS re-execution must qualify the eventual combined follow-up after the
current owner acknowledges termination. The healthy remainder of e7 continues.
The unchanged cancellation case also reproduces alone against the retained e7
daemon harness: 0/1, zero ignored, libtest 0.00s (0.404s command), exit 101 with
the identical StaleDeferred error. Harness SHA-256
eced9933325abfbe2aa6c3eefc029c28fd8ecf29fb2fbdc67ce2c8f6ffef90ff
matches before/after. This is a deterministic library-integration baseline,
not a remote compiler/fleet probe. Receipt and preserved executable:
`/scratch/rabs-native-a11a6788-20261030/cancellation-baseline-e7a94e7c-20261101`.
The combined follow-up formats cleanly. Its scoped UBS completes with exit 1,
retaining two reviewed existing constructs (controlled prlimit execution and a
test-only sleep process), 339 warnings and 104 info, without suppression. It
remains uncompiled pending the current owner's terminal acknowledgment.
All four e7 TLS/continuation targets pass: 10/10 in 2.05s, execution 26/26 in
9.09s, interruption 5/5 in 1.94s and resume 3/3 in 1.61s, zero ignored or
filtered, combined command 49.163s. Real-Cargo worktrees pass 11/11 (seven actual
Cargo, four support), 394.85s, live protocol 8/8, 0.63s, and repeat wrapper units
112/112; the complete corrected runner exits 0 in 445.977s with every selected
binary hash unchanged. Tiny same-invocation timing pairs include two losses;
these remain informational. Feature and direction pass 5/5 each; budget remains
3/4 with the five original overages. Sandbox passes 458/458 executed, zero
ignored and one separately privileged case filtered, 22.57s (43.420s command).
Worker retains the same three target-reuse failures, 337/340, zero ignored,
63.32s (85.974s command). The other five RABS libraries complete successfully:
action 49/49 (0.01s), CAS 407/407 executed (727.08s) with its one positive
physical reflink case separately ignored, key 439/439 (1.47s), replay 45/45
(0.70s), scheduler 87/87 (0.02s). Their combined command exits 0 in 1,538.451s.
All except the explicitly separate CAS case have zero ignored or filtered.
The original CAS crash-state differential completes before its library summary;
the separate physical-XFS positive case below also passes. The RCH component
targets and full all-target workspace checks continue; no current whole-cohort
or strict-Clippy pass is claimed.
The RCH common library then finishes 2,496 passed, one failed, eight ignored,
zero filtered, 271.83s (415.077s command). The sole failure is
`toolchain::worker_cache::tests::worker_bootstrap_isolates_python_without_changing_cargo_inputs`:
the embedded lifetime suite times out after its original five seconds when it
sends SIGINT. The adapter explicitly owns TERM/HUP during setup but inherits
Python's INT disposition. The exact compiled Rust case reproduces 0/1, zero
ignored, 2,504 filtered, 30.54s (31.407s command) when INT is inherited ignored.
Its 65,681,280-byte native harness is retained independently, SHA-256
50ff2053c0e06971bcbcc2dd00a0150f95ba1224c35ad02bb0e1f390bdea985a,
with the original physical-XFS guard 0 and unchanged before/after hashes:
`/scratch/rabs-native-a11a6788-20261030/bootstrap-baseline-e7a94e7c-20261101/run.json`.
The draft owns every existing SETUP_SIGNALS member during setup and restores
the exact original dispositions before Cargo exec. No timeout, cleanup refusal,
process ownership, fallback or one-exec gate changes. Two new native regressions
require cancellation of an ignored-INT parent's owned preparer/descendant with
no Cargo, then restoration of ignored INT for the successful Cargo exec. Against
the exact old embedded adapter, these are one pass/one timeout error, exit 1.
Against the exact draft, all three Python suites pass: bootstrap 9/9 (12.609s),
lifetime 16/16 (13.634s), cleanup 9/9 (11.111s), zero skipped, while INT is
explicitly inherited ignored. This is real process/pipe/lock/signal evidence
with fixture preparation/Cargo; it is not real compiler/cache/fleet proof or a
rebuilt Rust pass. All source hashes match before/after, physical-XFS guard 0;
receipt: `/scratch/rabs-native-a11a6788-20261030/bootstrap-draft-20261101/run.json`.
Scoped Python UBS completes exit 1: seven reviewed loader/test-process findings,
three warnings, 83 info, no suppression. Rebuilt original Rust bootstrap case,
full RCH common, daemon and CLI must qualify the final combined follow-up.
The RCH daemon completes 1,913/1,923, zero ignored or filtered, 304.21s
(845.360s command), retaining ten failures. Three original API history cases
write group-writable positive fixtures under umask 002, then correctly hit the
production exact-inode/owner/link/mode/bytes refusal. The independently retained
105,570,592-byte Cargo-selected daemon harness, SHA-256
d45e870e1fe9773547338519f873a3fd4546a5ad511f8c6d408da758a763def3,
reproduces all three unchanged cases: 0/3 at umask 002, 3/3 at umask 077,
zero ignored. The original physical-XFS guard passes and both executable hashes
remain unchanged. Receipt:
`/scratch/rabs-native-a11a6788-20261030/journal-baseline-e7a94e7c-20261101/run.json`.
The draft uses create_new and mode 0600 only for the canonical positive lease
fixtures, retaining every original assertion and all deliberately malformed or
aliased witnesses. The production guard is not edited. Its separate real
`journal_reap_requires_the_exact_unchanged_regular_snapshot` case passes in the
e7 common library, including writable-file, replacement, hardlink, symlink and
FIFO refusals. Rebuilt API cases under the original umask remain pending.
The other seven daemon failures demand a complete process-CWD census. Exact
production CWD helpers return typed unknown (2) for PID 1 as the worker user,
and known idle (0) for the same PID under a read-only sudo control. No process
is skipped, signalled or cleaned; no fixture assertion is weakened and root
inspection is not reported as an unprivileged cleanup pass. The native daemon
failures remain visible. Read-only witnesses are cwd-observation.json and
cwd-privilege-control.json beside the journal baseline. CLI compilation and
the full workspace/all-target check, strict Clippy and formatting continue.
After all five draft source edits, cargo fmt --check and diff whitespace pass.
The four-file combined UBS completes 1 with nine reviewed existing loader,
original-Cargo/test-execution findings, 342 warnings, 187 info; the separate API
fixture scan completes 0, zero critical, 1,628 warnings and 537 info. No rule,
acceptance flag or exclusion is changed; these are not a clean broad scan.
The CLI finishes 3,917 passed, 28 failed, two ignored, zero filtered, 284.01s
(970.896s command). The complete failure inventory remains an open consumer
qualification gap. An independently retained CLI harness, 149,984,504 bytes,
SHA-256 f64a7691191f30e6088b2831370e1572d9ed1dead2a8b20bb60059905cc444ac,
reproduces two exact original cases 0/1 each, zero ignored, 3,946 filtered:
the portable verifier (0.53s) and empty-legacy-cancellation assertion (0.44s).
Physical-XFS guard 0 and both before/after hashes match. Receipt:
`/scratch/rabs-native-a11a6788-20261030/cli-baseline-e7a94e7c-20261101/run.json`.
The portable fixture's resolve(sh) selects /home/ubuntu/.local/bin/sh, whose
env-Bash interpreter is absent from the intentionally minimal tool PATH. Its
checksum tools are genuine executable implementations; the shim, not a digest
failure, causes exit 127. The draft selects /bin/sh, the exact concrete shell
already used by run_source_verifier. No interpreter is added to the private
PATH, Python remains absent, and every positive/mutated source assertion stays.
Its formatting check passes; scoped UBS completes 0, zero critical, 515 warnings
and 564 info. The six-file draft still needs native compilation and full checks.
The separate legacy test expects its cancellation marker to disappear, while
the existing production contract explicitly requires a permanent matching fence
(source_claim_registry.sh:109-124, 612-616, 749-755, 806-815). No production guard
or acceptance assertion is changed for that discrepancy; retain its red receipt
and require a reviewed contract/negative-control split before any gate correction.
The other CLI failures include journal permission/identity refusals, source-pair
ownership, retry/recovery controls, setup deadlines and target-location evidence.
These are recorded individually below, not guessed away as host-only failures.
The full workspace/all-target check is running after all native baseline targets.
Both ignored CLI storage probes are also executed separately using the preserved
e7 harness on physical XFS: real whole-clone isolation 1/1, zero ignored, 0.21s
(0.395s command), and 2,048 fsync-backed rustdoc publications 1/1, zero ignored,
109.95s (110.087s command). Both have 3,946 filtered cases, the original 20-GiB
guard passes, and the executable SHA-256 matches before/after. The clone gate
rejects copy fallback and checks private writes/truncation/mode changes. The
publication case uses production staging/publication with a fixture observed
remote exit; neither test establishes compiler acceleration, real-worker or
fleet qualification. Receipt:
`/scratch/rabs-native-a11a6788-20261030/rch-storage-e7a94e7c-20261101/run.json`.
The common library's eight ignored cases use global mock transport state;
they remain unrun and are not real-worker evidence. No ignored case is silently
included in the broad-suite denominators.
The entire e7 23-command baseline is now terminal, CLI 101. Workspace/all-target
check passes 0 in 1,349.138s (Cargo 22m28s); strict workspace/all-target Clippy
finishes 101 in 544.633s, solely the recorded const_item_mutation, without an
allowance or suppression. Formatting passes 0 in 7.656s. Supported recovery
reports completed 101 and terminal ACK true for the exact original wrapper
rchw-da8a4ad3-339c-4af2-87ff-15c516944cc0 / build 30080135327647937, before any
native/quality target reuse. Every earlier runtime failure remains retained.
The six reviewed source edits are committed privately as b5b43b3e. They were
uncompiled at freeze; the actual repaired-source results follow. The commit
remains unpublished. Its 59,248,640-byte archive SHA-256 is
e3708206ba7ed54077b447ed2342a8be579243f7fd8f040b6bc012b89a19d015;
the 320,517-byte all-source manifest SHA-256 is
2b8492891b65385d3adf3728e87851537083055db2e9275bb8fb31d45d8b91d4.
All 1,729 regular tracked files, 46 original declared transfer exclusions and
1,199 Rust/TOML/lock files are retained; Rust aggregate is
5a9fb7cae124dc8151acf62ebc1b6ca463336362b20bf2bbbfc8af1e122eac0c.
The separate 17-command follow-up preserves every original test bound, runs
the unchanged failing controls before mandatory compiler checks and full
consumers, and strengthens source custody with before/after regular-file,
executable-bit and content audits. Its immutable script is 7,138 bytes, SHA-256
3168394e04b484f3c8ce0662fe8f4546b0abc7533101c7f89d08e145b16bc1ad.
The CSS source capsule is separately audited against that aggregate; the TRJ
script/manifest are UID-bound and mode 0400. Dispatch is requested only after
the exact e7 terminal acknowledgment. It is admitted under build
30080135327647953 / rchw-27f40934-e087-4c5c-b4a0-a4520773b43f. Before Cargo,
1,683 tracked files match, with only the same 46 declared exclusions absent;
zero content, type or executable-bit differences. All three original 20-GiB
guards pass. The unchanged original cancellation case passes 1/1, all shared
work cases 19/19, the compiled Rust bootstrap embedding 1/1 (three Python suites,
34 cases), API scan cases 7/7 and portable no-Python source verifier 1/1.
Full workspace/all-target check passes 0 in 274.234s, strict Clippy passes 0 in
262.093s and formatting passes 0 in 7.349s. Complete daemon units pass 1,344/1,344,
zero ignored, 63.65s; actual continuation/TLS targets pass 10/10, 26/26, 5/5 and
3/3. Real Cargo worktrees pass 11/11 (223.59s), live protocol 8/8 (0.56s) and
wrapper 112/112 (4.79s), zero ignored, within the corrected 268.881s runner.
Its tiny-fixture stock/served pairs are 168.287/188.690ms and 144.372/264.194ms:
both are losses, informational only, with no performance claim. Full RCH common
passes 2,497/2,497 executed, eight explicitly ignored mock-transport cases,
249.64s libtest / 249.969s command. Full RCH daemon finishes 1,916 passed / seven
failed, zero ignored, 307.33s libtest / 308.227s command. The three canonical
journal fixture repairs pass in the complete suite; all seven unprivileged
CWD-inspection failures remain red, with no census omission or root-suite pass.
Full CLI finishes 3,917 passed / 28 failed / two ignored, 659.56s libtest /
660.456s command. The portable verifier repair passes in the complete suite;
the additional failure is source_lock_lifecycle_supervised_claim_release_and_caller_loss,
whose supervisor exits before acquisition with retained ownership and status 9.
An independent same-invocation comparison of the preserved old/current harnesses
finds the identical failure at e7 (0/1, 0.619s command) and b5 passing (1/1,
0.917s). Both hashes stay unchanged. This establishes inconsistent outcomes,
not a cause or a new repair; retain the failing complete-suite receipt.
All 17 commands complete, CLI 101. Final source audit again matches 1,683/1,729
regular tracked files with exactly the same 46 exclusions absent and zero
content/type/executable-bit differences. Supported recovery confirms completed
101 and terminal ACK true for build 30080135327647953 before source reuse.
The whole invocation is red. Static success does not qualify the
original optimized archive consumer, shipping, performance or fleet operation.
Follow-up log: /Volumes/trj-data/rabs-execute-20261101-followup-b5b43b3e.log.
DSR has a separate private, nonpublishable diagnostic-native recipe at
`/Volumes/trj-data/rabs-dsr-diagnostic-20261101/config`. Its clean user-owned
source clone `/Users/jemanuel/projects/rabs_dsr_execution_b5_20261101` and private
annotated tag `v2.1.34-rabsdiag.b5b43b3e` bind the exact b5 commit. Strict dry-run
passes 0 on native TRJ with concurrency one and publishable=false. Fresh DSR
health passes with all original 20-GiB root/home/build/temp/target floors; the
physical XFS build root also passes SBH. The earlier NFS source-ownership refusal
and missing-directory health receipt remain preserved. Only dispatcher source,
state and cache use user-owned APFS; compilation remains physical TRJ. The
existing registered RCH recipe and global configuration are unchanged. The
private recipe records `rustup which cargo` and preserves the full pinned August
31 SDK. It declares every compiler invocation directly to DSR, captures the
actual Cargo JSON with the existing strict collector, retains matching tools by
verified physical-XFS CoW, then runs the unchanged original archive case through
direct Cargo test. The earlier opaque-runner recipe was preparation only and
was replaced before any build; the actual direct-Cargo recipe passes DSR dry-run,
DSR's read-only native-target selection, shell syntax and Python syntax checks.
None of those planning checks is a compiler/runtime pass. At that preparation
checkpoint no DSR build had started; the actual invocation follows. No new
public tag, release or artifact publication occurs.
The private native-TRJ recipe also sets the installed shim's documented
RCH_SHIM_LOCAL_IDE=1 so DSR executes its selected native compiler without
submitting a nested RCH build. This is confined to the DSR worker environment;
one compiler job, all DSR/SBH floors, strict source/toolchain attestation and
the original test limits remain. No Mac compiler or global setting changes.
Update: the actual DSR build is submitted at 03:38:42 UTC after the current
canary's supported terminal acknowledgment. Exact source synchronization to one
TRJ host succeeds. Optimized compilation and the original archive test remain
pending. Private recipe SHA-256 is
41aeb275846b18fb23160138d226ef2866438b012b3f5425858da0951a50dea0;
logs are native-build.json/native-build.stderr in the private DSR directory.
The first explicit Cargo build (optimized wrapper, worker and Cargo supervisor)
finishes successfully in 80m40s; the conditional pipeline advances to daemon /
canonical-harness preparation. This is compiler proof only. The original
archive runtime gate and final DSR source/toolchain/artifact checks are pending.
The e7 dev pair and worktree harness are retained by verified XFS CoW under
`preserved-worktrees-e7a94e7c/custody.json`. Wrapper SHA-256 is
5eb81a6ff4fa242b10a9a07fbbea7eff415d0cbc19db905e3ba07c1d9cd5e707;
daemon 9ead04cb79ec23d4938df5a4888163087eafc3cb8fc21d79fe9c3b80882a8657;
harness b3288d6bef452f486cad48b87a67112294df215b92f532a09b0a58ed3d335087.
These preserve component evidence, including the known cancellation failure;
they are not shipping qualification. The current Cargo-selected sandbox harness
is retained independently and runs the privileged bind-mount rejection case
1/1, zero ignored, 0.03s (0.105s command) in its private mount namespace. Its
78a5e4434646274537851e9ecd84214960554ff0e71b4113173286f629616a75 hash stays
unchanged before/after, as does the parent mount namespace; the original
physical-XFS 20-GiB guard passes. Receipt:
`/scratch/rabs-native-a11a6788-20261030/privileged-e7a94e7c-20261101/run.json`.
The Cargo-selected CAS harness is independently retained by physical-XFS CoW
while the main crash-matrix tests continue. Its separately ignored positive
reflink case passes 1/1, zero ignored, 407 filtered, 0.04s (1.595s command),
after the original 20-GiB disk guard passes. The original assertions require a
real reflink, reject copy fallback, and verify independent inode, bytes, mode
and mtime. Original and retained harness hashes match before/after:
dcb8325fbb4709dcfd78ff4a22f3a383ffebea2bd5ac388dbdc8724eb67ba0ea,
107,281,120 bytes. Receipt and preserved fixture:
`/scratch/rabs-native-a11a6788-20261030/reflink-e7a94e7c-20261101/run.json`.
This separate physical-filesystem pass does not finish the main CAS library run.
The original real-rabs-key canary at 1d completes with five actual Cargo exits 0,
fresh stock plus four fresh wrapped targets. All eleven metadata files match
stock in every wrapped round. Cold execution commits eight dependency results;
the next two rounds each execute and verify eight; the final round reports eight
hits, eight served and zero dependency executions. Every round also has four
shadow decisions. Both original 20-GiB guards pass, the default serving budget
and earned verification policy remain unchanged, and both binary hashes match
before/after. Raw times are stock 6.009s, cold 31.469s, verification 8.334s/8.151s,
served 4.679s. This dev-profile, local unsandboxed lane establishes real current
repository reuse and byte parity, not shipping, general workspace or performance
qualification. CLI 0; supported recovery completed 0, terminal ACK true for
build 30080135327647935 / `rchw-d75dd0a1-b9d5-4750-affc-ba7370df40c7`.
Local receipt: `/Volumes/trj-data/rabs-key-canary-1d081ac4-20261101/run.json`.
The same original five-command repository canary is now executed with the final
b5 dev pair, four fresh wrapped targets and a fresh stock target. All five Cargo
commands exit 0; all eleven metadata files match stock in every wrapped round.
Cold: eight executed/eight committed. Each verification round: eight executed /
eight verified. Final round: eight hits/eight served/zero dependency executions,
four shadows. Original serving budget, earned verification policy and both
20-GiB guards remain; 1,199 source hashes and before/after binary hashes verify.
Times: stock 10.178s, cold 122.384s, verification 110.082s/15.650s, served 5.785s.
This is real repository functional reuse in the dev/local unsandboxed lane;
the cold/verification costs remain visible and no performance qualification follows.
Its immutable 6,898-byte script SHA-256 is
12617871ac5852e87247a0d9aee5bcf8ec334dfa5173d8bfff705916507459d8;
only source/path/hash constants differ from the original 1d probe.
The outer RCH invocation correctly fails collection with exit 102 because the
dispatcher declared rabs-key-canary-b5b43b3e-outer while the script wrote
rabs-key-real-canary-b5b43b3e. Supported recovery acknowledges the exact owner
rchw-c7b4ee4e-1f8f-48ba-9985-516798c923f7 / build 30080135327647956, retaining
terminal 102. It does not replay or turn that invocation green. The genuine
sixteen result files are separately copied and verified before/after, 49,343
bytes; no empty substitute or altered receipt is used. Local archive:
`/Volumes/trj-data/rabs-key-canary-b5b43b3e-20261101/run.json`, SHA-256
050a84ffa8d25a34079a23bfbc5470ebec3d83b421f7bd277e52b5f11b66653d.
The original collection failure and custody record remain alongside this pass.
Cold and first-verification latency are material unresolved costs: this exact
invocation takes 122.384s/110.082s versus 10.178s stock. Do not cherry-pick the
5.785s served round into a speedup qualification or attribute the difference
from earlier cohorts to a code regression without a controlled comparison.
The broad changed-source UBS scan returns partial 2 because its AST output
exceeds 16 MiB. Repeating the same fifty files individually, without changing
rules, exclusions or acceptance flags, completes every scanner: 34 file scans
exit 0 and sixteen exit 1, with 98 critical findings, 23,504 warnings and 12,172
info in aggregate. Critical contexts include deliberate native shell fixtures,
resolved tool/fixture executable paths, public filesystem identity and exit-code
comparisons, and the local SSH fixture proxy's explicit operator-selected root.
The scanner findings remain unsuppressed; this is not a scanner pass or a claim
that its complete warning inventory is cleared. Raw per-file logs and exits are
retained under `/Volumes/trj-data/rabs-merged-e7a94e7c-ubs-bounded-20261101`.
An independent read-only audit during the frozen run also checks all 1,725 Git
archive files: 1,679 match content and length, zero differ, and 46 are absent
under the unchanged exclusions (40 Beads files, five .ntm files and the dashboard
environment example). No other source, helper or fixture omission is observed.
This is read-time full-archive evidence, not a prelaunch attestation; the
1,199-file Rust/TOML/lock digest remains the actual pre-Cargo gate. Receipt:
`/scratch/rabs-native-a11a6788-20261030/source-audit-1d081ac4/audit.json`.
Do not inherit any old pass or close a milestone.
Invocation is build 30080135327647922 /
`rchw-d8e3a2e5-436b-4040-bf51-701e563d5461`; transcript is
`/Volumes/trj-data/rabs-execute-20261031-current-478a8866.log`. The source gate's
earlier refused 77 transcript, complete-input 77 loss and all cancelled 177
streams are retained separately.
The registered mminiold is native arm64 with the exact 908501772 compiler, but
its existing guards refuse all checked build volumes: internal APFS 33.63GB,
6.803%; external APFS 46.75GB, 8.712%; USB NVMe 1.983TB, 12.389%, all below
the unchanged 14% floor. Its configured data-volume automount does not expose
the requested path. No build, cleanup, policy change or provisioning follows.
An alternate static host, vmi1153651, has three free scheduler slots and the
exact 90850177249efe0321573c569aec5d12b257f8d6 compiler. Its SBH preflight
nevertheless exits 1: 40,653,905,920 bytes free, 4.892% against the unchanged
14% threshold. No build is launched there, no queued trj job is cancelled,
and no storage/capacity policy is changed to manufacture admission.
A separate clean 177 wrapper clone submits the complete wrapper unit target
with one Cargo job, one test thread and one requested RCH slot, requesting a
worker-verified source-content receipt. It never reaches admission. Its
first launch is rejected by CLI argument validation because clean-overlay and
source-content-receipt are mutually exclusive; that exit 2 runs no compiler or
test. The corrected invocation queues behind older multi-slot jobs. Source
review confirms the deliberate queue hold that drains workers for starving
multi-slot jobs; spare capacity does not authorize bypassing that hold. Cancel
only this redundant probe after matching its live lease, PID, cwd and exact
source/test command. Supported cancellation releases zero slots; recovery
acknowledges terminal 130 with null admission. No source receipt or test result
is established, and the original combined native run retains the full target.
Read-only source review also rules out the old one-byte-driver hypothesis:
both the worker FrameReader and coordinator read_record already read bounded
4,096-byte chunks and yield after 32 reads. The adapter's older comment alone
does not justify another buffering change. The actual source and build paths
are local Btrfs and XFS, respectively; they are not NFS paths.
The cancelled 177 optimized job declares the earlier overhead runner, but its
overhead body never executes; there is no gate result for that source.
The next runner candidate rebuilds the normal wrapper after preparing the
harness, requires its exact original production hash, verifies the daemon and
harness stayed unchanged, then invokes the Cargo-selected harness directly.
Cargo cannot silently restore the dev graph during execution. The original
Rust test, five warmups, 60 samples and 10ms gate are unchanged. All 36 Linux
runner regressions pass in 80.265s, explicitly with Cargo doubles, not Rust
runtime proof. Python 3.9 grammar and whitespace checks pass. Scoped UBS retains
seven findings, 11 warnings and 121 info: intentional argv-based subprocesses
and public filesystem signatures, without shell execution or suppression.
The corrected runner is retained separately on worker XFS at
`runner-2bad0306/test_rabs_live.py`, SHA-256
`c8c57b81656c14267df10c825b94c0d98ec200eae09824d238e628d27c573dfe`.
Its Git blob and retained copy agree; `custody.json` records both runner source
2bad and binary source 177. The later group-zero failure invalidates 177 as a
shipping candidate. Preserve this retained runner as evidence, but qualify the
repaired implementation with the same corrected runner bytes. The uncertain
614 selection is not permission to reuse its clone or target. Bind each new
independent invocation's actual source, binaries, complete workload and outcome.
The current evidence checkpoint parses all 2,218 unique Beads records, with
2,186 closed, seven in progress and 25 open. Its four changed owners contain
comments and the M6/S7 moves to in-progress; none is closed. Cycles including
closed items are zero. UBS on Markdown/JSONL exits 3 because it supports neither
format and checks nothing; that is not a scanner pass or a reason to enable
its no-scan override. Python source findings are reviewed separately above.

**Latest completed native component and local Cargo qualification:**
`ab0f22e1e0fa5b61f333148dbd08c7b619484166`. Wrapper units pass 109/109,
metadata socket/protocol cases 13/13, live protocol 8/8, daemon library including
native toolchain CoW 1,309/1,309, and real-Cargo worktrees 11/11 (seven Cargo,
four support). Workspace/all-target check, strict Clippy and formatting all
pass on ts1: 500.160s, 547.704s and 10.655s. These jobs both end 0.
At 16a95337, all 441 sandbox cases, worker CoW 2/2 and CAS H017 real reflink
1/1 also execute successfully. The dependency-direction probe passes 5/5;
the unchanged budget probe remains red (3/4, five excesses). The three worker
source-edit acceptance failures remain open. No full-system pass follows.
**Earlier maintenance candidate (actual compiler failure retained):**
`58f32a6ab02525fad6a32b52a08f065bf3c3e3c9`.
717566a1 explicitly sets TCP_NODELAY before both sides' authenticated TLS
handshake, using the pinned Asupersync socket API. A real-socket test checks
the default and configured kernel option and unchanged TTL on accepted and
connected sockets. The test is not yet executed; no transfer speedup is claimed.
58f32a6a addresses observed wrapper cleanup timeouts by querying kernel process
groups before opening unrelated procfs files. Every positive member and thread
still has its complete original identity/state checked in two independent
sweeps, with the same unreaped PID fence, two-second deadline and 262,144-entry
bound. Unknown kernel membership still refuses cleanup. The complete old
observer remains a same-invocation native identity/timing oracle; the original
live-member negative remains. This uses the existing Rustix dependency's
process feature, with no additional dependency or lock change. Its
[getpgid API](https://docs.rs/rustix/latest/rustix/process/fn.getpgid.html)
is a membership query, not completion authority. Formatting and locked offline
metadata pass; UBS retains one original constant-shell fixture finding, 56
warnings and 48 info, without suppression. These are maintenance candidates,
not native or fleet qualification yet. The workspace/all-target check at 58f
ends 101 after 2,369.779s on the incorrect PID conversion. The following Clippy
is stopped on this known broken source; its cancellation RPC times out E504,
then supported recovery acknowledges terminal 143. Formatting was unrun.
No daemon restart, manual journal clearing or peer cancellation follows. The native
job is admitted at 17:35 UTC but loses SSH completion before its result
directory exists; supported recovery of build 30088853255618836 /
`rchw-306dda39-5bb2-4608-9689-384de4a30568` acknowledges terminal 102. No test
body is established by that launch. Only after acknowledgment, its clean
native execution clone advances to 4ea997bb for a fresh combined run.
The same-invocation TCP control in
`/Volumes/trj-data/rabs-execute-20261031-tcp-nodelay-control.jsonl` preserves
64 records, 256 bytes per record, window four and identical payload hashes
per arm, alternating order across four pairs. NODELAY-off/on milliseconds
are 41.668/6.812, 11.073/5.949, 8.912/6.147 and 18.639/13.861. This is a small,
variable plain-TCP loopback control, without TLS or a compiler; it establishes
neither the cold-transfer cause nor a RABS performance win.

**Newer integrated source, not yet compiler/native qualified:**
`4ea997bb1089a3f4d8c8ef8b149cb102c9cd6959` merges upstream through
`d036f2a8b34caa5e4bde717b1b90a63f1ffec12d`. It adds leased ELF runtime images,
private bounded metadata prefetch and completed-workspace metadata delivery,
plus upstream SSH ownership/disable repairs. The original canonical archive
assertions are strengthened to cover workspace metadata too. Reviewed the
runtime ownership, independent verification, negotiated private-byte receiver,
terminal-manifest selection and sticky exposure-failure paths; no native pass
is inherited from the frozen 58f jobs. Upstream reports 26 runtime-cohort cases
and eight isolated protocol/preview cases, but explicitly leaves full worker,
coordinator and actual Cargo validation unrun after OOM/ENOSPC. Those are
peer-reported component results only. Merge has no conflicts or manifest/lock
change. Scoped UBS scans 25 Rust files: 12 critical, 5,495 warnings, 1,724 info.
Critical findings cover three public filesystem-stamp comparisons, one
integer-PID shell fixture and eight executable-path selections; they are
retained without suppression, not a scanner-green claim. Beads import is
current and cycles including closed items remain zero. The 4ea native launch
also loses SSH before creating its result directory; recovery acknowledges
terminal 102, not a test result. Its 725 successor never starts: cancellation
reports 130 and zero released slots, then recovery acknowledges 130 before
source reuse. The fresh 177 native invocation includes all protocol, adapter,
wrapper, daemon, sandbox and worker libraries; TLS/continuation, metadata
protocol and real worker process/Cargo cases; feature/direction/budget probes;
and complete Cargo worktrees. It retains every command's result, including
expected old worker/budget reds, rather than stopping at a failing test.
A scoped compile preflight now precedes the expensive full runs; a compiler
failure retains the command manifest and leaves the remaining commands unrun.
Fresh exit-0 SBH checks confirm
719,765,680,128 scratch bytes and 104,401,612,800 tmp bytes free, above 20 GiB.

**Last completed static/TLS repair:** `2432bae3e2c9b9b0801eae110b1a612e055b82eb`.
Merged upstream projection reuse and sealed-result continuation at 9e5c7020.
That native run passes daemon 1,312/1,312, continuation receiver 10/10,
sandbox 448/448 plus the separate private-mount case, TLS interrupt 5/5 and
TLS resume 3/3. TLS execution is 24/26; worker library has six failures,
including the original three target-reuse failures. Check passes; strict
Clippy rejects the oversized continuation enum; formatting passes. The
999187c3 repair boxes its owned continuation, gives two source-cache fixtures
their required 0700 parents, retires the old writer before corruption/reopen,
and serves the failure fixture's zero-byte stdout range before stderr. It
changes no original byte-integrity, no-execution, output or exit assertion.
The 999187c3 run passes daemon 1,312, continuation ten, sandbox 448 plus
private mount one, TLS interrupt five and resume three. Worker is 331 passed,
three failed: the three new cache failures now pass, while the original three
codegen target-reuse failures remain. Its TLS test compilation catches a
missing PermissionsExt import in this repair; that is corrected at 2432bae3.
The actual 2432bae3 TLS execution suite passes 26/26 in 6.39s, command 33.325s,
outer RCH 0. Workspace check, strict Clippy and formatting all pass at 2432bae3
in 137.928s, 142.531s and 7.319s. Its matching dev-profile worktrees run passes
109 wrapper units and 10/11 worktrees (six real Cargo cases, four support).
The tracked-OUT_DIR negative fails: zero execute decisions instead of one,
with two LIVE_DEP_REFUSED_ENV decisions. Every original assertion remains;
4be42338 adds the complete decision records to that failure message and its
focused actual-Cargo rerun passes 1/1 (ten filtered), 51.57s. It changes no
production behavior, so the previous failure remains an intermittent concern.
The subsequent 4be42338 full worktrees run passes 109 wrapper units and 7/11
worktrees: two explicit compiler-group quiescence deadline failures, one large
package case that never gets past toolchain warming, and a cold-serving case
whose sysroot probe expires. No bound is increased. That run loses SSH
completion after its actual libtest summary; supported recovery acknowledges
255 (daemon had recorded 130), not a passing outer job. Its raw body failures
remain evidence. The separate 4be static launch loses SSH before its result
directory exists and recovers acknowledged 102; no compiler check is claimed.
The optimized original archive case
fails 0/1, 29 filtered, 321.64s: Cargo reaches its unchanged 300s deadline
during cold toolchain upload. A hash-bound read-only observation of this run's
own worker sees 34,513 staged files / 2,436,496,841 bytes before expiry and
null request high-water. This is an observed transfer/preparation bottleneck,
not evidence that toolchain bytes may be omitted. The preceding two 2432bae3
launches passed duplicate --nocapture flags and ran no test bodies; those
libtest setup failures are retained, then corrected in fresh result directories.

**Split-profile wiring candidate:** `8d028adb59b356135e767755cba20963c1ab9302`.
The existing live-test runner now prepares the real daemon-release daemon and
wrapper-release wrapper/test harness for the unchanged overhead test. CI's
previous generic-release invocation is replaced with that exact runner.
All 32 Linux orchestration tests pass (42.378s), including rejection of a
nonshipping profile, a foreign harness, a mutated wrapper, and a failed second
build. These use explicit Cargo doubles; they are not native RABS proof.
Workflow YAML parses. Scoped UBS retains seven findings on intentional local
argv-based Cargo subprocesses and public filesystem-stamp comparisons; there
is no shell execution or secret comparison and no suppression is added.
Later review of its actual Cargo JSON exposes another qualification gap:
the initial wrapper build enables Rustix fs, while test preparation enables
fs plus net and rebuilds the wrapper at the same path. The runner then selects
that dev-graph wrapper. A shipping profile alone does not prove the normal
production wrapper. Preserve the runtime failure, but withdraw the stronger
shipping-pair claim; the correction above must execute independently.
The actual source-8d run compiles the normal production daemon-release graph in
103m09s, wrapper-release wrapper in 1m35s and the actual test harness. Preparation
takes 6,409.816s and the test command 8.278s, total 6,418.263s. Its original five
warmups, 60 samples and 10ms p95 bound remain. Runtime is four support cases
passed, one latency gate failed: **p95 116,913us**, original bound 10,000us,
libtest 4.76s. The 606,968-byte test-graph wrapper is below 2 MiB; that is
this artifact's size proof, not shipping-size, latency or release qualification.
Its SHA-256 is
`702f5768329c04461f83238c9abc6375c4c42259b40e81861a7435eddd31d3a2`.
The explicit fake-rustc control measures wrapper/daemon overhead, not compiler
acceleration. SSH loses confirmed completion after the actual failure summary;
supported recovery acknowledges 255. The runtime 101 and outer 255 remain
distinct. All three Cargo-selected binaries are preserved by verified XFS CoW
in `preserved-overhead-8d028adb/custody.json` before target/source reuse.
A one-invocation, 10-second/1-MiB syscall diagnostic with those exact bytes
executes ordinary pass-through, issues 271 reads and joins its own daemon.
The trace measures neither the original gate nor compiler acceleration. It
motivates the bounded-read buffer candidate, not a performance win claim.
S7 remains in progress, including the older frozen unacknowledged shipping
wrapper and all original install/fleet gates. Source-717 native/static jobs had not been admitted: both
were cancelled before start, zero slots released, then recovered acknowledged
130, so their validation can be batched at source 58f. No test or compiler body
ran in those cancelled invocations. No peer job was cancelled or altered.

**Canonical e8083f9d result:** 10 passed, nine failed, one interrupted and ten
unrun of the original 30; outer job exit 137 after its configured 10,800s.
The runner prepared normal tools in 14m55s and the actual test graph in 25m20s.
Several archive/generated cases hit the unchanged 300s Cargo deadline after
remote admission, often with null worker request high-water. One archive case
also misses its original metadata-prefix denominator. There is no complete
canonical pass. Preserve the full transcript and original limits while
diagnosing this next integration failure.

**Earlier repair:** `e8083f9d0882917820d804022410d3a7b8f5be66`.
The canonical driver now binds its retained toolchain library path in the
recorded environment before planning. Full daemon units pass 1,309/1,309 and
workspace/all-target check, strict Clippy and formatting pass (363.381s,
668.876s, 6.832s). Its canonical runtime results are above.
Do not promote the loader control or earlier component results to this suite.
Frozen c4e1b570 completed workspace/all-target check
(1,360.109s) and strict Clippy (337.350s), both exit 0; its
optimized canonical run was stopped after three original Cargo deadlines
failed, with one case passed and the fifth interrupted. A focused optimized
canonical retry at 9ffe42d8 now ends 101: 0/1 passed, 29 filtered, 167.76s.
The original Cargo deadline is met, but all three admitted remote compilers
fail and local fallback supplies the successful Cargo build. This fails the
unchanged offload assertion; there is no passing canonical suite.
**Compiler-checked integration:** `2432bae3e2c9b9b0801eae110b1a612e055b82eb`
passes workspace/all-target check, strict Clippy (`-D warnings`) and formatting.
The worker's source-edit acceptance and the dependency-budget gate remain red
as recorded below; static checks are not full-system runtime qualification.
**Merged implementation:** incorporating upstream d896c296's
freshly published remote metadata delivery plus existing callback-type reuse
in its production and fixture install paths. Its actual ab0f22e1 results above
qualify the component/local Cargo scope, not canonical offload. The preceding
ec646b74 merge preserves concurrent
streaming, explicit application-input and early-metadata changes through
d3635d3d. That older merge's workspace check and strict Clippy
both ended 101; subsequent compiler/lint repairs, the profiled encoder and
producer-boundary tests are committed through 16a95337. Its current daemon and
native capability results are scoped below. Those newer
features do not inherit a runtime pass from an earlier source cut.
The newer source includes the two daemon compiler repairs, source-bound release
identity, retained toolchain images, a persistent canonical service and shared
remote dependency flights. Their presence is distinct from passing acceptance.
**Upstream work integrated at 9e5c7020; full qualification remains open:**
`d05cefb2f40d8d0f01788c95829c4b86f596a302` adds worker input projections;
`a1fe627c25716dc25c752222b678a461d966d5c5` adds sealed live-result continuation.
Their commit receipts report 35 filesystem and ten receiver component cases,
respectively. They explicitly leave full worker/daemon, TLS and native Cargo
qualification unrun after Asupersync resource exhaustion. These are peer-reported
component results, not this run's source qualification. The subsequent native
9e5c7020 results above retain the actual TLS/worker failures; they do not
establish a fleet or canonical Cargo pass.
This section supersedes the older assessments below. Its consumers are the
operator deciding whether to enable RABS and agents implementing the original
milestones. It addresses the observed mismatch between closed milestones and
undelivered or unqualified product acceptance. Replace its current-state claims
when a later dated, source-bound execution changes them; preserve the original
requirements and historical evidence.

### Bounded anti-ceremony and honesty review — October 31, 17:28 UTC

Window: the four implementation commits 8d028adb, 4be42338, 717566a1 and
58f32a6a. Examined their complete source, test, workflow and manifest diffs,
the last eight reflog entries, native transcripts and recent Beads closures.
Purpose from the README: transparently offload agent compilation to remote
workers. Classification: USER 2 (socket/cleanup candidates, still unqualified),
ENABLER 2 (shipping-profile runner and failure diagnostics), PROCESS 0,
UNKNOWN 0. These labels count changes, not shipped capabilities. No newly
qualified complete system or public release was delivered in this window.

Honesty inventory, using the skill's question numbers:

1. No (checked: all four test/workflow diffs); original assertions, deadlines,
   byte windows, five warmups, 60 samples and 10ms bound remain.
2. Yes: runner tests extend their explicit Cargo double. They test command,
   profile, artifact and failure propagation only; native jobs supply runtime
   evidence separately (RH-2/5). No compiler acceleration is attributed to them.
3. No (checked: four commit diffs); no golden/snapshot regeneration.
4. Yes: 8d028adb changes the CI invocation to the split shipping profiles and
   tests its runner. The unchanged Rust acceptance remains the authority;
   no suppression, bypass or tolerance increase was added (RH-1/13/14/15).
5. No (checked: production and test diffs); no benchmark-path branch or
   post-result denominator change. Original 30 canonical cases remain named.
6. Yes: the focused 4be run filters out wrapper/protocol bodies. Only its one
   actual OUT_DIR case is counted; the zero-body summaries are not passes
   (RH-2). Earlier duplicate-nocapture setup failures remain recorded above.
7. No (checked: terminal receipts against this report); queued/building is
   not reported as executed or passed.
8. Yes: the later Cargo-record review does not establish the stronger source-8d
   shipping-pair claim: test preparation replaces the wrapper with its dev
   graph. The runtime red remains; 2bad0306 restores production bytes before
   running the unchanged harness. Actual corrected qualification is pending
   (RH-2). Cargo-double, TCP-control and fake-rustc scopes remain explicit.
9. Yes: an earlier Beads comment said three cleanup deadlines; the transcript
   contains two. An appended correction and this report retain two. The
   7/11 full-worktrees result and intermittent OUT_DIR failure remain visible.
10. Yes: the unchanged overhead fixture discards child daemon output and uses
    fake rustc. It is only wrapper/daemon overhead evidence, not compiler or
    archive-delivery proof (RH-2). Compiler build diagnostics remain retained.
11. No (checked: recent closure timestamps and session status mutations);
    no Bead closed, no unmet acceptance moved to a replacement (RH-7/9).
12. No (checked: plan/source diffs); current-state evidence changes, not the
    original capabilities, budgets or acceptance requirements (RH-10).
13–17. No (checked: this window's agent activity and receipts); no new
    delegation, agent closure, unexamined delegated result, refusal farming
    or independent-confirmation claim. Earlier peer component reports remain
    explicitly peer-reported and were followed by our native merged runs.
18. No (checked: run commands, filters and original test list); every filtered,
    interrupted and unrun case remains distinct from a pass.
19. Explain before replay: the missing PermissionsExt import and duplicate
    nocapture arguments wasted runs; both were disclosed and corrected.
    The original reds and failed launch receipts were not removed (RH-17).
    Later compiler evidence catches the mistaken Rustix PID conversion too;
    the fix adds a scoped compile preflight before the expensive workspace run.
    Its 58f exit-101 receipt remains, with Clippy interrupted and fmt unrun.
20. Strongest bounded positive: actual source-2432 TLS execution is 26/26,
    with static gates all zero; source-999 worker cache repairs leave exactly
    the original three worker acceptance failures. These are re-executable
    component results, not this window's pending candidate qualification.

Older-session check used cass's existing stale-but-searchable index, six
bounded lexical queries and exact archived-message context for one hit each.
All searches completed without budget timeout; their top-three pages are not
an exhaustive historical audit. The archive includes an earlier agent's
admission of script edits/missed UBS, preserved RABS jobserver/soak failures,
and a renderer-only R010 closure. Those historical reports do not qualify
today's system or justify closing its original milestone owners.

Process worksheet: this existing report is PROCESS, requested by the operator
as the granular TODO. Its concrete consumer is the operator deciding whether
to enable RABS and the implementing agent preserving original acceptance.
It catches the observed closed-milestone/undelivered-capability mismatch.
Retire the active checklist when its named original acceptances are qualified,
preserving historical evidence; create no additional report hierarchy.
Verdict: implementation work is real, but no new system win yet. The next
block stays on native execution, original archive delivery and S7's actual
shipping pair; it does not add process machinery. The oldest user-visible
gap is reliable remote canonical Cargo execution. Its unchanged acceptance,
the dependency-budget red and worker reuse reds remain open. Every affirmative
inventory answer above names its artifact, correction/boundary and pattern;
none is grounds for a clean all-project honesty claim.

**Verdict: RABS contains substantial runnable software, including actual
dependency serving and canonical worker execution. It is not yet the finished,
deployed, fleet-wide acceleration system in the master plan.** A closed task
graph is particularly misleading here. At intake, `br stats --json` reported
2,218 issues: 2,207 closed, six open and five in progress. All RABS program and
milestone beads were closed. A full-status text search for RABS returned 598
issues, 597 closed and one unrelated Darwin-routing issue in progress; this is
a lexical search count, not a complete membership denominator.

### What exists, and what that does not establish

### Execution checklist — user-authorized implementation and live qualification

Consumer: the implementing agent and operator running the original milestones.
This checklist prevents losing implementation or acceptance work during long
native builds. Update it in place; retire it when the original milestones have
their cited acceptance, retaining their evidence in Beads. A checked step is
only the stated step, never closure of the surrounding milestone.

- [x] Read the complete AGENTS/README and audit original plan against code.
- [x] Restore 19 existing unmet program/milestone/probe owners without changing goals.
- [x] Run the original frozen-source Cargo suite and workspace check to terminal outcomes.
  The check exited 101 with two daemon compiler errors; the Cargo suite's
  companion build failed and its outer command subsequently hit the 7,200s
  deadline (137). Neither establishes a native passing suite.
- [x] Correct the missing source-delivery `BTreeMap` import and borrow the
  formatted dependency-negotiation error passed to `invalid(&str)`.
- [x] Compile a mutually matching current wrapper, coordinator and worker on Linux.
  - [x] Bind the exact source/overlay, toolchain, profile, Cargo artifacts and binary hashes.
    The 7c9c1828 canonical manifest includes all four source-stamped dev tools
    and its actual test harness, each with a SHA-256 and length. Compilation
    succeeds; its first runtime case exposes the shutdown defect below.
  - [x] Include validated `RCH_BUILD_SOURCE` in the default release/service identity
    and add the cross-overlay verdict rejection regression (`1a5487bc`).
  - [x] Execute the source-stamped Rust release/identity selection: 12/12 passed,
    exit 0, wrapper-release profile at `78abd733` on trj (build `30087403704156409`).
    This tests authorization/identity logic, not the daemon or cache serving.
  - [x] Keep strict remote execution, disk preflight and existing ownership intact.
    The current trj checks use XFS scratch with 944,918,491,136 free bytes
    (34.13%), an exit-0 20-GiB SBH preflight, two admitted slots per job and
    source-stamped 7c9c1828 builds. The ts1 pair uses its healthy NAS target.
  - [x] Diagnose the canonical worker's missing modules as a transfer-policy
    failure: the installed RCH's custom `target_*/` excludes six tracked
    `rabs-wkr/src/target_cache/` files. Preserve the df9ba871 exit-101 receipt;
    change only the private qualification config to root-anchored `/target_*/`.
    Confirm the production modules arrive and the worker compiles unchanged.
  - [ ] Complete the rerun with the full source tree; retain its terminal result.
  - [ ] Resolve every compiler error; rerun workspace/all-target check and strict Clippy.
    Workspace/all-target check at 7c9c1828 passed exit 0 in 12m38s; source
    receipt root `d901c82333ab94ddc928e4beb7baec05ff62fcd327d0af49b8b08e2260de573d`.
    Strict Clippy then failed `large_enum_variant` in `PreparationToolchain`.
  - [x] Box the owned captured-toolchain variant instead of suppressing its lint.
  - [x] Name the existing six-case toolchain mutation table type; the next
    strict Clippy pass reached its `type_complexity` lint. Keep every mutation,
    refusal and retained-reader assertion unchanged, without lint allowances.
  - [ ] Rerun check, strict Clippy and formatting after the native repairs.
    - [x] Formatting and diff whitespace checks pass after the ec646b74 merge.
    - [ ] Retain terminal all-target workspace check and strict Clippy at that
      exact merged revision; `.rch-tmp/rabs-workspace-quality-ec646b74/run.jsonl`
      records each command and exit independently, including failures.
      That invocation found E0599 in the newly merged metadata-replay corruption
      test (`SqlMetadataStore` intentionally has no raw `execute`), and strict
      Clippy found a complex callback type in `live_dependency::install_inner`.
      Use a separate real SQLite engine connection to the fixture's private DB,
      assert exactly one publication row was corrupted, and name the existing
      callback type without changing its lifetime or behavior. Rerun both gates.
      The complete ec646b74 run ended 101 for check (871.783s) and strict Clippy
      (1,200.842s). It also exposed three unnecessary cloned one-element slices
      in the new CAS metadata-pipeline tests. Borrow those same locations without
      changing any equality assertion; retain the original red receipts.
    - [x] Requalify the latest merged daemon and native capability cases.
      At 9ffe42d8 the daemon compiled in 7m26s and executed 1,298 passed,
      five failed, one ignored (83.28s). Four failures match the subsequent
      preflight/fixture repairs; the new fifth is the actual planning-process
      cancellation/drain probe returning Other rather than Interrupted. Its
      unchanged assertion now prints the exact cleanup error. Investigate
      before altering any cleanup bound, error precedence or root ownership.
      The encoder's same-invocation incumbent comparison passed all byte
      assertions: 524,291 bytes, old formatter 80,387,766ns, candidate 16,907,482ns.
      This unoptimized single microcomparison is not system performance proof.
      At aaaaa519 the daemon runs 1,302 passed, two failed, one ignored (46.79s).
      The producer-record filesystem test and all corrected native/output
      preflight cases pass. Remaining fixture repairs: retain `create_dir_all`
      for the pre-existing cargo-home and set every mapped root to 0700;
      expect Outputs for unsupported object/assembly/LLVM shapes while keeping
      UnclosedCodegenInputs for modeled link outputs. Every actual edge shadow,
      original argv, no-wait and no-serving assertion remains. This diagnostic
      correction admits no additional local output class. The isolated
      cancellation probe passed 1/1 (1.37s), and its full-library invocation
      passed too; neither erases the previous Other-kind failure or proves a
      cleanup repair, because no production cleanup code or bound changed.
      The broader aaaaa519 library run completed: action 49/0/0, adapter
      125/0/0, CAS 407/0/1, key 439/0/0, protocol 498/0/0, replay 45/0/0,
      sandbox 433/0/8, scheduler 87/0/0, worker 324/3/2 (passed/failed/ignored).
      CAS's complete reference/FrankenSQLite SQL fault matrix passed; its
      library run took 1,082.70s and is not a process-kill or soak qualification.
      Wrapper units ended 107/1/0: the backpressure fixture received its whole
      8-MiB report. A fresh worker socket confirms a 16-MiB default send buffer.
      Set and verify a small SO_SNDBUF on that test's own socket with rustix's
      [documented socket option API](https://docs.rs/rustix/1.1.5/rustix/net/sockopt/fn.set_socket_send_buffer_size.html),
      enabling `net` only as a Unix dev feature. Preserve the report size,
      deadlines and every cancellation/partial-frame assertion; runtime
      dependency count remains two of three. Record the before/after capacity.
      Independent workspace check passes (261.190s); strict Clippy ends 101
      (1,019.004s) on the metadata-replay test callback's complex type, and fmt
      passes. Reuse its existing parent MetadataCallback alias, without allowances.
      At 16a95337 the corrected daemon passes 1,305/1,305, including its ignored
      native toolchain-CoW case, in 57.38s. The planning-cancellation case passes
      unchanged; its earlier intermittent failure remains an S8 concern because
      no production cleanup repair has been established. Wrapper units pass
      108/108 (3.26s), metadata protocol 10/10 (2.43s), sandbox 440/440 (24.89s,
      only the private-mount case filtered), worker CoW 2/2 (0.12s), and CAS
      real reflink 1/1 (0.02s). These are actual native executions; the protocol
      fixture uses an explicit fixture daemon and does not replace real Cargo.
      The backpressure socket reports capacity 16,777,216 -> 8,192 bytes for
      the unchanged 8,388,647-byte report, with every original assertion and
      deadline retained. Same-invocation encoder comparison: 67,444,952ns old,
      11,346,278ns candidate, byte-identical 524,291-byte payload; still only a
      development-profile microcomparison. Direction passes 5/5; budget remains
      3/4 with the same five excesses. The outer native job exits 101 solely
      for that budget probe, with all command results retained independently in
      `.rch-tmp/rabs-native-16a95337/run.jsonl`.
      - [x] Run the corrected wrapper backpressure case and full wrapper units.
      - [x] Execute CAS's remaining ignored H017 real-reflink case on XFS.
      - [x] Retain native all-daemon and current check/Clippy/fmt results after
        the two e4892b5d fixture corrections and callback/socket test repairs.
        Native results are above; ts1 workspace check, strict Clippy and fmt
        all exit 0 in 483.618s, 410.303s and 16.902s. Source stayed frozen until
        terminal acknowledgment; `.rch-tmp/rabs-static-16a95337-ts1/run.jsonl`
        preserves all three commands. This does not qualify the later d896 merge.
      - [x] Execute the original private-mount case separately at 16a95337,
        using Cargo JSON to select its exact harness and verify its hash before
        and after the bounded private namespace run. Earlier 9ffe proof is retained.
        It passes 1/1, outer RCH exit 0 (20.5s), and the selected harness retains
        SHA-256 `0f5dc54b7d633ca8bf413fde8831ea30fb6b67e822daedf2023ee8f5535b7ff7`
        and 21,710,432-byte length. All 441 distinct sandbox cases now execute
        at the current source. Receipt: `.rch-tmp/rabs-private-mount-16a95337/`.
      - [x] Requalify the matching real-Cargo worktrees suite at 16a95337;
        the seven real Cargo and four support cases at 7c9c1828 remain historical.
        The source-stamped runner ends 0 on trj: real-Cargo worktrees 11/11
        (210.21s), wrapper units 108/108 (4.62s), live protocol 8/8 (0.56s).
        Preparation takes 456.274s; all test commands take 215.614s. Cargo JSON
        selects the matching tools and harness, and every hash remains unchanged
        after execution. Three tiny-fixture same-invocation informational timings
        favor stock: 136.567/178.181ms, 141.590/181.074ms, 149.349/185.764ms
        (stock/served). These are losses, not speedup qualification. The earlier
        larger actual-repository canary remains a single development observation.
        Receipt: `.rch-tmp/rabs-worktrees-16a95337/{run.json,binaries.json}`.
        Before reusing the target, the three exact binaries were retained with
        verified SHA-256/length in XFS `preserved-worktrees-16a95337/custody.json`.
        A first cross-device reflink attempt failed and its empty destination
        remains recorded; the successful copy uses the source XFS volume.
      - [x] Integrate the new upstream d896c296 result-delivery implementation
        in the isolated checkout, preserving all active source/target snapshots.
        Review its published-result authority, exact capture/action/manifest ACK
        identity, sticky exposure failure, replay sampling and strengthened
        canonical prefix-order assertions. The new producer fixtures retain
        zero verification comparisons and prove delivery creates no replay right.
      - [x] Reuse the existing callback aliases in the newly added production
        and producer-fixture paths, without allowances or lifetime changes.
        UBS production file: exit 0, zero critical, 326 warnings, 200 info;
        fixture file: exit 1, one existing test-only `panic!("install count shape")`,
        84 warnings, 29 info. The fixture panic checks an impossible SQL result
        shape and is not used by production; scanner red is retained, not hidden.
      - [x] Run workspace check, strict Clippy and formatting at ab0f22e1.
        The first ts1 launch lost completion before creating its report;
        recovery of build 30087403704156584 acknowledges terminal delivery 102
        (execution 255, earlier daemon 130). No check body ran. A fresh
        `.rch-tmp/rabs-static-ab0f22e1-ts1-admitted/` invocation ends 0:
        check 500.160s, strict Clippy 547.704s, formatting 10.655s.
      - [x] Run its full daemon and wrapper libraries and complete metadata
        protocol integration harness, retaining every failure independently.
        `.rch-tmp/rabs-merged-ab0f22e1/` ends 0: daemon including ignored native
        case 1,309/1,309 (34.24s), wrapper 109/109 (4.60s), live protocol 8/8
        (0.56s), metadata protocol 13/13 (4.80s). Matching real Cargo worktrees
        pass 11/11 (210.43s), all binary hashes stable. The runner records
        224.819s preparation and 215.802s tests. Three tiny-fixture observations
        still favor stock: 136.849/176.400ms, 140.079/183.519ms and
        138.343/185.997ms, stock/served. No performance win follows.
        Matching tools/harness were preserved on XFS before target reuse;
        `preserved-worktrees-ab0f22e1/custody.json` binds their exact hashes.
      - [ ] Qualify the new remote prefix path with actual canonical Cargo;
        its fixture/socket tests alone do not prove real compiler pipelining.
  - [x] Run full native component libraries at bd5a74f9: coordinator 1,274
    passed/7 failed/1 ignored, sandbox 413/18/8, worker 319/7/2. Retain every
    failure and the 324.474s outer exit-101 run. No full-library pass yet.
  - [x] Make the affected sandbox/daemon/worker positive fixture parents
    explicitly 0700 under umask 0002. Preserve the production ownership gate;
    add filesystem negatives proving 0770/0707 parents refuse before creation.
  - [x] Repair output-contract fixture setup to include mandatory dep-info;
    preserve every original assertion and add link/metadata-only refusal twins.
  - [x] Supply the generated-input fixture's complete empty OUT_DIR listing.
  - [x] Keep workspace native preflight bound to its own OUT_DIR rather than
    treating an unbound path as an independently captured foreign producer.
  - [x] Use the same output-refusal representation in preflight and full planning.
  - [ ] Natively verify those repairs against all original library cases,
    including the new path/refusal tests and the rabs-key library.
    At 22c7670b the key library passed 436/436 in 23.16s. Sandbox/daemon/worker
    commands exited 101 during compilation of the same three descriptor-error
    conversions; their test bodies did not execute. All six command receipts
    and source stamp are retained in `.rch-tmp/rabs-component-tests-22c7670b/run.jsonl`.
    - [x] Corrected c4e1b570 sandbox library on ts1: 433 passed, zero failed,
      eight ignored, 14.66s. All 18 previous failures and both new filesystem
      refusal/path-proof cases pass; this is an executed Linux library result.
    - [x] Inspect and run the eight ignored sandbox and two ignored worker
      cases on a capable Linux host, preserving their original capability gates.
      Ordinary library green does not imply those native cases executed.
      Four retained-runtime fixture owners and the two ignored worker reflink
      parents now use explicit 0700 creation under umask 0002 through the existing
      private fixture helpers; every compile, CoW, byte and escape assertion remains.
      The source-cache CoW fixture's nested input and receiver owners also now
      request 0700 explicitly on that same XFS root; ordinary tempdir defaults
      otherwise violate the receiver's existing private-parent requirement.
      trj has cc/ar and a real CoW-capable XFS root. Unprivileged user-namespace
      remapping is refused; its already-authorized `sudo -n unshare --mount
      --propagation private true` probe succeeds. Run the original private-mount
      case as a separately bounded privileged test, with no host mount changes
      and no root Cargo compilation or modification of the shared target.
      At 9ffe42d8, sandbox 440/440 passed (18.46s), including seven ignored
      real rustc/ELF/archive/namespace cases, with only the mount case filtered.
      The separately executed original private-mount case passed 1/1 (0.01s),
      inside `sudo -n unshare --mount --propagation private`, bounded at 45s.
      Cargo JSON selected its actual library harness; SHA-256
      `0f5dc54b7d633ca8bf413fde8831ea30fb6b67e822daedf2023ee8f5535b7ff7`
      and 21,710,432-byte length match before/after execution. All 441 cases
      therefore executed at this cut, with no ignores left unrun. Both worker
      CoW cases passed 2/2 (0.07s); coordinator toolchain CoW passed 1/1 (0.01s);
      the selected CAS metadata-pipeline cases passed 6/6 (0.40s). None of these
      narrow component results qualifies the whole canonical Cargo/TLS suite.
      Receipts: `.rch-tmp/rabs-native-tests-9ffe42d8/run.jsonl` and
      `.rch-tmp/rabs-private-mount-9ffe42d8/{run.jsonl,artifacts.jsonl}`.
    - [x] Retain the corrected daemon library's terminal verdict.
      Frozen c4e1b570 on ts1 ended 1,277 passed, four failed, one ignored
      (39.34s). Its remaining failures are the warmed canonical generated
      fixture, propagated native preflight, missing own OUT_DIR, and output
      refusal classification; none is silently waived.
      - [x] Create the fixture's five canonical mapping directories with mode
        0700, retaining the production ancestor ownership/write checks.
      - [x] Derive propagated roots for both canonical preflight modes using
        the same bounded validator as final planning. This fixes a premature
        workspace refusal; producer records, exact inventories and negotiated
        worker capability remain mandatory downstream.
      - [x] Check the existing output option model before the local serving
        class, matching final derivation's refusal precedence. Both paths still
        reject object output in the local dependency lane.
      - [x] Natively rerun every original assertion after these three repairs.
        At 16a95337 the complete daemon library, including the original failure
        cases and producer-record refusal twins, passes 1,305/1,305.
      - [x] Qualify the corrected own-versus-foreign OUT_DIR expectation with
        actual producer-record refusal twins. The original two preliminary
        refusal assertions conflict with the implemented propagated-native
        contract (`propagated_native_roots_work_without_own_out_dir_and_bind_every_producer`).
        Its replacement requires an absent own root and the exact foreign root,
        on both original hosts. The new filesystem case uses that actual
        workspace planner, then proves missing and mismatched Cargo producer
        records cannot be captured; a complete matching record can, and omitting
        its binding still refuses. Existing host searches, modifiers, archive,
        tree, record and output-alias negatives remain unchanged. Retain the
        original C4 failure and publish the changed admission split: canonical
        foreign intent without consumer OUT_DIR may be planned; missing or
        mismatched producer evidence still cannot authorize execution. This
        aaaaa519 executes the new filesystem probe and corrected preflight
        assertions successfully. This is component proof, not milestone closure.
  - [ ] Resolve all six remaining worker target-reuse failures: metadata-context
    eligibility, real check source/data edits, Clippy edit-family consistency,
    failed-build restart reuse, test restart reuse, and package/target selections.
    Exact fixture root/tree/manifest diagnostics are added without changing
    expectations. These failures remain actual failed probes, not completed work.
    The eligibility check passes an empty required-output set to `TreeInventory::scan`,
    whose path validator rejects it before any source read. Use the existing
    `scan_complete` API, preserving its full closure and nonempty-tree checks.
    Add actual manifest-mutation, nonprivate-root, external-hard-link and symlink
    refusal cases; run every original target-reuse assertion before claiming repair.
    The original 22c7670b component invocation stays frozen to establish its result.
    - [x] At caf9529292ba5b12ae3b990a9e09daccfd4e2144, the original metadata
      eligibility, real check source/data edits and Clippy-family cases pass.
      The new actual manifest/0700/hard-link/symlink refusal test also passes.
    - [ ] Qualify failed-build restart, edited-test restart and package/target
      selection source edits. Native worker library: 324 passed, three failed,
      two ignored, 30.48s. All three failures expect restored codegen/build-script
      target seeds after a source/data edit. `metadata_seed` currently refuses
      codegen and project executors; complete same-source restart reuse passes.
      Preserve that refusal and all original assertions until the missing
      input/executor closure is proven. Do not count a cold correct compilation
      as successful target reuse, or relax the gate to close these failures.
  - [x] Run A012's original budget probe: 2/3 passed, one failed; its subsequent
    direction harness did not execute because Cargo stopped after that failure.
    The textual guard reports sandbox 6 > 4 and omits target-specific edges.
  - [ ] Audit all actual direct/platform edges and strengthen the detector;
    do not widen budgets to manufacture green. Independent manifest parsing
    reports sandbox 7/4, adapter 4/3, CAS 8/7, worker 13/9 and daemon 16/13.
    Wrapper remains 2/3 and protocol 0/0. Reopened original A012 and Epic A.
    The revised guards parse TOML with the already workspace-locked `toml` as
    a protocol **dev-only** dependency; its shipped runtime cone remains empty.
    They include every platform and actual renamed package, deduplicate the
    same edge across targets, and report all excesses. Budgets stay unchanged.
    Detector-fix win/lose split: the prior first failure was sandbox 6/4;
    corrected counts expose five failing crates (7/4, 4/3, 8/7, 13/9, 16/13).
    No previously rejected runtime edge becomes accepted. New multiline,
    target-table, duplicate-platform and renamed-forbidden-package cases must
    execute natively before this detector repair is considered verified.
    Resolve inherited workspace declarations too: an innocuous alias with
    `workspace = true` must not conceal a forbidden actual package, and the
    same inherited/direct edge across platforms must count once.
    Native corrected-source result at caf95292: direction 5/5 passed; budget
    three passed/one failed. Both new parser cases pass; all five over-budget
    crates are reported exactly as the independent TOML inventory predicts.
    - [x] Reject removal of active production reference SQLite as a budget trick;
      coordinator/janitor authority uses RusqliteEngine in janitor/store.rs.
    - [x] Identify the actual test-only filetime edge: the import is cfg(test),
      every use is in timestamp fixtures, while production uses held-file
      set_modified in materialization.rs/staged.rs. Preserve all fixture calls.
    - [x] Freeze manifest-only correction at 8e7815b0, with no gate or Rust code
      change. Original runtime edge set loses only filetime; dev declaration
      remains the same workspace version. Cargo.lock is unchanged.
    - [x] Formatting/diff checks and targeted UBS pass; no skipped Cargo phase is
      counted as compiler or test proof. Manifest SHA-256:
      13b8284eb99d30f2447ed955d8be46120fa8541cea91d438a03e912321ee9e9e.
    - [x] Finish the complete CAS library at the exact source below. Normal
      production checking and the original budget probe have completed.
      Expected direct-count split is CAS 7/7 with four other overages retained;
      the original test's actual result, not the parser prediction, decides.
      Preparation only: the 59,248,640-byte 8e source archive SHA-256 is
      ccacb2c0fa3073e375d5f1787aba66c3387878b2ec483481866b8affba34a367;
      full manifest SHA-256 is 86f43b1a00f14f66cc01c36df85ef98a398966f3ad5d686f3cddfa4e5ebb16be.
      All 1,729 regular files independently match the staged CSS checkout; only
      rabs-cas/Cargo.toml differs from the b5 tree. Rust/TOML/lock aggregate for
      1,199 files is 681716c29fa72bbbc575face748404570cf7255b2fad51d83a98d7f53ca97360.
      The 5,511-byte ten-command driver SHA-256 is
      e87b22cce07930d7d9f8436abad0e6d2f4aaf76e8faa99b14b3e6f8a560f5cd5.
      Script/manifest are UID-bound mode 0400 on TRJ, with before/after source
      type/content/executable-bit audits, original guards and real reflink root.
      Dispatch follows the b5 DSR terminal/process retirement. RCH owner is
      rchw-eb8e4541-cb57-46e3-9a34-90f2b7c58009, build 30080135327647985,
      fingerprint blake3:ce7a5861a3276c6013783673a3aa9012c4b191cf6173c9e9c10020cf07aa3383.
      All three guards pass. Normal CAS --lib check exits 0 in 785.619s;
      actual Cargo metadata exits 0, SHA-256
      1f3344286572d3130bf55a0b5c7d6333fc6ef48d9d5f93848faca17477fd6a11.
      It reports seven runtime edges and filetime only as a dev dependency.
      Original budget probe: three passed / one failed, 5.138s exit 101;
      CAS's excess is removed and the four other overages remain unchanged.
      Full CAS library passes 408/408, zero ignored, including real reflink,
      in 764.86s libtest / 791.293s command. Workspace/all-target check passes
      in 1,347.371s (Cargo 22m27s). Strict Clippy passes in 870.200s and fmt in
      8.434s. Final source audit retains zero byte/type/executable differences
      and the exact same 46 exclusions. Supported recovery confirms terminal
      101 and ACK true; no overall green status is manufactured.
    - [x] Finish mandatory workspace/all-target check, strict Clippy and fmt;
      retain source/binary/receipt custody and exact owner terminal ACK.
    - [ ] Resolve the remaining sandbox/adapter/worker/daemon runtime edges and
      complete A012's transitive-cone/license/reproducibility acceptance before
      closing the parent. A012 is in progress, not complete.
      Read-only follow-up finds no analogous test-only removal among sandbox's
      three extra edges: memchr drives leak scanning, rustix owns descriptor
      and process operations, and tempfile owns live toolchain/projection
      directories. Adapter rustix also participates in production process
      ownership. Keep these real requirements visible; no dependency is hidden
      behind an adapter or moved to dev-dependencies to satisfy the count.
  - [x] Execute the dependency-direction harness independently and retain its verdict.
    The original guard passed 4/4 at 22c7670b (0.635s command); this is the old
    detector and does not verify the subsequently corrected parser. Its separate
    budget probe remained red (2/3 passed, command 101).
  - [ ] Retain the 22c7670b check transport failure separately: build
    30087403704156506 lost confirmed SSH completion before compiler output;
    supported recovery acknowledged 255 (earlier daemon status 130). This is
    neither a source failure nor a successful check. Re-admit a fresh check
    only after the acknowledged terminal custody outcome.
    Further isolated check/transport launches at builds 30087403704156508
    and 30087403704156510 also ended in acknowledged 255; the canonical
    30087403704156507 setup never created its result directory and recovery
    acknowledged delivery 102. No runtime pass follows. A ts1 transport probe
    then succeeded exit 0; new c4e1b570 quality and canonical jobs both reached
    actual compiler execution on their respective workers. Do not repeat a
    source mutation against any active invocation.
    An extra guard invocation mistakenly fetched the older c4e1b570 execution
    clone while stamping caf95292. Preserve its evidence as invalid for the
    claimed source: build 30087403704156520 was explicitly cancelled through
    its own wrapper, terminal 143 acknowledged. Repoint that private checkout
    to the integration repository, verify the full 40-character source and clean
    status, and rerun into a new result directory. The corrected run above is
    `.rch-tmp/rabs-worker-guards-caf95292-correct-source/run.jsonl`; no stale
    guard result is promoted to a current-source pass.
    A later core-library setup (build 30087403704156525) also never created its
    result directory; supported recovery acknowledged 102 after execution 255.
    It adds no sandbox/daemon test result. The already admitted ts1 invocation
    continues to own the corrected library checks; do not clear worker claims.
- [x] Run real Cargo cross-worktree dependency acceptance to a terminal result (M4).
  - [x] Cold compiler execution, two comparisons, later compiler skip and stock byte parity.
  - [x] Registry and vendored inputs, source mutation/unlisted files, large packages/artifacts.
  - [x] Cargo Fresh rebuild and workspace-only edit; restricted build-script cases.
  - [x] Retain complete failures/refusals and distinguish support tests from Cargo tests.
  Native result: 10/10, exit 0, 212.75s of test execution at `a11a6788` on ts1;
  six real Cargo consumer cases plus four artifact-resolver/helper cases. This
  qualifies the narrow fixture behavior, not M4's still-open field/performance gates.
- [ ] Run canonical namespace and authenticated worker acceptance unchanged (M4/M9).
  - [x] Extend the existing native runner with `--suite canonical`: build wrapper,
    daemon, worker and Cargo supervisor together from source-checked Cargo JSON
    artifacts; include all original ignored tests and bound default test concurrency.
    The runner contract selection passed 25/25, exit 0, 23.715s on trj after
    lint cleanup, with explicit Cargo doubles; transcript
    `rabs-execute-20261030-runner-canonical-contract-final.log`.
    The first new contract run failed five subcases because artifact hashing
    still selected the original pair; corrected the selector and reran all 25.
  - [x] Prepare canonical Cargo's actual test graph before binding its daemon
    and harness: `cargo test --no-run`, source-checked JSON artifacts and unchanged
    binary checks before/after test execution. Its dev dependencies enable
    additional runtime/CAS features, so a normal-build daemon hash is insufficient.
    Expanded runner contract: 28/28, exit 0, 42.341s on trj; explicit Cargo doubles.
  - [x] Run the production base namespace argv with `/usr/bin/true`: exit 0 on
    trj and ts1. This proves namespace creation only, not a Cargo build.
  - [x] Run the complete-source canonical suite far enough to expose its first
    native failure: the benchmark compiled successfully, but the standalone
    coordinator's normal subsystem shutdown set its cancellation flag, making
    post-compile retained-input validation fail `source preparation cancelled`.
    Preserve the 26-case invocation: one failed, the second interrupted by
    supported cancellation, 24 unrun; outer 143, no full-suite verdict.
  - [x] Separate expected standalone subsystem drain from caller cancellation,
    using the existing unexpected-exit guard for both edge and coordinator.
    Preserve signal/unexpected-exit cancellation and retained-input validation.
  - [x] Run the new real-runtime lifecycle regression for normal and already
    cancelled callers, plus existing unexpected-exit/shared-subscriber tests.
    At 6d9b174e all 30 canonical-local units passed, zero failed, 1,241 filtered
    out, 0.46s; test-profile compilation 5m22s, command 323.077s. This is actual
    coordinator/CAS/runtime and socket ownership testing, not native Cargo/TLS
    acceptance. Current workspace/all-target check also ended 0; receipt root
    `df819d86206bd6c63e0811bd6aa42103cbf3b5db4202db142e4a54eac2beaddd`.
  - [ ] Rerun every original canonical assertion, including the failed benchmark.
    A frozen 6d9b174e run builds the optimized `daemon-release` profile and
    includes all 26 cases, including ignored tests, with two Cargo jobs and
    unchanged assertions. Its wrapper shares that profile for functional
    acceptance; this does not qualify the separate tiny shipping-wrapper profile.
  - [x] Verify the original failed benchmark under optimized 6d9b174e: it now
    passes its no-run delivery and repeated current-execution assertions.
  - [x] Diagnose subsequent actual worker-dispatch failures: the pinned Rust
    loader emits `bin/../lib` and `bin/../lib/../lib` for retained internal DSOs;
    the generic ELF parser rejects them before any worker execution (0 vs 3
    required). Retain the exact `ldd` witness and every original failed assertion.
  - [x] Implement same-file, beneath-root descriptor proof for toolchain-local
    parent spellings. Retain generic/external traversal refusal, no-symlink and
    no-cross-device resolution, exact root/file stamps and existing key encoding.
  - [ ] Run the new filesystem path-proof cases and full native worker suite;
    keep unchanged every actual dispatch, earned replay, byte-parity and
    delivered-program assertion. Implementation alone establishes no pass.
    The 6d9b174e invocation lost confirmed outer completion after an attempted
    supported cancellation; later custody reports acknowledged 255. Its partial
    benchmark pass and worker failures are real; no full-suite verdict follows.
    The 22c7670b native component build exposed three missing explicit
    rustix-Errno-to-io conversions in the new descriptor helper (E0277).
    Correct the conversions and compile again; its 436/436 rabs-key result is
    independent of this sandbox compilation failure. Do not claim a path-proof
    test pass until the corrected Linux helper actually executes.
  - [x] Run the optimized c4e1b570 matching graph: normal tools built in 2m29s,
    actual test graph in 20m46s; all 27 cases, including ignored, were selected.
    The benchmark passed. Three archive/native Cargo cases failed their original
    command timeouts; the fifth case was interrupted and 22 were unrun. Supported
    cancellation of build 30087403704156517 acknowledged terminal 143. There is
    no full-suite pass or performance qualification.
  - [x] Retain native stall evidence: coordinator GDB reaches toolchain upload
    ACK handling; worker stacks and a three-second CPU profile are preserved.
    The 188-sample profile lost zero samples: about 49% formatting/allocation,
    26% memory copying. A repeated worker error hash matches the public system
    error `worker connect: Connection refused (os error 111)` during setup;
    that startup diagnostic alone does not explain an admitted transfer stall.
  - [x] Replace source/toolchain payload hex formatting's per-byte allocations
    with one bounded-capacity lowercase digit-table encoder. Keep the old
    formatter live in the same test invocation, compare every byte across an
    odd-ended multi-chunk payload, and retain both measured durations.
  - [ ] Execute that independent wire comparison and rerun the failed real
    Cargo cases with every original timeout, dispatch, replay, output and program
    assertion intact. The encoder is a profiled candidate, not a measured system
    win. A functional dev-profile run does not qualify shipping-profile latency.
    The comparison passes at 9ffe42d8, aaaaa519 and 16a95337. The focused
    optimized 9ffe rerun builds its normal tools in 72m49s and actual test graph
    in 25m12s (cold relocated dependency graph), then executes the original
    archive offload case in 167.76s. It fails 0/1, 29 filtered: three offers are
    admitted, all report `private remote compiler did not finish successfully`,
    and none completes. Stock fallback builds all four Cargo units successfully
    in 2m24s, below the original 300s bound; that is not successful offload.
    The complete runner ends 101 and retains its before/after binary hashes in
    `.rch-tmp/rabs-canonical-9ffe42d8-focused/{run.json,binaries.json}`.
    - [x] Capture the exact worker compiler failure. A bounded diagnostic
      rerun keeps the same frozen source, profile, test and deadlines. It
      attaches strace only to its own descendant worker, after binding its
      executable hash, UID/private fixture and process birth; only fd-2 writes
      are traced, at most 1 MiB and 210 seconds. No ptrace sysctl or process
      authority changes; this instrumented run is not performance proof.
      The traced case ends 101 in 262.60s; its trace limit expires before the
      compiler diagnostics, so no stderr body is claimed from that trace. A
      read-only inotify observer of its private request journal captures actual
      completed receipts: executed=true, exit=127, stop_reason=null, zero residual
      group members and stderr SHA-256
      `84e0fceb88836fb1fc6fa24c7cb2f6ed9b9804eacfef52e5f494404469c69f05`.
      That digest exactly identifies the reproduced loader diagnostic:
      `librustc_driver-71507feaec57108a.so: cannot open shared object file`.
      A same-invocation native bwrap control reproduces exit 127 and that exact
      stderr hash without procfs, then exits 0 for the pinned rustc -vV when
      LD_LIBRARY_PATH names the retained toolchain's lib directory. Its read-only
      host-library mounts make this a loader control, not worker qualification.
      Receipts: `.rch-tmp/rabs-canonical-9ffe42d8-traced/` and
      `/Volumes/trj-data/rabs-execute-20261031-loader-no-proc-control.jsonl`.
    - [x] Bind that selected loader path in the canonical driver's original
      command environment before source identity, Cargo planning and compiler
      key derivation (e8083f9d). It bypasses no loader-directory, runtime-cohort,
      sandbox or input-closure gate, and preserves the no-procfs archive view.
      Application-supplied LD_* controls remain forbidden. Four driver entries
      now consume the same 256-entry environment limit; its boundary test uses
      252 application entries, still rejects the 257th total, then removes one
      to restore 256. No limit is raised. Source changes are confined to the
      existing canonical driver; primitive sandbox/fixture files are unchanged.
      Formatting passes. Scoped UBS retains three pre-existing public FileSig
      comparisons misclassified as secret/signature comparisons (inode, device,
      size and timestamps), with 366 warnings/182 info; no suppression is added.
    - [ ] Complete source-e8083f9d full daemon, workspace/check/strict-Clippy/fmt
      and optimized canonical acceptance, preserving every original assertion
      and 300-second Cargo deadline. Reuse the quiescent optimized target at
      the same path; all five prior canonical binaries are first preserved by
      hash/length in XFS `preserved-canonical-9ffe42d8/custody.json`.
      - [x] Full daemon including the native toolchain case: 1,309/1,309,
        34.61s, command 68.668s, outer RCH exit 0. This includes the original
        environment value/override/bounds assertions with the same total limit.
      - [x] Finish static gates. The ts1 job was queued without admission and
        was cancelled through its own wrapper; recovery acknowledges 130, no
        build allocated. The first trj launch loses confirmed completion before
        its report; build 30087403704156613 recovers as acknowledged delivery
        102, execution 255. The fresh trj-admitted result directory remains
        was queued, with the source frozen. It is now admitted: workspace/all-
        target check exits 0 in 363.381s; strict Clippy exits 0 in 668.876s and
        formatting exits 0 in 6.832s. Outer RCH exit 0, terminal delivery complete.
        Receipt: `.rch-tmp/rabs-static-e8083f9d-trj-admitted/run.jsonl`.
      - [ ] Pass all 30 canonical cases. The initial e808 preparation selected
        /home/ubuntu/.cargo instead of the earlier /scratch/tmp/rch-cargo-cache-trj
        and began rebuilding unchanged optimized dependencies. Its cancellation
        RPC times out (RCH-E504); supported recovery acknowledges terminal 255
        for build 30087403704156607. Only a partial Cargo build log exists;
        no test ran. An own-target process census confirms quiescence before
        reuse. A new result directory fixes that same existing Cargo cache
        explicitly is now admitted. Normal optimized tools compile in 14m55s;
        the actual test graph is compiling. Acceptance fixtures, comparison rounds,
        deadlines, profiles and assertions are unchanged; reusing compiler-build
        dependencies does not prewarm their independent caches or earn samples.
      - [x] Update README's opt-in/local-serving scope and the canonical
        environment documentation; preserve the source-bound qualification
        distinction and the fixed loader input's application-override refusal.
      - [ ] Integrate the newer d05cefb2 input projection and a1fe627c sealed-
        result continuation changes without mutating the active e8083f9d source.
      - [ ] Compile/check/strict-Clippy/fmt the merged daemon and worker; retain
        every new compiler or lint failure rather than inheriting e808's pass.
      - [ ] Run the projection/source-transfer/generated-input component cases,
        full relevant worker/daemon libraries, and live-result continuation
        receiver/TLS checks. Peer component reports do not qualify integration.
      - [ ] Bind matching tools at that merged cut for native Cargo/worker
        qualification, preserving the original deadlines, samples and assertions.
    - [ ] Repair the proven compiler/sandbox cause, preserve all original
      dispatch/replay/program assertions, rerun the focused case and then the
      applicable full canonical acceptance selection. Do not treat fallback,
      admission, successful transport or a local executable as an offload pass.
  - [ ] Exercise retained toolchain/runtime and private target roots with actual Cargo.
  - [ ] Local canonical dependency reuse and source invalidation across worktrees.
  - [ ] Real mutual TLS worker metadata execution, earned replay and no dispatch on hits.
  - [ ] Real archive execution, final delivered executable and observed program output.
  - [ ] Generated/native roots, propagated consumers, archive-byte and directory invalidation.
  - [ ] Pool occupancy/bypass, both worker slots and independent delivery ownership.
  - [ ] Wrong capability/pin, corrupt/partial output, lost ACK, cancellation and result-only recovery.
- [ ] Qualify shared canonical service and cross-edge authority (M6).
  - [ ] Compile the new persistent service and run its real concurrent Cargo fixture.
  - [ ] Two overlapping roots, third-root refusal, independent caller cancellation.
  - [ ] One authority with independent edges; root permits and C-1 jobserver accounting.
  - [ ] Delivered binary, Cargo Fresh state, source invalidation and stopped-service refusal.
  - [ ] Two distinct edge hosts join one action lineage; coordinator restart/stale-offer fencing.
  - [ ] Final-subscriber drain and no leaked process, token, lease, pin or partial destination.

### Current integration repair and execution TODO

- [x] Merge upstream d05cefb2/a1fe627c without changing the running e808 source.
  The sole conflict is the same six-case mutation-table type alias; all cases
  and assertions survive. Merge 9e5c7020 includes no manifest/lock changes.
- [x] Execute the new real-filesystem projection and real-socket continuation
  code within full native daemon/sandbox/worker runs; retain the actual reds.
- [x] Box the 232-byte owned continuation variant; add no lint allowance.
- [x] Set required private modes on two cache fixture parents and the TLS
  source receiver fixture. Production directory refusal remains unchanged.
- [x] Retire the prior cache writer before the corruption/reopen test's next
  owner. Corrupt bytes still require upload, cannot seal, then repair exactly.
- [x] Serve and verify zero-byte stdout before the failed compiler's stderr
  in the actual TLS receiver fixture; preserve compiler exit 101 and no output
  installation, no artifact request and no second execution assertions.
- [x] Correct the missing Unix trait import found by actual compilation.
- [x] Re-execute the complete TLS receiver suite: 26/26 at 2432bae3.
- [x] Finish 2432bae3 workspace/all-target check, strict Clippy and formatting.
- [x] Execute 2432bae3 matching real-Cargo worktrees and exact archive consumer.
  Preserve 10/11 worktrees and 0/1 archive, not a qualification pass.
  Normal optimized tools prepare in 2m31s with the existing cache context;
  runtime acceptance remains pending. Original 300s Cargo limits remain.
- [ ] Fix the next real canonical failure before another full 30-case run;
  retain all nine e808 failures, one interruption and ten unrun cases.
- [ ] Diagnose the real tracked-OUT_DIR refusal from complete decision records;
  retain the original execute/no-hit/no-publication and current-output assertions.
- [x] Re-execute that unchanged case alone, 1/1 at 4be42338; do not treat its
  pass as an established production repair. The complete rerun retains four
  distinct real-Cargo failures above, including two cleanup deadline failures.
- [x] Implement explicit no-delay policy on both authenticated socket paths.
- [x] Try typed kernel nonmembership filtering before complete owned-group
  verification. Actual 177 native tests reject it: Linux group zero cannot be
  represented by Rustix's return type. Retain both raw failures; no speedup.
- [x] Replace that query with bounded PID-checked procfs membership in ffd60644,
  preserving both sweeps, entry/deadline bounds, full member/thread identities
  and the successful-signal/live-member negative. Add group-zero fixture coverage.
  Actual 77 wrapper acceptance is 111/112 and the filter loses the same-invocation
  timing control. It is withdrawn at 478a8866; no performance win is claimed.
- [x] Restore the complete bounded wrapper observer after that measured loss,
  retaining both independent sweeps, original two-second budget, full identities,
  group-zero coverage and successful-signal/live-member negative.
- [x] Correct the transport wake timer's clock-domain mismatch in ffd60644.
  Injected time alone decides expiry; early native wakes rearm without granting
  expiry. Preserve the original exact-nanosecond J011 and native-wakeup tests.
- [x] Reuse scan storage and parse only the existing required fields in the
  shared process observer (77de3a25), without truncation or fewer observed PIDs.
- [x] Compile and execute the 77 wrapper target; retain 111/112 and withdraw the
  losing filter. Adapter compilation and later targets were interrupted by
  exact owned cancellation; supported recovery acknowledges terminal 255.
- [x] Diagnose the 177 metadata test hang from actual native thread state.
- [x] Bound the existing fixture's listener accept by its original ten-second
  IO budget; keep all original protocol assertions and stream deadlines.
- [x] Execute the complete final 1d081ac4 cohort, including the complete wrapper,
  complete adapter, original process-group cleanup negatives, native timer
  wakeups and actual TLS consumers. Existing 177/77 results remain red above.
  The 478 predecessor's results and superseded static commands remain explicit
  below; do not rerun a known obsolete source to manufacture qualification.
  All nineteen commands complete. Component fixes pass their original targets;
  budget, worker reuse and private-parent fixture reds remain explicit.
- [x] Recover an existing current CSS dispatcher without replacing/restarting
  the controller daemon or enabling Actions. Keep its one-slot capacity.
- [x] Diagnose the source gate's 1,191/1,199 refusal. Preserve target_cache source
  and reviewed public Git templates through private capsule exclusions; verify
  all 1,199 source hashes before Cargo. No global config or expected hash is weakened.
- [x] Retire only the obsolete 478 owner after its real-Cargo consumer finishes;
  retain all completed rows and interrupted/unrun phases. Supported recovery
  acknowledges 143 before any warm target reuse; CLI 255/daemon 130 remain distinct.
- [x] Retain complete 478 protocol 499/499, wrapper 112/112, metadata 10/13 and
  adapter 125/129 outcomes. Original cleanup/shutdown timing limits remain.
- [x] Execute all 1,328 daemon library cases and all four TLS/continuation
  targets at 478, zero ignored, all passing. Later source changes need their
  own relevant consumer checks; no distinct-host/fleet proof follows.
- [x] Repair the actual completed-Sleep repoll in d6273c0e; require repeated
  early polls to stay live, arrange another wake and expire only at the exact
  injected-clock boundary. Complete adapter target at 1d passes 130/130,
  including the new negative, original J011 and native timer consumers.
- [x] Trace blocked-prefix failure against the exact native wrapper. It expires
  before stderr delivery after fixture formatting consumes about 357/500ms.
- [x] Prepare the identical fixture wire bytes before startup, keeping every
  product deadline and prefix/ACK/compiler assertion. Add subprocess diagnostics.
- [x] Execute the complete metadata protocol target at 1d: 13/13, zero ignored,
  both blocked-prefix lanes pass. Earlier no-connect failures do not reproduce;
  their cause remains unproven. No producer-generation latency claim follows.
- [x] Compile and execute the d627 repairs within the final 1d081ac4 cohort's
  complete adapter target, all thirteen metadata
  cases and actual TLS/continuation consumers. Publish both lane outcomes and
  retained failures; this fixture excludes producer-generation latency.
- [x] Run 1d081ac4 full workspace/all-target check, strict Clippy and formatting
  after unchanged disk guards; do not inherit the frozen 478 check results.
  All three exit 0: 1,064.900s / 264.688s / 7.295s.
- [x] Diagnose scan-count-based residual escalation in the actual cleanup
  failures; repair the original 100ms wall-clock policy at 1d081ac4 without
  reducing complete observations or treating a signal as settlement.
- [x] Compile and execute its slow-real-census regression, both original process
  timing cases, native shutdown bound and the complete adapter target: 130/130.
- [x] Complete the daemon and worker consumer targets at the same repaired source.
  Daemon and all four TLS/continuation targets pass; worker retains 337/340 with
  the three original Cargo reuse failures. This is execution, not qualification.
- [x] Strengthen the new slow-census falsifier when integrating the reviewed
  upstream snapshot: a 250ms injected full-scan delay guarantees the old ten-scan
  policy misses the unchanged two-second bound even on a fast host. Keep real
  processes, complete scans, independent settlement and reaping assertions;
  compile and run the strengthened test. Do not claim the current 120ms fixture
  deterministically rejects the old policy on every host.
  The 250ms version compiles and passes within the complete e7 adapter target:
  130/130, zero ignored or filtered, 46.20s libtest / 97.358s command.
- [x] Apply the 250ms falsifier and explicit 0700 fixture parents in the isolated
  integration checkout while the frozen full run continues. Formatting passes;
  scoped UBS findings remain reviewed and unsuppressed.
- [x] Compile and execute the full fourteen-case process-tree target after the
  private-parent fixture repair. Preserve every original compiler, namespace,
  jobserver, output, cancellation and process-settlement assertion, and report
  explicit SKIP markers separately from executed native cases.
  At e7a94e7c it passes 14/14, zero ignored, filtered or SKIP markers, 833.63s;
  command exits 0 in 860.953s. Every original assertion remains unchanged.
- [x] After the 478 real-Cargo consumer and terminal acknowledgment, launch
  the complete 1d cohort with all 1,199 source files verified and three guards 0.
- [x] Finish all nineteen declared commands at 1d081ac4, including full
  workspace/all-target check, strict Clippy, formatting and every original red.
  The unsubmitted d627-only probe is superseded and must not be launched.
  CLI 101; supported recovery completed 101, terminal ACK true. Preserve the
  overall failure and all per-command receipts; no cancellation or inherited pass.
- [x] Audit every tracked source byte independently during the frozen run:
  1,679 match, zero differ; only the 46 declared metadata/example exclusions
  are absent. Preserve the source audit and full public Git archive.
- [x] After the current full run and terminal ACK, retain the matching current
  dev pair and rerun the original real-rabs-key canary: stock plus four fresh
  wrapped targets, earned verification, unchanged serving policy, all metadata
  byte comparisons and before/after binary hashes. Do not seed trust or infer
  performance qualification from one ladder.
  All five actual Cargo commands pass, all eleven metadata files match stock,
  and the final round serves eight dependencies without dependency execution.
- [x] Review and integrate the fixed upstream dceec4f3 snapshot before publishing;
  it adds admission/cancellation/reconnect/submodule work and RCH recovery fixes
  across 57 files (15,452 insertions, 1,590 deletions), with no file deletion or
  Beads graph delta. Preserve the active source and all peer work; requalify the
  merged source rather than inheriting this cohort's runtime/static results.
- [x] Freeze corrected merged e7a94e7c in a new private source capsule and prepare the
  complete 23-command successor, with the native fixture and stronger falsifier
  first and a pre-Cargo audit of every nonexcluded tracked file. Retain the
  unsubmitted fde preparation as superseded; do not launch it.
- [x] Complete the changed-source scanner after its aggregate analyzer-output
  failure by scanning all fifty original files individually with unchanged rules.
  Retain all sixteen finding exits and review their critical contexts; no
  acceptance flag, rule or exclusion changes and no scanner-green claim.
- [x] Complete the admitted merged-source 23-command run to a terminal result
  and supported owner acknowledgment. Keep every red gate and distinct native,
  static, shipping, performance, canonical and fleet boundary visible.
  Admitted at 00:42:32 UTC; both source gates and all three original disk guards
  pass before compilation. All 23 commands finish, CLI 101, supported terminal
  ACK true. The baseline failures remain individually recorded.
- [x] Record the new merged daemon result, 1,342/1,343, and exact StaleDeferred
  failure before changing anything. Preserve the original queue-cancellation
  test and existing stale-replacement refusal assertions.
- [x] Retain the exact e7 daemon harness and reproduce the original failing case
  alone, 0/1, exit 101 with identical StaleDeferred, before follow-up validation.
  Preserve its hash and deterministic baseline receipt without weakening a gate.
- [x] Implement a draft recognizing reaped, cancelled, unstarted demand only
  under its originating supervisor, retaining foreign/consumed/replacement
  refusal and adding a cross-supervisor shutdown/cancellation regression.
- [x] Repair the compiler-reported mutable-reference-to-constant warning with
  an ordinary counter initialized to the same full member limit; no allowance
  or assertion change.
- [x] Retain the merged RCH common failure and exact compiled-harness baseline:
  explicit inherited SIGINT=SIG_IGN reproduces original timeout, 0/1, exit 101.
- [x] Draft explicit setup ownership of INT alongside TERM/HUP, restoring the
  exact caller dispositions at Cargo exec. Preserve every existing gate.
- [x] Prove the two new real-process regressions reject the old adapter (one
  pass/one error), then run all three draft Python suites under ignored INT:
  9/9 bootstrap, 16/16 lifetime, 9/9 cleanup, no skipped cases. Keep fixture
  Cargo/preparation scope distinct from the pending compiled Rust embedding.
- [x] Retain the complete daemon result, 1,913/1,923, and independently preserve
  the exact selected harness before later Cargo graphs can replace it.
- [x] Reproduce all three original API journal cases with the unchanged harness
  under both umasks: 0/3 at 002, 3/3 at 077. Retain every failure and the exact
  permission-guard positive/negative split before changing the fixtures.
- [x] Draft private create_new/mode-0600 creation for canonical positive lease
  fixtures only; preserve malformed/alias evidence and every production guard.
- [x] Use the exact read-only production CWD helpers to identify the separate
  seven-failure host inspection boundary: same PID 1 yields unknown as the
  worker user and known idle as root. No cleanup, signal or census omission.
- [x] Rebuild the three original API cases under the normal 002 umask and retain
  the unchanged writable-journal negative. Preserve the seven unprivileged
  cleanup failures pending qualification with complete inspection; do not skip
  inaccessible processes or claim that the read-only root control passes them.
  All seven scan cases pass at b5, zero ignored; full RCHd remains pending.
- [x] Retain the complete CLI result (3,917 passed, 28 failed, two ignored) and
  exact Cargo-selected native harness. Reproduce portable-verifier and legacy
  cancellation failures independently, 0/1 each, before changing their scope.
- [x] Draft a concrete /bin/sh binding only in the portable fixture's restricted
  no-Python PATH; preserve both genuine hash-tool variants and all original
  positive/thirteen-mutant checks. Format and scoped UBS pass; native pending.
- [x] Run the exact portable case with the compiled repair and both unchanged
  finite-input modes; retain the old missing-Bash failure and source witnesses.
  At b5 it passes 1/1, zero ignored, 3.62s; all original mutation checks remain.
- [x] Execute both separately ignored CLI storage probes with the retained e7
  executable and physical-XFS preflight: real clone 1/1; 2,048 durable rustdoc
  publications 1/1. Preserve assertions, hashes and fixture-only remote-exit scope.
- [ ] Resolve the original broader CLI failure inventory without weakening
  source/identity/ownership gates; these are not cancelled or reclassified:
  - [ ] hook::ssh::tests::durable_source_registry_repairs_empty_legacy_cancellation_as_unowned
  - [ ] hook::ssh::tests::source_lock_scaling_cancelled_acquisition_releases_its_prefix
  - [ ] hook::ssh::tests::source_lock_lifecycle_supervised_claim_release_and_caller_loss
    Added by the b5 full-suite result; preserved e7 also fails independently,
    while preserved b5 passes independently. Cause remains unestablished.
  - [ ] hook::ssh::tests::source_pair_claim_does_not_mutate_source_before_full_grant
  - [ ] hook::ssh::tests::source_pair_execution_transport_loss_preserves_a_running_reader
  - [ ] hook::ssh::tests::source_pair_holder_loss_blocks_setup_capability_fallback
  - [ ] hook::ssh::tests::source_pair_holder_loss_never_authorizes_another_writer
  - [ ] hook::ssh::tests::source_pair_serializes_until_retirement_and_explicit_release
  - [ ] hook::ssh::tests::terminal_cancellation_command_preserves_quoted_evidence_and_exact_control_result
  - [ ] hook::tests::a_refused_retry_selection_keeps_the_previous_admission
  - [ ] hook::tests::clean_overlay_subdirectory_real_git_archive_and_cargo_preserve_selected_cwd
  - [ ] hook::tests::retry_custody_deduplicates_refusals_and_cannot_complete_a_new_attempt
  - [ ] hook::tests::retry_custody_preserves_direct_readmission_and_leaves_first_admission_unarchived
  - [ ] hook::tests::retry_custody_survives_uncertain_selection_and_writer_loss
  - [ ] hook::tests::retry_failover_socket_preserves_endpoint_and_admission_constraints
  - [ ] hook::tests::retry_selection_cancelled_response_requires_explicit_terminal_receipt
  - [ ] hook::tests::retry_selection_definitive_refusal_restores_previous_settled_evidence
  - [ ] hook::tests::retry_selection_dropped_query_leaves_durable_pending_without_old_receipt
  - [ ] hook::tests::retry_selection_late_refusal_cannot_restore_over_confirmed_cancellation
  - [ ] hook::tests::retry_selection_old_observed_completion_cannot_acknowledge_new_admission
  - [ ] hook::tests::retry_selection_selected_response_stays_pending_until_new_admission
  - [ ] hook::tests::retry_selection_unconfirmed_retains_new_intent_and_never_exhausts
  - [ ] hook::tests::test_layer0_pack_reaches_the_executed_remote_command
  - [ ] hook::transfer_orchestration::recovery::recovery_completion::tests::retired_recovery_resumes_at_daemon_handoff_without_contacting_worker
  - [ ] hook::transfer_orchestration::recovery::result_recovery::tests::other_results_publish_and_terminal_failure_resumes_without_recollection
  - [ ] hook::transfer_orchestration::recovery::tests::returned_outputs_do_not_authorize_terminal_ack_until_sources_release
  - [ ] hook::transfer_orchestration::recovery::tests::terminal_cargo_recovery_checks_original_local_producer_before_shortcuts
  - [ ] transfer::tests::durable_execution_missing_receipt_does_not_block_on_unread_stderr
- [x] After the complete e7 run and terminal ACK, freeze the combined follow-up,
  compile and run the original failing queue case, complete SharedWork tests,
  new foreign-owner regression, submodule closure/budget tests, complete daemon
  and actual TLS/continuation consumers. Run mandatory full workspace/all-target
  check, strict Clippy and formatting; retain e7's warning and failure receipts.
  Also rebuild and execute the original RCH common embedding test, its complete
  library, and RCH daemon/CLI consumers after the embedded Python byte change.
  The b5 17-command invocation completes with the explicit failing full-suite
  outcomes above; this checks execution, not overall acceptance or qualification.
  - [x] Freeze exact b5 source, before-Cargo full-source audit and three guards.
  - [x] Original cancellation control 1/1 and complete SharedWork target 19/19.
  - [x] Original compiled bootstrap embedding 1/1, including all 34 Python cases.
  - [x] Workspace/all-target check, strict Clippy and formatting, all exit 0.
  - [x] Complete daemon 1,344/1,344 and all 44 continuation/TLS cases.
  - [x] Complete actual Cargo worktrees and retain their selected binary pair.
    Actual worktrees 11/11, protocol 8/8 and wrapper 112/112 all pass. Matching
    pair/harness retained under preserved-worktrees-b5b43b3e/custody.json with
    verified before/after hashes; daemon SHA-256
    713fafb21f3f9d4586008a4eee289f3cc0a15c57e5d533624517a9a624dd6d78.
  - [x] Complete RCH common, daemon and CLI libraries; retain all residual reds.
    Common 2,497 passed / eight ignored; daemon 1,916 passed / seven failed;
    CLI 3,917 passed / 28 failed / two ignored. Overall 101, not qualification.
  - [x] Complete final full-source audit and exact owner terminal acknowledgment.
    Zero source/type/mode differences, exact prior exclusions; supported ACK true.
- [x] Execute the original optimized archive consumer through DSR after owner
  ACK. The supported DSR outer build bound is 10,800s, matching the earlier
  native orchestration envelope; original canonical per-command 300s remains.
  Preserve the full pinned SDK and keep run records outside the source root.
  DSR defaults its native outer bound to 3,600s. This private diagnostic bound
  was declared before dispatch; it does not qualify the routine one-hour CI
  envelope. The actual cold compile exceeds an hour while the pinned Git
  Asupersync compiler remains CPU-active. Preserve that build-cost gap, with no
  claim that runtime, shipping CI or the original archive consumer has passed.
  - [x] Prepare clean exact-tagged source and strict diagnostic-native dry-run,
    native TRJ only, concurrency one, nonpublishable, all storage floors intact.
  - [x] Confirm prior exact owner ACK, dispatch DSR, bind source/tag/run identity,
    synchronize exact source and pass actual target/tmp guards before compilation.
  - [x] Finish optimized tools/harness and verify actual Cargo-selected identities.
    Tools finish in 80m40s and daemon/harness preparation in 70m22s, both exit 0.
    Existing strict Cargo-JSON artifact collection identifies all five binaries;
    CoW copies match original bytes before/after capture. Local genuine custody
    receipt is rabs-dsr-diagnostic-20261101/canonical-custody.json, SHA-256
    de1b87edbcbafb8e443da8d63013453884f99ec1bcd088b872e4ffd8cab0641d.
    Optimized daemon SHA-256 is
    a4c23bd349648909d3a8d87f26a384cce4d3939b1090f7f86e9b6bc723b69c53;
    harness SHA-256 is
    058b6998f17c015007785092abb677558ff76c73aa5f12efd920f17b1912a063.
    At 06:12:18 UTC libtest reports running exactly one original archive case.
    Its runtime verdict and the post-execution custody check remain pending.
  - [x] Execute the unchanged original archive consumer and retain its raw verdict.
    0 passed / one failed / zero ignored / 30 filtered, 330.02s. First command
    times out at its original 300s bound; coordinator admission is logged, but
    the worker journal has no completed execution. No archive/replay pass.
  - [x] Verify source/toolchain/artifact custody after execution and terminal DSR
    status; distinguish runtime, collection, packaging and portable ABI outcomes.
    DSR exits 6 after rejecting its final artifact inventory. Its native target
    incorrectly says success despite Cargo's 101; preserve both receipts.
    Source audit: all 1,729 files match, zero differences. All ten original and
    retained binary hashes match; archive-passed.json is absent. Postrun receipt
    SHA-256 c1067008b3bc66a5fc4dc272a211527d5bcc6b4bc4d7c540df62c1e4d66ba980.
    Read-only process checks find no surviving test/compiler processes.
- [ ] Resolve the first canonical remote-execution timeout with the full SDK,
  unchanged refusal policy and original 300s bound before expanding this suite.
  - [x] Count the actual unchanged SDK: 70,324 regular files, 2,486 directories,
    no symlinks, 2,950,651,711 logical bytes. This is input size, not proof of
    the timeout's cause; no SDK component is removed or substituted.
  - [x] Prepare an original-case repeat using the same five retained optimized
    b5 binaries, full source/binary audits and read-only own-descendant process
    CPU/I/O/thread counters. No debugger, syscall tracer, kernel setting,
    threshold, source instrumentation or product code change is introduced.
    Immutable 5,344-byte TRJ driver SHA-256 is
    3a504edef857c5340616109a4994d0fcdf6a683df8481111cb0291fffd243a8e.
    Its exact result directory matches declared RCH collection. Dispatch awaits
    the active 8e terminal/owner ACK and precedes the broader DSR test job.
  - [x] Execute that bounded functional diagnostic, retain the raw 1-case
    verdict and missing-counter states, then use the observations to distinguish
    ongoing SDK transfer from a stall. A repeat pass would show intermittency,
    not a source repair or a statistical performance improvement.
    Actual repeat: 0 passed / one failed / zero ignored / 30 filtered, 192.38s,
    strict RCH raw 101 and owner ACK true. The first Cargo build completed in
    2m54s with three successful real TLS remote archive executions; its fresh
    workspace and delivered-program (42) assertions passed. The next original
    assertion failed: two parsed metadata-prefix ACKs, three required. Raw
    stderr shows Cargo text splitting the first JSON event. No assertion,
    parser, timeout or SDK input was weakened. All 1,729 source files and ten
    retained/original binary hashes still match. Genuine five-file evidence is
    retained in /Volumes/trj-data/rabs-archive-observe-b5-20261101; acceptance
    log SHA-256 7934b4977031a98f01de5391cf4e30b2ddf4f34ddd25c164336b4a3fb1fceea3.
  - [x] Repair the observed shared-stderr framing defect in private main
    7f2a3f6632984b4e6dbff057bb46d0253c97699a: render each bounded event with
    both newline delimiters before one write; route the metadata ACK through
    that same writer at its existing real acknowledgement boundary.
  - [x] Add a real OS-pipe regression with a separate foreign writer: the
    previous formatter loses 128/128 deliberately interleaved records; the new
    writer must preserve every record and escaped field. This is an executable
    negative control, not yet a native test result. Formatting/diff checks pass;
    targeted UBS reports zero critical, 220 warnings and 64 info across the two
    complete files. Existing contextual findings are not a clean scanner claim.
  - [x] Compile/run the new pipe regression and full daemon library suite on
    Linux, then mandatory workspace/all-target check, strict Clippy and fmt.
    New regression: one passed / zero failed / zero ignored / 1,344 filtered,
    actual test 0.01s after native compilation. Full daemon library: 1,344
    passed / zero failed / one ignored, 63.80s. The ignored case is the explicit
    real reflink toolchain-capture probe, requiring RABS_REFLINK_TEST_ROOT.
    Workspace/all-target check exits zero (267.21s); strict Clippy exits zero
    (291.91s, -D warnings); formatting exits zero (7.97s).
    Wrapper rchw-c0986833-275f-41c9-b8aa-2ed6ae7af0fc / build
    30080135327648001 is terminal zero with owner ACK true. Thirteen genuine
    result files are SHA-verified in rabs-framing-7f2a3f66-results-20261101;
    run.json SHA-256 d90472724a58199fd8840f5513b05626402615b4b8d57cfb169fd260010cd6c9.
    A follow-up with a fresh physical
    Scratch reflink root and --include-ignored must complete before calling
    this a complete daemon-library qualification.
    Follow-up is prepared, not dispatched: five commands, fresh physical XFS
    reflink root, complete --include-ignored daemon library and the strengthened
    actual diagnostic consumer. Its 4,493-byte driver SHA-256 is
    3b05c3920c7050906d8bb5ac362b51f2a9df552f508bd3adaf7bd98e74fbc90e.
    The exact DSR fixture manifest SHA-256 is
    dc105db54a997409d2fbf99cf2c5f771f94dd4fab70faf6ce3844862315c41ce;
    it verifies that only inode identity differs in the replacement negative,
    and keeps preserved files outside the artifact inventory. Earlier unbound
    inode-fixture preparation is preserved unused; it has no execution verdict.
    This follow-up then completes raw zero, full daemon library 1,345 passed /
    zero failed / zero ignored (66.57s libtest, 67.35s command), including the
    real reflink probe; strengthened DSR consumer also zero. Source audits
    retain all 1,683 transferred RABS files with exactly 46 declared exclusions
    and all 409 DSR files, zero differences. Wrapper
    rchw-dd968e02-67f4-4d3d-99fd-b0ec1aa12d99 / build 30080135327648003 is
    terminal zero, owner ACK true. Eight genuine result files are SHA-verified
    locally; run.json SHA-256
    431572d6ce6aee8c92eb0689a8bad21771d92ec92fc04d76a1931f634d27dfb7.
    Prepared strict RCH source 7f2a3f66: all 1,729 archive files, 1,199 Rust/
    manifest inputs; aggregate 0ef3f92b35099f32d3fb1e2a2b21ff9767d2c345ce204a6c15c66c3c39d1c3cd.
    Ten-command driver SHA-256
    3df19209dc35ee1fcd1ae26aaa52ae18be26eae4de1b57964261b1643b67eb11,
    5,073 bytes, exact result directory .rch-tmp/rabs-framing-7f2a3f66-20261101.
    The same batch first executes the corrected real DSR diagnostic fixture;
    its 409-file snapshot differs from the tested predecessor only in caller
    initialization. Test-file syntax and targeted UBS pass (zero findings).
    Dispatched at 08:17 UTC after the exact predecessor's terminal/owner ACK.
    All four original storage checks pass; corrected real DSR fixture is active.
  - [x] Build the exact repaired production-profile tools through DSR and rerun
    the unchanged original archive gate, retaining all three ACK assertions.
    The prior 300s timeout and subsequent receipt corruption remain failed
    evidence; first-build success alone does not qualify archive/replay.
    DSR run d844049b-b775-47f2-bdee-a9841cb14afd now terminates zero, one
    native Linux target successful, diagnostic-native/nonpublishable. The exact
    unchanged archive/replay consumer passes one / zero failed / zero ignored /
    30 filtered in 823.96s; each original 300s command bound remains intact.
    This current functional pass does not establish the cause of the older
    timeout or a comparative performance benefit. Genuine retained logs and
    final run.json are in rabs-dsr-diagnostic-20261101/system-7f2a3f66-retained-evidence.
- [ ] Repair DSR's two independently observed boundary errors before trusting
  subsequent target qualification. Keep the original run failed and unpublishable.
  - [x] Identify lost status: strict Unix reconstruction appends toolchain
    verification after the configured AND-list, masking a middle-command failure.
  - [x] Execute a four-case actual-shell/real-metadata baseline, retain failed
    setup separately, then verify preserved failure and no artifact collection.
    Final baseline is 3/4, with only early-AND falsely returning success and
    collecting an artifact. The fixed source is 4/4; the native supervisor's
    documented failure code is 6, while the controlled helper exits 101.
    Initial path/parser setup refusals and mistaken raw-code expectations are
    retained separately and are not product-gate or runtime passes.
  - [x] Capture configured build status explicitly before post-verification;
    preserve success and final/multiline failure. Broader toolchain negatives
    remain queued for the native unit and full-suite runs.
  - [x] Identify collection-purpose mismatch: cmd_build calls availability with
    its default release purpose for a diagnostic-native target.
  - [x] Pass the actual admitted purpose and explicit-contract requirement.
  - [x] Execute the new real locked Rust diagnostic-build consumer;
    verify same-purpose diagnostic collection while mismatched purpose and
    changed bytes/inodes still refuse. Do not weaken publication eligibility.
    Corrected caller executes successfully through strict RCH on the exact
    409-file snapshot: raw zero, 17.55s, actual Cargo build + real collector +
    nonpublishable manifest, same-purpose accepted, explicit release/default
    purposes refused and changed archive bytes refused. The original faulty
    fixture run remains failed; this result does not erase the broader 301/2.
    An explicit same-bytes/new-inode refusal assertion is now added to the
    existing fixture. It preserves both files, restores the original inode,
    requires original receipt availability again, then independently corrupts
    bytes. No inode-refusal result is inherited from the earlier byte-only run.
    Strengthened real consumer subsequently passes on Linux, raw zero, 19.62s:
    actual locked Cargo build/collection, nonpublication, same-purpose
    acceptance, explicit/default wrong-purpose refusal, identical-byte inode
    replacement refusal with no other receipt-field difference, original-inode
    restoration accepted, and independent byte-corruption refusal. Both files
    remain retained outside the tracked artifact inventory. Syntax/targeted UBS
    pass with zero findings. Production source is unchanged between these runs.
  - [ ] Run focused regressions, syntax/ShellCheck/UBS and appropriate broader
    DSR checks; preserve concurrent source/index changes and all failed receipts.
    Bash syntax checks pass; four-file targeted UBS passes with zero critical,
    zero warnings and 249 info. Full local ShellCheck terminates 143 without
    a verdict; no pass is claimed. The native successor repeats that exact
    whole-scope command and syntax checks. The two
    409-file frozen DSR snapshots differ only in dsr and src/act_runner.sh; same
    test inputs, all source bytes verified after capture. Immutable TRJ driver
    was 3,991 bytes; that unused preparation remains preserved. Current
    eleven-command driver is 4,302 bytes, SHA-256
    61544c692398f2ecf3dc895a2659b9a7fcd01d65db72e757e5d75ca86ede00b2.
    The first execution refused the original /var/tmp storage floor (13.3886%
    free versus 14% required), without executing tests. After its terminal ACK,
    a successor uses documented DSR_STRICT_BUILD_ROOT on physical Scratch for
    both strict diagnostic fixtures. All original 20G guards pass; no threshold,
    cleanup or global configuration changes. Its 4,713-byte driver SHA-256 is
    7d5bc30b7b06f88460171bf8255a80209745955fd99abae8892669e21ea5b175.
    Actual worker status regression: baseline 3/4, repaired 4/4. Baseline real
    diagnostic build exits 6 at the observed collection-purpose error; repaired
    cmd_build actually compiles/collects successfully, one successful target,
    nonpublishable diagnostic manifest. The test then fails its own uninitialized
    workspace lookup. Corrected caller initialization is pending a successor
    run; same-purpose/mismatched-purpose/corrupt-byte assertions remain UNRUN.
    Full native unit checks finish raw 1: 301 passed, two failed. Preserve both
    failures: the real ordinary Cargo isolation test finds an existing but empty
    git directory (no operator config or checkout copied); genuine observation
    is operator-isolation-observation.json in the DSR evidence directory. The
    other test demands a mocked Go stage-cleanup command while this driver's
    explicit DSR_KEEP_BUILD_STAGES=1 deliberately retains stages. Neither failure
    is waived or counted as a pass. Whole-scope ShellCheck was stopped after
    728.59s of active analysis and approximately 17GB resident memory: raw 143,
    incomplete, not a pass. Only the exact own scanner PID was signaled through
    a verified pidfd/parent/source-root binding. Syntax exits zero. The full
    runner remains UNRUN: its unchanged original /var/tmp guard refuses 13.4157%
    free against 14%, raw one. No floor, test assertion or release gate changed.
    Whole eleven-command job exits one; both 409-file source snapshots still
    match every byte/executable bit. Wrapper rchw-b4686e43-031d-44d0-aa4f-6415efd848f0,
    build 30080135327647998, terminal/owner ACK true. Fourteen genuine result
    files are copied and independently SHA-verified under the DSR evidence
    directory's native-boundary-results; the raw broader failures remain.
  - [x] Compare the empty-Git-directory refusal with the identical baseline,
    preserving actual compile/config-isolation evidence before any gate change.
    - [x] Reproduce with actual filesystem/cache selection: baseline one passed /
      one failed; the checkout-only source incorrectly creates an empty private
      git directory. A database appearing during the copy is already refused.
      Frozen builder source matches the baseline module SHA-256
      1d775d3ffee883f26e5c3e255ec2445f1f311c076f090c5468a07758859ee14d;
      that independent preserved baseline still reproduces the same one/two.
    - [x] Omit only the unscoped Git namespace with no selected database; retain
      every source-root/missing-database anchor and drift comparison. Existing
      native isolation assertion is unchanged. New focused tests pass two/two.
    - [x] Run all 92 real filesystem/Git cache tests except the two genuine Rust
      consumers: 92 passed, zero failed, 44.12s. Source hashes are unchanged
      during execution; syntax and targeted UBS pass with zero findings.
      Receipt SHA-256 17fb8642d665e48edbbd93eb48c2ba4ef73a26ed86747246deb4e2a371d5c6de.
      Changed module SHA-256 45a7a03d7667532c34446f19fba9aafcd429ede1b8ebc8504d30eaa064ef217b.
      DCG rejected a dynamic test-argument list before execution; explicit literal
      selectors were used, with no override or bypass. The rejected command
      contributes no test evidence.
    - [x] Execute the unchanged original native isolation probe in the full
      native unit suite, plus both genuine Rust cache consumers, through strict
      RCH after the active DSR production job retires. Current 92/94 selection
      is not a full cache-suite or repaired native-isolation qualification.
      The active DSR build keeps its original immutable builder snapshot.
      The separate relocated-root suite also passes 16/16 on the same captured
      cache module, 6.70s; log SHA-256
      8d27b14bb71ff7b53b4517652af3261107d302c53b817f291c325bb9e762f16f.
      Final native follow-up is prepared and admitted November 1 after source
      404's terminal ACK: 409 files based on
      the earlier frozen working cut with exactly four captured file updates,
      manifest SHA-256 b6e79bbed8423015cae6544471029d634db4bf5a4ae08a6c3cbd2817afe68eea.
      Nine-command driver is 4,048 bytes, SHA-256
      33a7ce3de7bfb02182add31f95f70a5ed062dcd99c0b0539141adc293af68723.
      Actual native follow-up completes: full native unit script 304 passed /
      zero failed, 343.50s; complete cache suite 94/94 including both genuine
      offline Rust consumers, 13.92s; actual diagnostic-purpose build zero,
      17.68s; relocated-root suite 16/16, 2.98s; syntax zero. All 409 source
      bytes/executable bits match before/after. The last original /var/tmp
      storage guard refuses 11.060784765625% free against 14%; default full
      suite is UNRUN, no timeout/floor changes or cleanup. Whole batch remains
      raw one, owner ACK true: rchw-15869902-bc91-4c7e-8f16-4f47fbef3952 /
      build 30080135327648017. Twelve genuine receipt/log files are copied and
      SHA-verified in rabs-dsr-final-native-results-20261101; run.json SHA
      ba6b8f08451b127b9c5153efce2e50f4a69c7565c712ebc8c86a4e345462e16e.
      This repairs the two original scoped failures, not full DSR qualification.
      It retains the original root storage guard and full-runner 120s defaults;
      no native or full-suite result exists yet. Prioritize the active RABS
      gate's diagnosis/next real consumer before this broader DSR follow-up.
  - [x] Repeat the Go staging/cleanup assertion with its intended fixture-local
    retention setting; preserve the original 301/2 broader result separately.
    Actual same-source Mac baseline: cleanup mode two passed / zero failed;
    caller retention mode one passed / one failed. The existing cleanup
    assertion was expecting removal after requesting retention. Revised the
    existing fixture to explicitly exercise both policies, keeping every old
    staging/collection/cleanup predicate and adding retention refusal of a
    cleanup command. New --output-stage-only selects this existing test without
    unrelated Cargo executions. Both caller settings now pass three/zero, in
    7.00s/7.38s. Transports remain the original unit mocks, not actual Go builds;
    no compiler executes. Before/after hashes cover all production modules and
    the test; only the test differs across baseline/fixed. Genuine receipts and
    a review patch are retained under the DSR evidence directory. Native full
    301/2 remains its original raw result; no full-suite green is inferred.
    The 54 watched files are byte-stable within both executions; receipts
    SHA-256 ae8971d3639c4ea8e511134fb4ee968bb0c4831e1dec1c0402f496e627f90b45 /
    99bc4f5d0b646706c2f357ee38089213974a71034b952733e53dad27ed802d0e.
    Bash syntax and targeted UBS pass: zero critical, zero warnings, 180 info.
    The source snapshot used by the active DSR build is unchanged.
- [x] Execute corrected C010 through DSR with the actual production
  wrapper-release/daemon-release pair after the active archive-probe run retires.
  - [x] Prepare private nonpublishable native recipe, explicit Cargo commands,
    production/test-graph/restore hash records and direct prepared-harness launch.
  - [x] Validate shell/Python syntax, DSR read-only target selection and strict
    dry-run, all exit 0. The five warmups, 60 samples and 10ms p95 limit remain.
    Recipe SHA-256: 9492ae6952f59e82a1a4f821247edfe75b980ad956bd1d300eebc13483ab8908.
    That b5 preparation is superseded, never dispatched. The queued recipe is
    rebound to clean owned source `/Users/jemanuel/projects/rabs_dsr_execution_8e_20261101`,
    exact private tag v2.1.34-rabsdiag.8e7815b0, strict dry-run 0 / nonpublishable /
    native TRJ / one job. Current recipe SHA-256:
    c19e8434d5f7d6d8cac6bed06fef2f018b42a0d3ead22c65d758b0cd45aa0c6f.
    The original timing inputs and graph-restoration checks are unchanged;
    actual dispatch waits for the b5 DSR terminal and 8e native validation.
    That 8e plan is now superseded, never dispatched. A combined original
    archive/C010 DSR consumer is prepared for clean private source 7f2a3f66,
    tag v2.1.34-rabsdiag.7f2a3f66, outside the managed projects directory at
    /Users/jemanuel/.local/state/rabs-dsr-source-7f2a3f66-20261101. Its exact
    recipe SHA-256 is 8d7445f8dfebd9930058c2b7b3c0ac5564ba39a56b1496789f889837b43fa131;
    shell and all three inline Python programs parse, strict native dry-run
    exits zero (one TRJ job, nonpublishable, no build executed). It records real
    production daemon/worker/root/wrapper bytes before building both harnesses,
    restores both original production build graphs and requires byte identity.
    Both original consumers then run directly, each raw verdict retained even
    if the other fails. This avoids another duplicate complete optimized build;
    original archive 300s and C010 five-warmup/60-sample/10ms gates remain exact.
    Dispatch is gated on the new native checks and real DSR refusal assertions.
    Those prerequisites pass. Actual DSR build begins 08:33:33 UTC, run
    d844049b-b775-47f2-bdee-a9841cb14afd, native linux/amd64 on TRJ, one job,
    diagnostic-native/nonpublishable. Before invocation, all 1,729 source files,
    all 409 frozen builder files and the exact recipe match their manifests;
    private source HEAD and tag both resolve to 7f2a3f66, clean working tree.
    Production daemon/worker/root-tool build finishes zero (38m23s), followed
    by production wrapper-release zero (10.60s). Actual production fingerprints
    are recorded; the canonical harness dependency graph is now compiling.
    Canonical harness build finishes zero (41m23s), overhead harness zero
    (17.82s), production graph restores zero (0.41s daemon / 0.14s wrapper).
    The restored four-tool production map exactly matches the original map.
    Both original runtime consumers finish zero: archive one passed (823.96s),
    overhead/support five passed (0.27s), zero failed or ignored. C010 p95 is
    4,562us against the unchanged 10,000us limit, five warmups / 60 samples.
    This is the absolute harness SLO, not a comparative acceleration claim.
    Final DSR exit zero, native target one / one, actual collected artifact one;
    diagnostic-native and publishable=false. No release or Actions invocation.
    Independent postrun verifies all 1,729 source inputs and all 12 original/
    retained binary hashes unchanged; receipt SHA-256
    aceec063d26fc9f8c2e59c02416e722bc6a010b8d3fe526d1d690f58357c3017.
  - [x] Build the production pair and harness, prove the restored wrapper equals
    its recorded production bytes, then run all original overhead/support cases.
  - [x] Preserve the raw latency verdict and before/after artifact hashes, with
    no win claim without a live incumbent comparison or gate weakening after loss.
  This diagnostic primary archive contains only the wrapper; matching daemon
  and harness are independently retained. It is not S7 packaging or ABI proof.
- [ ] Profile current real-repository cold/first-verification costs with a live
  stock comparator and original policy before claiming an acceleration benefit.
  Keep the actual 122.384s/110.082s costs visible; do not select only warm hits.
  The unchanged lockfile contains distinct registry and pinned-Git Asupersync
  0.5.0 packages. Eight fsqlite crates select the registry package; rabsd,
  rabs-wkr and rabs-asupersync select revision 78b64636. Audit the resulting
  cold-build cost and API/runtime implications before considering unification.
  This source observation is not a measured saving, and neither pin is changed.
- [ ] Run the newly merged original canonical workspace-queue consumer with
  matching optimized tools after the original archive canary. It must show
  distinct fresh same-key workspace executions and cancellation of one waiter
  without coalescing, replay, fallback or cancellation of the other. The e7
  library failure and draft fix do not establish this real Cargo/TLS behavior.
  - [x] Run the unchanged original workspace queue consumer against the exact
    six retained production tools/harnesses from DSR source 7f2a3f66. Raw 101,
    zero passed / one failed / zero ignored / 30 filtered, 95.92s. Three
    independent same-key queue identities and one real worker admission are
    observed before cancelling one caller. The test times out at its original
    30s drain assertion: service says "operation was cancelled", while the
    original assertion requires "operation was drained". Operation-directory
    removal at failure is not independently established by that OR condition.
    All source inputs and all 12 binary hashes still match. Genuine four-file
    evidence is in rabs-workspace-queue-7f2a3f66-results-20261101; run.json
    SHA-256 b8abfcf6dffa93e4b122f59aabe0ce278fe77d86d3a4601844f014540f224220.
    The RCH published inventory uses a different digest; its 2d161915 value
    must not be labelled SHA-256. The copied files were independently hashed
    with sha256sum remotely and hashlib locally, all four matching.
    Wrapper rchw-31b16795-f115-460e-b8c4-016d8bc8b232 / build
    30080135327648008 is terminal 101, supported owner ACK true.
  - [x] Trace ownership: OperationOwner::drop already cancels and joins; the
    wire emits its error before that join, and is also used before admission.
    Move the drained confirmation to the relay boundary after dropping/joining
    its owner; make wire EOF report disconnection without claiming ownership.
    Strengthen the existing real Unix-socket test with an output-readable
    half-close and exact post-drain error plus completed-writer assertions.
    Source edits are prepared; native validation is still pending. No original
    acceptance assertion, timeout, queue identity or worker policy is changed.
    Review narrows the confirmation to OperationOwner::check_client after
    explicit stop_and_join. Worker-side ConnectionAborted errors preserve their
    cause; a second component regression checks that distinction. The wire
    reports only disconnection and never claims an unadmitted operation drained.
    A superseded candidate's exact own RCH job was cooperatively cancelled:
    rchw-562b9cf0-3d4c-4df8-8cc6-411393f5d68d / build 30080135327648009.
    Original outer SSH exit 255, daemon completion 130, recovered delivery 143,
    supported terminal ACK true. Three storage guards passed; its compilation
    did not finish and provides no native qualification. Its inputs/logs remain.
    Final working source is 7f2a3f66 plus exactly service.rs and service/wire.rs;
    1,729-file manifest SHA-256
    75a6b5e380f89af0e97458487634b6f331c1ecd7eec97e4d97d4584496aef235,
    archive SHA-256 2420ca680bf599feec959b9d1f0779e5c96fa560bcb570856cc9de280269e5ec.
    The two-file repair is now private main commit
    d4bb2fbb9b4d65bd032710a1c39e66bfbf3fee3a. Its clean 1,729-file archive
    is byte/type/executable-identical to that admitted working cut; source
    manifest SHA-256 abc289110a086592d746b71fb94d4057ae77e0ce5bf483a310de43ca204b10fa.
    The original checkout at b26b8682 has 240 concurrent dirty entries and
    remains untouched. This private commit is not canonical-main qualification.
    Native eight-command check is active through strict RCH; immutable driver
    4,325 bytes, SHA-256
    5da29da2e7cafd2a835e16fcdecd4ad4133627a5d52a0696fb42256d57f6f8e7.
    Full-file UBS raw one: one critical / 229 warnings / 31 info. The critical
    is the unchanged wire.rs:67 kernel peer UID equality misclassified as a
    secret comparison. Same-source baseline also flags it. Public UID metadata
    is not a bearer secret; no equality, UID gate, scanner rule or threshold
    was changed to obtain a green result. This remains an adjudicated scanner
    false positive, not a claim that the raw scan passed.
  - [x] Compile/run the strengthened real-socket regression and complete daemon
    library, then mandatory workspace all-target check, strict Clippy and fmt.
    Cancellation-only d4 candidate: all 12 service tests passed (0.75s), then
    complete daemon library 1,346 passed / zero failed / zero ignored (64.84s),
    including the physical reflink probe. Its workspace-check batch was stopped
    through exact-own supported cancellation after the combined source below
    superseded it. Wrapper rchw-54a13165-9463-46a2-b586-54b4671ca6a7 / build
    30080135327648010: outer 255, daemon 130, recovered delivery 143, owner ACK
    true. Workspace check unfinished; Clippy/fmt unrun in that batch, no whole
    batch pass. Eight genuine files SHA-verified locally; partial run.json
    SHA-256 84ddc8f4296eac18b6644217ddc9be3c77cd14bc10e0a0dccca6209369097a42.
    Independent post-cancel audit still matches 1,683 / 1,729 inputs with the
    exact 46 exclusions, zero differences; receipt SHA-256
    f8091e00e27e22192c09f99f59c68c0cda40cd523ba5a98f46466fa8a299a212.
  - [x] Inspect the service's remaining receipt writers against the observed
    framing defect. Four still stream serde_json Display into the shared stderr
    descriptor. Wire them to the existing single-frame writer, retaining each
    caller's prior write-error policy and every event field/meaning. Private main
    commit 6a79d4539dd7567788c644ef82e916744b347224; exactly three code files
    differ from 7f. Local rustfmt/diff checks zero. Full three-file UBS remains
    raw one (one unchanged public-UID false-positive critical / 442 warnings /
    89 info); no rule or policy is disabled. This is not a clean scanner claim.
  - [x] Finish combined source 6a's native checks before production execution.
    Source manifest df4f1113568a5ae8ef9977ad9cf8117dd4502513e53709ecb4bd200dd30fbff9,
    archive 51adfb5b6953c7e25020c39a28eb905f1b9e85c251a5196b5ba2004563935972,
    1,729 files / three exact code changes. Nine-command strict RCH job is
    active, after the predecessor's terminal ACK; immutable 4,560-byte driver
    SHA-256 fc54966c2dfc2501fda1038baacaf81a694008e9227ffbada4722e810e7960ee.
    All three original storage guards pass. Actual pipe negative-control
    regression passes one / zero failed / zero ignored (0.03s). Service tests
    pass 12 / zero failed / zero ignored (0.75s); complete daemon library passes
    1,346 / zero failed / zero ignored (75.19s), including real reflink. Required
    workspace check exits zero (1,449.94s), strict Clippy exits zero (674.15s,
    -D warnings), formatting zero (9.02s). All nine commands finish zero;
    source before/after matches 1,683 / 1,729 with exactly 46 exclusions, zero
    differences. Wrapper rchw-01490d70-92d9-4da3-9b32-1b7b8cb6a95a / build
    30080135327648011 is terminal zero, supported owner ACK true. Twelve genuine
    files are SHA-verified locally in rabs-service-6a79d453-results-20261101;
    run.json SHA-256 b222dbf1e951f4bfd0e028c9c19d85c5e14e8f18eeed6cca559076a721161a8f.
    Source code leases are released; only report/Beads leases remain active.
  - [x] Rebuild matching production tools through DSR and rerun the original
    queue consumer; retain the original raw 101 and all later raw verdicts.
    A new private diagnostic build command is prepared, not dispatched: exact
    source/ref binding awaits the final native check and private commit. It
    builds/restores both production graphs, retains all six Cargo-selected
    executables, and launches seven original canonical cases plus the five
    original overhead/support tests. Every successful invocation must also
    report its exact expected test count. No original fixture was edited.
    Shell and three inline Python programs parse; script SHA-256
    5217b3548a40bbf391e92089aa693a838fcd3d6e3f62615f6d8658ec4f8400a0.
    Strict DSR dry-run exits zero for private tag v2.1.34-rabsdiag.d4bb2fbb,
    one native TRJ target / one job / diagnostic-native / publishable=false.
    Recipe SHA-256 bb56b8b373ce157a67dff13575458d836e8d94cfae398d8a3c62fe45f1cc31d2.
    Preflight independently verifies all 1,729 clean source files and all 409
    frozen builder files; preflight SHA-256
    d2bb8930e485cd7aaad99177dc06a5b3de863d76ca22124f19078940fca4ce6a.
    The d4 recipe is now superseded and was never dispatched. Its preparation
    is retained. The combined source 6a is bound to private clean tag
    v2.1.34-rabsdiag.6a79d453 in a separate source clone. New DSR dry-run zero,
    one native TRJ target / one job / diagnostic-native / publishable=false;
    recipe f807cd23aa86fe8e2ffa15ba3af18d3af58c5ce236c744550fa8a264bc8ec433.
    All 1,729 source and 409 frozen builder files match independently;
    preflight ad0277592a99e601f151a99fc7eec4cb1dbd0ba3e25d0c6054a4412248953f00.
    Those native prerequisites now pass. Immediately before launch, all 1,729
    source inputs, 409 builder inputs, recipe and script hashes are rechecked;
    the private source is clean and HEAD/tag both equal 6a79d453. Actual DSR
    build starts 11:30:41 UTC, native TRJ / one job / diagnostic-native, original
    seven canonical cases plus five overhead/support cases pending. All earlier
    source cuts and all losing receipts remain. No Actions or publication.
    Actual run ID 1fb5e0ec-e660-4f4f-8ca4-0cb2b91b1774. Source sync completes
    and native Cargo compilation starts. Controller log delivery can lag;
    read-only /proc observations restricted to this exact run root show live
    compiler CPU progress through Asupersync, protocol and database crates.
    These observations are liveness diagnostics, not acceptance/performance
    results. All production build/restore and runtime verdicts remain pending.
    Production daemon tools now finish zero (33m20s), followed by the thin
    production wrapper zero (10.39s). Four Cargo-selected production hashes
    are recorded; wrapper is 606,600 bytes, SHA-256
    6793db9484196533e0ae0b70bd965ced086c102f630f96ca8acf73626fdb217b.
    Final run: six canonical passed / one failed / zero ignored, plus all five
    overhead/support tests passed. Archive passes one / zero / zero, 834.56s;
    C010 p95 is 3,988us against the unchanged 10ms SLO (five warmups, 60 samples).
    This is an absolute wrapper overhead check, not real-compiler acceleration.
    Native raw 101 propagates to DSR frontend six; status failed and
    publishable=false. The failing overlap teardown remains a failed case.
    All 12 original/retained binary hashes remain unchanged. Independent fresh
    postrun audit verifies all 1,729 source files, zero differences, all 12
    binary hashes and original SDK metadata: 70,324 regular files,
    2,950,651,711 logical bytes, zero symlinks. SDK bytes are not rehashed.
    Eleven genuine retained receipts/logs are copied and SHA-verified locally
    in rabs-dsr-service-6a79d453-20261101/retained-evidence. Final run.json SHA
    6266cce9335deb2f57eee654a7f22e25a112091ba059e104c4efd5e7cfb72e6f;
    fresh postrun receipt SHA
    86713e360dbec9eec43c0f40e554c672e5e9abd8e11de5d30e1d675a87766ff6.
    These build times are receipts, not a comparative speed claim.
  - [x] Run other original shared-service cancellation/admission consumers with
    the same pair, retaining exact denominators and unchanged safety assertions.
    Six original canonical consumers pass; overlap fails only its final image
    cleanup assertion. This execution checkbox is not whole-batch acceptance.
  - [ ] After fixing and verifying overlap, execute all 31 original canonical
    cases plus the new shutdown-control test (32 total) in one process,
    including every ignored native case and
    the remaining generated/native-input/namespace classes. Keep the original
    assertions and timeouts. This adds coverage and tests cross-case resource
    cleanup; the targeted invocations alone do not establish that full-suite
    behavior. Reuse the Cargo-selected retained production pair/harness and
    audit both source trees plus all 12 original/retained binary hashes before
    and after. Clear RCH's automatic fixture debug overrides to retain original
    Cargo defaults; no debug level is lowered to obtain a result.
    Source-6a draft rabs-canonical-all-6a79d453-20261101.py parses, 4,750 bytes;
    SHA-256 242b59680419aa1a431350514a40581d4dcd77a1bd9d42cf48b28bb3175d0047.
    It is now custody-bound but remains undispatched because source 6a has a
    known overlap teardown failure. Rebind the corrected 32-case source and
    explicitly distinguish any dev diagnostic from production qualification.
    No known failing source is dispatched to manufacture qualification. The full
    DSR/cache/native QA follow-up remains queued after these RABS consumers.
  - [ ] Resolve the new original service-overlap shutdown failure before the
    full canonical suite. Current 6a DSR build/restore steps all exit zero:
    canonical harness 26m17s, overhead harness 20.39s, daemon restore 0.42s,
    wrapper restore 0.24s; four production records exactly restored and all six
    executables retained. Custody SHA-256
    3487968921d8ed95e7bda943553174d74de8b6706d2ea7bdf5c9d16efd864e53 is
    provenance before the tests, not a runtime pass receipt.
    - [x] Execute the previously failing original workspace queue consumer:
      libtest one passed / zero failed / zero ignored, 213.56s. Its fresh
      executions, one-waiter cancellation, exact output and nonpublication
      assertions all remain unchanged. Full DSR batch is raw 101/frontend six.
    - [x] Retain new losing overlap result: zero passed / one failed / zero
      ignored, 72.28s, original canonical_check_local.rs:2171. Earlier overlap,
      cancellation, private-target reuse, source invalidation and output
      assertions passed; after final service cancellation, a retained compiler
      image still exists. Do not relabel this whole case as a pass.
    - [x] Identify a possible supervision mismatch without changing a gate:
      SharedServiceChild::finish(cancel=true) uses ManagedProcessGroup's
      250ms TERM/KILL escalation, while the test passes a 15s service budget.
      ToolchainPool::shutdown synchronously drops full retained SDK ownership.
      The paired unchanged-source diagnostic below establishes interrupted
      cleanup. Production service and pool ownership code are unchanged.
    - [x] Run a paired unchanged-source diagnostic after the DSR batch:
      real canonical Cargo check, full original SDK, original 250ms TERM/KILL
      supervision versus ordinary TERM with the existing 15s service budget.
      Record actual exit/signal, elapsed shutdown, SDK image/file counts and
      signal masks, preserving both fixture trees and all 12 executable hashes.
      Immutable 6,332-byte driver SHA-256
      3103f6d16cdd7dca9f8719103b575a618677df895eed7548aa29085690fd9833,
      physical Scratch inode 6932359586, mode 0400 / UID 1000 / one link.
      Strict RCH terminal zero, owner ACK true, wrapper
      rchw-aa5f7905-ad9d-4150-b578-4a3dab658ae0 / build 30080135327648015.
      Original 250ms: forced SIGKILL, exit -9 after 0.25738s; 60,551 SDK
      files remain. Ordinary TERM with the existing 15s budget: no KILL,
      exit zero after 1.26685s, zero retained images. Each starts with the
      original 70,324-file SDK; all 12 binaries remain byte-identical.
      Genuine run.json SHA
      d5a9dae3b0d0b1c5e6a3bc5f38082c793c4ab9812566b333398ebd7f763f1cd9.
      Both diagnostic fixture trees are preserved. No concurrent compiler job.
    - [x] Fix the demonstrated supervision defect; retain the
      losing original receipt and the exact evidence for any legitimate test
      correction. Preserve the original safety assertions and named budgets,
      include a negative control, and publish what the correction admits/refuses.
      Private main 404f98a5c425f2ab887494f7e6dff3b975aabc79 changes only
      canonical_check_local.rs. Ordinary service teardown uses existing
      graceful_shutdown within the original 15s total budget. Foreground
      client cancellation remains at 250ms. Image-emptiness assertions stay;
      clean exit zero, no escalatory KILL and resolved ownership are now also
      required. This admits cooperative full-SDK cleanup after 250ms but
      within the original budget; refuses TERM-ignoring and nonzero exits.
      New real-process test also proves the original policy interrupts a
      400ms cleanup, then the corrected helper lets it complete. Controls
      compile and pass one / zero / zero, 2.69s. The dev-profile original
      overlap then fails earlier, before teardown: zero / one / zero, 121.45s,
      toolchain capture interrupted. Source inspection finds the existing
      independent 120s preparation deadline; no budget is raised. This is
      consistent with a full-SDK dev capture hitting that bound, not evidence
      of corrected teardown in this consumer. Mandatory workspace/all-target
      check zero (276.90s), strict Clippy -D warnings zero (248.61s), formatting
      zero (7.40s). The nine-command batch retains overall raw 101. Source
      before/after matches 1,683 of 1,729 files with the exact 46 transfer
      exclusions, zero differences; retained wrapper/worker hashes stable.
      Wrapper rchw-6cc7f8d4-e4f5-40ea-b2c1-735094825995 / build
      30080135327648016 is terminal 101, owner ACK true. Twelve genuine files
      copied and SHA-verified locally in rabs-shutdown-404f98a5-results-20261101;
      run.json SHA
      fffaa21ab0f4efd89b62be6feb6bd0af397ef172c11127dc58ab0354901e75b9.
      Test source lease is released. M6 remains in progress.
      Full-file UBS raw one: three unchanged command-executable findings /
      1,050 warnings / 256 info. These same three calls occur in the baseline
      at lines 841/3666/4101: real fixture binaries and the explicitly selected
      worker, not new untrusted executable paths. The external baseline copy
      additionally flags six test panics because its path lacks tests/.
      No scanner rule, path gate or threshold was disabled; raw scan is not green.
    - [ ] Rerun the original overlap consumer and required source checks; only
      then resume the full original canonical suite.
      A production-profile DSR recipe is prepared for source 404f98a5: execute
      original overlap first, run all 32 canonical cases together only if that
      prerequisite passes, then all five overhead/support cases. Full suite is
      explicitly UNRUN if overlap fails; every raw failure propagates. The new
      batch limit is 21,600s, declared before its first invocation for the
      expanded 32-case scope; all original per-case/per-command bounds stay.
      Both production graphs and both harness graphs are built and restored;
      all 12 executable hashes remain checked. Clean 1,729-file source clone
      and private tag are verified; no public push or publication. Script
      6,420 bytes / SHA
      f46a8bac07bd8dab179517e36e61b7ba2f8d6ee265abc7ec7ea75a15681f3128;
      recipe SHA
      617d3c868061740cec57784f8c4234bf588ad9aadb4f609bc2bc828804ee6724.
      Native optimized execution remains gated on mandatory checks and the
      current own job's terminal ACK. That ACK is now true. The separately
      prepared DSR/cache nine-command native QA is admitted afterward as the
      only own compiler job; it now completes with the native/cache/diagnostic
      passes and original full-suite storage refusal recorded above. After its
      terminal ACK, all 409 corrected builder files are frozen in the separate
      rabs-dsr-tool-cache-fixed-20261101 directory (working cut, not a clean
      canonical commit). All 1,729 source inputs, 409 builder inputs, private
      HEAD/tag/clean status, script and recipe are verified before launch;
      preflight SHA
      32d9d502cd7b0d2d244d254d46f1c5edfd30346cfd3ad564a13515676894e158.
      Final dry-run zero, one native target, diagnostic-native, publishable=false.
      Actual DSR build starts 13:42:52 UTC, one job, corrected builder snapshot;
      this first attempt exits frontend one before compilation: its new private
      config directory omitted the inherited host configuration, so native
      source admission refuses. CLI run 9EF79CD8-3EA8-4C39-8212-A242AA429312;
      no product test result. Restore the exact preceding config/hosts/repos
      bytes, with the same Scratch build root, root free-space policy and one
      worker. Config/hosts/repos SHA respectively
      b0bfd430be33256f176e0bca5f9ab95f6b168dde4f35af1d615932940b24213c,
      c12f8e4ebfabd2d208dfd338a7f64a44b5c61addd8f2cb1096643ce8ea90b5a9,
      a3a0ceb96849dd8f4b1ca6d85244f32d6c9935fffb2dd2d7dd82888491ab1dec.
      Actual Scratch-host health is healthy=true / status ok, 481.51GiB free;
      no policy is lowered or global host configuration changed. Fresh source,
      builder, config and recipe preflight SHA
      2a2da6738e8c3141b624f068852c8e9723774471b38ecadcc3e1660517382b64.
      New DSR attempt starts 13:45:49 UTC, retaining the first logs; all
      optimized runtime outcomes remain pending. Both earlier builder cuts,
      all raw failures and the unchanged original-checkout work remain preserved.
  - [ ] Complete shared-checkout integration and qualify its captured source;
    private-cut evidence alone does not qualify evolving canonical main.
    - [x] Inspect the live checkout at observed HEAD
      2f8992fb164ab5254e2c9d68d857c498e7cd3939. Four runtime file contents are
      byte-identical to their exact pre-fix private bases; concurrent new tests
      and other changes remain distinct. Fresh advisory lease checks find no
      conflicts; reserve only these four files.
    - [x] Manually apply the already tested 7f/d4/6a runtime changes in the
      original checkout: server framing, delivery-ACK framing, four service
      receipts and owner-confirmed client drain. Each resulting file is
      byte-identical to the tested private runtime source; rustfmt check zero.
      Original HEAD/index/peer staging are not changed by this work. The
      original checkout is now modified by these four owned runtime repairs,
      superseding earlier historical statements that it remained untouched.
      All four source leases are released after this integration; report and
      Beads leases remain active. No shared index entries are staged or committed.
    - [ ] After the optimized overlap prerequisite passes, manually reconcile
      orderly service teardown and its real-process controls into the original
      canonical test file. Preserve every concurrent new leaf/selection case;
      the original test file is much larger than the frozen private copy.
    - [ ] Capture the merged shared source, preserve its actual working-cut
      identity, and run native pipe/service/daemon checks plus required
      workspace/all-target check, strict Clippy and fmt after the sole active
      DSR job retires. These combined-source commands are currently UNRUN;
      equality of four runtime files does not supply whole-workspace proof.
    - [x] Reconcile the execution history into the shared Beads tracker. Its
      JSONL/DB had remained at the initial reopened snapshot; private comments
      alone did not mark the shared task in progress. Supported import then
      additive reconciliation applies nine newer rows, zero creates/deletes.
      Two three-way note conflicts retain complete newer notes, each verified
      to include its old note verbatim. All 2,218 IDs, every old note/comment
      author/text/time, labels and dependency sets are preserved; br adds two
      merge audit comments and may normalize local comment IDs. Fresh sync
      status healthy, zero coverage drift; dependency cycles empty. M6 is
      in_progress and not closed. Original JSONL backup SHA
      b07fbc67c54cd0e9f76aae50ea6b0f47c7081c7e315a20629fbcd2a6c3b12166;
      immediately reconciled shared JSONL SHA
      4d1717b99d03a03993112900804f89969bfce70a80397ccc0d2d7fcd89f51356.
      Future Beads mutations target the original shared root; the private
      tracker history through comment 2195 remains preserved.
    Other current DSR libtest reports are one / zero failed / zero ignored
    apiece: admission queue 59.84s, origin cancellation 316.47s, queued shared
    cancellation 328.68s, failover 350.08s. Archive and overhead now pass as
    recorded above; one original teardown failure prevents batch qualification.
- [x] Retain the merged-source Cargo-selected dev pair, worktree harness and
  sandbox harness with before/after hashes before later targets can replace
  their build-graph artifacts. Preserve the e7 component evidence and its known
  cancellation failure, without a shipping or whole-program qualification claim.
- [x] After the combined repair's terminal ACK, repeat the original five-command
  repository canary with its exact final pair, unchanged verification policy and
  fresh stock/wrapped targets. Keep the 1d canary's successful but earlier-source
  scope explicit; do not run a known superseded pair to manufacture qualification.
  At b5 all five Cargo exits are 0, every wrapped metadata set equals stock,
  and the final round serves eight without dependency execution. Preserve the
  separate original RCH collection failure 102, supported terminal ACK and
  byte-verified genuine output archive; do not relabel that wrapper invocation.
- [x] Execute the separate private-mount probe with the retained merged-source
  sandbox harness and original real-bind-mount assertion; preserve the parent
  namespace and independent binary hashes.
  At e7 it passes 1/1, zero ignored, 0.03s; hash and parent namespace unchanged.
- [x] Execute CAS's separately ignored physical reflink case
  `materialization::tests::h017_real_reflink_backend_is_required_and_mutation_independent`
  using its retained current Cargo-selected harness and the existing private XFS
  root after that library compiles. The default library run must report this
  ignored case honestly; verified-copy fallback cannot satisfy its assertion.
  Exact retained e7 harness passes 1/1, zero ignored, 407 filtered, 0.04s;
  original physical-XFS disk guard 0 and before/after hashes unchanged. The
  ordinary library run and crash matrix remain separate pending results.
- [x] Re-execute the separate privileged mount case with the independently
  preserved current Cargo-selected sandbox harness and verify its binary hash
  before and after: 1/1, real private namespace, parent namespace unchanged.
  The retained executable permits this without reusing the active target.
- [ ] Execute the real socket-option case, all adapter/wrapper/daemon units,
  TLS/continuation cases, feature/direction/budget probes and complete real-Cargo
  worktrees. The 58f32a6a launch has no result directory and recovers terminal
  acknowledged 102; no native pass there. Its combined successor is frozen at
  4ea997bb, retaining all results including expected red budget acceptance.
- [x] Retain 58f32a6a's actual full check failure: 101, 2,369.779s. Clippy
  interrupted by owned cancellation, recovered terminal 143; fmt unrun.
- [x] Correct the PID conversion at 725bbfd2; scoped all-target wrapper check
  passes 41.76s. Full workspace/all-target check exits 0 in 5,773.280s;
  strict Clippy exits 0 in 2,899.601s and formatting exits 0 in 47.663s.
  Outer exit 0 and supported terminal acknowledgment precede source reuse.
- [x] Integrate upstream runtime reuse, workspace metadata delivery and private
  prefetch in the isolated checkout at 4ea997bb, keeping active sources frozen.
- [ ] After terminal acknowledgment frees an execution clone, compile and run
  4ea997bb's full adapter, daemon, sandbox and worker libraries plus TLS,
  continuation, metadata protocol and real-Cargo worktrees. Retain the original
  worker reuse and dependency-budget reds and distinguish peer component proof.
  The 4ea launch has no result directory and recovers acknowledged 102. Its
  725 successor is cancelled before start, recovered acknowledged 130. The
  combined native successor is frozen at 177acee0, including the buffer bound.
  That successor is now terminal, with adapter 125/128, wrapper 110/112, daemon
  1,326/1,328, worker 337/340, sandbox 458/458 and four TLS/continuation targets
  passing. Metadata is interrupted after six passes/six failures; retain that
  incomplete denominator. The 478 successor must qualify its own changes.
- [x] Finish strict Clippy and formatting at 725 after its passing full check.
- [ ] Qualify the later 177 buffer source explicitly, without inheriting a pass.
  Its separate native preflight passes and protocol execution is 499/499;
  full static is cancelled before admission after the real wrapper failure.
  The bound regression passes, but wrapper qualification is 110/112, red.
- [x] Execute the separate 177 privileged mount case after terminal ACK: 1/1
  passes against its exact Cargo-selected harness, preserving real bind-mount
  rejection and parent namespace assertions. This does not qualify 478.
- [ ] Re-run the original optimized archive consumer with TCP_NODELAY after the
  current shipping-profile target owner completes; preserve all 300s limits and
  the exact full toolchain. Do not overlap writers of that optimized target.
- [x] Wire C010 to actual shipping profiles using Cargo-selected byte identities.
- [x] Run all 32 runner regressions on Linux; preserve explicit Cargo-double scope.
- [x] Run the unchanged native overhead gate on the actual source-8d shipping
  profiles. Its wrapper has the confirmed dev graph; preserve its size and
  p95 116.913ms failure, four support passes, and withdraw shipping-pair proof.
- [x] Preserve the exact shipping binaries, raw failure, recovery acknowledgment
  and bounded pass-through syscall trace. No original bound is increased.
- [x] Implement bounded read-buffer reservation and exact byte/PID-limit regression.
- [x] Diagnose the overhead wrapper's dev-feature replacement from original
  Cargo records; implement production restoration and direct selected-harness
  execution without changing the Rust gate or any bound.
- [x] Execute all 36 runner regressions (80.265s), including failed restoration, changed
  wrapper/daemon/harness, inherited jobserver capacity, arguments, exits and
  signals. Explicit Cargo doubles establish orchestration only.
- [ ] Rerun the corrected harness against matching repaired production binaries.
  Bind the runner source separately from the frozen binary source, keep both
  hashes. The old 177 target owner recovers 255 ACK true after owned cancellation;
  its overhead body never runs. The 614 selection remains uncertain and its
  clone/target remain frozen. Use a separate source/target for new qualification.
- [ ] Compile and execute that candidate's full wrapper and Cargo consumers;
  rerun the unchanged shipping gate. A timing/control trace is not a gate pass.
  A separate one-slot wrapper-unit probe never admits, then is cancelled and
  recovered terminal acknowledged 130 with zero slots released. It cannot
  bypass the older multi-slot queue hold and adds no source receipt or test
  denominator. The combined native run retains the complete wrapper target.
- [ ] Close the codegen-input ownership/freshness gap behind the original three
  worker target-reuse failures; do not relax metadata_seed or its refusal tests.
- [ ] Retain source-bound receipts, update original M6/M8/M9 owners and rerun
  graph cycles; preserve the original dirty checkout and unacknowledged S7 job.

### Canonical e8083f9d case ledger

The preserved 9ffe42d8 Cargo-selected harness lists these 30 cases; the source
diff through e8083f9d adds a metadata-assertion helper, not a test function.
Membership is source inventory, not execution proof. Tick each only from the
new full-suite transcript, retaining any failure and the final denominator.
Its completed transcript supplies ten passes and nine failures. The twentieth
case was interrupted by the outer deadline; the last ten never ran.
Passes below are scoped to e8083f9d and do not qualify later merged changes.

- [x] `canonical_cargo_bench_delivers_no_run_then_executes_each_current_custom_harness`
- [x] `canonical_cargo_build_bundles_generated_native_archives_replays_and_invalidates_them`
- [ ] `canonical_cargo_build_executes_own_native_workspace_archives_fresh_while_dependencies_replay`
- [ ] `canonical_cargo_build_offloads_archives_replays_and_delivers_a_working_binary`
- [ ] `canonical_cargo_build_offloads_generated_archives_and_delivers_changed_output`
- [ ] `canonical_cargo_build_offloads_generated_archives_and_delivers_current_generated_code`
- [ ] `canonical_cargo_build_offloads_propagated_native_archives_and_invalidates_transitive_consumers`
- [x] `canonical_cargo_check_executes_own_native_workspace_metadata_fresh_while_dependencies_replay`
- [ ] `canonical_cargo_check_offloads_binary_example_and_test_harness_metadata_without_running_them`
- [x] `canonical_cargo_check_offloads_native_dependency_metadata_replays_and_invalidates_archives`
- [ ] `canonical_cargo_check_offloads_propagated_native_roots_and_invalidates_transitive_consumers`
- [x] `canonical_cargo_doctests_execute_with_captured_rustdoc_and_preserve_failures`
- [x] `canonical_cargo_earns_cross_worktree_dependency_hits_and_invalidates_changed_source`
- [ ] `canonical_cargo_offloads_generated_dependency_metadata_and_invalidates_generated_bytes`
- [ ] `canonical_cargo_offloads_generated_metadata_replays_and_invalidates_changed_out_dir`
- [x] `canonical_cargo_offloads_real_dependency_samples_then_replays_across_worktrees`
- [x] `canonical_cargo_run_preserves_default_target_input_arguments_and_every_current_exit`
- [x] `canonical_cargo_tests_deliver_no_run_artifacts_and_execute_each_current_run`
- [x] `canonical_clippy_preserves_current_lints_and_separates_private_target_families`
- [ ] `canonical_explicit_environment_rebuilds_private_targets_and_reaches_cargo_descendants`
- [ ] `canonical_private_targets_reuse_relocated_builds_and_preserve_current_outputs`
- [ ] `canonical_shared_client_refuses_missing_service_before_namespace_or_state_acquisition`
- [ ] `canonical_shared_environment_rebuilds_private_targets_without_ambient_service_inputs`
- [ ] `canonical_shared_remote_failover_preserves_generation_and_surviving_subscriber`
- [ ] `canonical_shared_remote_flight_survives_origin_cancellation`
- [ ] `canonical_shared_remote_queue_coalesces_and_survives_origin_cancellation`
- [ ] `canonical_shared_service_overlaps_builds_scopes_cancellation_and_reuses_private_targets`
- [ ] `canonical_shared_service_queues_before_capture_and_cancels_only_waiting_interest`
- [ ] `cli_refuses_executing_run_and_bench_terminal_input_before_touching_profile_roots`
- [ ] `cli_rejects_profile_environment_that_replaces_driver_control`

### Remaining distribution and roadmap checklist

- [ ] Repair and qualify distribution, then opt-in canary (S7/S8).
  - [x] Add complete receipts to the three failing assertions without changing deadlines
    or acceptance; preserve the original red 78-case run. Exact old failure cause remains unknown.
  - [x] Run all 78 installer regressions, including corrupt/mixed bundles and lost
    acknowledgments: exit 0, 121.445s on trj, transcript
    `/Volumes/trj-data/rabs-execute-20261030-installer-complete-inputs.log`, SHA-256
    `0f5819cfcf1a79a0a96a2c5669c2ff6785be71b19114e3ce92b149bcb4aeaabe`.
    A preceding copied test bundle omitted the launcher and exited 1 with 14
    setup errors; its transcript is retained as `rabs-execute-20261030-installer.log`.
  - [x] Exercise a fresh private bundle install with actual preserved native ELF
    tools from 2432bae3. The current installer/launcher bytes are identical to
    that source. All seven declared commands exit 0: install, actual Cargo plugin
    help, wrapper-to-true execution, daemon/worker/root versions and daemon config.
    Installation takes 2.033s; all five installed hashes match the retained
    inputs. Config binds the full source identity, live dependency stays false,
    and no socket/service is created. The retained private generation is
    `install-native-2432bae3-20261031/bin/.rabs-versions/gen-hj74rspd` on XFS;
    its `run.jsonl` and seven stdout/stderr pairs remain. This is from-bundle
    component proof only: all four binaries use daemon-release, including the
    3,137,168-byte wrapper. It does not satisfy shipping-profile/size acceptance,
    the archive CLI, managed upgrade, current-177 qualification or fleet rollout.
  - [x] Start that installed native daemon in fresh private state, send its real
    Unix-socket hello/status exchange, and let --run-for-ms 5000 shut it down.
    Status reports available, authority held, CAS/lease registry/destination
    arbiter mounted and prepared jobs accepting. Automatic exit is 0 in
    5.367s; the owned socket is retired and the binary hash is unchanged.
    Serving remains off. `lifecycle.jsonl` and daemon/status streams remain
    under the same private install root. This is a short 2432 component probe,
    not current-shipping qualification, elapsed soak or fleet deployment.
  - [ ] Build correct wrapper/daemon release profiles; validate actual complete archives.
  - [ ] Clean private install/upgrade on capable Linux hosts; version/hash/doctor checks.
  - [ ] Real-repository Cargo canary compared with stock/current RCH in the same invocation.
    Initial actual `rabs-key` canary is red: stock plus four wrapped checks exit
    0 with identical eleven-file metadata inventories, but each wrapped check
    records twelve shadow decisions and zero serves. Eight registry dependencies
    refuse `toolchain-refused: compiler path is not absolute`; ordinary Cargo
    passes bare `rustc`, while the successful fixtures force an absolute `RUSTC`.
  - [x] Implement caller-PATH compiler binding in the wrapper, without weakening
    the daemon's native-compiler/proxy checks, then rerun that real consumer.
    Safe effective-ID executable access uses the already-locked rustix; direct
    wrapper dependencies remain within the unchanged budget (two of three).
    Include missing/nonexecutable/directory/relative/symlink cases, a no-`RUSTC`
    real Cargo ladder, fresh binary pins, byte parity and the existing overhead
    and footprint gates. Rustup proxies remain refused until separately modeled.
  - [x] Compile the repair at 7c9c1828 and run all wrapper units on ts1:
    104/104 passed, exit 0, 4.88s, including the three new path/access cases.
  - [x] Finish the 11-case Cargo suite and wrapper socket/protocol tests at that source.
    The unchanged 11/11 Cargo suite (seven real Cargo cases, four support cases)
    passed in 305.28s; all 8/8 socket/protocol cases passed in 1.09s. Build,
    test-graph preparation and execution ended 0; full runner 555.315s.
  - [ ] Execute all thirteen current `metadata_protocol` wrapper cases on
    their actual Cargo-selected wrapper subprocess and Unix sockets. Keep
    every prefix/tail deadline, exact-identity, closed/blocked stderr and
    no-second-compiler assertion. Their daemon/artifact/compiler markers are
    explicit protocol fixtures; they are not real Cargo compilation proof.
    The 177 attempt records six passes/six failures and one unfinished case,
    then exact owned cancellation acknowledges terminal 255. Its unbounded
    fixture accept is fixed in 3e491a34; 478 verification is pending.
  - [ ] Requalify the matching real Cargo pair after the new metadata path.
  - [x] Rerun the real `rabs-key` stock/four-fresh-target canary with the newly
    fingerprinted pair; preserve the original zero-serving red result.
  - [x] Retain the updated NAS canary's refusal: eight executions committed,
    two rounds independently verified all eight, then eight hits all refused
    `private-stage-dir: staging directory is not private`. All five Cargo
    checks still exited 0 with eleven-file metadata inventories identical to
    stock; the canary correctly ended 1 for zero served outputs. This NAS
    cannot satisfy the current private-output contract. Do not relax it.
  - [x] Finish the same-pair canary on trj's capable local XFS, with fresh stock
    and four targets, unchanged serving budget and before/after binary hashes.
    Passed exit 0: eight committed executions, two rounds verifying all eight,
    then eight hits/eight served results and no dependency execution on the
    fourth fresh target. All eleven metadata files match the same-invocation
    stock inventory; all five Cargo checks exit 0. Stock 31.284s, cold 52.703s,
    verification 34.807s/33.882s, served 7.793s. This single dev canary has no
    A/A or repetition denominator and does not qualify the performance gates.
  - [x] Build the shipping `wrapper-release` artifact at 7c9c1828: compiler
    exit 0, 38.42s, 585,464 bytes (<2 MiB), SHA-256
    `58ff8f5b2111cb988e041c7744f1b3f08c4201361a91eb319b3dd71d56e11d3b`.
    RCH delivery to the controller's NAS refused private-copy ownership
    (exit 102); supported recovery repeats that refusal and leaves the journal
    retained. This is not a successful artifact delivery or an acknowledged job.
    Preserve build 30087403704156456 / rchw-a2490d4e-03ac-456b-a60a-93ed72139e37.
  - [ ] Qualify the shipping pair's wrapper overhead and clean private install
    using a filesystem that preserves its required Unix ownership/permissions.
  - [ ] Add an early operator-visible target-filesystem capability diagnosis
    for private-directory/ownership failures; preserve conservative materialization.
  - [ ] Source/env/toolchain/dependency/negative-input invalidation and output/diagnostic parity.
  - [x] Bound CI Cargo concurrency, add workspace/check/strict-Clippy prerequisites,
    retain manually requested source runs across main updates, validate with actionlint,
    re-enable the workflow and dispatch source `a11a6788`.
  - [ ] Obtain terminal DSR CI/build results against the frozen candidate and
    exact profiles. The user explicitly prohibits GitHub Actions; the earlier
    enablement question is closed. Preserve the historical zero-job dispatch
    as unqualified history, keep Actions disabled and use DSR for CI/releases.
    Strict RCH native component/consumer qualification remains distinct.
  - [ ] Publish tested matching tools; verify downloaded archive and fresh installed execution.
  - [ ] Sustained shadow/soak, incident-free cleanup and explicit rollback per original gates.
    - [x] Identify and gracefully retire our old interrupted 6d9b174e fixture
      worker (PID 2786204, start ticks 114850697). Its live executable SHA-256
      `f0b106596b3d97489b3ddeb23ab8e5caa0e8f9e5f3736d0f020ee2112d041fc2`
      exactly matches the retained binary manifest. PIDfd-bound SIGTERM proves
      exit; the journal remains. This exposes a cancellation cleanup gap.
    - [x] After stopping the red c4e1b570 run, bind its two fixture children to
      their manifest hashes and birth ticks, then retire them through PIDfd
      SIGTERM; both exit and their journals remain. No fleet daemon is stopped.
    - [ ] Qualify automatic cancellation/child retirement under the original S8
      fault probe. Manual verified cleanup does not satisfy the no-orphans gate.
      The current NativeWorker fixture starts before its coordinator listens;
      reconnect::run documents that --once also disables initial connect retries.
      Adding that flag alone would break startup. A fixture-ownership repair
      must preserve those retries while draining after actual owner loss.
- [ ] Deliver native/header/final-link serving (M5), not just retained archive execution.
  - [ ] Wire CC/CXX/AR interception and exact ordered inputs/toolchain/environment.
  - [ ] Close header, script, response-file, native search and negative-input dependencies.
  - [ ] Earn publication/replay; stock differential outputs, changed-input misses and failures.
- [ ] Deliver workspace action serving with canonical minimal closure and lineage (M10).
  - [ ] Publish selected workspace results through existing actors and trust gates.
  - [ ] Preserve Cargo events/pipelining, provisional ancestor gating and private destinations.
  - [ ] Large shadow corpus and source/env/toolchain/dependency/negative-input twins.
- [ ] Deliver governed build-script post-state replay (M11).
  - [ ] Preserve exact Cargo directives, environment, jobserver, pre-state and post-state.
  - [ ] Stage complete generated trees including deletions; prove channel/toolchain compatibility.
  - [ ] Corpus coverage, side-effect/network/secret refusals and stock differential acceptance.
- [ ] Deliver admitted test-result serving (M12).
  - [ ] Wire actual runner, exact binary/data/environment identity and isolated effects.
  - [ ] Stable-pass/failure evidence; flaky/time/network/side-effect classifications.
  - [ ] Real skipped test bodies with replay parity and changed-input reruns; release bypass.
- [ ] Deliver incremental ancestry and private state reuse (M13).
  - [ ] Exact/nearest-compatible state selection and toolchain/platform fencing.
  - [ ] Quiescent immutable capture, private writable clones, retention and crash safety.
  - [ ] Branch ping-pong comparison and transfer/storage ROI; keep losses visible.
- [ ] Connect edit/git/CI prewarming to existing actors (M14).
  - [ ] Coherent snapshots, supersession, foreground promotion and bounded optional resources.
  - [ ] Actual event-source integration and saved latency minus wasted-work measurement.
- [ ] Deliver receipt-backed explanation and advice (M15).
  - [ ] Live action/build identity queries for why, fragmentation and worker decisions.
  - [ ] Actual `rch advise` command with compiler-second attribution and evidence limits.
  - [ ] Real repeated Cargo workload with planted splits; stable JSON and no automatic edits.
- [ ] Qualify native ATP control/data and every original quantitative gate (M7/M8/W2).
  - [ ] Cancellation/control under bulk congestion, partition/resume and corruption.
  - [ ] Paired ATP/current SSH-rsync correctness and cost on distinct hosts.
  - [ ] <50ms hit and <1-2% admitted miss overhead with declared floors and denominators.
  - [ ] Agent median >=3x/p90 >=2x; 15-agent useful-throughput/tail >=3x.
  - [ ] Branch >=3x, cold workspace >=1.5x and warm converged served fraction >90%.
  - [ ] Retain A/A controls, queue/transfer/setup/storage costs and zero-divergence evidence.
- [ ] Perform the original frontier proceed/kill review (M16); defer only with evidence.
- [ ] Finish with exact source/test denominators, retained failures, graph validation,
  Beads sync, scoped commits and non-force synchronization of both required branches.
  - [x] Integrate concurrent warm-input-import and same-generation retry changes
    (0c48e223/672d39a2) without crediting them with earlier frozen-source results.

The two native compiler fixes are committed at `3ddd07170c35df57c90e543dc549dc6448b4380e`.
The first matching build request refused with queue timeout before compiling.
The installed CLI forbids both clean-overlay/job and source-receipt/job
combinations. The separate frozen checkout's off-root attempt ultimately refused
namespace initialization before compilation; its transcript is
`/Volumes/trj-data/rabs-execute-20261030-native-canonical-root-job.log`.
A later source-bound standard checkout on ts1 reached compilation but its outer
`CARGO_TARGET_DIR` was rewritten onto the pressured root volume. Only that owned
invocation (`rchw-311d56b6-e1ab-4e08-8775-d19b33c034a5`, build
`30087403704156396`) was cooperatively cancelled with `rch jobs cancel`; it
terminated 143 and its result receipt was retrieved. No other build was stopped.
The next trj attempt refused on unfinished overlapping source ownership, before
compilation; its existing claims were left intact. At 22:56 UTC, source
`a11a6788` began the native runner on ts1 with its explicit `--target-dir`
`/mnt/je_nas/rch-rabs-execution-20261030/native-a11a6788-target`, two Cargo jobs,
dev profile, debug information/incremental disabled, and a new result directory.
Worker process argv confirms real Cargo/rustc use that healthy volume. The
transcript is `/Volumes/trj-data/rabs-execute-20261030-native-nas-explicit-target.log`.
That build subsequently passed the 10-case suite, as recorded below. Its RCH job
does not inject a compile-time source stamp; qualify source identity separately
with explicit `RCH_BUILD_SOURCE`, keeping these initial dev results distinct.

The existing native-runner contract suite independently passed **21/21, exit 0,
21.563s** on trj; transcript
`/Volumes/trj-data/rabs-execute-20261030-runner-contract.log`. Its Cargo executable
is an explicit double; it proves artifact/process/jobserver orchestration, not
compiled RABS behavior. The production base bubblewrap argv ended 0 on both
trj and ts1, using `/usr/bin/true`; full Cargo isolation remains a separate test.

The new canonical runner contract subsequently passed **25/25** as described in
the checklist. Scoped UBS remains exit 1 with seven reviewed critical flags:
four identify the intended operator-selected Cargo/argv subprocess boundaries
(no shell evaluation), and three mistake public filesystem stat tuples named
`signature` for authentication secrets. File descriptors close in `finally` or
file contexts; test JSON parsing intentionally propagates malformed receipts.
No suppression or scanner change was applied. Ruff findings were corrected
manually, including executable modes, import spacing and explicit test
`check=False`; actionlint and `git diff --check` pass. Retained scan:
`/Volumes/trj-data/rabs-execute-20261030-runner-ubs-reviewed.log`.

The native `rabs-protocol` release-authorization selection then compiled and ran
**12/12, exit 0**, with 486 other tests filtered out. RCH explicitly injected
`RCH_BUILD_SOURCE=78abd733d6ebc58be078521a615e15d5af2fe3d5`; the derived-identity
test therefore exercised the validated compiled-stamp branch, and the different
overlay verdict was rejected. The source-content receipt covers 1,652 files,
46,322,110 bytes; receipt root
`ee90272387519345e7311f696ae54a105ffca9e7f228b45be38c548ba0fae9f3`.
Transcript `/Volumes/trj-data/rabs-execute-20261030-stamped-release-identity-owned.log`.
An earlier isolated off-root attempt ended with unconfirmed SSH completion;
supported `rch jobs recover` subsequently acknowledged 255. It supplies no
Rust test verdict. The a11a6788 workspace check subsequently ended with an
unconfirmed SSH/deadline completion; supported recovery acknowledged 255.
It supplies no compiler verdict. The fresh 7c9c1828 workspace/all-target check
uses the corrected private source filter and a bounded 10,800-second outer
deadline, retaining the original acceptance checks and timeout receipt.

**Real Cargo serving result (23:31 UTC):** the ts1 wrapper/daemon dev build
finished 0 after 1,843.070s, and the unchanged `live_cargo_worktrees` suite
finished **10/10, exit 0**, 212.75s in libtest (252.802s including its harness
build). Six cases invoke real Cargo/rustc and a real daemon/CAS; four are
artifact-resolver/helper checks. The registry-layout and vendor fixtures earn
their results through cold execution and two comparisons, then serve without
admitting dependency compiler work. Stock bytes, Cargo Fresh behavior,
workspace-only edits, changed and unlisted vendor inputs, large source/output
preparation, restricted build-script reuse and tracked `OUT_DIR` refusal pass.
This is narrow fixture correctness, not a production-repository canary,
authenticated worker proof, release-profile qualification or M4 closure.

The build source is `a11a6788179e4d5732880400f07d6a52053c6abe`, toolchain
nightly-2026-08-31 (`rustc 90850177249efe0321573c569aec5d12b257f8d6`), dev
profile, two Cargo jobs with dev/test debug information and incremental disabled.
Prepared and consumer-verified binaries:
`rabs-wrap` 1,463,840 bytes, SHA-256
`48f7b2ee3c1037c1ab2726d54df8d4062d6c1b1d3e3314fbd49e68a32768caac`;
`rabsd` 58,597,352 bytes, SHA-256
`9b55f29cc1c31c09097b37c6a2fa5baaa4f40ee1ad79e6d3cc20cb339eb7729e`.
The RCH job lacks the explicit compile-time source stamp as disclosed above;
this does not authorize a release. Build `30087403704156398` acknowledged 0 and
retrieved all three result files: `binaries.json`, `run.json`, `cargo-build.jsonl`
under `/Users/jemanuel/projects/rabs_native_execution_20261030/.rch-tmp/rabs-native-nas-live/`.
The complete transcript is
`/Volumes/trj-data/rabs-execute-20261030-native-nas-explicit-target.log`, SHA-256
`bb7ce2b4445b5e94571310ecdcac2adbce53a74f8e9ac81d4be8299e1e3af11d`.
Both non-gating tiny-fixture timing observations remain visible: stock/served
1.305108005s/579.522201ms and 524.727451ms/547.2483ms. The latter served run was
slower; neither pair qualifies the original performance targets.

The canonical runner subsequently gained a test-graph preparation phase because
`rabsd`'s dev dependencies enable `asupersync/test-internals`, CAS test support
and additional rustix features. Build wrapper/worker/supervisor normally, prepare
the exact canonical integration target with `cargo test --no-run`, then bind the
actual daemon and test executable from Cargo JSON before the unchanged test
invocation. Check retained binaries again after preparation and execution.
The expanded contract selection passed **28/28, exit 0, 42.341s**; it uses Cargo
doubles and is not native acceptance. An earlier 27-case attempt had one
ordering failure in the nonsibling-supervisor case; moving that refusal before
test preparation preserved its fail-before-any-extra-work contract, and all
28 were rerun. Transcript:
`/Volumes/trj-data/rabs-execute-20261030-runner-test-graph-contract-fixed.log`.

### Capability assessment

| # | Original testable goal | Current evidence and boundary | Status / owner |
|---|---|---|---|
| 1 | Conventional RCH offloads actual jobs and preserves ownership | Installed client and daemon are 2.1.34; the live Mac daemon reports 17 configured workers, 15 healthy, 43 effective slots and 35 available at observation. Three workers have critical disk pressure. A source-ownership refusal is an infrastructure refusal, not a RABS test result. | Operational, degraded fleet; existing conventional RCH issues remain |
| 2 | Boot real wrapper, edge/coordinator and worker processes | `rabsd/src/main.rs`, the Asupersync runtime adapter and worker binaries are real. Ordinary daemon dependency serving defaults off. No RABS executables resolved on the Mac or the checked `trj` login PATH, and no RABS process was observed on that worker. This does not inventory every fleet host. | Implemented; deployed serving unestablished / S7 |
| 3 | Earn automatic dependency hits from real compiler results | At 7c9c1828, the matching worktrees suite passes 11/11 (seven real Cargo and four support cases). The actual-repository `rabs-key` canary now works with bare `rustc`: eight registry dependencies execute/commit, two rounds verify all eight, then the fourth fresh target serves 8/8 with zero dependency executions. All five Cargo checks exit 0 and all eleven metadata outputs match stock bytes. The local metadata lane is opt-in, unsandboxed and separately keyed; this is not canonical or cross-host qualification. | Actual opt-in local serving demonstrated; wider acceptance open / M4 |
| 4 | Execute canonical Cargo on an authenticated worker | `cargo-rabs --rabs-canonical`, prepared jobs, `secure_worker_delivery` and `rabs-wkr` implement capture, mTLS/ATP, execution and verified delivery. This whole-Cargo profile is explicitly execution-only. | Implemented; full acceptance unqualified / M9 |
| 5 | Distribute dependency units to workers and replay their results | `coord/live_dependency/remote.rs` and `remote_dependency_transport.rs` bind pinned workers, closed inputs, execution and result installation. Real ignored fixtures cover a Cargo dependency DAG and a two-worker pool. A loopback authenticated worker process is real execution, but is not multi-host fleet proof. | Implemented; live qualification needed / M4, M6 |
| 6 | Serve workspace rustc results across worktrees | `coord/canonical_local.rs` emits `workspace_cache:false`; supported workspace requests execute afresh. Private Cargo target restoration may make Cargo report Fresh, but does not publish a workspace action-cache result. | Partial: execution and private freshness / M10 |
| 7 | Cache native subcompiles and final links | Native input/key modules and captured static-archive support exist. The documented per-unit lane excludes final linking; final linking through Cargo is not an exact-link cache. M5's close reason instead cites dependency offload. | Product integration gap / M5 |
| 8 | Cache build-script runs with complete effects | Config-only reuse and generated-input capture have fixtures. They do not establish general BuildScriptRun interception, complete post-state replay, stable/beta/nightly parity or the observed-registry >80% target. `docs/rabs-n001-feasibility-matrix.md` retains adverse shim observations. | Restricted capability / M11 |
| 9 | Serve admitted test results safely | The canonical driver explicitly reports `test_result_cache:false`, and Test/Run/Bench bodies execute on every request. Eligibility/runner libraries and compiling test binaries are not test-result serving. | Product integration gap / M12 |
| 10 | Restore nearest compatible incremental ancestry with positive ROI | Private target seed capture/restoration is real. `edge/snapshot_lineage.rs` models requested/resolved source lineage; that is not the full portable incremental snapshot/ancestry program or its 3x branch gate. | Partial / M13 |
| 11 | Watch edits/git events, prewarm and promote real actions | `CoordLive` exposes speculation/prewarm methods, but the searched call sites for `handle_git_prewarm_event`, `submit_default_on_speculation` and `publish_ci_canonical_prewarm` are definitions and tests. No production event source was found in the audited executable paths. | Library capabilities; wiring/ROI gap / M14 |
| 12 | Explain live decisions and deliver `rch advise` | `rch why` accepts explicit prior/current JSON or a refusal code. `rch advise --help` is an unknown subcommand, and the source CLI has no Advise variant. Key-analysis libraries are not a delivered advice command. | Partial / M15 |
| 13 | Fleet authority, cross-edge singleflight and root permits | Current source adds a persistent canonical service owning one coordinator, independent Cargo clients and shared remote dependency flights with per-subscriber cancellation. Real concurrent Cargo/TLS fixtures exist, including origin cancellation. They are not yet qualified here, and do not establish two distinct edge hosts sharing authoritative lineage. | New implementation awaiting native acceptance; cross-host proof gap / M6 |
| 14 | Native transport cutover with control isolation and data advantage | `worker_transport.rs` uses real ATP frames over native Asupersync mutual TLS. QUIC reactor/batcher types cited by the M7-M9 closure occur in `rabs-protocol/object_transfer.rs` definitions/tests, not the audited worker transport. Full control-under-bulk, WAN recovery and rsync comparison acceptance remain necessary. | Partial / M7, M8 |
| 15 | Meet the original quantitative performance gates | `benchmarks/GATE_LEDGER.md` still marks eight of eleven rows PENDING, including hit latency, miss overhead, agent loops, storm, branch ping-pong, cold workspace and served fraction. Layer-0/sccache numbers are baselines, not RABS wins. Its in-process metadata claim is not a substitute for a timed production lookup measurement. | Unproven / `bd-yb4ib`, `bd-hjhe3`, `bd-3wscg` |
| 16 | Ship the tested RABS tools together | Main's release workflow and `install.sh --with-rabs` contain packaging support. The actual latest published v2.1.34 x86_64 GNU tarball lists only `rch`, `rchd`, `rch-wkr`. Its revision is `ff152a046086f26845cbd4e9b0541a7b782fc64f`, 415 commits behind the assessed source. Source packaging is not shipped packaging. | Release gap / S7 (`bd-n8qt3`) |
| 17 | Qualify safety and rollout with production soak | S8's close reason cites seven chaos tests and component/Cargo suites, not its 24-hour shadow soak or the bridge's continuous shadow-week acceptance. No such new soak was performed by this audit. | Proof gap / S8 (`bd-rb754`) |
| 18 | Pursue frontier features only after positive evidence | M16's closure cites an optional C/C++ compile plane, rather than its hypothesis/benchmark/proceed/kill review. Frontier candidates remain optional and must not block or replace core delivery. | Decision/evidence gap / M16 |

At intake the live GitHub API reported the **RABS Binaries workflow was
`disabled_manually`**, last changed August 20. Its most recent listed successful
run is August 12 at `42b50f317010c1715c0425cb5cadc06c5a2e73c0`
([run 31627022560](https://github.com/Dicklesworthstone/remote_compilation_helper/actions/runs/31627022560)).
The workflow has now been re-enabled and explicitly dispatched for `a11a6788`:
[run 41140223977](https://github.com/Dicklesworthstone/remote_compilation_helper/actions/runs/41140223977).
At 22:57 UTC it remained queued with zero jobs started. All original acceptance
tests and thresholds remain; Cargo concurrency is bounded at two, formatting,
workspace checks and strict Clippy precede the release build, and manual source
qualifications survive unrelated main pushes. Actionlint passes. A workflow
dispatch is not a CI pass, a published release or rollout authorization. A
subsequent `GET /repos/Dicklesworthstone/remote_compilation_helper/actions/permissions`
returned `enabled:false`: repository-level Actions remains disabled. The
workflow enable alone therefore supplies no execution route. The broader
repository setting has been preserved; direct native fleet execution continues.
The user subsequently explicitly prohibited GitHub Actions and required DSR
only for CI/release builds. This historical dispatch supplies no qualification
and must not be retried or used as an enablement route. DSR is available on both
dispatchers; the Mac registry's tool key is remote_compilation_helper (the CSS
registry has no matching entry). Its existing local_path names the original
dirty checkout, so source/profile binding must be corrected in a private DSR
configuration before a candidate build; do not build unrelated dirty work.

The executable paths inspected are substantial implementations, not a collection
of `todo!()` bodies. The central failure mode is **proof-class inflation**:
component arithmetic, fixture outcomes, existing private Cargo freshness and
closed descendants are repeatedly credited as full live product acceptance.
For example, M12's close reason labels governed build scripts as M12, while
the original bead is explicitly test-result caching. Preserve its original
description and reopen its unmet acceptance rather than rename the vision.

### Fresh execution and retained evidence

The complete project AGENTS and README were read. The referenced local
`/data/projects/AGENTS.md` is absent; the actual Mac parent guidance and the
checked Linux worker's suite guidance were read. The Mac Data-volume
`sbh check --need 20G` refused on its percentage threshold; the external
`/Volumes/trj-data` and worker `/data` checks both passed. No heavy local
compilation, deletion, daemon restart or installation was performed.

The first strict-remote attempt to run `scripts/test_rabs_live.py` on `trj`
ended with exit 103 before compilation because an existing durable source
owner overlaps the ordinary mirror. Its claim was left intact. A second
attempt combined `--clean-overlay` and `--job`; the CLI refused that combination
with exit 2. Neither is a test pass or a product-test failure.

The supported alternative uses the exact committed tree and an external local
target destination:

```sh
CARGO_TARGET_DIR=/Volumes/trj-data/rabs-reality-20261030-target \
RCH_REQUIRE_REMOTE=1 RCH_WORKER=trj RCH_BUILD_SLOTS=4 \
  rch exec --base 7ae3f5fe0cf4a4ca533c235e9e1d89dbfd413ff3 \
  --clean-overlay --no-overlay -- cargo test --locked \
  -p rabs-wrap --test live_cargo_worktrees -- --nocapture --test-threads=2
```

Its transcript is retained at
`/Volumes/trj-data/rabs-reality-20261030-cargo-worktrees.log`.
Execution results will be recorded here after the terminal outcome; a running
compiler is not a passed suite. The companion daemon is built by the suite's
existing Cargo-artifact resolver at the same source/profile/target, rather
than selected from PATH or a guessed installed binary.

The independent launcher-contract selection was also executed against that
frozen worker source:
`python3 -I -S scripts/tests/test_cargo_rabs_canonical.py -v` completed
**88/88 tests, exit 0, 323.675 seconds** on `trj`. This suite uses an explicit
native-driver double: it proves exec/filesystem/argv/signal/recovery handoff,
not Cargo compilation, TLS, namespace isolation or a cache hit. Transcript:
`/Volumes/trj-data/rabs-reality-20261030-launcher-linux.log`, SHA-256
`9edd77209e82beed3e6847f473d18fab471db9c9519d49ffe1f1bef88d7bcff6`.
The earlier Mac run executed 88 tests and exited 1 (95 failing subcases and
32 errors); its positive canonical cases hit the documented Linux-only
preparation/recovery refusal. It is retained as
`/Volumes/trj-data/rabs-reality-20261030-launcher.log`, not relabeled a Linux
product regression or silently discarded.

The Linux installer selection (`python3 -m unittest discover -s tests -p
'test_install_rabs*.py' -v`) ran **78 tests, exit 1: two failures and one
error, 360.703 seconds** on the frozen `trj` source. One mixed-fleet result was
`unconfirmed` instead of `installed`; a parallel case lacked a `target` field;
the lost-ACK case had not reached installation at its assertion. These tests
exercise real local receiver/archive/generation processes with explicit SSH,
platform and compiler-tool doubles, not actual fleet deployment or Rust.
All three unchanged failing cases passed on `vmi1152480` (two fleet cases in
2.096 seconds; the lost-ACK case in 0.380 seconds). Their installer/test source
is identical between `7ae3f5fe` and `7f5901d4`. This host contrast supports a
contention/deadline hypothesis, but does not identify the first run's exact
refusal cause: its assertions omit the full deployment receipt. Keep the
original 78-case run red and require captured refusal receipts for attribution;
do not lengthen its deadlines or claim a 78/78 pass from three selected reruns.
Transcripts: `/Volumes/trj-data/rabs-reality-20261030-install-linux.log`
(SHA-256 `fb835890c62e558cfdf179ceebe56d5c9b8041f0ff1f53d69f5ba72850e40a56`),
`rabs-reality-20261030-installer-failure-twins.log` and
`rabs-reality-20261030-installer-lost-ack-twin.log` in the same directory.

A matching three-binary build requested while the first lane held worker
capacity refused with exit 103 / `queue_timeout`; it compiled nothing. A
capacity refusal is not a failed RABS test. The test host reports substantial
CPU contention, so elapsed times from this window cannot qualify performance.
The same native suite was requested on `vmi1149989`: the first request refused
before admission because its four-core estimate exceeded two slots; an explicit
`-j 2` request then queued and timed out with exit 103. Neither ran tests. The
original `trj` run remains owned as build `30087403704156295`; it was still
compiling its pinned daemon dependencies at this observation. Observe that
original job rather than submit another request to infer its outcome.

During the audit, origin advanced to `665b3fe33de65c3d120678ca91a561285553389a`.
Its native-input modeling adds retained foreign build-script roots and key/view
validation, explicitly preserving execution-only workspace actions. Its commit
reports library tests and says full namespace tests still require a capable
host. That delta does not close exact-link, workspace/test-result serving,
cross-edge, rollout or performance gaps above. The native test already running
remains frozen to `7ae3f5fe`; it cannot qualify the added native-root feature.
Origin subsequently advanced through `38d6d198` (complete retained directory
admission) to `10407d76e1550ae7f119c2b2c7234278ebb6dc5c` (native-input
propagation through capture, admission, transfer and worker execution). Those
changes explicitly keep workspace execution fresh-only and require the new
worker capability. Their reported isolated native-archive tests are narrower
than full canonical Cargo tests; the latter remain host-dependent and were not
reported passing in that commit. The assessment was rebased onto this source;
the original native test remains pinned to its original revision. A fresh
workspace/all-target check is running separately against assessment commit
`7f5901d4725428f29b18095b55ee42654019a9c4`. Local `cargo fmt --check` passes.

### Bridge order and original bead acceptance

**Completing the 11 issues open at intake would not close the RABS vision.**
They concern conventional RCH publication fixtures, native portability, Darwin
placement and storage retention. Most RABS gaps have historical beads, but no
open owner. Reopen the original milestones and probes with these observations;
retain completed implementation children and every original acceptance clause.

1. **Qualify the narrow dependency product first (M4, S7, S8).** Run unchanged
   real Cargo cross-worktree checks, then the canonical metadata/archive worker
   fixtures, source/env/toolchain/dependency invalidation and installed-output
   parity. Bind matching binaries and source. A stock comparison must be in the
   same invocation. Publish the complete tested toolset as an opt-in canary;
   validate the actual downloaded archive, then fresh installed doctor and
   execution, followed by the original soak. Preserve old active generations.
2. **Connect edge hosts to one authority (M6), then qualify transport (M7/M8).**
   Reuse `CoordLive` actors and the existing worker protocol; do not build a
   second scheduler. Two independently launched edge hosts must join one key
   and primary lineage, cancel independently, retain root/jobserver permits,
   survive coordinator restart and reject stale offers. Then test bounded
   control latency under congested source/artifact transfer, partition/resume,
   corruption and ATP-versus-rsync equality/cost on actual distinct hosts.
3. **Make each original W2 target an actual gate.** `bd-yb4ib` owns <50ms hit
   and <2% admitted-action miss overhead; `bd-hjhe3` owns the 15-agent >=3x
   storm; `bd-3wscg` owns >=3x median and >=2x p90 agent loops. Retain raw
   A/A and paired incumbent/candidate results, equal outputs and diagnostics,
   cold/warm placement, queue/transfer costs and a declared workload denominator.
   An observed loss stays a loss. Do not weaken targets, change corpus after
   seeing outcomes, or count self-speedup/Layer-0 data as a RABS win.
4. **Expand served classes through their existing owners (M5, M10-M12).** Wire
   native/header/link closure and complete result replay; then canonical
   workspace minimal-closure publication and provisional lineage; then governed
   build-script post-state and admitted test-result serving. Each class needs
   earned compiler/runner evidence, source/data/negative-input miss twins,
   cancellation/failure/partial-delivery tests and stock differential outputs.
   A restricted execution-only lane remains useful, but does not close serving.
5. **Earn state/intelligence/frontier authority (M13-M16).** Connect real
   ancestry selection and immutable private snapshot clones to branch traces;
   connect watcher/git/CI events to existing actors and measure saved latency
   minus wasted work; expose receipt-backed `rch why`/`rch advise` with actual
   compiler-second attribution. Use each frontier item's original proceed/kill
   criteria. Explicit evidence-based deferral is valid; substituting an unrelated
   implemented feature is not. These optional features never preempt core gates.

Every implementation change includes its unit, negative and real E2E proof in
the same original work item. Existing tests should be extended rather than
adding another status framework. Logs must distinguish action identity,
attempt, worker, publication, subscriber delivery and terminal exit; credentials
and raw private environments stay out of public evidence.

### Ambition and refinement decisions

Two ambition passes strengthened the bridge without changing the vision:
first, require one delivered vertical dependency slice rather than a green
library graph; second, require two edge hosts and a live paired incumbent so
local cache reuse cannot be mistaken for fleet acceleration. Five refinement
passes cover (1) original milestone-to-evidence mismatches, (2) shipped versus
main and host eligibility, (3) input invalidation and delivery/recovery twins,
(4) earned sampling/soak and equal-work performance denominators, and (5)
dependency cycles and redundant work. Keep existing original owners; no new
parallel milestone hierarchy is needed. Final graph validation and fresh test
outcomes belong to this section's execution update, not to a waived gate.

Nineteen original issues were reopened with self-contained implementation and
unit/negative/E2E acceptance notes; no new issue hierarchy was created. M4 also
depends explicitly on its existing hit/miss-performance probe `bd-yb4ib`.
`br dep cycles --json` reports zero active cycles. Validation with the current
`~/.local/bin/bv`, explicitly selecting `.beads/issues.jsonl`, loaded all
2,218 records with zero errors/skips and found 2,550 edges with no cycles.
The older Homebrew `bv` silently omits the five `docs` records, so its 2,213-row
view is not the authoritative denominator. The validated graph has 25 open,
five in-progress and 2,188 closed issues; S7 is its top actionable RABS pick.
`git diff --check` passes. Scoped UBS on the two changed Markdown/JSONL files
returns 3 because it supports neither language and ran no scanner; this is
not a code-scan pass. No Rust or other executable source was changed by the
assessment. Concurrent RABS native-input changes are distinguished above from
the original source selected for the live test.

## Previous assessment — October 14, 2026

This dated assessment updates the September 26 one against `main` @ `a6df23de`
and shipped `v2.1.22` (`96a144b50904`, October 13, 2026). It is written for the
operator and implementing agents choosing the next delivered capability. The
original goals and acceptance below still stand. Revise this section in place
when new execution evidence changes it. It waives no product acceptance.

**Assessment revision:** `a6df23de` (568 non-merge commits / 622 total commits
since the September 26 `fb0344cf` baseline: ~379 touching conventional `rch*`,
~44 touching `rabs*`).
**Released revision:** `v2.1.22` (`96a144b5`, October 13, 2026) — **23 releases
(`v2.1.0` through `v2.1.22`) shipped in 15 days**, closing the 490-commit
release gap noted on September 26 (`bd-iiyvx` closed). The installed operator
binaries on `hetzner2` are `rch 2.1.22` and `rchd 2.1.22`, only 20 commits
behind `HEAD`.

**Conclusion:**
1. **Conventional RCH has shipped major user-visible capabilities into
   production (`v2.1.0`–`v2.1.22`)**, including mandatory minisign/Sigstore
   verification in `rch update` (`bd-oxxnk`), Go (`go build -o`, `go test`,
   `go vet`, `bd-ow7t6`), Nix (`nix build`/`nix-build`/`nix flake check`/`nix
   develop -c`/`nix shell -c`), `cargo xwin`, `cargo package`/`publish
   --dry-run`, named Cargo JSON (`RCH_CARGO_JSON_STDOUT=1` + `rch jobs recover
   <id> --cargo-json`), `--require-tool` verified tool probes, Darwin
   `xcodebuild`/`xcrun` OS-fenced routing (`bd-nknnm`), owned
   `--source-content-receipt` pairs, `--clean-overlay`, learned build disk
   footprints (`history.footprints.json`, `bd-wv746`), opt-in dispatcher speed
   gate (`bd-2spi4`), SpeedScore v2 (`bd-uerk9`), stuck-detector exponential
   backoff + lease wakeup (`bd-r1kcc`), and source-registry writability probes
   (`bd-5ojmb`).
2. **However, three concrete production bottlenecks still degrade live fleet
   capacity and reliability today**:
   - **Hardcoded 5% `critical_free_ratio` (`bd-xxck3`, open P1)** in
     `rchd/src/disk_pressure.rs:381,400` zeroes 774–1,900 GiB workers even when
     they have 30–70 GiB free (4 workers in `CRITICAL` with 0 slots and 5 in
     `WARNING` on `hetzner2` right now; caused 466 queue timeouts/hr on `css`).
   - **Selection ignores per-worker overlapping source claims (`bd-jqhno`, open
     P1)**, repeatedly dispatching parallel builds of the same project to a
     worker that already holds a canonical-mirror claim (298 `unfinished
     overlapping source owner` failures/24h on `css`).
   - **Dual-role live-checkout clobber risk (`bd-fbtws`, in_progress P1)** and
     dispatcher PATH ordering (`rch shim status` on `hetzner2` warns `PATH does
     NOT resolve the shim first` with 2 unmanaged local `rustc` processes).
3. **RABS built a real opt-in local dependency cache lane (`bd-14t4j`,
   `bd-k52xe` partial), but still serves ZERO production traffic and has 50.2%
   unwired library modules**:
   - Unlike September 26 (when `rabs-wrap` unconditionally exec'd `rustc`),
     `rabs-wrap/src/main.rs:1210-1218` + `rabsd/src/edge/server/rustc_request.rs`
     + `rabsd/src/coord/live_dependency.rs` now implement `rustc-request` →
     `hit` → `rustc-accept` → `served` (`compiler_skip_authorized: true`) and
     two-phase miss capture (`execute` → `rustc-complete` → `rustc-captured` →
     `rustc-capture-ack` → `CoordLive::commit_offer`).
   - **Why it is still not real production serving:** (a) `live_dependency`
     defaults to `false` (`rabsd/src/main.rs:39,47`); (b) when enabled, it is
     100% **local and unsandboxed** on the edge host (`edge-local:<host>`,
     never touching `rabs-wkr` or `/__rabs/...` bwrap namespaces); (c)
     `LIVE_SAMPLING_POLICY = SamplingPolicy::sample_all(2, 10_000)` requires 3
     local compiles before the 4th short-circuits `rustc`, and refuses any
     invocation whose `-L dependency=` directory contains a proc-macro `.so`
     (`rabs-key/src/live_dependency.rs`); (d) `rabsd`, `rabs-wrap`, and
     `rabs-wkr` are still omitted from `release.yml` tarballs and `rch fleet
     deploy` (`bd-n8qt3`), and are not installed on `hetzner2`; and (e) **124
     of 247 non-test modules (50.2%) across the 8 `rabs-*` library crates have
     zero production callers**.

### Evidence gathered for this revision (2026-10-14 @ `a6df23de`)

- `RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --workspace --all-targets -- -D warnings`
  (worker `hz4`): **exit 0** in 13m38s (`bd-kuy6y` fixed and closed).
- `cargo fmt --check -- -l`: **FAILS on 5 files** (`rabs-wrap/src/singleflight.rs`,
  `rabs-wrap/tests/live_cargo_worktrees.rs`,
  `rabsd/src/edge/server/rustc_request.rs`,
  `rch-common/src/tool_requirement.rs`,
  `rch-common/tests/exact_runtime_admission.rs`).
- `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p rabs-wrap --test live_cargo_worktrees -- --nocapture`
  (worker `hz3`): **exit 137 (killed at 30m timeout)** after spending 26m19s
  compiling an inner `rabsd` from scratch inside the test harness, and
  `real_cargo_warms_large_packages_and_prebuilt_dependencies_before_execution`
  **panicked** at `rabs-wrap/tests/live_cargo_worktrees.rs:320:5`:
  `no package-facts-pending observation in real Cargo build: {"preparing": 183, "toolchain-warming": 183}`
  (because `rabs-wrap` exhausted `MAX_RETRIES = 60` waiting on cold
  `toolchain-warming` before `rustc_request::decide` ever reached package-facts
  warming).
- RABS workspace test suite (`bd-sopct`, `bd-h3fu2`, `bd-8hhef`, `bd-xo7x0`):
  still fails on `serve_frame_live::the_running_daemon_serves_a_committed_hit_over_the_socket`
  (`Sampling(ElevatedClassRisk)` because `commit_one_action` bypasses
  `submit_action` and verification samples), `k007_failure_ttl_lifecycle_*` in
  `rabs-cas/src/serving_state.rs:1337-1345` (`QuarantineRequiresRepair` after
  the `bd-rhdef` fix), `nested_runtime_prohibition` in `rabs-asupersync` (11
  non-allowlisted `.block_on(` files), `h015` crash-matrix divergence at
  `commit-0`, and ~180 `umask 002`-sensitive `private_directory()` test
  failures in `rabs-sandbox`.
- Live fleet on `hetzner2` (`rch status --workers --jobs`, `rch doctor`,
  `rch shim status`, `rch hook status`): daemon `v2.1.22` running (`uptime 1d
  2h`), posture `degraded`, 11/12 workers healthy, 16/24 slots available;
  `ovh-a` disabled (`/tmp` tmpfs usrquota exhausted, `bd-5ojmb`), 4 workers in
  `CRITICAL` disk pressure with 0 slots (`vmi1156319` 10.6G free, `vmi1152480`
  36.9G free, `hz1` 10.2G free, `vmi1149989` 28.5G free), 5 in `WARNING`
  (`vmi1227854`, `vmi1167313`, `vmi1153651`, `vmi1293453`, `hz4`). `rch shim
  status` reports 5 wrapped toolchains (`v7`) but `PATH does NOT resolve the
  shim first` and `2 local rustc running`.
- Authoritative Beads tracker (`.beads/issues.jsonl` truth): **2,185 total
  beads — 1,979 closed (90.6%), 171 open, 33 in_progress, 2 deferred**, zero
  dependency cycles (`has_cycles: false`). Note: `.beads/beads.db` has an open
  `rusqlite` vs `fsqlite` WAL format conflict (`bd-zvam5`); always query
  `.beads/issues.jsonl` or pass `--db .beads/issues.jsonl` to `bv`.

### Vision checklist against current evidence (October 14, 2026)

| # | Goal | Status | Reality at `a6df23de` (`v2.1.22`) | Blocking / Remaining Beads |
|---|---|---|---|---|
| 1 | Classify safe commands & preserve hook semantics | **WORKING** | 5-tier classifier handles Rust (`build/test/check/clippy/doc/bench/run/nextest/zigbuild/xwin/package/publish --dry-run`), Bun, `tsc --noEmit`, Go (`build -o`, `test`, `vet`), C/C++, Make/CMake/Ninja/Meson, Nix, `&&` chains, `bash -c`, and benign pager pipes. | Cargo shim (`rch/src/commands/shim.rs:347`) omits `package`/`publish`; `README.md:47-55,1192` & `AGENTS.md:360` stale (`NO_BEAD`). |
| 2 | Execute remotely & return exact outputs/artifacts | **WORKING** | Linux rsync + Windows bounded tar, `--bin`/`--example` narrowing + payload-aware timeouts (`bd-3tkcz`), Named Cargo JSON (`RCH_CARGO_JSON_STDOUT=1`), Go `-o` delivery (`bd-ow7t6`), `--job --result-dir`. | Final fleet verification & close on `bd-3tkcz`, `bd-ow7t6`. |
| 3 | Job mode (`--job`, `--require-tool`, Darwin `xcodebuild`/`xcrun`, `rch admit`) | **PARTIAL** | `rch exec --job --result-dir --require-tool` and Darwin OS-fenced routing (`bd-nknnm`) work. **However, `rch admit` (`rch/src/commands/status.rs:1031-1135`) never queries `rchd`** (`refine_recommendation` has 0 callers, so `Queue`/`Defer` are unreachable), ignores `.rch/config.toml` `[jobs] required_tools`, and omits 4 human fields. | `bd-nknnm` (live verify); **`NO_BEAD` gap** for `rch admit` daemon query & config wiring. |
| 4 | Protect dispatcher CPU across harnesses | **PARTIAL** | Unmanaged local build detector (`rch/src/local_builds.rs`), remote `RCH_CARGO_WRAPPER_BYPASS=1` stripping, and opt-in speed gate (`bd-2spi4`) landed. Still 2 unmanaged local `rustc` on `hetzner2` because `~/.local/share/rch/shims` is not first on `PATH`. | `bd-g2ppt`, `bd-2spi4`, `bd-raobv`, `bd-qawj7`. |
| 5 | Coherent source snapshots, receipts, & live-checkout safety | **PARTIAL** | `--source-content-receipt` (with owned source/target pairs and macOS 12-char rsync itemize fix `bd-3fudt`) and `--clean-overlay` work. Dual-role worker sync can still overwrite live checkouts unless `/etc/rch/live-checkouts` is configured (`bd-fbtws`). | `bd-fbtws`, `bd-3fudt`, `bd-n41ig`, `bd-p2m5h`, `…qe8dk`. |
| 6 | Schedule within real fleet capacity & source ownership | **PARTIAL (DEGRADED)** | Learned footprints (`history.footprints.json`), `disk_headroom_gib`, SpeedScore v2 (`bd-uerk9`), and registry writability probe (`bd-5ojmb`) landed. **Still broken:** hardcoded 5% `critical_free_ratio` zeroes big disks with 30–70 GiB free (`bd-xxck3`), and selection ignores overlapping per-worker source claims (`bd-jqhno`). | `bd-xxck3` (P1), `bd-jqhno` (P1), `bd-81htz` (P0), `bd-5ojmb`, `bd-uerk9`. |
| 7 | Recover surviving jobs after daemon/client loss | **PARTIAL** | Startup restores active slots from `history.jsonl` even for removed workers and reaps dead queue owners (`bd-w2qrp`); stuck detector has exponential backoff + lease wakeup (`bd-r1kcc`). **Still broken:** aged-out (`not_found`) leases with dangling target symlinks cannot be retired by `rch jobs cancel`/`recover` (`bd-ey7fr`), and startup does not actively SSH-probe workers (`ocv9i.10.3`). | `bd-ey7fr`, `bd-w2qrp`, `bd-r1kcc`, `bd-s528w`, `…ocv9i.10.3`. |
| 8 | Truthful outcome & OTLP observability | **PARTIAL** | `exit_code == 0` build outcome (`bd-88fpl`), `rchd` OTLP export (`rch-telemetry/src/otlp.rs`), and `rch doctor` OTLP export work. Short-lived `rch` hook invocations still skip OTLP init (`rch/src/main.rs:2220`). | `bd-88fpl` (verify/close), `…62u24.17`, `bd-bddpd`. |
| 9 | Meet hook (<1ms), selection (<10ms), & pipeline (<15%) budgets | **UNPROVEN** | Only in-process classifier latency is asserted; process-level hook spawn (~6–8ms) and 15% pipeline overhead remain unasserted. | `bd-1nhd`, `bd-1t3v`. |
| 10 | Release cadence & update/install integrity | **WORKING (with `install.sh` gap)** | 23 releases shipped (`v2.1.0`→`v2.1.22`, `bd-iiyvx` closed). `rch update` enforces minisign/Sigstore verification (`bd-oxxnk` closed). **Gap:** `install.sh:837-855` still verifies only SHA-256 checksums on downloaded tarballs. | **`NO_BEAD` gap** for `install.sh` minisign verification (or explicit non-claim enforcement). |
| 11 | Boot Asupersync RABS spine & green workspace tests | **PARTIAL (TESTS RED)** | `rabsd`, `rabs-wrap`, and `rabs-wkr` compile and pass `clippy -D warnings`, but `cargo fmt --check` fails on 5 files and the RABS test suite has 5 failing/hanging clusters (`serve_frame_live`, `k007`, `nested_runtime_prohibition`, `h015`, `umask 002`, plus 26m nested `cargo build -p rabsd` in E2E tests). | `bd-sopct`, `bd-h3fu2`, `bd-8hhef`, `bd-xo7x0`. |
| 12 | Authenticated, resumable `rabs-wkr` sessions & canonical exec | **PARTIAL** | `rabs-wkr` runs bwrap canonical sandboxes over mTLS + newline JSON (`rabs-asupersync/src/worker_transport.rs`), driven only by operator CLI flags (`rabsd --worker-exec-tls` / `--job-submit`) with `publication_authorized: false`. Disconnected from `rabs-wrap`. | `bd-085cm` (S5). |
| 13 | Serve automatic Cargo dependency hits (`bd-14t4j`, `bd-k52xe`) | **PARTIAL (OPT-IN LOCAL ONLY)** | `rabs-wrap` short-circuits `rustc` (`compiler_skip_authorized: true`) when `live_dependency = true`, after 3 local runs. **Limits:** off by default; runs locally unsandboxed on edge host; requires 3 compiles before 1st hit; refuses any crate whose `-L dependency=` dir has a proc-macro `.so` (`rabs-key/src/live_dependency.rs`); cold `toolchain-warming` times out `live_cargo_worktrees` (`NO_BEAD`). | `bd-k52xe` (P0), `bd-14t4j` (close/verify), plus proc-macro `.so` dir refusal & cold toolchain-warming timeout. |
| 14 | Trust, SPRT sampling ladder, & CAS/GC correctness | **PARTIAL** | `bd-rhdef` (quarantine preservation) and `bd-2y15k` (`plan_swap` SHA-256) fixed in library code. **Still open:** `bd-okthi` is a fixed 16-install cap (not SPRT); `bd-2d0j0` (`gc_snapshot` ignores `expires_at_seq`); `bd-i7zop` (124/247 library modules have 0 production callers); `bd-9xawm` ($O(n\cdot m)$ `leak_scanner`). | `bd-okthi`, `bd-2d0j0`, `bd-i7zop`, `bd-9xawm` (close `bd-rhdef`, `bd-2y15k` after fixing `k007`). |
| 15 | Ship & sustain RABS on the fleet + Phase 2–5 classes | **NOT_STARTED in prod** | `release.yml`, prebuilt `install.sh`, and `rch fleet deploy` still omit `rabsd`, `rabs-wrap`, and `rabs-wkr` (`bd-n8qt3`). 24h soak (`bd-rb754`) not run. Workspace/build-script/test/link/snapshot/speculation serving (M5–M16) exist only as unwired library modules. | `bd-n8qt3` (S7), `bd-rb754` (S8), W2 gates, M5–M16 epics. |

### Bridge: prioritized order of work from `a6df23de`

1. **Immediate Hygiene & Unblocking Fleet Capacity (Conventional RCH P0/P1)**
   - Format the 5 unformatted files (`cargo fmt`) so `cargo fmt --check` is green alongside `cargo clippy`.
   - Fix **`bd-xxck3`** (`rchd/src/disk_pressure.rs:381,400`, `main.rs:1504`, `workers.rs:1128`): cap the 5% ratio rule on multi-hundred-GB disks (e.g., `min(ratio * total, cap_gb)` + wire `[remediation.disk_pressure]`) and rely on learned footprints (`FootprintBook`) so workers with 30–70 GiB free are not zeroed out into `CRITICAL` pressure.
   - Fix **`bd-jqhno`** (`rchd/src/selection.rs`): track active per-worker canonical source roots in `rchd` (and feed back `unfinished overlapping source owner` / `RCH_SYNC_LIVE_CHECKOUT_REFUSED` refusals) so selection never routes a build to a worker already holding an overlapping source claim.
   - Complete **`bd-fbtws`** (dual-role live-checkout protection), **`bd-ey7fr`** (retiring aged-out `not_found` leases with dangling target symlinks via `rch jobs cancel`/`abandon`), and wire **`rch admit`** (`rch/src/commands/status.rs:1031-1135`) to query `rchd` (`refine_recommendation`) and load `.rch/config.toml` `[jobs] required_tools`.
2. **Make the RABS Test Suite Deterministic & Green (`bd-sopct`, `bd-h3fu2`, `bd-8hhef`, `bd-xo7x0`)**
   - Fix `rabsd/tests/serve_frame_live.rs` (`bd-8hhef`) to submit the action and satisfy or explicitly configure the sampling/replay gate.
   - Fix `k007_failure_ttl_lifecycle_*` in `rabs-cas/src/serving_state.rs:1337-1345` to use the explicit quarantine-repair path introduced by `bd-rhdef`, then close `bd-rhdef` and `bd-2y15k`.
   - Fix `nested_runtime_prohibition.rs` in `rabs-asupersync` by removing/refactoring the 11 unauthorized `.block_on(` sites and updating the stale `rabs-wkr/src/main.rs` allowlist entry.
   - Fix `private_directory()` test helpers in `rabs-sandbox` to `chmod 0o700` explicitly under `umask 002`, fix `h015` `commit-0` migration/checkpoint parity in `rabs-cas/src/crash_matrix.rs`, and stop E2E tests (`live_cargo_worktrees.rs`, `chaos_faultinjection.rs`) from compiling `rabsd` from scratch into a cold temp target dir (use `CARGO_BIN_EXE_rabsd` or shared prebuilt binary) + fix cold `toolchain-warming` retry budget so `live_cargo_worktrees` passes in <60s instead of timing out at 30m.
3. **Make RABS Phase 1 Dependency Serving Real Across Real Workspaces (`bd-k52xe`, `bd-okthi`, `bd-2d0j0`)**
   - Fix `rabs-key/src/live_dependency.rs` so dependency directories containing unrelated proc-macro `.so` files do not cause every downstream crate in a real Cargo workspace to be refused (`dependency-dir-unsupported-entry`).
   - Replace the hardcoded 3-compile warmup + 16-install fixed cap with the real SPRT-governed sampling ladder (`bd-okthi`) and fix `SqlMetadataStore::gc_snapshot` to honor `expires_at_seq` (`bd-2d0j0`).
4. **Package, Deploy, and Soak RABS on the Fleet (`bd-n8qt3` S7, `bd-085cm` S5, `bd-rb754` S8)**
   - Add `rabsd`, `rabs-wrap`, and `rabs-wkr` to `.github/workflows/release.yml`, `install.sh` prebuilt download + minisign verification, and `rch fleet deploy` (`bd-n8qt3`).
   - Connect `rabsd`'s live dependency lane to `rabs-wkr` canonical sandbox execution (`bd-085cm`) and run the real 24h shadow/canary soak (`bd-rb754`) before expanding to Phase 2–5 action classes (`bd-i7zop`).

---

## Previous assessment — September 26, 2026 (superseded where the October 14 section above differs)

This dated assessment replaces the September 15 one. It is written for the
operator and the implementing agents who choose the next delivered
capability. The original goals and acceptance below still stand. Revise this
section in place when new execution evidence changes it. It waives no product
acceptance.

**Assessment revision:** `fb0344cf` (plus one other agent's uncommitted edit to
`rchd/src/benchmark_scheduler.rs`), with bead IDs as of `64fa4105`.
**Released revision:** still `v2.0.0` (`3289f5e4`, September 13). Main is
about 490 commits past it, and about 540 commits landed after the
September 15 assessment. The installed operator binaries are the
September 15 diag build (`b4775837`). Linux dispatchers reinstall the latest
*release* every night, so nothing merged after September 13 is running in
production.

**Conclusion:** conventional RCH is doing real work in production right now.
A snapshot of the operator daemon's recent builds showed 20 offloaded
clippy/test jobs across four repositories, lasting 27 seconds to 49 minutes:
17 exit 0, two exit 101 (lint/test failures), and one exit 127 (a
bypass-wrapped command). HEAD compiles, but it
fails the mandatory workspace clippy gate. The dispatcher it exists to protect
was at load average 78, with about 580% CPU of *local* rustc. RABS still
serves zero automatic Cargo hits: the wrapper execs rustc unconditionally.
Most RABS effort since September 15 built a second, operator-driven
remote-build system instead of the first served class this plan sequences
next.

### Evidence gathered for this revision

- `rch exec -- cargo check --workspace --all-targets` (remote,
  `RCH_REQUIRE_REMOTE=1`): **exit 0**, 16m22s.
- `rch exec -- cargo clippy --workspace --all-targets -- -D warnings`:
  **exit 101**. Four lints in `rabs-wkr` (`request_journal.rs:87`,
  `source_transfer.rs:32,37`). → `bd-kuy6y`.
- `rch exec -- cargo test --workspace --no-fail-fast` **cannot produce a
  verdict.** The cold attempt was still compiling test targets when its
  90-minute deadline killed it (exit 137, reported correctly; no local
  fallback). The warm attempt reached the RABS binaries, then hung for more
  than 30 minutes in `rabs-cas` `h015_frankensqlite_matrix_matches_reference_at_every_kill_point`.
  Because binaries run in package order, that hang prevents every core crate
  from running. Before the hang it logged 6 failures, including a nested
  `block_on` regression in the new `worker_transport.rs`. → `bd-h3fu2`.
- Core crates only (`cargo test -j 7 -p rch -p rchd -p rch-common -p rch-wkr
  -p rch-telemetry --no-fail-fast`, hz3, 34m55s): **5,463 passed, 39 failed,
  20 ignored**, and the `rch` bin unit tests aborted with SIGABRT (`bd-dl3qs`).
  Thirty failures share one signature: a harness-spawned rchd answers with an
  empty response or EAGAIN. That cluster is not on the environment-bound list
  recorded before v1.0.60. Cause undetermined (regression vs environment),
  and the fix gates the release. → `bd-5rbv4`.
- Live fleet (`rch status --workers --jobs --json`, operator Mac): 16/18
  workers healthy, 42/66 slots free. wsurf's circuit is open after 2,613
  consecutive failures. hz4 is disabled. hz1 and mminiold are at critical
  disk. Five workers have zero effective slots. Posture is permanently
  `degraded`. → `bd-81htz`.
- Hook process cost (`hyperfine -N`, non-compilation input, load average
  ~78): about 8.3 ms user+sys per Bash call, against about 1.9 ms for
  `/usr/bin/true` and about 22 ms for the dcg hook. The AGENTS.md budget is
  under 1 ms (panic threshold 5 ms). Only the in-process classifier is
  asserted against it. → comment on `bd-1nhd`.
- Local rustc on the dispatcher traced to the cargo shim passing through
  (a) a project outside the canonical root, for which `rch diagnose`
  nevertheless answers "WOULD INTERCEPT" (→ `bd-raobv`), and (b) a
  `cargo ltest` alias with a `local_*` target directory (possibly a deliberate
  escape hatch; ask the operator).
- On hz3 during the test run (load average ~35 on 64 cores), the operator
  daemon saw only its own 8-slot job. The rest of the load came from other
  dispatchers' builds, which this daemon cannot see (each rchd accounts slots
  independently). `asupersync` and `fsqlite_core` were being compiled
  concurrently in separate per-project caches. This is live evidence of the
  cross-dispatcher duplication that RABS M6/Epic I (fleet singleflight and
  resource scheduler) and the served classes exist to remove, and none of it
  is live.
- Production call sites were read for every RABS claim below. Test-only and
  library-only code is not credited as delivered.

### Vision checklist against current evidence

| Goal | Reality now | Remaining work / proof |
|---|---|---|
| Classify safe commands, preserve hook semantics | **Working.** It is in production use across repositories. The classifier covers more than the README lists (go, tsc, zigbuild/xwin, `cargo run`). | `rch diagnose` can contradict execution for off-root projects (`bd-raobv`). The hook process costs about 6 ms of CPU above spawn baseline, against a budget under 1 ms (`bd-1nhd`). |
| Execute remotely, return correct output/artifacts | **Working** on Linux Rust paths. Named `--bin`/`--example` narrowing landed on main (unreleased; the README still says it doesn't exist). | `bd-3tkcz`, `bd-dl3qs`. Ship it: `bd-iiyvx`. |
| Protect dispatcher CPU across harnesses | **Partial, and failing at the time of observation.** The shim is installed and wraps 14/14 toolchains. Even so, about 580% of dispatcher CPU was local rustc. | `bd-raobv` (off-root silent local builds), `bd-g2ppt`/`bd-ousos`, `bd-qawj7` (its part 1, the ledger, is on main via `64fa4105` but unreleased; `rch status` has no summary yet). |
| Coherent source/dependency snapshots | Unchanged since September 15: implemented, with the closure tasks still open. | `bd-n41ig`, `bd-p2m5h`, `…materialization-closure-qe8dk`. |
| Schedule within real fleet capacity | Works, but the fleet is degraded. Five of 18 workers contribute zero slots, one has been dead for thousands of probes, and the largest worker is disabled. | `bd-81htz`. |
| Recover surviving jobs after daemon loss | **Partial.** Active builds are restored. Queued jobs are dropped. Reattach cannot work on macOS because process identity is read from `/proc`. Startup fails hard if a recorded worker was removed from config. | `bd-w2qrp` (new), `…ocv9i.10.3`. |
| Truthful outcome and observability | **Fixed on main, unreleased.** Build success is now `exit_code == 0` (`rchd/src/history.rs:82`), and the daemon OTLP exporter is real. Hook/watch/doctor OTel is still unfinished, and the README says so. | Independently verify and close `bd-88fpl`. Continue `62u24.17`. Operator commands that fake success: `bd-bddpd` (new). |
| Meet hook/selection/pipeline budgets | **Unproven.** Only the in-process classifier is asserted. Selection latency is measured but never asserted. The 15% pipeline overhead is not enforced. | `bd-1nhd` (see its measurement comment). |
| Ship what main contains | **Not happening.** There has been no release in 13 days and about 490 commits, and the nightly job reverts hand deploys. | `bd-iiyvx` ← `bd-kuy6y`. |
| Update integrity | **Overclaimed.** Updates are checksum-only. `.minisig` files are never verified, and sigstore is skipped when absent (it is absent in v2.0.0). | `bd-oxxnk` (new). |
| Boot the Asupersync RABS spine | **Working.** A real current-thread asupersync runtime runs, with edge, coord and janitor regions, plus a prepared-job driver. | S8 soak `bd-rb754` has not started. |
| Authenticated, resumable worker sessions | **Substantially improved.** Native mutual TLS plus ATP control framing, with SPKI peer identity (`rabs-asupersync/src/worker_transport.rs`). Only the operator lane uses it. | S5 `bd-085cm`: orchestrated D003/D005 proof, flap/restart resume, and coordinator-only publication authority. |
| Serve automatic Cargo dependency hits | **No change: zero.** `rabs-wrap/src/main.rs:377` execs rustc unconditionally. Every edge consult reply is pass-through. `commit_offer` and the `serve` frame have only `#[cfg(test)]` callers, so production never commits an entry. | `bd-14t4j` → `bd-k52xe` (untouched since mid-August and September 15). `bd-1vf05`'s title ("a wrapper that acts on the answer") overstates what shipped; its close reason discloses the split. |
| Trust and zero-divergence serving | Sampling and quarantine are wired into the serve code, but that code has no production traffic. The T011 release gate is Advisory and never refuses. | `bd-okthi`, `bd-rhdef`, H012. |
| Multi-agent speedup, advanced cached classes | None measured. There is still no supported 3× or >90%-served claim. | W2 gates and the K–Q/T milestones. |
| Ship and sustain RABS on the fleet | Unchanged. Prebuilt install and release omit the RABS binaries, and the launchd plist has no installer. | S7 `bd-n8qt3`, S8 `bd-rb754`. |

### What happened since September 15 (steering signal)

- There were 542 commits: 116k lines inserted and 7k deleted outside
  `.beads/`. **389 cite no bead.** 93 say tests or compilation were not run.
  One (`8dd4b378`) had to restore daemon/worker compilation. Only 55 beads
  closed in the window.
- About 225 of the commits touched RABS. The biggest theme (roughly 50–95
  commits, mostly untracked) is an **operator prepared-build job system**:
  `rabsd --worker-build-tls`, `--job-submit/status/wait/follow/cancel/resume/
  acknowledge/recover-local`, vendored/alternate registry preparation,
  durable job history, and diagnostics replay. Its operator doc,
  `docs/rabs-worker-delivery.md`, is now 70 KB. It is real remote execution
  over authenticated ATP, but it is **Phase 3 (M9) scope** built ahead of
  Phase 1. Nothing in `rch` calls it and nothing packages it. It also
  duplicates what conventional RCH already does in production.
- Everything on this plan's critical path to a served hit is unchanged:
  `bd-14t4j`, `bd-k52xe`, `bd-okthi`, `bd-rhdef`, S7 and S8.
- `bv --robot-triage` ranks deep RABS graph nodes highest, such as D013, a
  macOS VM helper idle for 50 days. Graph centrality will keep pulling
  agents away from shipping and dispatcher protection unless priorities
  override it.

### Bridge: order of work from here

0. **Ship what exists (new, first).** Make HEAD pass every mandatory gate:
   clippy (`bd-kuy6y`), and core-crate tests green or explained
   (`bd-5rbv4`). Then cut a release from that exact revision (`bd-iiyvx`).
   Make the workspace test suite able to produce a verdict (`bd-h3fu2`), but
   do not let RABS test debt hold the core release hostage. Until a release
   ships, every fix below is invisible to users.
1. **Dispatcher protection is the product.** Silent off-root local builds and
   a lying `diagnose` (`bd-raobv`), shim durability (`bd-g2ppt`/`bd-ousos`),
   and the fallback ledger (`bd-qawj7`). Measure success by local rustc CPU
   on dispatchers during agent storms, not by bead closure.
2. **Truthful operator surfaces.** Remove or implement the commands that
   fake success (`bd-bddpd`). Make update authenticity real (`bd-oxxnk`).
   Close the recovery gaps (`bd-w2qrp`, `ocv9i.10.3`). Restore fleet
   capacity and make posture meaningful (`bd-81htz`).
3. **Measure the budgets for real** (`bd-1nhd`): process-level hook latency,
   asserted selection latency, and paired worker-direct vs RCH pipeline
   overhead on a quiet host. Do not weaken the 15% requirement.
4. **RABS: freeze the prepared-build lane at its current scope** until the
   operator decides whether it is sanctioned. Put RABS effort into the one
   path that turns the program into user value: a production commit path
   (`commit_offer` with a real caller), live materialization (`bd-14t4j`),
   sampling/quarantine integrity (`bd-okthi`, `bd-rhdef`), then a wrapper
   that actually skips rustc on a verified hit (`bd-k52xe`). Follow with the
   two-worktree M4 demo. The September 15 Phase 1 acceptance stands
   unchanged.
5. **Then** S7 packaging and the S8 soak, and only after that the later
   phases, each through the same shadow → sampled → ratcheted serving ladder.

### Verification limits

This revision re-ran check, clippy and tests remotely, observed the live
fleet and processes, benchmarked the installed hook, and read production
call sites for every RABS claim (with two independent read-only audits,
spot-checked by direct reads). It did not run a quiet-host performance
benchmark, crash the shared daemon, run any RABS binary, perform macOS
qualification, or execute a soak. The hook timing was taken on a heavily
loaded machine with the installed (September 15) binary.

## Previous assessment — September 15, 2026 (superseded where the September 26 section above differs; its detailed recovery, measurement and serving rules still bind)

This update is for the operator and implementing agents choosing the next
delivered capability. It corrects observed library-only closures, missing live
wiring, and the historical claim below that no RABS process boots. Keep the
original goals and acceptance below; revise this dated assessment when new
execution evidence changes it. No product acceptance is waived here.

**Assessment revision:** `32927446` (before these tracking/document edits).
**Released revision:** `v2.0.0`, `3289f5e4`, September 13. The installed client
reports that release. Main is 50 commits ahead, including source/overlay,
deadline, artifact-transfer and dependency changes. A passing main candidate
is not an installed upgrade. The downloaded Linux release archive contains
`rch`, `rchd`, and `rch-wkr`; it does not contain the RABS binaries.

**Conclusion:** conventional RCH delivers useful real remote compilation.
RABS has a running runtime, daemon, coordinator/CAS and shadow path, plus a
separate operator serve endpoint. It does not yet deliver automatic Cargo
action-cache hits. Completing only the previously open beads would have left
several promised capabilities unfinished because their original beads were
closed at component or prototype fidelity.

### Vision checklist against current evidence

| Goal | Reality | Remaining work / proof |
|---|---|---|
| Classify safe commands and preserve hook semantics | Implemented; real Rust CLI offload demonstrated. Five-tier classifier and hook command replacement exist. | Performance proof remains separate; non-Rust recognition is not full ecosystem qualification. `bd-1nhd`. |
| Execute remotely and return correct output/artifacts | Working for exercised Linux Rust paths. Same binary hash returned over actual SSH. | Exact selected Cargo outputs and true stalled-peer/caller-cancellation tests: `bd-3tkcz`; teardown abort investigation: `bd-dl3qs`. |
| Protect dispatcher CPU across harnesses | Hook, dispatcher role and Cargo shims exist. | Current shim status reports installed/up-to-date and five wrapped toolchains but no effective PATH interception. This does not prove every toolchain route bypasses. Finish `bd-g2ppt` / `bd-ousos`. |
| Preserve coherent source/dependency snapshots | Ordinary closure locks, explicit receipts and clean overlays exist; pinned sibling overlay has live evidence. | Finish original closure/materialization and native validation acceptance: `bd-n41ig`, `bd-p2m5h`, `remote_compilation_helper-cargo-materialization-closure-qe8dk`; correct source-version stamping: `bd-xho6o`. |
| Schedule within real fleet capacity | Live daemon selection, queue, slots and pressure state work. | At the captured observation 7/13 configured workers were critical, 6 warning; zero normal. Availability cannot be inferred from CPU slots alone. Existing pressure/staging/benchmark tasks remain operationally important. |
| Recover surviving jobs after daemon loss | Planned-restart barrier and durable client identity exist; live recovery is incomplete. | History reload forgets active/queued jobs; unknown heartbeats are ignored. Reopened `bd-session-history-remediation-ocv9i.10.3`. |
| Report truthful outcome and observability | Status, Prometheus and diagnostics have production consumers. | Test/signal exits are incorrectly inferred to prove successful compilation (`bd-88fpl`). Daemon OTel initializer remains a stub; library exporter/layer not installed (`remote_compilation_helper-62u24.17`). Both reopened. |
| Meet original hook/selection/pipeline budgets | Classifier microbenchmarks and partial tests exist. | SSH connect timing without assertions is not selection timing; full pipeline budget coverage missing. Reopened `bd-1nhd`; retain full-pipeline child `bd-1t3v` scope. |
| Support native platform lifecycle | Linux path is strongest; macOS release exists and startup fixes are present on main. | Native launchd and baseline-red tests remain open (`bd-mhv3x`, `remote_compilation_helper-qqa0y`). RABS D013/D021 macOS isolation and Windows transport tasks remain incomplete. |
| Boot the Asupersync RABS spine | Real runtime and edge/coord/janitor mounting exist. Historical no-process claim is obsolete. | Running processes alone do not prove the entire Phase S contract. |
| Run authenticated, resumable worker sessions | A canonical-execution TCP prototype works against a test coordinator. | Fixed token and raw newline TCP are not authenticated ATP. Reopened S5 `bd-085cm`; retain J/K transport and execution scope. |
| Serve automatic Cargo dependency hits | Operator `serve` reaches materialization; wrapper consult remains shadow and then always execs rustc. | `bd-14t4j` then `bd-k52xe`, with real action identity, completion/publication and full output coverage. Shadow keys are intentionally incomplete and must never authorize reuse. |
| Enforce trust and zero-divergence serving | Serving gates and sampling/quarantine libraries exist. | Sampling/demotion not wired into live serving; unresolved quarantine can be lifted by reevaluation. `bd-okthi`, `bd-rhdef`, H012 and trust/authority tasks. |
| Deliver multi-agent speedup and advanced cached classes | Scheduler, CAS, materialization and action libraries are substantial. | B009, W2 gates and open K–Q/T milestones cover actual throughput, workspace/build-script/test/link reuse, snapshots and speculation. No supported 3x or >90% served claim yet. |
| Ship and sustain RABS on the fleet | Service/doctor/source-build/prototype deployment pieces exist. | Reopened S7 `bd-n8qt3` for released install path and S8 `bd-rb754` for actual 24-hour soak/continuous-week exit evidence. Compressed stress is not elapsed production soak. |

### Bridge: close the user-visible paths first

1. **Conventional correctness and capacity.** Finish existing coherent-source,
   dispatcher interception and artifact tasks; implement daemon crash recovery
   before trusting restart-resumed admission. Recovery must preserve uncertain
   ownership and never rerun a possibly completed command. Use durable
   wrapper/build/worker identities, not PID-only reconstruction. Test overlapping
   builds, crash during execution and retrieval, duplicate heartbeats/releases,
   stale identities, exact artifacts and no leaked or double-admitted slots.
2. **Truthful decisions and measurement.** Fix build outcome classification;
   keep raw exit, known compile/test phase and unknown state distinct. Complete
   the original performance suite using actual hook processes, actual selection
   and paired worker-direct/RCH workloads. Include failures, cold/warm caches,
   artifact parity, network cost and streaming latency. Do not weaken the 15%
   requirement to make small-build results green. Wire the existing metrics
   layer/exporter into the actual daemon and verify a real collector receives
   the promised metrics/traces/logs with bounded failure and shutdown flush.
3. **Repair the actual RABS worker/coordinator path.** Complete S5 authenticated
   ATP control/output transport, real enrollment/incarnation fencing and
   coordinator-only publication authority, still refusing commits until Phase
   1 as S5 requires. Run sandbox acceptance through the actual
   daemon and worker, including reconnect, restart and malformed-peer cases.
   Finish S7 provisioning and the real S8 shadow/chaos/soak acceptance.
4. **Deliver one sound automatic served class.** Use immutable registry/git
   dependency actions first. Connect real input descriptors and completed
   compiler outputs to coordinator scheduling/publication and the existing
   materializer. Never promote the shadow upper-bound projection into an
   authoritative key. Integrate sampling/quarantine and complete output/path/
   freshness checks before permitting the wrapper to skip rustc. Demonstrate
   two worktrees: first execution publishes, second hit actually avoids compiler
   execution, outputs match, and input changes miss. Revoked or partial results
   cannot be counted as successful hits. Fallback is allowed only before the
   delivery frontier with remote write rights revoked; partial installation or
   a lost acknowledgment requires safe recovery or refusal, never a compiler
   racing late remote writes. `bd-k52xe` now also depends on `bd-okthi` and
   `bd-rhdef`, retaining its materialization prerequisite.
5. **Expand only on measured delivery.** Apply the same live integration and
   differential proof to fleet singleflight/jobserver, workspace actions,
   build scripts, tests, links and snapshots. Keep original feature scope;
   defer default-on speculation/frontier work behind demonstrated correctness
   and positive value. Use the existing B/W2/T corpus and gates, not another
   reporting framework. Qualify native platforms and publish artifacts from
   their exact tested revisions before treating main-only fixes as shipped.

### Coverage corrections and verification limits

Initial authoritative tracker count: 2,067 total; 1,860 closed, 185 open,
20 in progress, two deferred. This is bookkeeping, not percent vision
delivery. Seven original beads were reopened above; no duplicate gap epics
were needed. Existing open work covers the other identified gaps, provided
closure means full original live acceptance rather than another library slice.

The assessment used complete primary README/AGENTS reads, full original and
RABS plan reads across independent reviewers, production call-site inspection,
current read-only CLI/status/installation observations, release archive listing,
Beads history and explicit `bv --db .beads/issues.jsonl` graph validation.
Do not confuse archived plans, fixtures, component tests or agreement between
reviewers with independent runtime proof.

Retained same-source verification from the preceding work includes remote
workspace check/strict Clippy and 14 focused retrieval tests; actual SSH quiet
and streaming artifact returns took 39.351s and 39.249s where the installed
baseline failed at 30s. No-op retrieval returned zero files successfully and
remote/local executable hashes matched. Those are correctness results under
deliberate throttling, not general speedup benchmarks. This assessment did not
rerun the entire workspace, crash the shared daemon, complete native macOS
qualification, or execute a production-duration RABS soak.

The detailed implementation and negative-test TODOs are embedded in each
reopened original bead. Review passes checked vision coverage, production
wiring, counterexamples, original acceptance, dependencies and shipped/main
separation. The historical plan follows as the retained target, not a current
completion report.

## Historical bridge baseline — August 10, 2026

> Companion to `COMPREHENSIVE_MASTER_PLAN_FOR_RABS_ASUPERSYNC_NATIVE.md`.
> That document is the vision; THIS one is the gap-closure execution plan
> from the 2026-08-10 reality check. Finding: 261/513 beads closed, the
> M1 keystone live-proven on the fleet, ~92K LOC of tested domain logic —
> and zero end-to-end capability, because no process boots RABS. The
> dominant gap is the SPINE. This plan closes every identified gap, spine
> first, then converts each library into delivered capability one served
> class at a time, with §6 targets wired as enforcing gates the moment
> each becomes measurable. Revised in place; never forked.

## Governing principles

1. **Spine before flesh.** No new pure-library modules whose consumer
   process doesn't exist. The walking skeleton lands first; everything
   after lands INSIDE it.
2. **Shadow before authority.** Every serving class runs in shadow
   (observe + would-have-hit + divergence-compare against real local
   execution) on real production traffic before serving a byte. The
   0-divergence sentinel is live from the first shadow day.
3. **Refuse, never fake.** Skeleton stubs are typed refusals with reason
   codes, not mocks that pretend success.
4. **Pay the re-integration tax explicitly.** Every epic closed at
   library fidelity gets a named live-integration bead re-verifying its
   original acceptance UNDER THE RUNNING SPINE. Library-done + live-done
   together are the only real "done".
5. **Gates land with capabilities.** Each §6 target gets an enforcing
   gate in the same phase that makes it measurable. A gate that cannot
   yet run is listed PENDING with its unlock phase — never silently
   absent.
6. **T-epic runs vertical.** Every phase exits only with its own
   fuzz/chaos/soak slice green; the proof program is a lane, not a
   finale.
7. **One mechanism, no drift.** Wherever a live path exists (D003 argv
   builder, D024 leases, D031 arbiter, B001 recorder), the spine mounts
   THAT module — a spine that reimplements a proven library is a defect.

---

## Phase S — The Walking Skeleton

Everything else in this plan is blocked behind S. Internal order:
S1‖S2‖S5 in parallel → S3 → S4 → S6 → S7 → S8. Estimated grain: 8 beads,
each 0.5–2 sessions.

### S1. `rabsd` binary + real Asupersync runtime island (THE M2 keystone)

`rabsd/src/main.rs`. Work items, in order:

1. **Runtime boot**: instantiate the actual `asupersync` runtime (the
   pinned rev is already a dependency with a curated feature profile —
   bead A004 — and ZERO call sites today). Root region = daemon
   lifetime; child regions per plan §12: `edge`, `coord`, `telemetry`,
   `janitor`. Map the existing `rabs_asupersync::region_tree` MODEL onto
   real regions: the model becomes the introspection/assertion layer
   over the live tree (the model is the spec; the runtime is the
   implementation; a divergence between them is a boot-time panic).
2. **Obligation-clean shutdown**: SIGTERM → region-cancel cascade →
   every obligation in `rabs_asupersync::obligations` either fulfilled
   or explicitly abandoned-with-reason in the shutdown receipt. Kill -9
   recovery: next boot replays the crashpack (existing module) and
   reports orphaned state.
3. **Config**: reuse RCH's config precedence chain; `[rabs]` section in
   the existing config.toml; `RABS_*` env overrides; refuse-on-unknown-
   key (config drift = typed error, not silent ignore).
4. **T053 logging from process birth**: every region gets a trace ID at
   spawn; the daemon's own lifecycle emits the standard's records.

Acceptance: (a) `rabsd --version/--help/--check-config` under 10ms;
(b) boot-to-ready and SIGTERM-to-exit each under 100ms on csd and hz2;
(c) shutdown receipt shows zero unaccounted obligations across 100
boot/kill cycles (scripted); (d) kill -9 mid-work → next boot crashpack
names the orphaned region; (e) model-vs-runtime region-tree assertion
active in debug builds.

### S2. Tiny wrapper binary `rabs-wrap` (real RUSTC_WRAPPER)

New minimal crate (A021's split-profile work applies: `opt-level="z"`,
LTO, panic=abort, stripped). Decision path per invocation:

1. argv[1..] classification (rustc vs probe — reuse the D019/C009
   parser knowledge: `-vV`/`___` probes always pass through instantly);
2. breaker-state file read → `wrapper_breaker::decide` (existing);
3. Closed-breaker path: UDS connect with the C-epic connect budget →
   C001 handshake (existing schema) → send B001-shaped invocation
   summary → receive decision (shadow mode: always `PassThrough`);
4. exec the real rustc, preserving EVERYTHING (exit code, signals,
   stdio streaming — no buffering, C007);
5. breaker-state update via `on_outcome` (existing).

Acceptance: (a) C010 overhead gate RE-RUN measuring THIS binary
end-to-end against a live rabsd — replaces the noop proxy; p95 < 10ms
enforced release-profile on csd and hz2, recorded beside the existing
numbers; (b) C009 contract matrix re-run with `rabs-wrap` interposed on
stable/beta/nightly — byte-identical build results, fixtures unchanged;
(c) daemon-dead test: rabsd stopped → wrapper passes through within the
breaker budget, breaker opens after the configured failures, probe
cadence honored (existing state machine, now live); (d) `#![forbid
(unsafe_code)]`, release binary < 2 MiB.

### S3. UDS server in the edge region

Inside S1's `edge` region: listener at the configured socket path,
`socket_admission` (existing module) enforced per connection,
`version_negotiation` (existing) on every handshake, per-connection
child region so a hung connection cancels cleanly, T053 trace per
consult.

Acceptance: (a) 64-way concurrent wrapper storm: zero drops, zero
wedges, admission refusals typed; (b) malformed-frame fuzz (reuse
protocol fuzz corpus) against the LIVE socket — no panic, typed
refusals; (c) socket file permissions 0600; stale-socket takeover safe
(flock + liveness probe, not blind unlink).

### S4. Shadow decision plane (M0's "shadow-only" promise, delivered)

For every wrapper consult, in the edge region:

1. Reconstruct the invocation via the B001 recorder schema (same code
   path as the production corpus recorder — one schema, two consumers);
2. Compute the REAL action key through the Epic F pipeline;
3. Look up would-have-hit against the shadow index (starts empty;
   populated by shadow-observed completions — the F-epic discovery
   cycle live);
4. Emit a decision receipt (R-epic schema) with outcome
   `ShadowPassThrough{would_have_hit, reason}`;
5. Nightly (or on-demand) shadow report: hit-rate by action class,
   would-have-saved estimates against B015/B009 baselines, divergence
   candidates queued for B005 replay comparison.

Acceptance: (a) 24h of real multi-agent traffic on csd with the wrapper
installed for at least one project: zero build breakage, zero artifact
divergence on a 50-build checksum sample (built with vs without wrapper
interposed); (b) shadow report generated with per-class hit rates;
(c) added latency accounted: consult p95 within the C010 budget under
real load; (d) receipts complete: every consult has exactly one receipt
(count reconciliation vs the corpus recorder's NDJSON).

### S5. `rabs-wkr` skeleton: real ATP session + orchestrated canonical exec

1. Worker main: boot runtime (same S1 machinery, worker region layout);
   establish authenticated ATP session to the coordinator (integrate the
   real `asupersync`/ATP transport — first wire use of the J-epic
   schemas); heartbeat with capability + pressure report (reuse
   HostIsolationSupport probe + disk/load sampling);
2. Execution service: accept a `CanonicalExecRequest` (namespace spec +
   argv, J-epic schema), run it through the PROVEN rabs-sandbox
   launcher, stream stdout/stderr/exit back, offer outputs as
   prepared-result metadata (H-epic pin schema) — coordinator refuses
   commits until Phase 1 (typed refusal, exercised in tests).

Acceptance: (a) session csd↔hz2 over ATP with capability visible in
`rabsd` status output; (b) THE ORCHESTRATION PROOF: the D003/D005
acceptance suite executed remotely via the session — same assertions
that were hand-SSH'd during Epic D, now flowing through the real
control plane; (c) session survives network flap (ATP resume) and
worker restart (session re-establish + capability re-report);
(d) worker never sees a commit API (compile-time: the worker crate
imports no commit types — R50 structurally).

### S6. Coordinator role boots in-process

The `coord` region gets its loop: mount D024 `TargetLeaseRegistry`,
D031 `DestinationArbiter`, and a singleflight table keyed by action key.
Edge consults route through coord in-process (plan §10: one binary,
authority split structural).

Acceptance: (a) two concurrent shadow consults for one action key →
receipts show one leader + one follower; (b) lease/arbiter state
inspectable via `rabsd status --coord`; (c) coord region restart (fault
injection) does not take down edge consults (typed degraded mode,
breaker semantics per C-epic).

### S7. Packaging + fleet provisioning (the NO_BEAD gap, closed)

Release builds of `rabs-wrap`/`rabsd`/`rabs-wkr` in CI; install.sh
`--with-rabs` flag; `rch fleet deploy`-pattern rollout for rabs-wkr to
bwrap-capable workers (capability-gated: refuses non-bwrap hosts with
the reason); launchd (csd) / systemd (workers) units; `rabsd doctor`
covering socket, breaker file, worker sessions, CAS dir.

Acceptance: one-command deploy to hz2 + one vmi from clean state;
doctor green; uninstall leaves no live hooks (breaker file quiesced so
wrappers pass through permanently).

### S8. Spine chaos slice (T-lane for Phase S)

Fault-injection suite: kill each process at randomized points mid-
consult/mid-exec (seeded, T053-logged); assert fail-open invariants —
no wedged wrapper > budget, no lost receipt without a crashpack entry,
breaker state machine transitions exactly per the C-epic model under
real faults. Soak: 24h shadow mode under production agent load with
zero unexplained receipt gaps.

---

## Phase 1 — First served class: registry/git dep compiles (M4)

Smallest real value, largest denominator, lowest risk: registry/git dep
compiles are immutable-input, path-canonical (PROVEN), and dominate
cold/branch-switch builds. Ladder within the phase:

1. **Live CAS**: mount rabs-cas as the on-disk store under rabsd
   (re-integration bead: the library's atomic-publication acceptance
   re-run through daemon crash-kill cycles); quota + janitor region.
2. **Worker dep-compile execution**: coordinator plans the canonical
   namespace for a registry unit (D005 mounts + D006 mappings — proven),
   worker executes, harvests via K-epic beads, offers; coordinator
   commits under H-epic pins (the library machinery's first live
   commits).
3. **Edge materialization**: D009 dep-info derivation + D010 mtime
   choreography + D028 byte-correct derivation + D031 arbiter + D025
   replacement — every one library-proven, every one getting its live
   bead here.
4. **Serving ladder per class, with PRINCIPLED ratcheting**: shadow →
   serve-with-100%-divergence-sampling → staged reduction governed by a
   sequential probability ratio test (SPRT), not vibes: treat each
   sampled serve as a Bernoulli trial with H0 "divergence rate ≤ 1e-6"
   vs H1 "≥ 1e-4"; the sampling rate may step down (100% → 25% → 5% →
   1% floor) only when the accumulated log-likelihood ratio crosses the
   accept-H0 boundary at α=β=1e-3, and ANY observed divergence resets
   the class to 100% + quarantine review. This gives every ratchet step
   an explicit, auditable risk bound recorded in its receipt — the
   decision to trust is itself evidence-bearing. The floor never
   reaches 0.
5. **Divergence sentinel**: served result vs real local execution;
   ANY divergence = class-wide automatic demotion to shadow + incident
   receipt (H-epic quarantine machinery live) + the divergent pair
   preserved whole as a minimization corpus entry (T012 feedstock).

Gates landing in this phase (§6): local small-artifact hit < 50ms +
unavoidable fs cost; miss overhead < 2% on admitted actions; served-
result divergence = 0. All measured on the replay corpus + live sample,
stored beside B015/B009 baselines.

Milestone acceptance (M4): the two-worktree demo — worktree B's real
`cargo build` receives its registry deps SERVED from worktree A's
execution, wall-clock delta recorded honestly (including all overhead),
divergence 0 over ≥1000 served units, `rch why` explains every serve
from real receipts.

## Phase 2 — Authority, fleet, data plane (M6–M8)

- Coordinator authoritative commit machinery live (I5/I10; workers
  offer, never commit — R50 now enforced on the wire, tested by a
  malicious-worker fixture attempting a commit frame → typed protocol
  violation + session termination).
- ATP object data plane: chunked, resumable, digest-verified CAS
  transfer (J/K); cross-worker singleflight on ≥3 workers; hedged
  fetches for tail control.
- Scheduler + jobserver (Epic I) live: root-permit broker under real
  15-agent storms; the storm harness (T) built and baselined against
  current-RCH (completing B009's remaining arm as a side effect).
- Continuous convergence probe: D019's cross-machine digest equality as
  a scheduled fleet health check (a failing host is evidence of drift —
  auto-quarantine from serving, H-epic).

## Phase 3 — Whole-command + workspace plane (M9–M10)

- Whole-command canonical remote execution over ATP replaces the
  current-RCH SSH path for RABS-enrolled projects; D024 leases and D018
  snapshots live per command; D032 lineage sealing per resolution.
- Workspace-member rustc actions served (Epic M): M002 canonical
  snapshots + observed-input recipes; pipelined rmeta (early-metadata
  streaming from workers).
- Gate: median agent edit/check/test loop ≥3× and p90 ≥2× on the replay
  corpus — the headline numbers, measured honestly with the corpus
  flywheel.

## Phase 4 — The long tail (M11–M14)

Build-script run cache (Epic N — 0% today; D025 semantics live +
E-epic hermeticity classes), test-result cache (O live beads), link
acceleration (L), incremental snapshots/time travel (P, evidence-gated
per plan), speculation/prewarm (Q) fed by the edit-watcher. Each class
climbs the same serving ladder with its own T-lane slice.

## Phase 5 — Ops, advise, frontier (M15–M16)

`rch advise` + fragmentation analyzer, Epic N diagnostics surface,
R-epic ops polish, S-epic macOS lanes (D013/D021 land here where VM
infrastructure exists), and the evidence-gated frontier review: every
§6 gate green or explicitly waived with evidence.

---

## Cross-cutting workstreams

- **W1 Re-integration ledger.** Auto-rule: when a phase mounts a
  library-closed module, a live bead re-runs its ORIGINAL acceptance
  under the spine. Initial ledger: rabs-cas atomic publication (Ph1),
  H-epic pins/quarantine (Ph1/2), F-epic key pipeline (S4), C-epic
  breaker/handshake (S2/S3), I-epic broker (Ph2), D024/D031 (S6),
  D009/D010/D025/D028 (Ph1), R-epic receipts (S4).
- **W2 Gate ledger.** §6 table → enforcing gates: wrapper p95 (LIVE
  since C010, re-scoped in S2); hit latency + miss overhead + divergence
  (Ph1); storm throughput (Ph2); agent-loop ratios + branch ping-pong
  (Ph3); cold wide workspace (Ph2/3); served-fraction telemetry (Ph3+).
  Ledger doc lists status: ENFORCING / PENDING(phase) — never absent.
- **W3 T-epic verticalization.** The 44 open T-beads get phase labels;
  each phase's exit criteria include its T-slice. E023/T018 (Epic D fuzz
  debt) lands in Phase S/1 since its subject is already live.
- **W4 Honesty instrumentation.** T053 records + decision receipts wired
  through every process from birth; `rch why` answers from real receipts
  starting in shadow mode; refusal reason codes stable and documented.
- **W5 Corpus flywheel.** B001 production recorder keeps feeding replay;
  every phase's claims measured against the corpus next to B015/B009
  baselines (sccache cached cold build: 54.5s workspace / 32.9s
  asupersync — the numbers to beat are on record).

## The asupersync integration contract (S1/S5 exactness)

The runtime island is not "use a runtime somewhere" — it is a specific
contract, and naming it now prevents S1 from drifting into a Tokio-shaped
port:

- **Regions own lifetimes**: every daemon subsystem is a region whose
  drop cancels its children; there are no detached tasks anywhere (the
  no-orphans claim R90 rests on this + cgroup containment on workers).
- **Cx is the only capability channel**: spawn/timer/IO capabilities
  flow through the context parameter; a module that wants IO declares it
  in its signature. This is what makes S8's fault injection tractable —
  a lab Cx swaps in deterministic time and faulty IO without cfg tricks.
- **Obligations are typed completions**: the `rabs_asupersync::
  obligations` model maps 1:1 onto reserve/commit/abort of real
  completion tokens; the shutdown receipt is generated FROM the
  runtime's own accounting, and the model layer asserts equivalence in
  debug builds (spec-vs-implementation, mechanically held).
- **Upstream gap protocol**: any missing asupersync API discovered
  during S1/S5 becomes an issue in the asupersync repo + a pinned-rev
  bump bead here (A010's upgrade bot lane) — never a local fork, never
  a vendored patch.

## Risk register with kill-criteria

| Risk | Phase | Tripwire | Response |
|---|---|---|---|
| Asupersync integration reveals blocking upstream gaps | S1/S5 | any S1 acceptance unreachable without upstream change | pause S-work on that item only; file upstream; continue parallel S items (S is deliberately parallel) |
| Wrapper overhead regresses with a real daemon behind it | S2 | re-scoped C010 gate > 10ms p95 | breaker default flips to pass-through-always until fixed; shadow data still collected out-of-band via B001 recorder |
| Shadow mode perturbs production builds at all | S4 | any checksum mismatch in the 50-build sample | wrapper uninstalled by default; S4 acceptance blocks S6+ |
| Divergence > 0 in Phase 1 | Ph1 | sentinel fires | class demoted automatically; M4 gate blocked; divergent pair minimized (T012) before any re-promotion |
| Fleet too saturated for honest gates | any | gate variance > 30% run-to-run | gates run on a reserved quiet window (worker drained via existing rch drain), never on contended hosts; contended numbers recorded but marked non-gating |
| Re-integration tax exceeds estimates | Ph1+ | live bead reopens > 20% of a "closed" epic | reality-check re-run for that epic; its remaining closed beads get audit beads before further phases consume them |

## Definition of spine-complete (Phase S exit)

All eight S-acceptances green, PLUS: one continuous week of shadow mode
on csd with zero build perturbation and complete receipts; the
orchestrated D003/D005 proof green via ATP; `rabsd doctor` green on csd
+ hz2 + one vmi; C010/C009 gates re-scoped to the real binaries and
enforcing in CI. Only then does Phase 1 open.

## Sequencing and bead delta

S first (S1‖S2‖S5 → S3 → S4 → S6 → S7 → S8); Phase 1 after S; 2–5 follow
the existing milestone DAG. The 250 open beads map onto Phases 1–5 and
gain only sequencing. NET-NEW beads: 8 spine (S1–S8), ~8 W1 ledger,
~6 W2 gate ledger, 1 T-labeling task, plus milestone rewires (M2 ←
S1, M0-edge ← S3/S4). Everything else already exists in the graph.
