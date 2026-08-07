# RABS Incident Runbooks (bead R008)

Machine-readable twin: `rabs-protocol/src/incident_bundle.rs` — a
test pins every class anchor below against that registry, so these
runbooks cannot drift from the code. Each incident class has six
facets: detection signal, automatic containment, operator commands,
evidence bundle, recovery path, and a regression-test requirement
(an incident is not closed until its regression test exists).

## incorrect-result-divergence

- **Detect:** F022/J016 differential mismatch, or a same-key
  candidate classifying `SemanticDivergence` (A018).
- **Contain:** automatic — quarantine the ACTION key; serving for it
  stops fleet-wide; both candidates preserved.
- **Operate:** `rch why action KEY`; `rch inspect action KEY`;
  compare the two attempt evidence bundles.
- **Evidence:** both canonical manifests, both attempt evidence
  bundles, the key breakdown, the projection decision.
- **Recover:** root-cause the unsound key component; ship the key
  fix; epoch-bump if the fix changes key semantics; un-quarantine.
- **Regression:** a fixture reproducing the divergence must land
  red-then-green with the fix.

## object-corruption

- **Detect:** digest mismatch on read/verify (F024 hit verification),
  or the T044 collision quarantine firing.
- **Contain:** automatic — the object is quarantined (never served);
  peers re-fetch from source.
- **Operate:** `rch inspect object DIGEST`; check storage health.
- **Evidence:** the stored bytes (quarantined copy), expected digest,
  observed digest, storage-path metadata.
- **Recover:** re-ingest from an authoritative source; if disk-level,
  run storage diagnostics before re-admitting the volume.
- **Regression:** corruption-injection fixture over the read path.

## publication-fence-violation

- **Detect:** a publication attempt with a stale boot generation /
  incarnation (F029) or after an F031 tombstone.
- **Contain:** automatic — the publication refuses (fenced); the
  worker's lease is not renewed.
- **Operate:** `rch why worker DECISION-ID`; inspect fence sequence.
- **Evidence:** the fencing tokens (expected vs presented), the
  publication record, the worker identity row.
- **Recover:** the worker re-registers with a fresh incarnation;
  no data repair needed (the fence held).
- **Regression:** the F029/F031 fence suites already gate; add the
  new ordering if the violation found a hole.

## orphan-process-or-resource

- **Detect:** G002 obligation leak report / G015 dashboard; worker
  reap sweep finds unowned process groups or temp dirs.
- **Contain:** automatic — kill the process group; reap the temp
  tree under the crash-cleanup policy.
- **Operate:** `rch inspect operation OP-ID`; review the crashpack.
- **Evidence:** the G011 crash scene, obligation table snapshot,
  process/resource inventory.
- **Recover:** verify the reap; if obligations leaked, the G-series
  supervision bug is the incident, not the orphan.
- **Regression:** a cancellation-at-that-await fixture (G012 lab).

## protocol-compatibility-failure

- **Detect:** J002 negotiation refusals spiking, or the R009 doctor
  flagging skew.
- **Contain:** automatic — refused sessions stay refused (fail
  closed); no downgrade.
- **Operate:** `rch doctor --fleet`; follow its remediation lines.
- **Evidence:** both hellos, the doctor report, deploy timeline.
- **Recover:** upgrade the older side per the doctor; verify with a
  fresh doctor run.
- **Regression:** T009 upgrade-matrix case for the failing pair.

## worker-identity-mismatch

- **Detect:** S001 identity store mismatch: presented identity does
  not match the pinned worker key.
- **Contain:** automatic — the connection refuses; the worker is
  excluded from scheduling (I008 hard exclusion).
- **Operate:** `rch inspect worker WORKER-ID`; audit the identity
  store rotation log.
- **Evidence:** presented vs pinned identity, rotation history,
  connection metadata.
- **Recover:** if legitimate rotation: re-pin through the S001
  rotation path. If not: treat as compromise; rotate fleet secrets.
- **Regression:** identity-mismatch fixture on the handshake path.

## secret-exposure

- **Detect:** S007 nonshareable classification firing on an artifact
  that already left the box, or plaintext found in a
  transcript/receipt audit.
- **Contain:** automatic — the artifact's namespace is marked
  nonshareable and pulled from serving; the S003 tokens for the
  affected slot are revoked immediately.
- **Operate:** rotate the exposed secret at its source FIRST; then
  `rch inspect object` the exposure path.
- **Evidence:** the redaction outcome, the artifact identity, the
  slot name (never the value), the delivery audit trail.
- **Recover:** rotated secret + re-run of affected actions under the
  new slot version; confirm the old value is dead at the source.
- **Regression:** a planted-secret fixture through the exact leak
  path (S007's suite extends).

## storage-exhaustion

- **Detect:** S008 disk/temp quota refusals; store write failures.
- **Contain:** automatic — per-peer quotas already bound the blast
  radius; retention (P008/H-series) evicts by policy.
- **Operate:** `rch inspect cache`; review retention policy sizing.
- **Evidence:** quota counters, largest-namespace table, eviction
  log.
- **Recover:** raise quota or tighten retention; verify headroom.
- **Regression:** quota-exhaustion fixture stays bounded (S008).

## scheduler-pressure-collapse

- **Detect:** I006 pressure signals + I012 brownout engaging;
  admission refusals spiking.
- **Contain:** automatic — brownout sheds speculative load first
  (I012); hard exclusions protect collapsing workers (I008).
- **Operate:** `rch why slow BUILD-ID`; review I014 storm telemetry.
- **Evidence:** pressure receipts, brownout decisions, queue depths.
- **Recover:** capacity returns → brownout lifts by its own
  hysteresis; review pool sizing (I013/I017).
- **Regression:** an I014 storm scenario at the collapse shape.

## cancellation-hang

- **Detect:** a cancel acknowledged but the operation still holds
  obligations after its deadline (G002/G010 supervision).
- **Contain:** automatic — escalate kill to the process group;
  fence the attempt (F031) so late output is dead.
- **Operate:** `rch inspect operation OP-ID`; pull the crashpack.
- **Evidence:** the cancellation timeline (sequence-stamped), the
  await-point inventory, the crash scene.
- **Recover:** kill + reap verified; the hang's await point gets a
  G012 lab case.
- **Regression:** cancellation-at-every-await must cover the point.

## reconciliation-conflict

- **Detect:** I52 sequence-domain reconciliation finds two
  irreconcilable authoritative records for one identity.
- **Contain:** automatic — both records preserved; the identity is
  quarantined from serving (never pick a winner silently — the
  T044/H003 posture).
- **Operate:** `rch inspect action KEY`; compare publication
  records.
- **Evidence:** both records, their sequence provenance, the
  authority matrix rows in force.
- **Recover:** the A005 authority rules decide; if they cannot, the
  identity stays quarantined and the bug is in authority handling.
- **Regression:** a T040-family scenario reproducing the ordering.

## key-instability-regression

- **Detect:** Q011/F018 fragmentation spike on one component, or
  F014 invariance failures: identical inputs producing different
  keys.
- **Contain:** automatic — affected families demote to the
  path-preserving/local lane (D030) until stable.
- **Operate:** `rch why miss` on sampled misses; read the component
  histogram.
- **Evidence:** breakdown diffs, the fragmenting component's
  histogram, recent key-code changes.
- **Recover:** fix the unstable component; F014/F015 must pass;
  epoch-bump if persisted keys are poisoned.
- **Regression:** an F014 invariance case for the unstable input.

## hit-rate-fragmentation

- **Detect:** hit rate sags while Q011 shows variant spread rising.
- **Contain:** none automatic — this is an efficiency incident, not
  a correctness one; serving stays sound.
- **Operate:** run the Q011 analyzer; apply its costed convergence
  recommendations (R010 dashboard).
- **Evidence:** the analyzer report, per-category waste, the
  convergence deltas over time.
- **Recover:** converge the top fragmenter; re-measure.
- **Regression:** the fleet corpus report tracks the category —
  regression shows up as the waste number climbing back.
