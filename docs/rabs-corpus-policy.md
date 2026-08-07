# RABS Record/Replay Corpus Policy

**Bead:** `rabs-root-4pidu.20.7` (B007) · **Consumer:** the B002 recorder,
the corpus exporter, and the B011 minimizer — their implementations must
enforce every MUST below; reviewers gate those beads on conformance ·
**Gates:** B002/B004/B005/B011 cannot close without conforming ·
**Observed defect class:** credential/source leakage into durable
corpora and unshareable oversized traces · **Retirement:** never while a
corpus exists; supersede by versioned revision.

The corpus is simultaneously benchmark input, shadow-verification input,
regression suite, key-stability study, scheduler training data, and launch
evidence (plan §139). These roles pull toward keeping everything; privacy
pulls toward keeping nothing. This policy fixes the line.

## 1. Content rules (what a record may contain)

- Records MUST be `rabs.invocation-record` schema instances (B001): raw-byte
  **correlation digests** plus **redacted** presentation forms produced by
  the A007 library at capture time. There is no schema field for raw argv,
  raw environment values, or source bytes — additions of such fields are a
  policy revision, not an edit.
- Source contents MUST NOT be retained by default (B004). Where a study
  needs bytes (e.g. divergence minimization), retention is per-item,
  explicit, and expires with the incident that justified it.
- Worktree/home paths MUST be stored in redacted (`~`-relative or virtual)
  form. Hostnames and usernames MUST NOT appear.
- Outcome records keep signal-vs-exit distinction; timings and resource
  observations are unrestricted (they identify machines only via opaque
  peer IDs).

## 2. Retention

- **Default record lifetime:** 180 days rolling, then deletion; records
  referenced by an open incident, an active benchmark baseline, or a
  release evidence bundle (T013) are pinned until that reference closes.
- **Baselines** (B009/B015): retained indefinitely; they are the
  comparison anchors for every later claim.
- **Minimized reproductions** (B011): retained with their incident;
  deleted when the incident's regression test lands (the test supersedes
  the trace).
- Deletion is by the corpus tooling under this policy — never ad hoc; the
  AGENTS.md file-deletion rule applies to humans and agents alike, so the
  tooling's retention sweep is the single sanctioned deletion path.

## 3. Export (leaving the host/fleet)

- Records MAY move freely within the administrative trust domain (V1 is
  one domain — S014).
- Export OUTSIDE the domain (bug reports, upstream issues, publications)
  requires: (a) the B011 minimizer's output, never raw session dumps;
  (b) a fresh redaction pass with the then-current A007 library;
  (c) operator sign-off recorded next to the exported artifact.
- Secret scanners on export are advisory defense-in-depth: they cannot
  prove absence of secrets (plan §31.1); the structural rules in §1 are
  the actual control.

## 4. Minimization (B011 contract)

A minimized reproduction is the smallest record set that still reproduces
the finding, produced by: input bisection, invocation shrinking, and
dropping uninvolved records — re-verifying reproduction at every step.
Minimized artifacts carry: the originating record correlation digests,
the reduction log, and the deterministic seed(s) needed for replay
(T053 logs carry the seeds).

## 5. Stratification metadata

Records carry scenario labels (B006: clean/no-op/leaf/root/branch/storm/
CI/IDE) and repo/toolchain/action-class tags so replay selection (B010)
can cover the distribution. Tags are enumerated values, never free text —
free text is a leak channel.

## Change log

- 2026-08-07 — v1. Created with the B001 schema (bead B007).
