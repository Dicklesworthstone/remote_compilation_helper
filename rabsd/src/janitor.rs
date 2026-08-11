//! # janitor — the RABS on-disk store region (bead bd-hfhq2, W1)
//!
//! The `janitor` subsystem region owns the daemon's durable state: the
//! rabs-cas content-addressed **byte store** and its metadata index. Per
//! the bridge-plan W1 re-integration ledger, rabs-cas closed its beads at
//! *library* fidelity; this region re-runs its atomic-publication and
//! durability behavior **under the running daemon** — mounted here, owned
//! for the daemon lifetime, and reconciled fail-closed at every boot so a
//! prior unclean death can never let torn authoritative state serve.
//!
//! Authority split (unchanged): the janitor OWNS the store; the edge only
//! reads through it once serving is wired (a later W1 vertebra). The
//! worker still only OFFERS results and never commits (R50).

pub mod store;
