# Layer-0 baseline artifacts (bead B015)

NDJSON records (`kind=layer0-baseline`, `v=1`) produced by
`scripts/rabs_layer0_bench.sh`: per (repo, host, toolchain, variant,
scenario, iteration) wall-clock durations for `stock` vs `layer0`
(the B014 pack rendered for the capturing host by
`cargo run -p rabs-key --bin layer0_render`).

These stored measurements are the reference point for RABS performance
claims (B008 report family); B009 adds sccache and current-RCH variants
on the same scenarios.
