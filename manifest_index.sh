#!/usr/bin/env bash
# ACFS manifest index (auto-generated).
# Format: "<sha256>  <path>" (sha256sum -c compatible)
# Usage:
#   ./manifest_index.sh --print
#   ./manifest_index.sh --verify

set -euo pipefail

manifest_entries() {
  cat <<'MANIFEST_EOF'
e28c635b0dc93fd3289b97834ce37bf9c856cac0394b2a9d6cd929a229bd201c  .claude/skills/rch/SKILL.md
ce560d0df5c3fa39962339d4a887bfbff6fb659ec3ddc320e53cd311c4f8e6cf  .claude/skills/rch/assets/workers-template.toml
ad3a15555c717d7ec351938a741d791dafd4599795a6891b293de767f5d528af  .claude/skills/rch/references/COMMANDS.md
60bc06b1e100188e78be3abfdcc28a15c038e96763a2ca2caa8594e1d50d0a0c  .claude/skills/rch/references/CONFIGURATION.md
a9d2b280dc866987029a757debb2f507cd048638ef0ea1d18b2cc8a21a5f22bd  .claude/skills/rch/references/HOOKS.md
a486979e19f25d27ac308a057d20a1ea09bc09c47805232029359131d4dee9b5  .claude/skills/rch/references/OPERATIONS.md
2c6286a6d5f8289c3c7046bbdfa9669205ed7ae616fa38d10622d835f9583305  .claude/skills/rch/references/TROUBLESHOOTING.md
9c4b4e7e0679c9a618f5ea881759865959e2970f2a3296b75977d50241bf8a5d  .claude/skills/rch/references/WORKERS.md
21d13636cc465aeeceef2271361666216e72f51dd20edbc9d84d79acda71e8f5  .claude/skills/rch/scripts/validate-setup.sh
737d8b37b12f7003c90f07a7d62645fcb8035286f6148b5aeea2cdf68d2c3900  .claude/skills/remote-compilation-helper-setup/SKILL.md
ce560d0df5c3fa39962339d4a887bfbff6fb659ec3ddc320e53cd311c4f8e6cf  .claude/skills/remote-compilation-helper-setup/assets/workers-template.toml
a9d2b280dc866987029a757debb2f507cd048638ef0ea1d18b2cc8a21a5f22bd  .claude/skills/remote-compilation-helper-setup/references/HOOKS.md
2c6286a6d5f8289c3c7046bbdfa9669205ed7ae616fa38d10622d835f9583305  .claude/skills/remote-compilation-helper-setup/references/TROUBLESHOOTING.md
9c4b4e7e0679c9a618f5ea881759865959e2970f2a3296b75977d50241bf8a5d  .claude/skills/remote-compilation-helper-setup/references/WORKERS.md
21d13636cc465aeeceef2271361666216e72f51dd20edbc9d84d79acda71e8f5  .claude/skills/remote-compilation-helper-setup/scripts/validate-setup.sh
MANIFEST_EOF
}

case "${1:---print}" in
  --print)
    manifest_entries
    ;;
  --verify)
    manifest_entries | sha256sum -c -
    ;;
  *)
    echo "Usage: $0 [--print|--verify]" >&2
    exit 2
    ;;
esac
