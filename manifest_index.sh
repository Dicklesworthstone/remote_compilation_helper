#!/usr/bin/env bash
# ACFS manifest index (auto-generated).
# Format: "<sha256>  <path>" (sha256sum -c compatible)
# Usage:
#   ./manifest_index.sh --print
#   ./manifest_index.sh --verify

set -euo pipefail

manifest_entries() {
  cat <<'MANIFEST_EOF'
c36c21a1c4058ec4c17321f29c2830b118545874cde5213efc0f6627abba31fe  .claude/skills/rch/SKILL.md
5986307984ec9bd1e29588082e36b56fdf38f113ebf6d3cd4cf622b4fe760f40  .claude/skills/rch/assets/workers-template.toml
af6fc3f975e83e7e82413d6b9ceedd4fdabb8261f07945853b5827fcb5333e26  .claude/skills/rch/references/COMMANDS.md
dace3805e2933e20566e4c9b65c0a7a0ab383826e5ebe9e3ae19de4d32b8a0d0  .claude/skills/rch/references/CONFIGURATION.md
e8741ce6bcca3d0b6ab5c2f6ccd8f8c4df3c5fe95b6773f262ba5b062e99e142  .claude/skills/rch/references/DISK_AND_PRESSURE.md
a758dffe59e6edcbe29793f68f2677638b7c483e5aff13e5e1c3b344f4fa510b  .claude/skills/rch/references/ERROR_CODES.md
20cba16b629ed9748ef9dc6152b2cf3fdffd846a2f75b7aaec95f965bb270d6f  .claude/skills/rch/references/EXEC_MODES.md
6b85a40511a54e7d72e607d7eda6aceee98f4a9ea5d65f1a9989258cce9df8ad  .claude/skills/rch/references/FAIL_OPEN.md
44dabc9368f1a1940480012e5c6e2918d50d53e13591ce587ad364f19b8bbb2f  .claude/skills/rch/references/HOOKS.md
ed835b5a666a4dc4064c82e9a97f1b8e5f2ff63d77a4fefc8c4efc62e682ef17  .claude/skills/rch/references/MACHINE_INTROSPECTION.md
1986b304c09b9a712db48d8dbcaf0468857bd57383764d20ddbb4609048c8f58  .claude/skills/rch/references/MULTI_AGENT_CONTENTION.md
228ea605f8a69cb9779b0a3ee4ded6a2ba17714ef326b75c47fd56523d81906f  .claude/skills/rch/references/OPERATIONS.md
7bc3564426898803bc00e89e511d3a2c39944c024d5eaee8bbe1261b44e66272  .claude/skills/rch/references/PATH_DEPENDENCIES.md
dfb17553052f9197f49f48d9cca0d23933c9dbf9a8c8e9f680ad98b30e03d23d  .claude/skills/rch/references/RECOVERY_PLAYBOOKS.md
2ab5104ab64f90191598df70d60e543c9286008ebca972c073ebb57aedda1886  .claude/skills/rch/references/SELF_HEALING.md
70d2c567d7833de9d6d381934966af171af853fd6723aaae8438e57b9921bdc9  .claude/skills/rch/references/SHIM.md
14a12e257e66afcdd6293d35781d3d81720008898c10132174d5d4c516c1c9ec  .claude/skills/rch/references/SSH_KEY_RECOVERY.md
bc3c7b52d508da868c16db0ca170c6041c7c3ba40c39e983d5c92be6e9debf83  .claude/skills/rch/references/SSH_TUNING.md
6155d3459e1c75180b13f8743213c7803bf5c94906d4d51d7d85fa790cfb6b88  .claude/skills/rch/references/TELEMETRY_RECOVERY.md
15c13f1d1ea28af640cbf545424e2875b0f87cf884fac2fd721ac3fc62bf07af  .claude/skills/rch/references/TROUBLESHOOTING.md
a45897450ae751863361fe6b462914b47a418ebbbd3a08c702a58d26a1b58d65  .claude/skills/rch/references/WORKERS.md
2242cb3d6f75acca40344a768f8aa8113f151d660ce65310dc1300fcf24666e5  .claude/skills/rch/scripts/auto_recover.sh
b4feb9ee50963e2c51735417234cdd5d0bf6fc0843360a210cfe98d9c241838d  .claude/skills/rch/scripts/diagnose-rch.sh
06f3e09aef3f7f95c087b4b433e850e2ff04be27815a110d6af2b7d4b5987e4a  .claude/skills/rch/scripts/mine_rch_history.sh
75181ee410d39dbc6e7d1271494a34157e64b47d70feae90da4c9128bd7fecf5  .claude/skills/rch/scripts/multi_agent_safety.sh
ab02dfa5e60966485745f5c72eb246d75649c561eb87a6f8f41129e9fde63dd9  .claude/skills/rch/scripts/protocol_test.sh
b81a9e8d94e4d6e17a4fe8a8d2719cb34815a80e3f31a27eea0174dec351aa48  .claude/skills/rch/scripts/validate-setup.sh
84df331c61455c6cdbbf6c152d12df260223cf143cc2293be7a2db22858637c1  .claude/skills/rch/scripts/worker_disk_triage.sh
737d8b37b12f7003c90f07a7d62645fcb8035286f6148b5aeea2cdf68d2c3900  .claude/skills/remote-compilation-helper-setup/SKILL.md
b789a127cf6c1274d3ccb7e16b389613e3c058cbe91852d983a3be08bc9f0138  .claude/skills/remote-compilation-helper-setup/assets/workers-template.toml
a9d2b280dc866987029a757debb2f507cd048638ef0ea1d18b2cc8a21a5f22bd  .claude/skills/remote-compilation-helper-setup/references/HOOKS.md
2c6286a6d5f8289c3c7046bbdfa9669205ed7ae616fa38d10622d835f9583305  .claude/skills/remote-compilation-helper-setup/references/TROUBLESHOOTING.md
0dfdc37e17a39a2dbefc096935553df2234efe7c84132f6213f7e9266be872de  .claude/skills/remote-compilation-helper-setup/references/WORKERS.md
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
