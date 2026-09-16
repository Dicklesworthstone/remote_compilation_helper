#!/usr/bin/env bash
# Isolated HOME integration of install.sh with a real, already-built RCH binary.
# Does not compile, alter real toolchains, start services, or delete fixtures.
# Usage: bash scripts/install_shim_unit_test.sh /absolute/path/to/rch
set -euo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rch_test_binary=${1:?pass an already-built RCH binary}
[[ "$rch_test_binary" = /* && -x "$rch_test_binary" ]]
fixture=$(mktemp -d "${TMPDIR:-/tmp}/rch-install-shim.XXXXXXXX")
printf 'Retained installer fixture: %s\n' "$fixture"
export HOME="$fixture/home" RUSTUP_HOME="$fixture/rustup"
export RCH_CONFIG_DIR="$fixture/config" RCH_INSTALL_DIR="$fixture/bin"
export RCH_INSTALLER_LIB=1 RCH_NO_UPDATE_CHECK=1
mkdir -p "$HOME" "$RUSTUP_HOME" "$RCH_CONFIG_DIR" "$RCH_INSTALL_DIR"
ln -s "$rch_test_binary" "$RCH_INSTALL_DIR/rch"
# shellcheck source=../install.sh
source "$project_root/install.sh"
export MODE=local
export SHELL=/bin/bash
printf '[general]\nrole = "dispatcher"\n' > "$CONFIG_DIR/config.toml"
# No compiler is involved: fake local cargo is a PATH resolution sentinel only.
mkdir -p "$fixture/local-tools"
printf '#!/bin/sh\nprintf LOCAL_SENTINEL\\n\n' > "$fixture/local-tools/cargo"
chmod +x "$fixture/local-tools/cargo"
original_path="$fixture/local-tools:$PATH"
export PATH="$original_path"
configure_dispatcher_shim
[[ -x "$HOME/.rch/shims/cargo" && -x "$HOME/.rch/shims/cargo-clippy" ]]
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
first_rc=$(cat "$HOME/.bashrc")
configure_dispatcher_shim
[[ "$(cat "$HOME/.bashrc")" == "$first_rc" ]]
printf 'PASS: dispatcher install persists first Cargo PATH entry and is idempotent\n'

# Simulate an updater appending a competing PATH entry. Preserve all prior text.
printf '\nexport PATH="%s:$PATH"\n' "$fixture/local-tools" >> "$HOME/.bashrc"
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$fixture/local-tools/cargo" ]]
configure_dispatcher_shim
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
grep -F "$fixture/local-tools" "$HOME/.bashrc"
printf 'PASS: repeated install repairs updater PATH drift without discarding rc text\n'

before_rc=$(cat "$HOME/.bashrc")
export RCH_NO_RC=1
configure_dispatcher_shim
[[ "$(cat "$HOME/.bashrc")" == "$before_rc" ]]
unset RCH_NO_RC
printf 'PASS: RCH_NO_RC preserves shell configuration\n'

export NO_SERVICE=true
install_dispatcher_shim_watchdog
[[ -x "$HOME/.rch/shim-watchdog" ]]
[[ ! -e "$HOME/.config/systemd/user/rch-shim-watchdog.timer" ]]
printf '\nexport PATH="%s:$PATH"\n' "$fixture/local-tools" >> "$HOME/.bashrc"
chmod 644 "$HOME/.rch/shims/cargo"
PATH="$original_path" "$HOME/.rch/shim-watchdog"
[[ -x "$HOME/.rch/shims/cargo" ]]
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
before_rc=$(cat "$HOME/.bashrc")
printf 'PASS: a watchdog cycle repairs nonexecutable shim and updater PATH drift\n'

for role in worker hybrid; do
    printf '[general]\nrole = "%s"\n' "$role" > "$CONFIG_DIR/config.toml"
    before_shim=$(sha256sum "$HOME/.rch/shims/cargo")
    configure_dispatcher_shim
    "$HOME/.rch/shim-watchdog"
    [[ "$(sha256sum "$HOME/.rch/shims/cargo")" == "$before_shim" ]]
    [[ "$(cat "$HOME/.bashrc")" == "$before_rc" ]]
done
printf 'PASS: worker and hybrid roles are not changed\n'

printf '[general]\nrole = "not-a-role"\n' > "$CONFIG_DIR/config.toml"
if configure_dispatcher_shim; then
    printf 'FAIL: invalid role reported success\n' >&2
    exit 1
fi
[[ "$(cat "$HOME/.bashrc")" == "$before_rc" ]]
printf 'PASS: invalid config refuses without touching shell configuration\n'
