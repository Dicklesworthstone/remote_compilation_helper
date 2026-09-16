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
export XDG_CONFIG_HOME="$fixture/xdg-config" XDG_CACHE_HOME="$fixture/xdg-cache"
export XDG_DATA_HOME="$fixture/xdg-data" ZDOTDIR="$HOME"
export RCH_CONFIG_DIR="$fixture/config" RCH_INSTALL_DIR="$fixture/install bin's"
export RCH_INSTALLER_LIB=1 RCH_NO_UPDATE_CHECK=1
export RCH_NO_SELF_HEALING=1 RCH_SOCKET_PATH="$fixture/missing-daemon.sock"
mkdir -p "$HOME" "$RUSTUP_HOME" "$RCH_CONFIG_DIR" "$RCH_INSTALL_DIR"
ln -s "$rch_test_binary" "$RCH_INSTALL_DIR/rch"
# shellcheck source=../install.sh
source "$project_root/install.sh"
export MODE=local
export SHELL=/bin/bash
printf '[general]\nrole = "dispatcher"\n' > "$CONFIG_DIR/config.toml"
printf 'workers = []\n' > "$CONFIG_DIR/workers.toml"
doctor_shim_check() {
    local expected=$1 report exit_status=0
    report="$fixture/doctor-$1-$(date +%s%N).json"
    (cd "$HOME" && "$rch_test_binary" --json --no-self-healing doctor) > "$report" || exit_status=$?
    [[ "$exit_status" -le 2 ]]
    jq -e --arg expected "$expected" '.data.checks | map(select(.name == "dispatcher_shim")) |
        length == 1 and .[0].status == $expected and .[0].fix_applied == false' "$report"
}
# No compiler is involved: fake local cargo is a PATH resolution sentinel only.
mkdir -p "$fixture/local-tools"
printf '#!/bin/sh\nprintf LOCAL_SENTINEL\\n\n' > "$fixture/local-tools/cargo"
chmod +x "$fixture/local-tools/cargo"
mkdir -p "$RUSTUP_HOME/toolchains/fixture/bin"
cp "$fixture/local-tools/cargo" "$RUSTUP_HOME/toolchains/fixture/bin/cargo"
original_path="$RCH_INSTALL_DIR:$fixture/local-tools:$PATH"
export PATH="$original_path"
doctor_shim_check warning
configure_dispatcher_shim
[[ -x "$HOME/.rch/shims/cargo" && -x "$HOME/.rch/shims/cargo-clippy" ]]
"$rch_test_binary" --json shim status | jq -e '.up_to_date == true'
doctor_shim_check pass
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
[[ ! -e "$HOME/.bash_profile" ]]
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.profile"; exec bash --noprofile --norc -c "command -v cargo"')" == "$HOME/.rch/shims/cargo" ]]
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
before_inode=$(stat -c '%i' "$HOME/.rch/shims/cargo")
PATH="$original_path" "$HOME/.rch/shim-watchdog"
PATH="$original_path" "$HOME/.rch/shim-watchdog"
[[ "$(stat -c '%i' "$HOME/.rch/shims/cargo")" == "$before_inode" ]]
[[ "$(cat "$HOME/.bashrc")" == "$before_rc" ]]
printf 'PASS: healthy watchdog cycles preserve the shim inode and shell rc\n'
printf '\nexport PATH="%s:$PATH"\n' "$fixture/local-tools" >> "$HOME/.bashrc"
chmod 644 "$HOME/.rch/shims/cargo"
PATH="$original_path" "$HOME/.rch/shim-watchdog"
[[ -x "$HOME/.rch/shims/cargo" ]]
[[ "$(PATH="$original_path" bash --noprofile --norc -c '. "$HOME/.bashrc"; command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
before_rc=$(cat "$HOME/.bashrc")
printf 'PASS: a watchdog cycle repairs nonexecutable shim and updater PATH drift\n'
chmod 644 "$HOME/.rch/shims/cargo-clippy"
"$rch_test_binary" --json shim status | jq -e '.up_to_date == false'
"$HOME/.rch/shim-watchdog"
[[ -x "$HOME/.rch/shims/cargo-clippy" ]]
"$rch_test_binary" --json shim status | jq -e '.up_to_date == true'
printf 'PASS: watchdog repairs a nonexecutable companion Clippy shim\n'
printf '#!/bin/sh\n# rch-toolchain-wrap-version: 1\nprintf STALE\\n\n' > "$RUSTUP_HOME/toolchains/fixture/bin/cargo"
"$rch_test_binary" --json shim status | jq -e '.up_to_date == false'
"$HOME/.rch/shim-watchdog"
"$rch_test_binary" --json shim status | jq -e '.up_to_date == true and .toolchains_wrapped == 1'
printf 'PASS: watchdog refreshes a stale absolute-path toolchain wrapper\n'

if command -v zsh >/dev/null 2>&1; then
    export SHELL=/bin/zsh
    configure_dispatcher_shim
    [[ "$(PATH="$original_path" zsh -c 'command -v cargo')" == "$HOME/.rch/shims/cargo" ]]
    export SHELL=/bin/bash
    printf 'PASS: fresh Zsh resolves the installed shim first\n'
fi

for role in worker hybrid; do
    printf '[general]\nrole = "%s"\n' "$role" > "$CONFIG_DIR/config.toml"
    before_shim=$(sha256sum "$HOME/.rch/shims/cargo")
    configure_dispatcher_shim
    "$HOME/.rch/shim-watchdog"
    doctor_shim_check pass
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
