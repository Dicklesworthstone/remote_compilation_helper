#!/usr/bin/env bash
# install_no_downgrade_unit_test.sh - Unit tests for install.sh version-resolution safety.
#
# Regression cover for the fleet-wide downgrade of 2026-08-20: the GitHub API
# release lookup is rate limited to 60 req/hour per IP for unauthenticated
# clients. When a batch tool-update run exhausted that budget the response
# carried no "tag_name", the parse produced an empty string, and install.sh fell
# back to its built-in INSTALLER_VERSION floor - silently replacing rch 1.0.57
# with 1.0.52 on dispatchers, every nightly run.
#
# Run from project root: ./scripts/install_no_downgrade_unit_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
export PROJECT_ROOT
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/install_no_downgrade_unit.log"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/test_lib.sh"
init_test_log "$(basename "${BASH_SOURCE[0]}" .sh)"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log() {
    echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"
    log_json execute "$*"
}
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); log "PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); log "FAIL: $1"; }
start_test() { TESTS_RUN=$((TESTS_RUN + 1)); log "Test $TESTS_RUN: $1"; }
cleanup() { log "Retaining test directory and all fixture bytes: $TEST_DIR"; }
trap '_test_lib_cleanup; cleanup' EXIT

log "=== RCH Installer No-Downgrade Unit Tests ==="

if [[ ! -f "$PROJECT_ROOT/install.sh" ]]; then
    log "ERROR: install.sh not found at $PROJECT_ROOT/install.sh"
    test_fail "install.sh missing"
fi

export RCH_INSTALLER_LIB=1
# shellcheck disable=SC1090
source "$PROJECT_ROOT/install.sh"

USE_GUM=false
USE_COLOR=false

# Silence the guard's advisory output during tests
warn() { :; }
info() { :; }

# Build a fake rch that reports a chosen version
make_fake_rch() {
    local dir="$1" ver="$2"
    mkdir -p "$dir"
    cat > "$dir/rch" <<EOF
#!/usr/bin/env bash
echo "rch $ver (commit deadbeef)"
EOF
    chmod +x "$dir/rch"
}

# ---------------------------------------------------------------- version_gt
start_test "version_gt orders release versions correctly"
vg_ok=true
version_gt "1.0.57" "1.0.52" || vg_ok=false      # newer > older
version_gt "1.0.52" "1.0.57" && vg_ok=false      # older is not > newer
version_gt "1.0.57" "1.0.57" && vg_ok=false      # equal is not >
version_gt "1.0.10" "1.0.9"  || vg_ok=false      # numeric, not lexical
if $vg_ok; then pass "version_gt semantics"; else fail "version_gt semantics"; fi

# ------------------------------------------------- guard blocks the downgrade
start_test "stale fallback does NOT replace a newer install"
INSTALL_DIR="$TEST_DIR/case1"; make_fake_rch "$INSTALL_DIR" "1.0.57"
VERSION="1.0.52"; VERSION_EXPLICIT=false; SKIP_INSTALL_NO_DOWNGRADE=false
OFFLINE_TARBALL=""; FROM_SOURCE=false
enforce_no_downgrade
if [[ "$VERSION" == "1.0.57" && "$SKIP_INSTALL_NO_DOWNGRADE" == "true" ]]; then
    pass "downgrade 1.0.57 -> 1.0.52 refused"
else
    fail "downgrade refused (VERSION=$VERSION SKIP=$SKIP_INSTALL_NO_DOWNGRADE)"
fi

# ------------------------------------------------------ upgrades still happen
start_test "genuine upgrade is allowed"
INSTALL_DIR="$TEST_DIR/case2"; make_fake_rch "$INSTALL_DIR" "1.0.52"
VERSION="1.0.57"; VERSION_EXPLICIT=false; SKIP_INSTALL_NO_DOWNGRADE=false
enforce_no_downgrade
if [[ "$VERSION" == "1.0.57" && "$SKIP_INSTALL_NO_DOWNGRADE" == "false" ]]; then
    pass "upgrade 1.0.52 -> 1.0.57 allowed"
else
    fail "upgrade allowed (VERSION=$VERSION SKIP=$SKIP_INSTALL_NO_DOWNGRADE)"
fi

# -------------------------------------------- explicit pin overrides the guard
start_test "explicitly requested version still permits rollback"
INSTALL_DIR="$TEST_DIR/case3"; make_fake_rch "$INSTALL_DIR" "1.0.57"
VERSION="1.0.52"; VERSION_EXPLICIT=true; SKIP_INSTALL_NO_DOWNGRADE=false
enforce_no_downgrade
if [[ "$VERSION" == "1.0.52" && "$SKIP_INSTALL_NO_DOWNGRADE" == "false" ]]; then
    pass "explicit rollback honoured"
else
    fail "explicit rollback honoured (VERSION=$VERSION SKIP=$SKIP_INSTALL_NO_DOWNGRADE)"
fi

# ------------------------------------------------------- fresh install is a no-op
start_test "no existing install leaves target untouched"
INSTALL_DIR="$TEST_DIR/case4-empty"; mkdir -p "$INSTALL_DIR"
VERSION="1.0.52"; VERSION_EXPLICIT=false; SKIP_INSTALL_NO_DOWNGRADE=false
enforce_no_downgrade
if [[ "$VERSION" == "1.0.52" && "$SKIP_INSTALL_NO_DOWNGRADE" == "false" ]]; then
    pass "fresh install unaffected"
else
    fail "fresh install unaffected (VERSION=$VERSION SKIP=$SKIP_INSTALL_NO_DOWNGRADE)"
fi

# These additions use actual retained files and the installer's real digest
# helper. The older version-guard cases above use an explicit fake CLI; this
# script is not real-service installer, native-build or ACFS qualification.
start_test "release URLs remain on the requested tag for every archive name"
url_ok=true
for version in 2.1.16 v2.1.16 2.1.17-rc.1; do
    tag=$(installer_release_tag "$version") || url_ok=false
    for target in x86_64-unknown-linux-musl x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc linux-x86_64 darwin-aarch64 windows-x86_64; do
        for asset in "rch-${tag}-${target}.tar.gz" "rch-${target}.tar.gz" "rch-${target}.zip"; do
            actual=$(release_download_url "$tag" "$asset") || url_ok=false
            [[ "$actual" == "https://github.com/${GITHUB_REPO}/releases/download/${tag}/${asset}" ]] || url_ok=false
            [[ "$actual" != *"/latest/"* ]] || url_ok=false
        done
    done
done
for invalid in '' '2.1.16/other' '2.1.16?query' '2.1.16 with-space' 'main'; do
    if installer_release_tag "$invalid"; then url_ok=false; fi
done
if release_download_url v2.1.16 ../another; then url_ok=false; fi
if $url_ok; then pass "exact release tag and asset URL binding"; else fail "exact release tag and asset URL binding"; fi

start_test "real checksum files require one exact valid archive entry"
artifact="$TEST_DIR/rch-v2.1.16-x86_64-unknown-linux-gnu.tar.gz"
printf 'retained archive-byte fixture\n' > "$artifact"
if command_exists sha256sum; then
    digest=$(sha256sum "$artifact" | awk '{print $1}')
else
    digest=$(shasum -a 256 "$artifact" | awk '{print $1}')
fi
checksum_ok=true
name=$(basename "$artifact")
for prefix in '' '*' './'; do
    checksum_file="$TEST_DIR/checksum-${prefix//[^A-Za-z0-9]/x}-${#prefix}.txt"
    printf '%s  %s%s\r\n' "$digest" "$prefix" "$name" > "$checksum_file"
    verify_checksum "$artifact" "$checksum_file" "$name" || checksum_ok=false
done
sidecar=$(extract_checksum_from_manifest "$digest" "$name" true) || checksum_ok=false
[[ "$sidecar" == "$digest" ]] || checksum_ok=false
sidecar=$(extract_checksum_from_manifest "$(printf '%s\r\n\r\n' "$digest")" "$name" true) || checksum_ok=false
[[ "$sidecar" == "$digest" ]] || checksum_ok=false
upper=$(printf '%s' "$digest" | tr '[:lower:]' '[:upper:]')
[[ "$(extract_checksum_from_manifest "$upper  $name" "$name")" == "$digest" ]] || checksum_ok=false
index=0
for invalid in \
    "$digest  ${name}.another" \
    "$digest  ${name//./x}" \
    "not-a-digest  $name" \
    "$digest  $name extra-field" \
    "$(printf '%s  %s\n%s  %s' "$digest" "$name" "$digest" "$name")" \
    ""; do
    index=$((index + 1))
    checksum_file="$TEST_DIR/invalid-checksum-${index}.txt"
    printf '%s\n' "$invalid" > "$checksum_file"
    if verify_checksum "$artifact" "$checksum_file" "$name"; then checksum_ok=false; fi
done
if extract_checksum_from_manifest "$(printf '%s\n%s' "$digest" "$digest")" "$name" true; then checksum_ok=false; fi
if extract_checksum_from_manifest "$(printf '%s  unrelated\n%s  %s' "$digest" "$digest" "$name")" "$name" true; then checksum_ok=false; fi
mismatch="$TEST_DIR/mismatch-checksum.txt"
printf '%064d  %s\n' 0 "$name" > "$mismatch"
if verify_checksum "$artifact" "$mismatch" "$name"; then checksum_ok=false; fi
if command_exists sha256sum; then
    after=$(sha256sum "$artifact" | awk '{print $1}')
else
    after=$(shasum -a 256 "$artifact" | awk '{print $1}')
fi
[[ "$after" == "$digest" ]] || checksum_ok=false
if $checksum_ok; then pass "actual digest verification and preserved archive bytes"; else fail "actual digest verification and preserved archive bytes"; fi

start_test "actual source checkout must equal the requested release tag"
source_root="$TEST_DIR/release-source"
git init "$source_root"
git -C "$source_root" -c user.name=InstallerTest -c user.email=installer-test@example.invalid \
    commit --allow-empty -m 'retained release fixture'
git -C "$source_root" tag v2.1.16
git -C "$source_root" -c user.name=InstallerTest -c user.email=installer-test@example.invalid \
    tag -a v2.1.17 -m 'retained annotated release fixture'
source_ok=true
verify_source_release "$source_root" v2.1.16 || source_ok=false
verify_source_release "$source_root" v2.1.17 || source_ok=false
if verify_source_release "$source_root" v9.9.9; then source_ok=false; fi
printf 'retained untracked source fixture\n' > "$source_root/new-source.rs"
if verify_source_release "$source_root" v2.1.16; then source_ok=false; fi
git -C "$source_root" add -- new-source.rs
if verify_source_release "$source_root" v2.1.16; then source_ok=false; fi
git -C "$source_root" -c user.name=InstallerTest -c user.email=installer-test@example.invalid \
    commit -m 'retained different checkout fixture'
head_before=$(git -C "$source_root" rev-parse HEAD)
if verify_source_release "$source_root" v2.1.16; then source_ok=false; fi
[[ "$(git -C "$source_root" rev-parse HEAD)" == "$head_before" ]] || source_ok=false
if $source_ok; then pass "actual tag and checkout comparison, no source mutation"; else fail "actual tag and checkout comparison, no source mutation"; fi

# ------------------------------------------- the floor must not be a downgrade
start_test "INSTALLER_VERSION floor is not older than the published release"
published=$(curl -sL -o /dev/null --connect-timeout 5 --max-time 20 \
            -w '%{url_effective}' \
            "https://github.com/Dicklesworthstone/remote_compilation_helper/releases/latest" 2>/dev/null \
            | sed -n 's|.*/releases/tag/v*\([0-9][0-9.]*\).*|\1|p')
if [[ -z "$published" ]]; then
    fail "could not reach GitHub to verify the published release floor"
elif version_gt "$published" "$INSTALLER_VERSION"; then
    fail "INSTALLER_VERSION=$INSTALLER_VERSION is older than published $published - bump it"
else
    pass "INSTALLER_VERSION=$INSTALLER_VERSION >= published $published"
fi

log "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed, $TESTS_RUN run ==="
[[ $TESTS_FAILED -eq 0 ]] || exit 1
exit 0
