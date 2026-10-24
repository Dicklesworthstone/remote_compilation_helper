#!/usr/bin/env bash
# Behavioral tests for rabs_fleet_deploy.sh. Run with bash from any directory.
#
# Real openssl certificates, the deployment script, its generated remote shell,
# and real filesystem writes are exercised. SSH transport, bwrap availability,
# systemd, and the worker version response are controlled boundaries. This is
# not evidence of a live fleet deployment or a TLS handshake.
#
# Scratch trees and logs are retained for inspection; no cleanup deletes them.
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPLOY_SCRIPT="$SCRIPT_DIR/rabs_fleet_deploy.sh"
for required in bash openssl install stat uname cp ln cmp sed find sort sha256sum timeout grep head tail wc; do
    command -v "$required" >/dev/null || {
        printf 'required test command is unavailable: %s\n' "$required" >&2
        exit 1
    }
done

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/rabs-fleet-deploy-test.XXXXXXXXXX")
FIXTURE_BIN="$TEST_ROOT/bin"
CERT_DIR="$TEST_ROOT/credentials with spaces"
mkdir -p "$FIXTURE_BIN" "$CERT_DIR"
printf 'Retained fleet deployment test files: %s\n' "$TEST_ROOT"
export RABS_TEST_REAL_INSTALL RABS_TEST_REAL_STAT RABS_TEST_REAL_UNAME
RABS_TEST_REAL_INSTALL=$(command -v install)
RABS_TEST_REAL_STAT=$(command -v stat)
RABS_TEST_REAL_UNAME=$(command -v uname)

# Certificates use distinct real keys. The split-CA case intentionally trusts a
# coordinator CA different from the CA that signs the worker client identity.
make_ca() {
    local name=$1
    openssl genpkey -algorithm ED25519 -out "$CERT_DIR/$name.key"
    openssl req -new -x509 -key "$CERT_DIR/$name.key" -days 1 \
        -subj "/CN=RABS test $name" -out "$CERT_DIR/$name.pem" \
        -addext 'basicConstraints=critical,CA:TRUE'
}

make_client() {
    local name=$1 ca=$2 serial=$3
    openssl genpkey -algorithm ED25519 -out "$CERT_DIR/$name.key"
    openssl req -new -key "$CERT_DIR/$name.key" -subj "/CN=RABS test $name" \
        -out "$CERT_DIR/$name.csr"
    openssl x509 -req -in "$CERT_DIR/$name.csr" -CA "$CERT_DIR/$ca.pem" \
        -CAkey "$CERT_DIR/$ca.key" -set_serial "$serial" -days 1 \
        -extfile "$CERT_DIR/client.extensions" -out "$CERT_DIR/$name.pem"
}

cat > "$CERT_DIR/client.extensions" <<'EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXTENSIONS
make_ca coordinator-ca
make_ca client-ca
make_client client coordinator-ca 101
make_client split-client client-ca 102
openssl genpkey -algorithm ED25519 -out "$CERT_DIR/unrelated.key"
openssl pkey -in "$CERT_DIR/client.key" -aes-256-cbc \
    -passout pass:fixture-only-password -out "$CERT_DIR/encrypted.key"
printf 'this is not a PEM certificate or key\n' > "$CERT_DIR/malformed.pem"
cat "$CERT_DIR/client.pem" > "$CERT_DIR/malformed-trailing-chain.pem"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'not-valid-base64!!!' \
    '-----END CERTIFICATE-----' >> "$CERT_DIR/malformed-trailing-chain.pem"
cat "$CERT_DIR/client.key" "$CERT_DIR/unrelated.key" > "$CERT_DIR/multiple-keys.pem"
cat "$CERT_DIR/coordinator-ca.pem" "$CERT_DIR/coordinator-ca.key" > "$CERT_DIR/ca-with-private-key.pem"
cat "$CERT_DIR/client.pem" "$CERT_DIR/client.key" > "$CERT_DIR/client-with-private-key.pem"

cat > "$FIXTURE_BIN/ssh" <<'SSH'
#!/usr/bin/env bash
set -euo pipefail
printf 'CALL\n' >> "$RABS_TEST_CASE/ssh.log"
if env | grep -E -- '-----BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY-----' >/dev/null; then
    printf 'fixture: private PEM material was exported to SSH\n' >&2
    exit 94
fi
while (($#)); do
    case "$1" in
        -o|-p|-i|-F) shift 2 ;;
        -q|-T|-t) shift ;;
        --) shift; break ;;
        -*) printf 'unexpected fixture SSH option: %s\n' "$1" >&2; exit 90 ;;
        *) break ;;
    esac
done
target=${1:?missing SSH target}
shift
[[ "$target" == root@* ]] || { printf 'deployment must use root SSH\n' >&2; exit 90; }
[[ "${1:-}" != -- ]] || shift
remote_command="$*"
printf 'TARGET %s\n%s\n' "$target" "$remote_command" >> "$RABS_TEST_CASE/ssh.log"

# SSH joins command arguments for a remote shell. Execute that shell, mapping
# only the deployment's fixed filesystem roots into this case's private tree.
# Stage-path stdout is mapped back so the deployer's path validation runs on
# the same /etc/rabs-wkr/... namespace that a real SSH peer would return.
map_roots() {
    local text=$1 prefix
    for prefix in /etc/rabs-wkr /etc/systemd/system /usr/local/bin /var/lib/rabs-wkr /root/.local/state/rabs; do
        text=${text//"$prefix"/"$RABS_TEST_REMOTE_ROOT$prefix"}
    done
    printf '%s' "$text"
}
mapped_command=$(map_roots "$remote_command")
# Invalid-null fixtures redirect only the generated remote shell's device path
# to a private regular file or symlink. The host /dev/null is never changed.
if [[ -n ${RABS_TEST_NULL_PATH:-} ]]; then
    mapped_command=${mapped_command//"/dev/null"/"$RABS_TEST_NULL_PATH"}
fi
# A managed EnvironmentFile path is read from the unit as data at activation.
# Translate that indirect open into the same private filesystem namespace as
# the literal command paths, without rewriting the saved service/environment.
mapped_command=${mapped_command//'previous_environment=${line#EnvironmentFile=}'/'previous_environment="$RABS_TEST_REMOTE_ROOT${line#EnvironmentFile=}"'}
# A permissive peer default must not hide missing production chmod/umask.
umask 022
if [[ "${RABS_TEST_FAIL_TLS_TRANSFER:-0}" == 1 && "$remote_command" == *cat* \
    && ( "$remote_command" == *.pem* || "$remote_command" == *.key* ) ]]; then
    # Materialize a genuinely truncated staged file before simulating lost SSH.
    head -c 16 | bash --noprofile --norc -c "$mapped_command"
    printf 'fixture: TLS transfer interrupted\n' >&2
    exit 71
fi
if [[ "$remote_command" == *'bash -s'* || "$remote_command" == *'sh -s'* ]]; then
    remote_script=$(cat)
    map_roots "$remote_script" | bash --noprofile --norc -c "$mapped_command" \
        | sed "s|$RABS_TEST_REMOTE_ROOT||g"
else
    bash --noprofile --norc -c "$mapped_command" | sed "s|$RABS_TEST_REMOTE_ROOT||g"
fi
SSH

cat > "$FIXTURE_BIN/bwrap" <<'BWRAP'
#!/usr/bin/env bash
set -euo pipefail
inherited_marker=${RABS_TEST_PROBE_SENTINEL-unset}
if [[ -z ${RABS_TEST_CASE:-} ]]; then
    # Production clears the archive probe's environment, retaining only PATH.
    # Read this fixture's controls beside its per-case executable so that the
    # real env -i boundary remains exercised rather than bypassed by the test.
    [[ ${BASH_SOURCE[0]} == */probe-bin/bwrap ]] || exit 95
    RABS_TEST_CASE=${BASH_SOURCE[0]%/probe-bin/bwrap}
    mapfile -t controls < "$RABS_TEST_CASE/probe-bwrap-controls"
    [[ ${#controls[@]} == 2 ]] || exit 95
    RABS_TEST_BWRAP=${controls[0]}
    RABS_TEST_BWRAP_DENY=${controls[1]}
fi
printf '%s\n' "$*" >> "$RABS_TEST_CASE/bwrap.log"
printf '%s\n' "$inherited_marker" >> "$RABS_TEST_CASE/bwrap-env.log"
[[ "${RABS_TEST_BWRAP:-allow}" == allow ]] || exit 1
for argument do
    [[ "$argument" != "${RABS_TEST_BWRAP_DENY:-}" ]] || exit 1
done
BWRAP

cat > "$FIXTURE_BIN/stat" <<'STAT'
#!/usr/bin/env bash
set -euo pipefail
# Only the exact null-device metadata query is controlled. Every deployed
# permission, ownership and file-state assertion still uses the real stat.
if [[ $# == 4 && $1 == -c && $2 == '%t:%T' && $3 == -- && $4 == /dev/null ]]; then
    printf 'NULL\n' >> "$RABS_TEST_CASE/null-stat.log"
    case "${RABS_TEST_NULL_STAT:-actual}" in
        wrong-device) printf '1:5\n'; exit 0 ;;
        changed-after)
            if [[ $(wc -l < "$RABS_TEST_CASE/null-stat.log") == 1 ]]; then
                printf '1:3\n'
            else
                printf '1:5\n'
            fi
            exit 0
            ;;
        error) exit 1 ;;
        actual) ;;
        *) exit 96 ;;
    esac
fi
exec "$RABS_TEST_REAL_STAT" "$@"
STAT

cat > "$FIXTURE_BIN/uname" <<'UNAME'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# == 1 && $1 == -s && -n ${RABS_TEST_KERNEL:-} ]]; then
    printf '%s\n' "$RABS_TEST_KERNEL"
    exit 0
fi
exec "$RABS_TEST_REAL_UNAME" "$@"
UNAME

cat > "$FIXTURE_BIN/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$RABS_TEST_CASE/systemctl.log"
[[ "${RABS_TEST_SYSTEMCTL_FAIL:-}" != "${1:-}" ]] || exit 72
case "${1:-}" in
    show-environment|daemon-reload|enable|restart|is-active) ;;
    *) printf 'unexpected systemctl operation: %s\n' "$*" >&2; exit 91 ;;
esac
SYSTEMCTL

# The production peer is root. Keep the fixture usable without root: require
# exactly root ownership arguments, record them, and let real install/chmod
# enforce private modes under the invoking user's private scratch tree.
cat > "$FIXTURE_BIN/install" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
args=()
while (($#)); do
    case "$1" in
        -o|-g)
            [[ "${2:-}" == root ]] || exit 92
            printf '%s %s\n' "$1" "$2" >> "$RABS_TEST_CASE/ownership.log"
            shift 2
            ;;
        --owner=root|--group=root)
            printf '%s\n' "$1" >> "$RABS_TEST_CASE/ownership.log"
            shift
            ;;
        *) args+=("$1"); shift ;;
    esac
done
exec "$RABS_TEST_REAL_INSTALL" "${args[@]}"
INSTALL

cat > "$FIXTURE_BIN/chown" <<'CHOWN'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == root:root ]] || exit 92
printf '%s\n' "$*" >> "$RABS_TEST_CASE/ownership.log"
CHOWN

LOCAL_BIN="$TEST_ROOT/binary with spaces:rabs-wkr"
cat > "$LOCAL_BIN" <<'WORKER'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 1 && "$1" == --version ]] || exit 93
printf '%s\n' "$*" >> "$RABS_TEST_CASE/worker.log"
[[ "${RABS_TEST_VERSION_FAIL:-0}" != 1 ]] || exit 73
printf 'rabs-wkr 0.0.0-deploy-fixture\n'
WORKER
chmod 0755 "$FIXTURE_BIN/ssh" "$FIXTURE_BIN/bwrap" "$FIXTURE_BIN/systemctl" \
    "$FIXTURE_BIN/install" "$FIXTURE_BIN/chown" "$FIXTURE_BIN/stat" "$FIXTURE_BIN/uname" "$LOCAL_BIN"

TESTS_PASSED=0
ATTEMPT=0
CASE_DIR=
CASE_STDOUT=
CASE_STDERR=
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    [[ -z "$CASE_STDOUT" || ! -f "$CASE_STDOUT" ]] || cat "$CASE_STDOUT" >&2
    [[ -z "$CASE_STDERR" || ! -f "$CASE_STDERR" ]] || cat "$CASE_STDERR" >&2
    printf 'Retained evidence: %s\n' "$TEST_ROOT" >&2
    exit 1
}
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf 'PASS: %s\n' "$1"
}
snapshot_remote() {
    find "$CASE_DIR/remote" -printf '%P %y %m\n' | sort
    find "$CASE_DIR/remote" -type f -exec sha256sum '{}' ';' | sort
}

assert_no_private_logs() {
    local key payload leaked=0
    local -a logs=("$CASE_STDOUT" "$CASE_STDERR")
    [[ ! -f "$CASE_DIR/ssh.log" ]] || logs+=("$CASE_DIR/ssh.log")
    if grep -Eq -- '-----BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY-----' "${logs[@]}"; then
        leaked=1
    fi
    for key in client split-client unrelated encrypted coordinator-ca; do
        payload=$(sed -n '2p' "$CERT_DIR/$key.key")
        [[ -n "$payload" ]] || fail 'private-key fixture has no encoded key body'
        if grep -Fq -- "$payload" "${logs[@]}"; then
            leaked=1
        fi
    done
    if [[ "$leaked" == 1 ]]; then
        # Do not reprint a secret through fail()'s normal diagnostic log dump.
        printf 'FAIL: private PEM material leaked; inspect retained logs in %s\n' "$CASE_DIR" >&2
        exit 1
    fi
}

# Extra arguments are environment assignments, never shell source.
run_deploy() {
    local name=$1 expected=$2 worker=$3 coordinator=$4 status assignment
    local probe_bwrap=allow probe_deny=
    local -a shell_flags=()
    shift 4
    [[ "${RABS_TEST_BASH_X:-0}" != 1 ]] || shell_flags+=(-x)
    ATTEMPT=$((ATTEMPT + 1))
    CASE_DIR="$TEST_ROOT/$name"
    CASE_STDOUT="$CASE_DIR/attempt-$ATTEMPT.stdout"
    CASE_STDERR="$CASE_DIR/attempt-$ATTEMPT.stderr"
    if [[ ! -d "$CASE_DIR" ]]; then
        mkdir -p "$CASE_DIR/remote/usr/local/bin" "$CASE_DIR/remote/etc/systemd/system" \
            "$CASE_DIR/remote/root/.local/state/rabs"
        printf 'existing worker identity and durable state\n' \
            > "$CASE_DIR/remote/root/.local/state/rabs/retained-state"
    fi
    mkdir -p "$CASE_DIR/probe-bin"
    cp "$FIXTURE_BIN/bwrap" "$CASE_DIR/probe-bin/bwrap"
    for assignment in "$@"; do
        case "$assignment" in
            RABS_TEST_BWRAP=*) probe_bwrap=${assignment#*=} ;;
            RABS_TEST_BWRAP_DENY=*) probe_deny=${assignment#*=} ;;
        esac
    done
    printf '%s\n%s\n' "$probe_bwrap" "$probe_deny" > "$CASE_DIR/probe-bwrap-controls"
    snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.before"
    if env -u BASH_ENV -u ENV -u RABS_WORKER_ID -u RABS_WORKER_STATE_DIR \
        -u RABS_WORKER_TARGET_CACHE_BYTES -u RABS_WORKER_TARGET_CACHE_EPOCH -u RABS_DEPLOY_CAPABILITY \
        PATH="$CASE_DIR/probe-bin:$FIXTURE_BIN:$PATH" \
        RABS_TEST_CASE="$CASE_DIR" RABS_TEST_REMOTE_ROOT="$CASE_DIR/remote" \
        RABS_TEST_BWRAP=allow RABS_TEST_BWRAP_DENY= RABS_TEST_FAIL_TLS_TRANSFER=0 \
        RABS_TEST_NULL_STAT=actual RABS_TEST_NULL_PATH= RABS_TEST_KERNEL= \
        RABS_TEST_PROBE_SENTINEL=caller-environment \
        RABS_TEST_SYSTEMCTL_FAIL= RABS_TEST_VERSION_FAIL=0 \
        RABS_WORKER_TLS_CA="$CERT_DIR/coordinator-ca.pem" \
        RABS_WORKER_TLS_CERT="$CERT_DIR/client.pem" \
        RABS_WORKER_TLS_KEY="$CERT_DIR/client.key" \
        RABS_WORKER_TLS_SERVER_NAME=coordinator.example \
        "$@" timeout 30 bash "${shell_flags[@]}" "$DEPLOY_SCRIPT" "$worker" "$coordinator" "$LOCAL_BIN" \
        > "$CASE_STDOUT" 2> "$CASE_STDERR" < /dev/null; then
        status=0
    else
        status=$?
    fi
    assert_no_private_logs
    [[ "$status" != 124 ]] || fail "$name timed out"
    if [[ "$expected" == success ]]; then
        [[ "$status" == 0 ]] || fail "$name unexpectedly failed with status $status"
    else
        [[ "$status" != 0 ]] || fail "$name unexpectedly reported success"
        if grep -Eq '^(deployed|Installed) rabs-wkr ' "$CASE_STDERR"; then
            fail "$name printed deployment success after failure"
        fi
    fi
}

assert_local_refusal() {
    [[ ! -s "$CASE_DIR/ssh.log" ]] || fail "$1 contacted SSH before rejecting local inputs"
    snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
    cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
        || fail "$1 changed remote files"
    pass "$1"
}

assert_capability_refusal() {
    local status=$1 description=$2
    grep -Fq "\"status\":\"refused:$status\"" "$CASE_STDOUT" \
        || fail "$description did not identify its capability refusal"
    [[ $(grep -c '^CALL$' "$CASE_DIR/ssh.log") == 1 ]] \
        || fail "$description reached a later deployment step"
    snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
    cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
        || fail "$description wrote deployment files"
    [[ ! -s "$CASE_DIR/systemctl.log" ]] || fail "$description touched the service"
    pass "$description"
}

run_deploy missing-all failure worker.example coordinator.example:7443 \
    RABS_WORKER_TLS_CA= RABS_WORKER_TLS_CERT= RABS_WORKER_TLS_KEY= RABS_WORKER_TLS_SERVER_NAME=
assert_local_refusal 'missing TLS credentials'
for variable in RABS_WORKER_TLS_CA RABS_WORKER_TLS_CERT RABS_WORKER_TLS_KEY RABS_WORKER_TLS_SERVER_NAME; do
    run_deploy "missing-$variable" failure worker.example coordinator.example:7443 "$variable="
    assert_local_refusal "partial TLS credentials: $variable"
done
for variable in RABS_WORKER_TLS_CA RABS_WORKER_TLS_CERT RABS_WORKER_TLS_KEY; do
    run_deploy "malformed-$variable" failure worker.example coordinator.example:7443 \
        "$variable=$CERT_DIR/malformed.pem"
    assert_local_refusal "malformed PEM: $variable"
done
run_deploy leaf-only-ca failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_CA=$CERT_DIR/client.pem"
assert_local_refusal 'leaf-only coordinator trust bundle'
run_deploy ca-with-private-key failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_CA=$CERT_DIR/ca-with-private-key.pem"
assert_local_refusal 'CA certificate bundle must not ship an issuer private key'
run_deploy client-with-private-key failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_CERT=$CERT_DIR/client-with-private-key.pem"
assert_local_refusal 'client certificate chain must not contain private-key material'
run_deploy malformed-trailing-chain failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_CERT=$CERT_DIR/malformed-trailing-chain.pem"
assert_local_refusal 'valid leaf followed by a malformed certificate block'
run_deploy multiple-private-keys failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_KEY=$CERT_DIR/multiple-keys.pem"
assert_local_refusal 'multiple private-key blocks are ambiguous'
run_deploy mismatched-key failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_KEY=$CERT_DIR/unrelated.key"
assert_local_refusal 'certificate and key mismatch'
run_deploy encrypted-key failure worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_KEY=$CERT_DIR/encrypted.key"
assert_local_refusal 'encrypted key cannot prompt during deployment'
run_deploy injected-worker failure 'worker.example;echo injected' coordinator.example:7443
assert_local_refusal 'worker hostname shell injection'
run_deploy injected-server-name failure worker.example coordinator.example:7443 \
    'RABS_WORKER_TLS_SERVER_NAME=coordinator.example";echo injected'
assert_local_refusal 'TLS server-name injection'
run_deploy injected-coordinator failure worker.example $'coordinator.example:7443\nExecStart=/bin/false'
assert_local_refusal 'coordinator systemd injection'
run_deploy invalid-port failure worker.example coordinator.example:65536
assert_local_refusal 'out-of-range coordinator port'
for identity in '' 'worker name' 'worker/name' 'worker%h' 'worker"name' $'worker\nID=other'; do
    run_deploy "invalid-worker-id-$ATTEMPT" failure worker.example coordinator.example:7443 \
        "RABS_WORKER_ID=$identity"
    assert_local_refusal 'invalid worker identity cannot reach SSH'
done
for state_path in '' 'relative/state' '/' $'/var/lib/rabs\nRABS_WORKER_ID=other' $'/var/lib/rabs\tstate' $'/var/lib/rabs\377'; do
    run_deploy "invalid-state-$ATTEMPT" failure worker.example coordinator.example:7443 \
        "RABS_WORKER_STATE_DIR=$state_path"
    assert_local_refusal 'invalid journal directory cannot reach SSH'
done
for cache_bytes in '' '-1' '+1' '1.5' '0x100' ' 1' '1 ' '8589934593' '00000000000' $'1\nExecStart=/bin/false'; do
    run_deploy "invalid-target-limit-$ATTEMPT" failure worker.example coordinator.example:7443 \
        "RABS_WORKER_TARGET_CACHE_BYTES=$cache_bytes"
    assert_local_refusal 'invalid target-cache quota cannot reach SSH'
done
for cache_epoch in '.image' '../image' 'image/path' 'image with spaces' 'image%h' $'image\nExecStart=/bin/false'; do
    run_deploy "invalid-target-epoch-$ATTEMPT" failure worker.example coordinator.example:7443 \
        "RABS_WORKER_TARGET_CACHE_EPOCH=$cache_epoch"
    assert_local_refusal 'invalid target-cache runtime epoch cannot reach SSH'
done
for capability in '' metadata rlib Canonical 'dependency-rlib ' 'canonical;echo injected' $'dependency-rlib\nExecStart=/bin/false'; do
    run_deploy "invalid-capability-$ATTEMPT" failure worker.example coordinator.example:7443 \
        "RABS_DEPLOY_CAPABILITY=$capability"
    assert_local_refusal 'invalid deployment capability cannot reach SSH'
done

run_deploy bwrap-refused failure worker.example coordinator.example:7443 RABS_TEST_BWRAP=refuse
[[ -s "$CASE_DIR/ssh.log" && -s "$CASE_DIR/bwrap.log" ]] || fail 'bwrap gate was not exercised'
snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
    || fail 'bwrap refusal wrote deployment files'
[[ ! -s "$CASE_DIR/systemctl.log" ]] || fail 'bwrap refusal touched the service'
pass 'bwrap refuses before remote installation writes'

# Each controlled host admits the old root-bind userns smoke command but
# refuses one operation required by the actual canonical worker. The complete
# generated remote shell must reject it before transferring a single file.
for facet in --proc --dev --tmpfs --unshare-pid --unshare-ipc --unshare-uts --unshare-net; do
    run_deploy "canonical-refused-${facet#--}" failure worker.example coordinator.example:7443 \
        "RABS_TEST_BWRAP_DENY=$facet"
    grep -Fq 'refused:bwrap-present-but-canonical-fails' "$CASE_STDOUT" \
        || fail "$facet refusal did not identify the canonical capability failure"
    [[ $(grep -c '^CALL$' "$CASE_DIR/ssh.log") == 1 ]] \
        || fail "$facet refusal reached a later deployment step"
    snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
    cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
        || fail "$facet refusal wrote deployment files"
    [[ ! -s "$CASE_DIR/systemctl.log" ]] || fail "$facet refusal touched the service"
    env RABS_TEST_CASE="$CASE_DIR" RABS_TEST_BWRAP=allow RABS_TEST_BWRAP_DENY="$facet" \
        "$FIXTURE_BIN/bwrap" --unshare-user --uid 0 --ro-bind / / true \
        || fail "controlled $facet host must admit the old, insufficient smoke probe"
    pass "$facet failure refuses canonical deployment despite a working root-bind userns"
done

# Archive admission measures its own namespace. A root-bind-only probe cannot
# establish these axes; every missing facet must refuse before credentials,
# binaries, service settings or durable worker history are written.
for facet in --version --die-with-parent --unshare-user --unshare-pid --unshare-ipc \
    --unshare-uts --unshare-net --clearenv --dir --dev-bind --tmpfs /tmp /__rabs/tmp; do
    run_deploy "rlib-refused-$ATTEMPT" failure worker.example coordinator.example:7443 \
        RABS_DEPLOY_CAPABILITY=dependency-rlib "RABS_TEST_BWRAP_DENY=$facet"
    assert_capability_refusal bwrap-present-but-dependency-rlib-fails \
        "$facet failure refuses archive deployment before uploads"
done

for null_state in wrong-device error changed-after; do
    run_deploy "rlib-null-$null_state" failure worker.example coordinator.example:7443 \
        RABS_DEPLOY_CAPABILITY=dependency-rlib "RABS_TEST_NULL_STAT=$null_state"
    assert_capability_refusal dependency-rlib-invalid-null-device \
        "archive null identity $null_state refuses before uploads"
    if [[ "$null_state" == changed-after ]]; then
        [[ $(wc -l < "$CASE_DIR/bwrap.log") == 2 && $(wc -l < "$CASE_DIR/null-stat.log") == 2 ]] \
            || fail 'changed null identity was not checked after the archive no-op'
    else
        [[ $(wc -l < "$CASE_DIR/bwrap.log") == 1 ]] \
            || fail 'an invalid null identity reached the archive no-op'
    fi
done

REGULAR_NULL="$TEST_ROOT/regular-null"
printf 'invalid null device must remain untouched\n' > "$REGULAR_NULL"
run_deploy rlib-regular-null failure worker.example coordinator.example:7443 \
    RABS_DEPLOY_CAPABILITY=dependency-rlib "RABS_TEST_NULL_PATH=$REGULAR_NULL"
assert_capability_refusal dependency-rlib-invalid-null-device \
    'a regular file cannot provide the archive null device'
grep -Fxq 'invalid null device must remain untouched' "$REGULAR_NULL" \
    || fail 'archive preflight opened or truncated the invalid null file'
[[ $(wc -l < "$CASE_DIR/bwrap.log") == 1 ]] \
    || fail 'the regular null fixture reached the archive no-op'

SYMLINK_NULL="$TEST_ROOT/symlink-null"
ln -s /dev/null "$SYMLINK_NULL"
run_deploy rlib-symlink-null failure worker.example coordinator.example:7443 \
    RABS_DEPLOY_CAPABILITY=dependency-rlib "RABS_TEST_NULL_PATH=$SYMLINK_NULL"
assert_capability_refusal dependency-rlib-invalid-null-device \
    'a symlink to the real null device cannot enter archive deployment'
[[ -L "$SYMLINK_NULL" && $(wc -l < "$CASE_DIR/bwrap.log") == 1 ]] \
    || fail 'the null symlink was replaced or reached the archive no-op'

run_deploy rlib-non-linux failure worker.example coordinator.example:7443 \
    RABS_DEPLOY_CAPABILITY=dependency-rlib RABS_TEST_KERNEL=Darwin
assert_capability_refusal dependency-rlib-requires-linux 'archive deployment requires Linux'
[[ ! -s "$CASE_DIR/bwrap.log" ]] || fail 'non-Linux archive deployment ran bubblewrap'

run_deploy systemd-unavailable failure worker.example coordinator.example:7443 \
    RABS_TEST_SYSTEMCTL_FAIL=show-environment
grep -Fxq show-environment "$CASE_DIR/systemctl.log" || fail 'systemd preflight was not exercised'
snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
    || fail 'systemd refusal wrote deployment files'
pass 'unavailable systemd refuses before remote installation writes'

assert_mode() {
    local path=$1 expected=$2 actual
    actual=$(stat -c '%a' "$path") || fail "missing deployed path: $path"
    [[ "$actual" == "$expected" ]] || fail "wrong mode on $path: expected $expected, got $actual"
}

# Check actual transferred bytes and the complete path from the installed unit
# through its EnvironmentFile to the private generation's credentials.
assert_installation() {
    local client=$1 coordinator=$2 server_name=$3 unit environment_path environment_file stage
    local expected_id=${4-} expected_state=${5-} expected_bytes=${6-} expected_epoch=${7-} observed expected_key
    unit="$CASE_DIR/remote/etc/systemd/system/rabs-wkr.service"
    [[ -f "$unit" ]] || fail 'the service unit was not installed'
    environment_path=$(sed -n 's/^EnvironmentFile=//p' "$unit")
    [[ "$environment_path" =~ ^/etc/rabs-wkr/deploy\.[A-Za-z0-9]{10}/worker\.env$ ]] \
        || fail "invalid EnvironmentFile routing: $environment_path"
    environment_file="$CASE_DIR/remote$environment_path"
    stage=${environment_path%/worker.env}
    assert_mode "$CASE_DIR/remote/etc/rabs-wkr" 700
    assert_mode "$CASE_DIR/remote$stage" 700
    assert_mode "$environment_file" 600
    assert_mode "$CASE_DIR/remote$stage/ca.pem" 600
    assert_mode "$CASE_DIR/remote$stage/worker.pem" 600
    assert_mode "$CASE_DIR/remote$stage/worker.key" 600
    assert_mode "$unit" 644
    assert_mode "$CASE_DIR/remote/usr/local/bin/rabs-wkr" 755
    ! grep -q 'RABS_DEPLOY_CAPABILITY' "$unit" "$environment_file" \
        || fail 'deployment admission became a persistent worker capability claim'
    cmp "$CERT_DIR/coordinator-ca.pem" "$CASE_DIR/remote$stage/ca.pem" \
        || fail 'coordinator CA bytes changed in transfer'
    cmp "$CERT_DIR/$client.pem" "$CASE_DIR/remote$stage/worker.pem" \
        || fail 'client certificate bytes changed in transfer'
    cmp "$CERT_DIR/$client.key" "$CASE_DIR/remote$stage/worker.key" \
        || fail 'client private key bytes changed in transfer'
    cmp "$LOCAL_BIN" "$CASE_DIR/remote/usr/local/bin/rabs-wkr" \
        || fail 'worker binary bytes changed in transfer'
    grep -Fxq "RABS_WORKER_TLS_CA=$stage/ca.pem" "$environment_file" \
        || fail 'CA environment does not route to its credential generation'
    grep -Fxq "RABS_WORKER_TLS_CERT=$stage/worker.pem" "$environment_file" \
        || fail 'certificate environment does not route to its credential generation'
    grep -Fxq "RABS_WORKER_TLS_KEY=$stage/worker.key" "$environment_file" \
        || fail 'key environment does not route to its credential generation'
    grep -Fxq "RABS_WORKER_TLS_SERVER_NAME=$server_name" "$environment_file" \
        || fail 'TLS server name changed'
    grep -Fxq 'User=root' "$unit" || fail 'service lost its root identity and default durable state'
    grep -Fxq "ExecStart=/usr/local/bin/rabs-wkr --coordinator \"$coordinator\"" "$unit" \
        || fail 'coordinator route changed in the service unit'
    # The generated optional values use the POSIX double-quoted subset of
    # EnvironmentFile syntax. Evaluate that subset in an empty subprocess
    # environment to check the effective values, including literal dollar,
    # quote/backslash/backtick bytes; this is not a systemd service proof.
    observed=$(env -i bash --noprofile --norc -c \
        '. "$1"; printf "worker_id=%s\nworker_state=%s\ncache_bytes=%s\ncache_epoch=%s" "${RABS_WORKER_ID-}" "${RABS_WORKER_STATE_DIR-}" "${RABS_WORKER_TARGET_CACHE_BYTES-}" "${RABS_WORKER_TARGET_CACHE_EPOCH-}"' \
        -- "$environment_file") || fail 'worker environment could not be read'
    [[ "$observed" == "worker_id=$expected_id"$'\n'"worker_state=$expected_state"$'\n'"cache_bytes=$expected_bytes"$'\n'"cache_epoch=$expected_epoch" ]] \
        || fail 'installed service changed the selected identity, journal directory or target-cache settings'
    if [[ -z "$expected_id" ]]; then
        ! grep -q '^RABS_WORKER_ID=' "$environment_file" || fail 'default worker identity was overridden'
    else
        [[ $(grep -c '^RABS_WORKER_ID=' "$environment_file") == 1 ]] \
            || fail 'worker identity was duplicated or dropped during upgrade'
    fi
    if [[ -z "$expected_state" ]]; then
        ! grep -q '^RABS_WORKER_STATE_DIR=' "$environment_file" || fail 'default state path was overridden'
    else
        [[ $(grep -c '^RABS_WORKER_STATE_DIR=' "$environment_file") == 1 ]] \
            || fail 'worker journal path was duplicated or dropped during upgrade'
    fi
    if [[ -z "$expected_bytes" ]]; then
        ! grep -q '^RABS_WORKER_TARGET_CACHE_BYTES=' "$environment_file" || fail 'default target-cache quota was overridden'
    else
        [[ $(grep -c '^RABS_WORKER_TARGET_CACHE_BYTES=' "$environment_file") == 1 ]] \
            || fail 'target-cache quota was duplicated or dropped during upgrade'
    fi
    [[ $(grep -c '^RABS_WORKER_TARGET_CACHE_EPOCH=' "$environment_file" || true) -le 1 ]] \
        || fail 'target-cache runtime epoch was duplicated during upgrade'
    expected_key=$(openssl x509 -in "$CERT_DIR/$client.pem" -pubkey -noout |
        openssl pkey -pubin -outform DER | openssl dgst -sha256)
    grep -Fxq "Coordinator enrollment: RABS_DEPENDENCY_WORKER_SPKI_SHA256=${expected_key##* }" "$CASE_STDERR" \
        || fail 'coordinator enrollment pin does not match the deployed certificate'
    grep -Fxq 'existing worker identity and durable state' \
        "$CASE_DIR/remote/root/.local/state/rabs/retained-state" \
        || fail 'existing worker state was modified'
    printf '%s\n' 'daemon-reload' 'enable rabs-wkr.service' 'restart rabs-wkr.service' \
        'is-active --quiet rabs-wkr.service' > "$CASE_DIR/expected-activation"
    tail -n 4 "$CASE_DIR/systemctl.log" > "$CASE_DIR/actual-activation"
    cmp "$CASE_DIR/expected-activation" "$CASE_DIR/actual-activation" \
        || fail 'activation did not reload, enable, explicitly restart, and check service health'
    grep -q '^Installed rabs-wkr ' "$CASE_STDERR" || fail 'successful deployment did not finish'
    LAST_STAGE=$stage
}

run_deploy successful success worker.example coordinator.example:7443
assert_installation client coordinator.example:7443 coordinator.example
grep -Fq '"status":"canonical-ok"' "$CASE_STDOUT" \
    || fail 'the default deployment lost its canonical capability requirement'
FIRST_STAGE=$LAST_STAGE
pass 'valid credentials transfer exactly, remain private, and route through the installed service'

run_deploy successful success worker.example coordinator.example:7443
assert_installation client coordinator.example:7443 coordinator.example
[[ "$LAST_STAGE" != "$FIRST_STAGE" ]] || fail 'redeployment reused an existing credential generation'
[[ -d "$CASE_DIR/remote$FIRST_STAGE" ]] || fail 'redeployment discarded the previous credential generation'
cmp "$CERT_DIR/client.key" "$CASE_DIR/remote$FIRST_STAGE/worker.key" \
    || fail 'redeployment mutated a previous credential generation'
[[ $(grep -c '^restart rabs-wkr.service$' "$CASE_DIR/systemctl.log") == 2 ]] \
    || fail 'redeployment did not explicitly restart an already-enabled service'
pass 'redeployment uses a new private generation, restarts, and retains prior state'

assert_archive_probe() {
    # This is the native archive no-op argv, including its trusted measurement
    # runtime. Exact comparison prevents extra proc/device/host-root mounts or
    # a missing namespace, temporary root, clearenv or final working directory.
    local expected='--die-with-parent --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net --hostname rabs --clearenv --dir /dev --dev-bind /dev/null /dev/null --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/sbin /sbin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache --ro-bind-try /etc/alternatives /etc/alternatives --tmpfs /tmp --tmpfs /__rabs/tmp --chdir /__rabs/tmp -- /usr/bin/true'
    printf '%s\n' --version "$expected" > "$CASE_DIR/expected-archive-probe"
    cmp "$CASE_DIR/expected-archive-probe" "$CASE_DIR/bwrap.log" \
        || fail 'archive deployment probe differs from the native namespace'
    printf '%s\n' caller-environment unset > "$CASE_DIR/expected-probe-env"
    cmp "$CASE_DIR/expected-probe-env" "$CASE_DIR/bwrap-env.log" \
        || fail 'archive namespace probe inherited the caller environment'
    [[ $(wc -l < "$CASE_DIR/null-stat.log") == 2 ]] \
        || fail 'archive probe did not validate the null device before and after execution'
    grep -Fq '"status":"dependency-rlib-ok"' "$CASE_STDOUT" \
        || fail 'archive deployment did not report its measured capability'
    ! grep -Fq '"status":"canonical-ok"' "$CASE_STDOUT" \
        || fail 'archive deployment falsely reported canonical capability'
}

for facet in --proc --dev; do
    run_deploy "rlib-without-${facet#--}" success worker.example coordinator.example:7443 \
        RABS_DEPLOY_CAPABILITY=dependency-rlib "RABS_TEST_BWRAP_DENY=$facet"
    assert_installation client coordinator.example:7443 coordinator.example
    assert_archive_probe
    pass "explicit archive deployment works when the host refuses canonical $facet"
done

# The admission selection belongs to this invocation alone. Reusing the same
# managed worker without the variable must require canonical capability again,
# preserving the successful archive deployment on that refusal.
run_deploy rlib-without-dev failure worker.example coordinator.example:7443 RABS_TEST_BWRAP_DENY=--dev
grep -Fq 'refused:bwrap-present-but-canonical-fails' "$CASE_STDOUT" \
    || fail 'an omitted capability reused the previous archive admission'
snapshot_remote > "$CASE_DIR/attempt-$ATTEMPT.after"
cmp "$CASE_DIR/attempt-$ATTEMPT.before" "$CASE_DIR/attempt-$ATTEMPT.after" \
    || fail 'a later canonical refusal changed the existing archive deployment'
[[ $(grep -c '^restart rabs-wkr.service$' "$CASE_DIR/systemctl.log") == 1 ]] \
    || fail 'a later canonical refusal restarted the existing archive worker'
pass 'archive admission is not persisted and omitted selection still requires canonical isolation'

run_deploy explicit-canonical success worker.example coordinator.example:7443 RABS_DEPLOY_CAPABILITY=canonical
assert_installation client coordinator.example:7443 coordinator.example
grep -Fq '"status":"canonical-ok"' "$CASE_STDOUT" \
    || fail 'explicit canonical deployment reported another capability'
[[ $(wc -l < "$CASE_DIR/bwrap.log") == 1 && ! -e "$CASE_DIR/null-stat.log" ]] \
    || fail 'canonical deployment acquired the archive-only gate'
pass 'explicit canonical selection retains the original namespace requirement'

# The selected TLS identity alone does not set the protocol's worker label.
# Both the direct worker CLI's identity and its durable journal location must
# survive service installation and later credential-only/binary upgrades.
SPECIAL_STATE='/var/lib/rabs/worker with spaces\backslash"quote"$HOME`hostname`'
run_deploy selected-worker success worker.example coordinator.example:7443 \
    RABS_WORKER_ID=leaf-worker "RABS_WORKER_STATE_DIR=$SPECIAL_STATE"
assert_installation client coordinator.example:7443 coordinator.example leaf-worker "$SPECIAL_STATE"
grep -Fxq 'Coordinator enrollment: RABS_DEPENDENCY_WORKER_ID=leaf-worker' "$CASE_STDERR" \
    || fail 'the selected protocol identity was not reported for coordinator enrollment'
SELECTED_STAGE=$LAST_STAGE
pass 'selected worker identity and exact remote journal path reach the installed service'

run_deploy selected-worker success worker.example coordinator.example:7443
assert_installation client coordinator.example:7443 coordinator.example leaf-worker "$SPECIAL_STATE"
[[ "$LAST_STAGE" != "$SELECTED_STAGE" ]] || fail 'selected worker did not receive a new credential generation'
[[ -f "$CASE_DIR/remote$SELECTED_STAGE/worker.env" ]] || fail 'upgrade discarded prior worker settings'
pass 'omitting runtime settings during an upgrade retains the current identity and journal'

run_deploy selected-worker success worker.example coordinator.example:7443 RABS_WORKER_ID=leaf-worker
assert_installation client coordinator.example:7443 coordinator.example leaf-worker "$SPECIAL_STATE"
pass 'explicit identity with an omitted journal retains the existing journal assignment once'

run_deploy selected-worker success worker.example coordinator.example:7443 "RABS_WORKER_STATE_DIR=$SPECIAL_STATE"
assert_installation client coordinator.example:7443 coordinator.example leaf-worker "$SPECIAL_STATE"
pass 'explicit journal with an omitted identity retains the existing identity assignment once'

run_deploy retained-targets success worker.example coordinator.example:7443 \
    RABS_WORKER_TARGET_CACHE_BYTES=1073741824 RABS_WORKER_TARGET_CACHE_EPOCH=image-v1
assert_installation client coordinator.example:7443 coordinator.example '' '' 1073741824 image-v1
pass 'managed service receives the target quota and stable runtime epoch'

run_deploy retained-targets success worker.example coordinator.example:7443
assert_installation client coordinator.example:7443 coordinator.example '' '' 1073741824 image-v1
pass 'credential-only upgrade retains target-cache quota and runtime epoch'

run_deploy retained-targets success worker.example coordinator.example:7443 RABS_WORKER_TARGET_CACHE_BYTES=8589934592
assert_installation client coordinator.example:7443 coordinator.example '' '' 8589934592 image-v1
pass 'changing the target quota preserves the runtime epoch'

run_deploy retained-targets success worker.example coordinator.example:7443 RABS_WORKER_TARGET_CACHE_EPOCH=image-v2
assert_installation client coordinator.example:7443 coordinator.example '' '' 8589934592 image-v2
pass 'runtime epoch rotation preserves the configured target quota'

run_deploy retained-targets success worker.example coordinator.example:7443 RABS_WORKER_TARGET_CACHE_EPOCH=
assert_installation client coordinator.example:7443 coordinator.example '' '' 8589934592 ''
grep -Fxq 'RABS_WORKER_TARGET_CACHE_EPOCH=""' "$CASE_DIR/remote$LAST_STAGE/worker.env" \
    || fail 'empty epoch did not explicitly clear durable retention'
pass 'an empty epoch restores process-only retention without losing the byte quota'

run_deploy retained-targets success worker.example coordinator.example:7443 RABS_WORKER_TARGET_CACHE_BYTES=0
assert_installation client coordinator.example:7443 coordinator.example '' '' 0 ''
pass 'zero bytes explicitly disables target retention'

run_deploy selected-identity-only success worker.example coordinator.example:7443 RABS_WORKER_ID=identity-only
assert_installation client coordinator.example:7443 coordinator.example identity-only
pass 'selecting only an identity retains the worker default journal layout'

run_deploy selected-state-only success worker.example coordinator.example:7443 RABS_WORKER_STATE_DIR=/var/lib/rabs/durable
assert_installation client coordinator.example:7443 coordinator.example '' /var/lib/rabs/durable
pass 'selecting only a journal retains the remote hostname identity'

# Lost settings must not cause a credential update to replace the running
# service with hostname/default-state settings and forget execution history.
mv "$CASE_DIR/remote$LAST_STAGE/worker.env" "$CASE_DIR/remote$LAST_STAGE/worker.env.retained"
OLD_UNIT_HASH=$(sha256sum "$CASE_DIR/remote/etc/systemd/system/rabs-wkr.service")
OLD_BINARY_HASH=$(sha256sum "$CASE_DIR/remote/usr/local/bin/rabs-wkr")
run_deploy selected-state-only failure worker.example coordinator.example:7443
[[ $(sha256sum "$CASE_DIR/remote/etc/systemd/system/rabs-wkr.service") == "$OLD_UNIT_HASH" ]] \
    || fail 'unreadable prior settings replaced the old service unit'
[[ $(sha256sum "$CASE_DIR/remote/usr/local/bin/rabs-wkr") == "$OLD_BINARY_HASH" ]] \
    || fail 'unreadable prior settings replaced the old binary'
[[ $(grep -c '^restart rabs-wkr.service$' "$CASE_DIR/systemctl.log") == 1 ]] \
    || fail 'unreadable prior settings restarted the old service'
pass 'missing prior journal settings refuse before binary replacement or service restart'

run_deploy split-authorities success worker.example coordinator.example:7443 \
    "RABS_WORKER_TLS_CERT=$CERT_DIR/split-client.pem" "RABS_WORKER_TLS_KEY=$CERT_DIR/split-client.key"
assert_installation split-client coordinator.example:7443 coordinator.example
pass 'different coordinator and client certificate authorities are accepted'

run_deploy ipv6 success 2001:db8::1 '[2001:db8::2]:7443' RABS_WORKER_TLS_SERVER_NAME=2001:db8::2
assert_installation client '[2001:db8::2]:7443' 2001:db8::2
pass 'literal IPv6 worker, coordinator, and TLS server name retain their routing'

RABS_TEST_BASH_X=1 run_deploy traced-success success worker.example coordinator.example:7443
assert_installation client coordinator.example:7443 coordinator.example
pass 'bash tracing exposes no private key in logs or the SSH process environment'

run_deploy tls-transfer-failed failure worker.example coordinator.example:7443 \
    RABS_TEST_FAIL_TLS_TRANSFER=1
PARTIAL_CA=$(find "$CASE_DIR/remote/etc/rabs-wkr" -name ca.pem -type f)
[[ -n "$PARTIAL_CA" && $(wc -c < "$PARTIAL_CA") == 16 ]] \
    || fail 'the TLS interruption did not exercise a real partial file transfer'
[[ ! -e "$CASE_DIR/remote/usr/local/bin/rabs-wkr" ]] || fail 'TLS transfer failure installed a binary'
[[ ! -e "$CASE_DIR/remote/etc/systemd/system/rabs-wkr.service" ]] \
    || fail 'TLS transfer failure installed a service unit'
if grep -q '^restart ' "$CASE_DIR/systemctl.log"; then
    fail 'TLS transfer failure restarted the service'
fi
pass 'partial TLS transfer fails without activation or success'

run_deploy unusable-binary failure worker.example coordinator.example:7443 RABS_TEST_VERSION_FAIL=1
grep -Fxq -- '--version' "$CASE_DIR/worker.log" || fail 'staged binary version check was not exercised'
[[ ! -e "$CASE_DIR/remote/usr/local/bin/rabs-wkr" ]] || fail 'a failed version check replaced the binary'
if grep -q '^restart ' "$CASE_DIR/systemctl.log"; then
    fail 'a failed version check restarted the service'
fi
pass 'an unusable staged binary fails before activation'

for operation in daemon-reload enable restart is-active; do
    run_deploy "service-failed-$operation" failure worker.example coordinator.example:7443 \
        "RABS_TEST_SYSTEMCTL_FAIL=$operation"
    grep -Eq "^$operation( |$)" "$CASE_DIR/systemctl.log" \
        || fail "the $operation failure boundary was not exercised"
    pass "$operation failure cannot report deployment success"
done

printf 'PASS: %s fleet deployment behavioral checks; evidence retained at %s\n' \
    "$TESTS_PASSED" "$TEST_ROOT"
