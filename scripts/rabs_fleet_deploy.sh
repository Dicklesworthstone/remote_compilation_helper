#!/usr/bin/env bash
# S7 (bead bd-n8qt3): capability-gated fleet provisioning of rabs-wkr.
#
# Deploys the release rabs-wkr binary to a worker over SSH after measuring
# the selected execution namespace. The default requires canonical execution;
# RABS_DEPLOY_CAPABILITY=dependency-rlib selects the separate archive profile
# for hosts that cannot mount procfs. The native worker independently measures
# and advertises its supported modes; deployment never grants capabilities.
#
# Usage:
#   RABS_WORKER_TLS_CA=/local/ca.pem \
#   RABS_WORKER_TLS_CERT=/local/worker.pem \
#   RABS_WORKER_TLS_KEY=/local/worker.key \
#   RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
#   RABS_WORKER_ID=leaf-worker \
#   RABS_WORKER_STATE_DIR=/var/lib/rabs/leaf-worker \
#   RABS_WORKER_TARGET_CACHE_BYTES=1073741824 \
#   RABS_WORKER_TARGET_CACHE_EPOCH=worker-image-2026-01 \
#   RABS_WORKER_SOURCE_CACHE_BYTES=536870912 \
#   RABS_WORKER_TOOLCHAIN_CACHE_BYTES=8589934592 \
#   RABS_WORKER_TOOLCHAIN_CACHE_DIR=/var/lib/rabs/toolchains \
#   RABS_WORKER_TOOLCHAIN_FILE_CACHE_BYTES=8589934592 \
#   RABS_WORKER_HOST_BUDGET_DIR=/var/lib/rabs/host-budget \
#   RABS_WORKER_HOST_SLOTS=32 \
#   rabs_fleet_deploy.sh <worker-ssh-host> <coordinator-host:port> \
#       [path-to-release-rabs-wkr]
#
# TLS paths above are LOCAL files. All four settings are required, including
# for loopback. The CA authenticates the coordinator; the worker certificate
# may be issued by a different CA. This script never creates or learns trust.
# Identity, state directory, cache and shared-host settings are optional. Omit them
# to retain previous managed settings, or worker defaults on a fresh install.
# RABS_DEPLOY_CAPABILITY is canonical (default) or dependency-rlib. It selects
# only this deployment's admission probe and is not saved in the service.
# A nonempty target-cache epoch enables retention across restarts; change it
# before updating host tools, libraries or any other runtime input. An empty
# epoch selects process-only retention; zero bytes disables all target reuse.
# Source/target cache quotas are bounded at 8 GiB; whole-SDK and interrupted-SDK
# file cache quotas at 64 GiB. No quota is enabled or enlarged by deployment.
# RABS_SOURCE_CACHE_DIR selects an existing private remote directory; an empty
# override restores the worker journal directory. A nonempty toolchain cache
# directory requires an explicitly supplied nonzero toolchain quota. An empty
# RABS_WORKER_TOOLCHAIN_CACHE_DIR restores process-only SDK retention; supply it
# together with a zero quota to disable previously persistent SDK retention.
# Shared host directory/slots must be supplied together (1..4096 slots); supply
# both empty to remove shared-host admission. Existing host capacity is immutable:
# the worker refuses incompatible changes rather than resetting live leases.
# All directory ownership, permissions and existing cache contents are still
# verified by the worker. Deployment does not repair or empty those directories.
# The state path is on the REMOTE worker. Never
# change it to retry an uncertain execution: that would abandon its journal.
# Credential generations are private and retained across deployment attempts.
# Re-running replaces the binary + unit and explicitly restarts the service.
# A successful deployment verifies service startup, not coordinator admission.
set +x # Do not expose private PEM bytes if invoked with bash -x.
set +a
set -euo pipefail

usage() {
  echo 'Usage: rabs_fleet_deploy.sh <worker-ssh-host> <coordinator-host:port> [local-rabs-wkr]' >&2
  echo 'Required: RABS_WORKER_TLS_CA/CERT/KEY (local PEM files), RABS_WORKER_TLS_SERVER_NAME' >&2
  echo 'Optional: RABS_WORKER_ID, RABS_WORKER_STATE_DIR (absolute remote journal directory)' >&2
  echo 'Optional: RABS_WORKER_TARGET_CACHE_BYTES (0..8589934592), RABS_WORKER_TARGET_CACHE_EPOCH (stable host runtime identity)' >&2
  echo 'Optional: RABS_WORKER_SOURCE_CACHE_BYTES (0..8589934592), RABS_SOURCE_CACHE_DIR (private remote directory; empty restores default)' >&2
  echo 'Optional: RABS_WORKER_TOOLCHAIN_CACHE_BYTES (0..68719476736), RABS_WORKER_TOOLCHAIN_CACHE_DIR (private remote directory; empty clears persistence)' >&2
  echo 'Optional: RABS_WORKER_TOOLCHAIN_FILE_CACHE_BYTES (0..68719476736)' >&2
  echo 'Optional: RABS_WORKER_HOST_BUDGET_DIR and RABS_WORKER_HOST_SLOTS (1..4096; both empty disables shared admission)' >&2
  echo 'Optional: RABS_DEPLOY_CAPABILITY=canonical|dependency-rlib (default canonical; this deployment only)' >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
WORKER=$1
COORDINATOR=$2
LOCAL_BIN=${3:-target/release/rabs-wkr}
REMOTE_BIN=/usr/local/bin/rabs-wkr
SSH_OPTS=(-o ConnectTimeout=20 -o BatchMode=yes)

input_error() { printf 'rabs_fleet_deploy: %s\n' "$1" >&2; exit 2; }

DEPLOY_CAPABILITY=${RABS_DEPLOY_CAPABILITY-canonical}
case "$DEPLOY_CAPABILITY" in
  canonical|dependency-rlib) ;;
  *) input_error 'RABS_DEPLOY_CAPABILITY must be canonical or dependency-rlib' ;;
esac

dns_name() {
  [[ ${#1} -le 253 && $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$ ]]
}

# Literal IPv6 without a scope identifier. '%' is also a systemd specifier,
# so neither scope identifiers nor other interpolation syntax are admitted.
ipv6_address() {
  local value=$1 part left right count=0
  [[ $value =~ ^[0-9A-Fa-f:]+$ && $value == *:* ]] || return 1
  if [[ $value == *::* ]]; then
    left=${value%%::*}
    right=${value#*::}
    [[ $right != *::* ]] || return 1
  else
    left=$value
    right=''
  fi
  for part in "$left" "$right"; do
    [[ -n $part ]] || continue
    [[ $part != :* && $part != *: ]] || return 1
    local -a groups=()
    IFS=: read -r -a groups <<< "$part"
    local group
    for group in "${groups[@]}"; do
      [[ $group =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
      count=$((count + 1))
    done
  done
  if [[ $value == *::* ]]; then
    [[ $count -lt 8 ]]
  else
    [[ $count -eq 8 ]]
  fi
}

# SSH aliases are permitted, but user/options/shell syntax are not. Streaming
# files over SSH also avoids scp's special treatment of ':' in local paths.
[[ ${#WORKER} -le 253 && $WORKER =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
  ipv6_address "$WORKER" || input_error 'invalid worker SSH host (use a host or SSH alias, without user/options)'
if [[ $COORDINATOR =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]+)$ ]]; then
  COORD_HOST=${BASH_REMATCH[1]}
  COORD_PORT=${BASH_REMATCH[2]}
  ipv6_address "$COORD_HOST" || input_error 'invalid coordinator IPv6 address'
elif [[ $COORDINATOR =~ ^([^:]+):([0-9]+)$ ]]; then
  COORD_HOST=${BASH_REMATCH[1]}
  COORD_PORT=${BASH_REMATCH[2]}
  dns_name "$COORD_HOST" || input_error 'invalid coordinator hostname'
else
  input_error 'coordinator must be hostname:port or [IPv6]:port'
fi
[[ ${#COORD_PORT} -le 5 ]] && ((10#$COORD_PORT >= 1 && 10#$COORD_PORT <= 65535)) ||
  input_error 'coordinator port must be between 1 and 65535'
TLS_SERVER_NAME=${RABS_WORKER_TLS_SERVER_NAME:-}
dns_name "$TLS_SERVER_NAME" || ipv6_address "$TLS_SERVER_NAME" ||
  input_error 'RABS_WORKER_TLS_SERVER_NAME must be a DNS name or literal IP address'
RUNTIME_SETTINGS=(
  RABS_WORKER_ID RABS_WORKER_STATE_DIR
  RABS_WORKER_TARGET_CACHE_BYTES RABS_WORKER_TARGET_CACHE_EPOCH
  RABS_WORKER_SOURCE_CACHE_BYTES RABS_SOURCE_CACHE_DIR
  RABS_WORKER_TOOLCHAIN_CACHE_BYTES RABS_WORKER_TOOLCHAIN_CACHE_DIR
  RABS_WORKER_TOOLCHAIN_FILE_CACHE_BYTES
  RABS_WORKER_HOST_BUDGET_DIR RABS_WORKER_HOST_SLOTS
)

runtime_setting_index() {
  local index
  for ((index=0; index<${#RUNTIME_SETTINGS[@]}; index++)); do
    if [[ $1 == "${RUNTIME_SETTINGS[$index]}" ]]; then
      RUNTIME_SETTING_INDEX=$index
      return 0
    fi
  done
  return 1
}

bounded_decimal() {
  local value=$1 maximum=$2 max_digits=$3 normalized
  [[ $value =~ ^[0-9]+$ && ${#value} -le $max_digits ]] || return 1
  # Strip leading zeroes before arithmetic so even a padded SDK quota cannot
  # overflow the shell's integer range. Retain the caller's exact bytes on disk.
  normalized=${value#"${value%%[!0]*}"}
  normalized=${normalized:-0}
  [[ ${#normalized} -le ${#maximum} ]] && ((10#$normalized <= maximum))
}

runtime_directory() {
  local name=$1 value=$2 LC_ALL=C
  [[ $value == /* && $value != / && ${#value} -le 4096 && $value =~ ^[[:print:]]+$ ]] ||
    input_error "$name must be an absolute printable ASCII remote directory, up to 4096 characters"
  case "$name:$value/" in
    RABS_WORKER_STATE_DIR:*) ;;
    *'/../'*|*'/./'*) input_error "$name must not contain directory traversal components" ;;
  esac
}

# The same validators run before the first SSH operation and after merging the
# active managed service under its activation lock. Persisted settings do not
# bypass quota, path or paired-configuration checks during a credential update.
validate_runtime_settings() {
  local assignment name value LC_ALL=C
  local sdk_directory='' sdk_bytes='' host_directory='' host_slots=''
  local host_directory_set=0 host_slots_set=0
  for assignment in "$@"; do
    [[ -n $assignment ]] || continue
    name=${assignment%%=*}
    value=${assignment#*=}
    case "$name" in
      RABS_WORKER_ID|RABS_WORKER_TARGET_CACHE_EPOCH)
        if [[ $name == RABS_WORKER_TARGET_CACHE_EPOCH && -z $value ]]; then continue; fi
        [[ ${#value} -le 128 && $value =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
          input_error "$name must be 1..128 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit"
        ;;
      RABS_WORKER_STATE_DIR) runtime_directory "$name" "$value" ;;
      RABS_SOURCE_CACHE_DIR|RABS_WORKER_TOOLCHAIN_CACHE_DIR|RABS_WORKER_HOST_BUDGET_DIR)
        [[ -z $value ]] || runtime_directory "$name" "$value"
        if [[ $name == RABS_WORKER_TOOLCHAIN_CACHE_DIR ]]; then sdk_directory=$value; fi
        if [[ $name == RABS_WORKER_HOST_BUDGET_DIR ]]; then
          host_directory=$value
          host_directory_set=1
        fi
        ;;
      RABS_WORKER_TARGET_CACHE_BYTES|RABS_WORKER_SOURCE_CACHE_BYTES)
        bounded_decimal "$value" 8589934592 10 ||
          input_error "$name must be 1..10 decimal digits representing 0 to 8589934592 bytes"
        ;;
      RABS_WORKER_TOOLCHAIN_CACHE_BYTES)
        bounded_decimal "$value" 68719476736 4096 ||
          input_error "$name must be an unsigned decimal byte count from 0 to 68719476736 (up to 4096 characters)"
        sdk_bytes=$value
        ;;
      RABS_WORKER_TOOLCHAIN_FILE_CACHE_BYTES)
        bounded_decimal "$value" 68719476736 11 ||
          input_error "$name must be 1..11 decimal digits representing 0 to 68719476736 bytes"
        ;;
      RABS_WORKER_HOST_SLOTS)
        [[ -z $value ]] || { [[ $value =~ ^[1-9][0-9]{0,3}$ ]] && ((10#$value <= 4096)); } ||
          input_error "$name must be a canonical decimal number from 1 to 4096"
        host_slots=$value
        host_slots_set=1
        ;;
    esac
  done
  if [[ -n $sdk_directory ]]; then
    [[ $sdk_bytes =~ [1-9] ]] ||
      input_error 'RABS_WORKER_TOOLCHAIN_CACHE_DIR requires a nonzero RABS_WORKER_TOOLCHAIN_CACHE_BYTES; clear the directory explicitly to disable persistence'
  fi
  [[ $host_directory_set == "$host_slots_set" ]] ||
    input_error 'RABS_WORKER_HOST_BUDGET_DIR and RABS_WORKER_HOST_SLOTS must be supplied together'
  if [[ $host_directory_set == 1 ]]; then
    [[ -n $host_directory && -n $host_slots ]] ||
      [[ -z $host_directory && -z $host_slots ]] ||
      input_error 'shared-host directory and slots must either both be configured or both be empty to disable admission'
  fi
}

# Fixed indexed arrays keep the dispatcher compatible with macOS Bash 3.2.
# Each slot is either absent (empty) or an exact NAME=value assignment. NAME=
# therefore remains distinct from omission when clearing a previous setting.
PROVIDED_RUNTIME=()
for setting in "${RUNTIME_SETTINGS[@]}"; do
  if declare -p "$setting" >/dev/null 2>&1; then
    PROVIDED_RUNTIME+=("$setting=${!setting}")
  else
    PROVIDED_RUNTIME+=('')
  fi
done
validate_runtime_settings "${PROVIDED_RUNTIME[@]}"
[[ -f $LOCAL_BIN && -x $LOCAL_BIN ]] || input_error "no executable release binary at $LOCAL_BIN"
command -v openssl >/dev/null 2>&1 || input_error 'openssl is required to validate TLS credentials'

# Freeze each small PEM in memory, preserving trailing newlines, so validation
# and transfer use identical bytes even if the caller replaces an input file.
# A NUL or an oversized input refuses before any SSH invocation. This matches
# worker_transport::read_pem's 1 MiB limit and needs no temporary private key.
read_pem() {
  local variable=$1 destination=$2 path=${!1:-} size captured_size
  [[ -n $path && -f $path && -r $path && -s $path ]] ||
    input_error "$variable must name a readable, nonempty local PEM file"
  size=$(wc -c < "$path")
  ((size <= 1048576)) || input_error "$variable exceeds the worker's 1 MiB limit"
  if IFS= read -r -d '' -n 1048577 "$destination" < "$path"; then
    input_error "$variable contains a NUL byte or exceeds the worker's 1 MiB limit"
  fi
  captured_size=$(printf '%s' "${!destination}" | wc -c)
  ((captured_size == size && captured_size > 0 && captured_size <= 1048576)) ||
    input_error "$variable changed while being read or exceeds the worker's 1 MiB limit"
}
TLS_CA_PEM=''
TLS_CERT_PEM=''
TLS_KEY_PEM=''
export -n TLS_CA_PEM TLS_CERT_PEM TLS_KEY_PEM
read_pem RABS_WORKER_TLS_CA TLS_CA_PEM
read_pem RABS_WORKER_TLS_CERT TLS_CERT_PEM
read_pem RABS_WORKER_TLS_KEY TLS_KEY_PEM
[[ $TLS_CA_PEM != *'PRIVATE KEY-----'* && $TLS_CERT_PEM != *'PRIVATE KEY-----'* ]] ||
  input_error 'CA and certificate files must not contain private keys'

certificate_pem() {
  local certificates certificate='' line constraints has_ca=1
  certificates=$(printf '%s' "$1" |
    openssl crl2pkcs7 -nocrl -certfile /dev/stdin -outform DER 2>/dev/null |
    openssl pkcs7 -inform DER -print_certs 2>/dev/null) || return 1
  [[ $certificates == *'-----BEGIN CERTIFICATE-----'* ]] || return 1
  [[ ${2:-chain} == ca ]] || return 0
  # Match the runtime's strict trust-anchor gate without requiring the worker
  # client certificate to chain to the coordinator's (possibly different) CA.
  while IFS= read -r line; do
    if [[ $line == '-----BEGIN CERTIFICATE-----' ]]; then
      certificate=$line$'\n'
    elif [[ -n $certificate ]]; then
      certificate+=$line$'\n'
      if [[ $line == '-----END CERTIFICATE-----' ]]; then
        constraints=$(openssl x509 -noout -ext basicConstraints \
          < <(printf '%s' "$certificate") 2>/dev/null) || return 1
        [[ $constraints != *'CA:TRUE'* ]] || has_ca=0
        certificate=''
      fi
    fi
  done <<< "$certificates"
  return "$has_ca"
}
certificate_pem "$TLS_CA_PEM" ca ||
  input_error 'RABS_WORKER_TLS_CA must be a valid PEM bundle containing a CA:TRUE certificate'
certificate_pem "$TLS_CERT_PEM" || input_error 'RABS_WORKER_TLS_CERT is not a valid PEM certificate chain'
[[ $TLS_KEY_PEM != *'-----BEGIN ENCRYPTED PRIVATE KEY-----'* &&
   $TLS_KEY_PEM != *'Proc-Type:'*'ENCRYPTED'* &&
   ( $TLS_KEY_PEM == *'-----BEGIN PRIVATE KEY-----'* ||
     $TLS_KEY_PEM == *'-----BEGIN RSA PRIVATE KEY-----'* ||
     $TLS_KEY_PEM == *'-----BEGIN EC PRIVATE KEY-----'* ) ]] ||
  input_error 'RABS_WORKER_TLS_KEY must be an unencrypted PEM private key'
# OpenSSL uses the first key, whereas the native loader prefers PKCS#8 over
# PKCS#1/SEC1 and parses whole PEM streams. Refuse ambiguous multi-key bundles.
KEY_BEGIN_COUNT=0
KEY_END_COUNT=0
while IFS= read -r KEY_LINE || [[ -n $KEY_LINE ]]; do
  [[ $KEY_LINE != '-----BEGIN '* ]] || KEY_BEGIN_COUNT=$((KEY_BEGIN_COUNT + 1))
  [[ $KEY_LINE != '-----END '* ]] || KEY_END_COUNT=$((KEY_END_COUNT + 1))
done < <(printf '%s' "$TLS_KEY_PEM")
[[ $KEY_BEGIN_COUNT -eq 1 && $KEY_END_COUNT -eq 1 ]] ||
  input_error 'RABS_WORKER_TLS_KEY must contain exactly one unencrypted PEM private key'
openssl pkey -passin pass: -check -noout < <(printf '%s' "$TLS_KEY_PEM") >/dev/null 2>&1 ||
  input_error 'RABS_WORKER_TLS_KEY is not a valid private key'
CERT_KEY_ID=$(openssl x509 -pubkey -noout < <(printf '%s' "$TLS_CERT_PEM") 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256) ||
  input_error 'cannot extract worker certificate public key'
PRIVATE_KEY_ID=$(openssl pkey -passin pass: -pubout -outform DER < <(printf '%s' "$TLS_KEY_PEM") 2>/dev/null |
  openssl dgst -sha256) || input_error 'cannot extract worker private key public identity'
[[ $CERT_KEY_ID == "$PRIVATE_KEY_ID" ]] || input_error 'worker certificate and private key do not match'
WORKER_SPKI_SHA256=${CERT_KEY_ID##* }
[[ $WORKER_SPKI_SHA256 =~ ^[0-9a-f]{64}$ ]] || input_error 'cannot parse worker certificate SPKI SHA-256'

emit() { printf '{"kind":"fleet-deploy","worker":"%s","step":"%s","status":"%s"}\n' "$WORKER" "$1" "$2"; }
failed() { emit "$1" failed; printf 'rabs_fleet_deploy: %s\n' "$2" >&2; exit 1; }

# CAPABILITY GATE: exercise the selected namespace BEFORE any copy. The value
# interpolated into the remote command is one of the two fixed tokens above.
# Keep both no-input launches aligned with the native capability probes. The
# archive no-op uses trusted /usr bytes only to measure the base namespace;
# actual dependency execution requires its separately retained keyed runtime.
emit capability-probe start
CAP=$(ssh "${SSH_OPTS[@]}" "root@$WORKER" "RABS_DEPLOY_CAPABILITY=$DEPLOY_CAPABILITY"'
  bwrap_command=$(command -v bwrap) || { echo "no-bwrap"; exit 0; }
  case "$RABS_DEPLOY_CAPABILITY" in
    canonical)
      bwrap --die-with-parent --unshare-user --unshare-pid --unshare-ipc \
        --unshare-uts --unshare-net --hostname rabs --clearenv \
        --proc /proc --dev /dev --ro-bind /usr /usr \
        --symlink usr/bin /bin --symlink usr/sbin /sbin \
        --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
        --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
        --ro-bind-try /etc/alternatives /etc/alternatives \
        --tmpfs /__rabs/tmp --chdir / -- /usr/bin/true >/dev/null 2>&1 ||
        { echo "bwrap-present-but-canonical-fails"; exit 0; }
      ;;
    dependency-rlib)
      for tool in uname stat env; do
        probe_tool=$(command -v "$tool") || { echo "missing-rlib-probe-tool"; exit 0; }
      done
      [ "$(uname -s)" = Linux ] || { echo "dependency-rlib-requires-linux"; exit 0; }
      # Do not open /dev/null even for redirection until its identity is known.
      # A malformed regular file at that path must remain untouched on refusal.
      bwrap_version=$(bwrap --version 2>&1) ||
        { echo "bwrap-present-but-dependency-rlib-fails"; exit 0; }
      valid_null_device() {
        [ ! -L /dev/null ] && [ -c /dev/null ] &&
          [ "$(stat -c "%t:%T" -- /dev/null)" = "1:3" ]
      }
      valid_null_device || { echo "dependency-rlib-invalid-null-device"; exit 0; }
      env -i PATH="$PATH" bwrap --die-with-parent --unshare-user --unshare-pid --unshare-ipc \
        --unshare-uts --unshare-net --hostname rabs --clearenv \
        --dir /dev --dev-bind /dev/null /dev/null --ro-bind /usr /usr \
        --symlink usr/bin /bin --symlink usr/sbin /sbin \
        --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
        --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
        --ro-bind-try /etc/alternatives /etc/alternatives \
        --tmpfs /tmp --tmpfs /__rabs/tmp --chdir /__rabs/tmp -- /usr/bin/true >/dev/null 2>&1 ||
        { echo "bwrap-present-but-dependency-rlib-fails"; exit 0; }
      valid_null_device || { echo "dependency-rlib-invalid-null-device"; exit 0; }
      ;;
    *) echo "unsupported-deployment-capability"; exit 0 ;;
  esac
  for tool in bash systemctl flock install mktemp cat chmod mv; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing-deployment-tool"; exit 0; }
  done
  systemctl show-environment >/dev/null 2>&1 || { echo "systemd-unavailable"; exit 0; }
  echo "$RABS_DEPLOY_CAPABILITY-ok"
') || failed capability-probe 'worker is unreachable'

if [ "$CAP" != "$DEPLOY_CAPABILITY-ok" ]; then
  case "$CAP" in
    no-bwrap|bwrap-present-but-canonical-fails|bwrap-present-but-dependency-rlib-fails|\
    dependency-rlib-invalid-null-device|dependency-rlib-requires-linux|\
      missing-rlib-probe-tool|missing-deployment-tool|systemd-unavailable)
      emit capability-probe "refused:$CAP"
      printf 'REFUSED: %s (%s); no files copied\n' "$WORKER" "$CAP" >&2
      exit 1
      ;;
    *) failed capability-probe 'unrecognized worker capability response; no files copied' ;;
  esac
fi
emit capability-probe "$CAP"

# A private, never-reused credential generation keeps a running worker from
# observing a half-updated certificate/key pair. Failed stages are not activated.
emit tls start
STAGE=$(ssh "${SSH_OPTS[@]}" "root@$WORKER" '
  set -eu
  umask 077
  test ! -L /etc/rabs-wkr
  install -d -m 0700 -o root -g root /etc/rabs-wkr
  mktemp -d /etc/rabs-wkr/deploy.XXXXXXXXXX
') || failed tls 'cannot create protected remote credential directory'
[[ $STAGE =~ ^/etc/rabs-wkr/deploy\.[A-Za-z0-9]{10}$ ]] ||
  failed tls 'worker returned an invalid staging directory'
REMOTE_BIN_STAGE=/usr/local/bin/.rabs-wkr-${STAGE##*/}

upload_pem() {
  printf '%s' "$2" | ssh "${SSH_OPTS[@]}" "root@$WORKER" \
    "set -eu; umask 077; set -C; cat > '$STAGE/$1'; chmod 0600 '$STAGE/$1'" ||
    failed tls 'credential transfer failed; service was not restarted'
}
upload_pem ca.pem "$TLS_CA_PEM"
upload_pem worker.pem "$TLS_CERT_PEM"
upload_pem worker.key "$TLS_KEY_PEM"

# EnvironmentFile double quotes use POSIX double-quoted backslash rules;
# escape every special character so the worker receives the exact path.
# https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=
environment_setting() {
  local value=$2
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//\$/\\\$}
  value=${value//\`/\\\`}
  printf '%s="%s"\n' "$1" "$value"
}

worker_environment() {
  local assignment
  cat <<ENV
RABS_WORKER_TLS_CA=$STAGE/ca.pem
RABS_WORKER_TLS_CERT=$STAGE/worker.pem
RABS_WORKER_TLS_KEY=$STAGE/worker.key
RABS_WORKER_TLS_SERVER_NAME=$TLS_SERVER_NAME
ENV
  for assignment in "${PROVIDED_RUNTIME[@]}"; do
    [[ -z $assignment ]] || environment_setting "${assignment%%=*}" "${assignment#*=}"
  done
}
worker_environment | ssh "${SSH_OPTS[@]}" "root@$WORKER" \
  "set -eu; umask 077; set -C; cat > '$STAGE/worker.env'; chmod 0600 '$STAGE/worker.env'" ||
  failed tls 'worker environment transfer failed'
emit tls done

# The staged executable shares the final binary's filesystem for atomic rename.
emit copy start
ssh "${SSH_OPTS[@]}" "root@$WORKER" \
  "set -eu; umask 077; set -C; cat > '$REMOTE_BIN_STAGE'" < "$LOCAL_BIN" ||
  failed copy 'binary transfer failed; service was not restarted'
emit copy done

# Stage the complete unit before changing the live service. Explicit User=root
# supplies the root account's HOME for the existing durable worker state path.
emit unit start
ssh "${SSH_OPTS[@]}" "root@$WORKER" "set -eu; umask 077; set -C; cat > '$STAGE/rabs-wkr.service'" <<UNIT ||
  failed unit 'systemd unit transfer failed'
[Unit]
Description=RABS trusted worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=$STAGE/worker.env
ExecStart=$REMOTE_BIN --coordinator "$COORDINATOR"
Restart=on-failure
RestartSec=5
# The worker offers results, never commits (R50); no privileged mode.
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

# Refuse an unusable/wrong-architecture binary before replacing the running one.
emit verify start
VER=$(ssh "${SSH_OPTS[@]}" "root@$WORKER" "chmod 0755 '$REMOTE_BIN_STAGE' && '$REMOTE_BIN_STAGE' --version") ||
  failed verify 'staged worker failed --version; service was not restarted'
[[ $VER =~ ^rabs-wkr\ [A-Za-z0-9.+-]+$ ]] || failed verify 'staged binary did not identify itself as rabs-wkr'
emit verify done

# Decode only a one-line EnvironmentFile value, never shell source. The managed
# writer uses double quotes; simple unquoted and single-quoted operator settings
# are accepted too. More complex syntax refuses instead of silently losing a
# setting or making shell and systemd interpret different values.
decode_environment_value() {
  local encoded=$1 body character next index
  DECODED_ENVIRONMENT_VALUE=''
  [[ ${#encoded} -le 16384 ]] || input_error 'managed runtime setting is too large'
  case "$encoded" in
    \"*\")
      body=${encoded:1:${#encoded}-2}
      for ((index=0; index<${#body}; index++)); do
        character=${body:index:1}
        if [[ $character == \\ ]]; then
          index=$((index + 1))
          ((index < ${#body})) || input_error 'unfinished escape in managed runtime setting'
          next=${body:index:1}
          case "$next" in
            \"|\\|\$|\`) DECODED_ENVIRONMENT_VALUE+=$next ;;
            *) DECODED_ENVIRONMENT_VALUE+="\\$next" ;;
          esac
        elif [[ $character == \" ]]; then
          input_error 'unescaped quote in managed runtime setting'
        else
          DECODED_ENVIRONMENT_VALUE+=$character
        fi
      done
      ;;
    \'*\')
      DECODED_ENVIRONMENT_VALUE=${encoded:1:${#encoded}-2}
      [[ $DECODED_ENVIRONMENT_VALUE != *\'* ]] || input_error 'unescaped single quote in managed runtime setting'
      ;;
    *)
      [[ $encoded =~ ^[A-Za-z0-9_./:+-]*$ ]] ||
        input_error 'managed runtime setting must use one-line quoted or simple unquoted syntax'
      DECODED_ENVIRONMENT_VALUE=$encoded
      ;;
  esac
}

read_runtime_environment() {
  local path=$1 contents='' line name value LC_ALL=C
  READ_RUNTIME_SETTINGS=()
  for name in "${RUNTIME_SETTINGS[@]}"; do READ_RUNTIME_SETTINGS+=(''); done
  [[ -f $path && ! -L $path ]] || input_error 'managed worker environment is missing or not an ordinary file'
  if IFS= read -r -d '' -n 131073 contents < "$path"; then
    input_error 'managed worker environment contains a NUL or exceeds 128 KiB'
  fi
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line#"${line%%[!$' \t']*}"}
    name=${line%%=*}
    runtime_setting_index "$name" || continue
    [[ $line == "$name="* && -z ${READ_RUNTIME_SETTINGS[$RUNTIME_SETTING_INDEX]} ]] ||
      input_error "duplicate or malformed managed setting: $name"
    value=${line#*=}
    value=${value%"${value##*[!$' \t']}"}
    decode_environment_value "$value"
    READ_RUNTIME_SETTINGS[$RUNTIME_SETTING_INDEX]="$name=$DECODED_ENVIRONMENT_VALUE"
  done <<< "$contents"
}

# Serialize activation across concurrent deployments. Merge the currently
# active managed settings while holding the lock, then validate the resulting
# worker configuration before replacing the binary or the service. None of the
# prior environment file is executed, and explicit empty removals are omitted
# from the final EnvironmentFile rather than passed as invalid worker values.
activate_worker() {
  local stage=$1 remote_bin_stage=$2 remote_bin=$3
  local previous_environment='' line name assignment value index
  local -a selected=() previous=()
  exec 9>/etc/rabs-wkr/deploy.lock
  flock -x 9
  read_runtime_environment "$stage/worker.env"
  selected=("${READ_RUNTIME_SETTINGS[@]}")
  if [[ -f /etc/systemd/system/rabs-wkr.service ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      case "$line" in
        EnvironmentFile=*)
          [[ -z $previous_environment ]] || input_error 'existing worker service has multiple environment files'
          previous_environment=${line#EnvironmentFile=}
          ;;
      esac
    done < /etc/systemd/system/rabs-wkr.service
  fi
  if [[ -n $previous_environment ]]; then
    [[ $previous_environment =~ ^/etc/rabs-wkr/deploy\.[A-Za-z0-9]{10}/worker\.env$ ]] ||
      input_error 'existing worker service uses an unmanaged environment file'
    read_runtime_environment "$previous_environment"
    previous=("${READ_RUNTIME_SETTINGS[@]}")
    for ((index=0; index<${#RUNTIME_SETTINGS[@]}; index++)); do
      if [[ -z ${selected[$index]} ]]; then
        selected[$index]=${previous[$index]}
      fi
    done
  fi
  validate_runtime_settings "${selected[@]}"
  (
    set -C
    {
      while IFS= read -r line || [[ -n $line ]]; do
        case "$line" in
          RABS_WORKER_TLS_CA=*|RABS_WORKER_TLS_CERT=*|RABS_WORKER_TLS_KEY=*|RABS_WORKER_TLS_SERVER_NAME=*)
            printf '%s\n' "$line"
            ;;
        esac
      done < "$stage/worker.env"
      for assignment in "${selected[@]}"; do
        [[ -n $assignment ]] || continue
        name=${assignment%%=*}
        value=${assignment#*=}
        case "$name" in
          RABS_SOURCE_CACHE_DIR|RABS_WORKER_TOOLCHAIN_CACHE_DIR|RABS_WORKER_HOST_BUDGET_DIR|RABS_WORKER_HOST_SLOTS)
            [[ -n $value ]] || continue
            ;;
        esac
        environment_setting "$name" "$value"
      done
    } > "$stage/worker.env.complete"
  )
  chmod 0600 "$stage/worker.env.complete"
  mv -f "$stage/worker.env.complete" "$stage/worker.env"
  mv -f "$remote_bin_stage" "$remote_bin"
  install -m 0644 -o root -g root "$stage/rabs-wkr.service" /etc/systemd/system/rabs-wkr.service.new
  mv -f /etc/systemd/system/rabs-wkr.service.new /etc/systemd/system/rabs-wkr.service
  systemctl daemon-reload
  systemctl enable rabs-wkr.service
  systemctl restart rabs-wkr.service
  systemctl is-active --quiet rabs-wkr.service
}

activation_script() {
  printf 'set -euo pipefail\numask 077\n'
  declare -p RUNTIME_SETTINGS
  declare -f input_error runtime_setting_index bounded_decimal runtime_directory validate_runtime_settings \
    environment_setting decode_environment_value read_runtime_environment activate_worker
  printf 'activate_worker "$@"\n'
}
activation_script | ssh "${SSH_OPTS[@]}" "root@$WORKER" \
  "bash -s -- '$STAGE' '$REMOTE_BIN_STAGE' '$REMOTE_BIN'" ||
  failed unit 'service activation failed; inspect the worker before retrying'
emit unit done
printf 'Installed %s on %s and restarted rabs-wkr.service for %s. Coordinator authentication was not checked.\n' \
  "$VER" "$WORKER" "$COORDINATOR" >&2
if [[ ${RABS_WORKER_ID+x} == x ]]; then
  printf 'Coordinator enrollment: RABS_DEPENDENCY_WORKER_ID=%s\n' "$RABS_WORKER_ID" >&2
else
  printf 'Coordinator worker ID: retained from the managed service, otherwise the remote short hostname.\n' >&2
fi
printf 'Coordinator enrollment: RABS_DEPENDENCY_WORKER_SPKI_SHA256=%s\n' "$WORKER_SPKI_SHA256" >&2
