#!/usr/bin/env bash
# S7 (bead bd-n8qt3): capability-gated fleet provisioning of rabs-wkr.
#
# Deploys the release rabs-wkr binary to a worker over SSH — but ONLY
# after PROVING the host can run the canonical namespace. A non-bwrap
# host is a TYPED REFUSAL, not a silent skip and never a partial
# install: rabs-wkr itself refuses non-canonical hosts (S5), so shipping
# it there would only produce runtime refusals.
#
# Usage:
#   RABS_WORKER_TLS_CA=/local/ca.pem \
#   RABS_WORKER_TLS_CERT=/local/worker.pem \
#   RABS_WORKER_TLS_KEY=/local/worker.key \
#   RABS_WORKER_TLS_SERVER_NAME=coordinator.example.internal \
#   rabs_fleet_deploy.sh <worker-ssh-host> <coordinator-host:port> \
#       [path-to-release-rabs-wkr]
#
# TLS paths above are LOCAL files. All four settings are required, including
# for loopback. The CA authenticates the coordinator; the worker certificate
# may be issued by a different CA. This script never creates or learns trust.
# Credential generations are private and retained across deployment attempts;
# activation never changes the durable worker identity or journal directory.
# Re-running replaces the binary + unit and explicitly restarts the service.
# A successful deployment verifies service startup, not coordinator admission.
set +x # Do not expose private PEM bytes if invoked with bash -x.
set +a
set -euo pipefail

usage() {
  echo 'Usage: rabs_fleet_deploy.sh <worker-ssh-host> <coordinator-host:port> [local-rabs-wkr]' >&2
  echo 'Required: RABS_WORKER_TLS_CA/CERT/KEY (local PEM files), RABS_WORKER_TLS_SERVER_NAME' >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
WORKER=$1
COORDINATOR=$2
LOCAL_BIN=${3:-target/release/rabs-wkr}
REMOTE_BIN=/usr/local/bin/rabs-wkr
SSH_OPTS=(-o ConnectTimeout=20 -o BatchMode=yes)

input_error() { printf 'rabs_fleet_deploy: %s\n' "$1" >&2; exit 2; }

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

emit() { printf '{"kind":"fleet-deploy","worker":"%s","step":"%s","status":"%s"}\n' "$WORKER" "$1" "$2"; }
failed() { emit "$1" failed; printf 'rabs_fleet_deploy: %s\n' "$2" >&2; exit 1; }

# CAPABILITY GATE: probe bwrap + userns on the worker BEFORE any copy.
emit capability-probe start
CAP=$(ssh "${SSH_OPTS[@]}" "root@$WORKER" '
  command -v bwrap >/dev/null 2>&1 || { echo "no-bwrap"; exit 0; }
  # A real userns smoke test, not just a which(): bwrap must actually run.
  bwrap --unshare-user --uid 0 --ro-bind / / true >/dev/null 2>&1 ||
    { echo "bwrap-present-but-userns-fails"; exit 0; }
  for tool in systemctl flock install mktemp cat chmod mv; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing-deployment-tool"; exit 0; }
  done
  systemctl show-environment >/dev/null 2>&1 || { echo "systemd-unavailable"; exit 0; }
  echo "canonical-ok"
') || failed capability-probe 'worker is unreachable'

if [ "$CAP" != "canonical-ok" ]; then
  case "$CAP" in
    no-bwrap|bwrap-present-but-userns-fails|missing-deployment-tool|systemd-unavailable)
      emit capability-probe "refused:$CAP"
      printf 'REFUSED: %s (%s); no files copied\n' "$WORKER" "$CAP" >&2
      exit 1
      ;;
    *) failed capability-probe 'unrecognized worker capability response; no files copied' ;;
  esac
fi
emit capability-probe canonical-ok

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
ssh "${SSH_OPTS[@]}" "root@$WORKER" \
  "set -eu; umask 077; set -C; cat > '$STAGE/worker.env'; chmod 0600 '$STAGE/worker.env'" <<ENV ||
  failed tls 'worker TLS environment transfer failed'
RABS_WORKER_TLS_CA=$STAGE/ca.pem
RABS_WORKER_TLS_CERT=$STAGE/worker.pem
RABS_WORKER_TLS_KEY=$STAGE/worker.key
RABS_WORKER_TLS_SERVER_NAME=$TLS_SERVER_NAME
ENV
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

# Serialize activation across concurrent deployments. Each unit names exactly
# its own complete credentials. Retain all worker journals and prior credentials.
ssh "${SSH_OPTS[@]}" "root@$WORKER" "
  set -eu
  exec 9>/etc/rabs-wkr/deploy.lock
  flock -x 9
  mv -f '$REMOTE_BIN_STAGE' '$REMOTE_BIN'
  install -m 0644 -o root -g root '$STAGE/rabs-wkr.service' /etc/systemd/system/rabs-wkr.service.new
  mv -f /etc/systemd/system/rabs-wkr.service.new /etc/systemd/system/rabs-wkr.service
  systemctl daemon-reload
  systemctl enable rabs-wkr.service
  systemctl restart rabs-wkr.service
  systemctl is-active --quiet rabs-wkr.service
" || failed unit 'service activation failed; inspect the worker before retrying'
emit unit done
printf 'Installed %s on %s and restarted rabs-wkr.service for %s. Coordinator authentication was not checked.\n' \
  "$VER" "$WORKER" "$COORDINATOR" >&2
