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
#   rabs_fleet_deploy.sh <worker-ssh-host> <coordinator-host:port> \
#       [path-to-release-rabs-wkr]
#
# Idempotent: re-running replaces the binary + unit and restarts.
set -euo pipefail

WORKER=$1
COORDINATOR=$2
LOCAL_BIN=${3:-target/release/rabs-wkr}
REMOTE_BIN=/usr/local/bin/rabs-wkr
SSH_OPTS="-o ConnectTimeout=20 -o BatchMode=yes"

emit() { printf '{"kind":"fleet-deploy","worker":"%s","step":"%s","status":"%s"}\n' "$WORKER" "$1" "$2"; }

[ -x "$LOCAL_BIN" ] || { emit build refused; echo "no release binary at $LOCAL_BIN (cargo build --release -p rabs-wkr)" >&2; exit 2; }

# CAPABILITY GATE: probe bwrap + userns on the worker BEFORE any copy.
emit capability-probe start
CAP=$(ssh $SSH_OPTS "root@$WORKER" '
  command -v bwrap >/dev/null 2>&1 || { echo "no-bwrap"; exit 0; }
  # A real userns smoke test, not just a which(): bwrap must actually run.
  if bwrap --unshare-user --uid 0 --ro-bind / / true >/dev/null 2>&1; then
    echo "canonical-ok"
  else
    echo "bwrap-present-but-userns-fails"
  fi
' 2>/dev/null || echo "unreachable")

if [ "$CAP" != "canonical-ok" ]; then
  emit capability-probe "refused:$CAP"
  echo "REFUSED: $WORKER cannot run the canonical namespace ($CAP) — rabs-wkr installs only on bwrap-capable hosts" >&2
  exit 1
fi
emit capability-probe canonical-ok

# Copy the binary (atomic: temp + mv on the worker).
emit copy start
scp $SSH_OPTS -q "$LOCAL_BIN" "root@$WORKER:${REMOTE_BIN}.new"
ssh $SSH_OPTS "root@$WORKER" "chmod 0755 ${REMOTE_BIN}.new && mv -f ${REMOTE_BIN}.new ${REMOTE_BIN}"
emit copy done

# Install + (re)start the systemd unit.
emit unit start
ssh $SSH_OPTS "root@$WORKER" "cat > /etc/systemd/system/rabs-wkr.service" <<UNIT
[Unit]
Description=RABS trusted worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${REMOTE_BIN} --coordinator ${COORDINATOR}
Restart=on-failure
RestartSec=5
# The worker offers results, never commits (R50); no privileged mode.
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
ssh $SSH_OPTS "root@$WORKER" 'systemctl daemon-reload && systemctl enable --now rabs-wkr.service' 2>/dev/null || {
  emit unit "warn:systemctl-unavailable"
  echo "NOTE: $WORKER has no systemd; binary installed at $REMOTE_BIN — start it manually" >&2
}
emit unit done

# Verify the binary answers --version on the worker.
emit verify start
VER=$(ssh $SSH_OPTS "root@$WORKER" "$REMOTE_BIN --version" 2>/dev/null || echo "no-version")
emit verify "$VER"
echo "deployed rabs-wkr ($VER) to $WORKER -> coordinator $COORDINATOR" >&2
