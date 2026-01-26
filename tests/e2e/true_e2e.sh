#!/usr/bin/env bash
# E2E_NAME=true_e2e
# E2E_SERIAL=1
# E2E_ARGS=--ci

set -euo pipefail

if [[ "${E2E_RUN_TRUE_E2E:-0}" != "1" ]]; then
    echo "True E2E skipped (set E2E_RUN_TRUE_E2E=1 to enable)" >&2
    exit 4
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

exec "$PROJECT_ROOT/scripts/run_true_e2e.sh" "$@"
