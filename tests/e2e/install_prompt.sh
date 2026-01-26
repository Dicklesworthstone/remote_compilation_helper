#!/usr/bin/env bash
# E2E_NAME=install_prompt
# E2E_SERIAL=1

set -euo pipefail

if [[ "${E2E_RUN_INSTALL:-0}" != "1" ]]; then
    echo "Install prompt E2E skipped (set E2E_RUN_INSTALL=1 to enable)" >&2
    exit 4
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

exec "$PROJECT_ROOT/scripts/e2e_install_test.sh" "$@"
