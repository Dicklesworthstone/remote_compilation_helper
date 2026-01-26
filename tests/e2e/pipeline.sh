#!/usr/bin/env bash
# E2E_NAME=pipeline
# E2E_SERIAL=1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

exec "$PROJECT_ROOT/scripts/e2e_pipeline.sh" "$@"
