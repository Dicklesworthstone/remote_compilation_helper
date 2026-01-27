#!/usr/bin/env bash
#
# test_dependabot_automerge_workflow.sh - Validate Dependabot automerge workflow
#
# Validates:
# 1. YAML syntax is valid
# 2. Workflow triggers on pull_request
# 3. Actor condition checks for dependabot[bot]
# 4. dependabot/fetch-metadata action is used
# 5. gh pr merge command is well-formed
#
# Usage:
#   ./scripts/test_dependabot_automerge_workflow.sh
#
# Exit codes:
#   0 - All validations passed
#   1 - Validation failed
#   4 - Test skipped (missing dependencies)
#

set -euo pipefail

# Source test library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$SCRIPT_DIR/test_lib.sh" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/test_lib.sh"
    init_test_log "test_dependabot_automerge_workflow"
else
    # Fallback minimal logging
    log_json() { echo "[TEST] [$1] $2"; }
    test_pass() { echo "[TEST] PASS"; exit 0; }
    test_fail() { echo "[TEST] FAIL: $1"; exit 1; }
    test_skip() { echo "[TEST] SKIP: $1"; exit 4; }
fi

WORKFLOW_FILE="$PROJECT_ROOT/.github/workflows/dependabot-automerge.yml"

# Check prerequisites
log_json setup "Checking prerequisites"

if ! command -v python3 &>/dev/null; then
    test_skip "python3 not available"
fi

if ! python3 -c "import yaml" 2>/dev/null; then
    test_skip "PyYAML not installed"
fi

if [[ ! -f "$WORKFLOW_FILE" ]]; then
    test_fail "Workflow file not found: $WORKFLOW_FILE"
fi

log_json setup "Prerequisites met"

# Run validation via Python
log_json execute "Validating workflow structure"

validation_result=$(python3 - "$WORKFLOW_FILE" << 'PYTHON_EOF'
import sys
import yaml
import json

workflow_path = sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/dependabot-automerge.yml"

errors = []
warnings = []

try:
    with open(workflow_path, 'r') as f:
        workflow = yaml.safe_load(f)
except yaml.YAMLError as e:
    print(json.dumps({"valid": False, "errors": [f"YAML parse error: {e}"], "warnings": []}))
    sys.exit(0)
except FileNotFoundError:
    print(json.dumps({"valid": False, "errors": ["Workflow file not found"], "warnings": []}))
    sys.exit(0)

# Check 1: Workflow has 'on' trigger
# Note: YAML 1.1 treats 'on' as boolean True, so we check both
on_key = 'on' if 'on' in workflow else (True if True in workflow else None)
if on_key is None:
    errors.append("Missing 'on' trigger section")
else:
    triggers = workflow[on_key]
    # Normalize to list of trigger types
    if isinstance(triggers, str):
        trigger_types = [triggers]
    elif isinstance(triggers, list):
        trigger_types = triggers
    elif isinstance(triggers, dict):
        trigger_types = list(triggers.keys())
    else:
        trigger_types = []

    # Dependabot workflows should use pull_request or pull_request_target
    if 'pull_request' not in trigger_types and 'pull_request_target' not in trigger_types:
        errors.append("Workflow should trigger on 'pull_request' or 'pull_request_target'")

    # Security note: pull_request_target is recommended for Dependabot
    if 'pull_request' in trigger_types and 'pull_request_target' not in trigger_types:
        warnings.append("Consider using 'pull_request_target' for better security with Dependabot PRs")

# Check 2: Permissions block exists
if 'permissions' not in workflow:
    errors.append("Missing 'permissions' block (explicit permissions recommended)")
else:
    perms = workflow['permissions']
    if 'contents' not in perms or perms['contents'] != 'write':
        warnings.append("'contents: write' permission recommended for auto-merge")
    if 'pull-requests' not in perms or perms['pull-requests'] != 'write':
        errors.append("'pull-requests: write' permission required for auto-merge")

# Check 3: Jobs section exists
if 'jobs' not in workflow or not workflow['jobs']:
    errors.append("No jobs defined in workflow")
else:
    jobs = workflow['jobs']

    # Find the automerge job
    automerge_job = None
    for job_name, job_config in jobs.items():
        if 'automerge' in job_name.lower() or 'dependabot' in job_name.lower():
            automerge_job = job_config
            break

    if not automerge_job:
        automerge_job = list(jobs.values())[0]  # Use first job

    # Check 4: Job has actor condition for dependabot[bot]
    job_if = automerge_job.get('if', '')
    if "github.actor == 'dependabot[bot]'" not in job_if and "github.actor == \"dependabot[bot]\"" not in job_if:
        errors.append("Job should have condition: if: github.actor == 'dependabot[bot]'")

    # Check 5: Steps exist
    steps = automerge_job.get('steps', [])
    if not steps:
        errors.append("No steps defined in automerge job")
    else:
        # Check for dependabot/fetch-metadata action
        has_fetch_metadata = False
        has_merge_command = False

        for step in steps:
            uses = step.get('uses', '')
            run = step.get('run', '')

            if 'dependabot/fetch-metadata' in uses:
                has_fetch_metadata = True
                # Check for github-token
                step_with = step.get('with', {})
                if 'github-token' not in step_with:
                    warnings.append("dependabot/fetch-metadata should have github-token input")

            if 'gh pr merge' in run:
                has_merge_command = True
                # Validate merge command format
                if '--auto' not in run:
                    warnings.append("gh pr merge should use --auto flag for CI-triggered merges")
                if '--squash' not in run and '--merge' not in run and '--rebase' not in run:
                    warnings.append("gh pr merge should specify merge strategy (--squash, --merge, or --rebase)")

        if not has_fetch_metadata:
            errors.append("Missing 'dependabot/fetch-metadata' action step")

        if not has_merge_command:
            errors.append("Missing 'gh pr merge' command in steps")

result = {
    "valid": len(errors) == 0,
    "errors": errors,
    "warnings": warnings,
    "checks_passed": 5 - len(errors)
}

print(json.dumps(result))
PYTHON_EOF
)

# Parse result
log_json verify "Parsing validation results"

valid=$(echo "$validation_result" | jq -r '.valid')
errors=$(echo "$validation_result" | jq -r '.errors | length')
warnings=$(echo "$validation_result" | jq -r '.warnings | length')

# Log errors if any
if [[ "$errors" -gt 0 ]]; then
    log_json verify "Validation errors found" "$validation_result"
    error_list=$(echo "$validation_result" | jq -r '.errors[]')
    test_fail "Workflow validation failed: $error_list"
fi

# Log warnings if any
if [[ "$warnings" -gt 0 ]]; then
    warning_list=$(echo "$validation_result" | jq -r '.warnings | join("; ")')
    log_json verify "Warnings (non-blocking): $warning_list"
fi

log_json verify "All validations passed" "$validation_result"
test_pass
