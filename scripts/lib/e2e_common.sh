#!/usr/bin/env bash
#
# Shared helpers for RCH E2E shell scripts.
# Intentionally does not set shell options; callers control strictness.
#

E2E_SKIP_EXIT=4

e2e_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'
}

e2e_now_ms() {
    if date +%s%3N >/dev/null 2>&1; then
        date +%s%3N
        return
    fi
    local seconds
    seconds="$(date +%s)"
    printf '%s000' "$seconds"
}

e2e_log() {
    printf '[E2E] %s\n' "$*"
}

e2e_default_parallelism() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return
    fi
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu
        return
    fi
    echo 4
}

e2e_slug() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/_/g'
}

e2e_xml_escape() {
    local value="$1"
    value="${value//&/&amp;}"
    value="${value//</&lt;}"
    value="${value//>/&gt;}"
    value="${value//\"/&quot;}"
    value="${value//\'/&apos;}"
    printf '%s' "$value"
}
