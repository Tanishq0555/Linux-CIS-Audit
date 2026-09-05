#!/usr/bin/env bash
# Shared output helpers and counters.

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Colour only when writing to a terminal, so redirected output stays clean.
if [[ -t 1 ]]; then
    C_PASS=$'\e[32m'; C_FAIL=$'\e[31m'; C_SKIP=$'\e[33m'; C_RESET=$'\e[0m'
else
    C_PASS=''; C_FAIL=''; C_SKIP=''; C_RESET=''
fi

report() {
    # report <id> <PASS|FAIL|SKIP> <title> [detail]
    local id="$1" status="$2" title="$3" detail="${4:-}"
    case "$status" in
        PASS)
            ((PASS_COUNT++))
            printf '%s[PASS]%s %-10s %s\n' "$C_PASS" "$C_RESET" "$id" "$title"
            ;;
        FAIL)
            ((FAIL_COUNT++))
            printf '%s[FAIL]%s %-10s %s\n' "$C_FAIL" "$C_RESET" "$id" "$title"
            [[ -n "$detail" ]] && printf '             %s\n' "$detail"
            ;;
        SKIP)
            ((SKIP_COUNT++))
            printf '%s[SKIP]%s %-10s %s\n' "$C_SKIP" "$C_RESET" "$id" "$title"
            [[ -n "$detail" ]] && printf '             %s\n' "$detail"
            ;;
    esac
}

summary() {
    echo
    echo "----------------------------------------"
    printf 'Passed: %d   Failed: %d   Skipped: %d\n' \
        "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    echo "----------------------------------------"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Must be run as root." >&2
        exit 1
    fi
}
