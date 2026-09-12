#!/usr/bin/env bash
# CIS Benchmark remediation — mirrors audit.sh, but with fix_* functions.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/distro.sh"
source "$SCRIPT_DIR/lib/fixes.sh"

DRY_RUN=1   # safe by default — must opt in to making changes

usage() {
    cat <<'USAGE'
Usage: remediate.sh [--apply] [--dry-run]

  --dry-run   Show what would change without changing it (default)
  --apply     Actually apply remediation
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)   DRY_RUN=0 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

run() {
    # run <description> <command...>
    local desc="$1"; shift
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[DRY-RUN] %s\n           $ %s\n' "$desc" "$*"
    else
        printf '[APPLY]   %s\n' "$desc"
        "$@"
    fi
}

backup_file() {
    # backup_file <path> — copies a file before it gets modified, timestamped
    local path="$1"
    if [[ -f "$path" ]]; then
        local backup
        backup="${path}.bak.$(date +%F-%H%M%S)"
        if [[ $DRY_RUN -eq 1 ]]; then
            printf '[DRY-RUN] would back up %s to %s\n' "$path" "$backup"
        else
            cp -p "$path" "$backup"
            printf '[APPLY]   backed up %s to %s\n' "$path" "$backup"
        fi
    fi
}

require_root
detect_distro

echo "CIS remediation — ${DISTRO_ID} ${DISTRO_VERSION} (family: ${DISTRO_FAMILY})"
[[ $DRY_RUN -eq 1 ]] && echo "Mode: DRY RUN (no changes will be made)" || echo "Mode: APPLY (changes WILL be made)"
echo

for fn in $(declare -F | awk '{print $3}' | grep '^fix_' | sort); do
    "$fn"
done
