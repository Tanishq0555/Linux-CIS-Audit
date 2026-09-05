#!/usr/bin/env bash
# CIS Benchmark audit — read-only. Makes no changes to the system.
set -uo pipefail   # deliberately NOT -e: one failing check must not abort the run

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/distro.sh"
source "$SCRIPT_DIR/lib/controls.sh"

require_root
detect_distro

echo "CIS audit — ${DISTRO_ID} ${DISTRO_VERSION} (family: ${DISTRO_FAMILY})"
echo

# Every function named check_* is discovered and run automatically,
# so adding a control means adding one function and nothing else.
for fn in $(declare -F | awk '{print $3}' | grep '^check_' | sort); do
    "$fn"
done

summary
[[ $FAIL_COUNT -gt 0 ]] && exit 1
exit 0
