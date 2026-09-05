#!/usr/bin/env bash
# Identify the running distribution family.

detect_distro() {
    if [[ ! -r /etc/os-release ]]; then
        DISTRO_FAMILY="unknown"; DISTRO_ID="unknown"; DISTRO_VERSION="unknown"
        return
    fi

    # shellcheck disable=SC1091
    . /etc/os-release

    case "$ID" in
        rocky|rhel|centos|almalinux) DISTRO_FAMILY="rhel"    ;;
        ubuntu|debian)               DISTRO_FAMILY="debian"  ;;
        *)                           DISTRO_FAMILY="unknown" ;;
    esac

    DISTRO_ID="$ID"
    DISTRO_VERSION="$VERSION_ID"
    export DISTRO_FAMILY DISTRO_ID DISTRO_VERSION
}
