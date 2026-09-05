#!/usr/bin/env bash
# CIS control checks. Each check_* function is auto-discovered by audit.sh.

# ---------------------------------------------------------------------
# SSH-01  Ensure root login over SSH is disabled
# CIS ID:    <look up in your benchmark PDF>
# Rationale: Direct root SSH destroys per-user accountability — you cannot
#            tell which admin did what. It also hands brute-force attackers
#            a username that is guaranteed to exist.
# Impact:    Admins must log in as a normal user and escalate with sudo.
#            Any automation using root SSH will break.
# ---------------------------------------------------------------------
check_ssh_root_login() {
    local id="SSH-01" title="SSH root login disabled"
    local value

    if ! command -v sshd >/dev/null 2>&1; then
        report "$id" SKIP "$title" "sshd not installed"
        return
    fi

    # sshd -T prints the EFFECTIVE config, resolving Include'd drop-in files.
    # Plain grep on sshd_config misses those and gives wrong answers.
    value=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin" {print $2}')

    if [[ "$value" == "no" ]]; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "PermitRootLogin is '${value:-unset}', expected 'no'"
    fi
}

# ---------------------------------------------------------------------
# FS-01  Ensure /tmp is mounted with noexec
# CIS ID:    <look up in your benchmark PDF>
# Rationale: /tmp is world-writable — any user or process can drop a file
#            there. Without noexec, a dropped file can also be executed,
#            which is a common privilege-escalation and malware pattern.
# Impact:    Some installers and build tools extract to /tmp and expect to
#            run from there. This is the control most likely to break
#            something real — know this when you talk about it.
# ---------------------------------------------------------------------
check_tmp_noexec() {
    local id="FS-01" title="/tmp mounted with noexec"
    local mount_info

    # findmnt -n /tmp prints one line of mount info for /tmp, nothing if
    # /tmp isn't its own separate mount (e.g. it's just part of /).
    mount_info=$(findmnt -n /tmp 2>/dev/null)

    if [[ -z "$mount_info" ]]; then
        report "$id" FAIL "$title" "/tmp is not a separate mount point"
        return
    fi

    if echo "$mount_info" | grep -qw "noexec"; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "/tmp mount options do not include noexec"
    fi
}

# ---------------------------------------------------------------------
# PKG-01  Ensure GPG signature checking is enabled for package management
# CIS ID:    <look up in your benchmark PDF>
# Rationale: Without gpgcheck, dnf/yum will install packages regardless of
#            whether they're signed by a trusted key. A compromised mirror
#            or repo could serve tampered packages silently.
# Impact:    None expected — gpgcheck=1 is the default on Rocky and should
#            already be set almost everywhere.
# Distro:    RHEL-family only. APT (Debian-family) verifies repo signatures
#            through a different mechanism entirely, so this control is
#            SKIPPED there rather than faked.
# ---------------------------------------------------------------------
check_pkg_gpgcheck() {
    local id="PKG-01" title="Package GPG checking enabled"

    if [[ "$DISTRO_FAMILY" != "rhel" ]]; then
        report "$id" SKIP "$title" "not applicable on $DISTRO_FAMILY family"
        return
    fi

    local bad_files=()

    # Check the main dnf.conf
    if ! grep -Eq '^\s*gpgcheck\s*=\s*1\s*$' /etc/dnf/dnf.conf 2>/dev/null; then
        bad_files+=("/etc/dnf/dnf.conf")
    fi

    # Check every repo file individually — a repo can override the global setting
    local repo_file
    for repo_file in /etc/yum.repos.d/*.repo; do
        [[ -e "$repo_file" ]] || continue   # glob didn't match anything
        if ! grep -Eq '^\s*gpgcheck\s*=\s*1\s*$' "$repo_file"; then
            bad_files+=("$repo_file")
        fi
    done

    if [[ ${#bad_files[@]} -eq 0 ]]; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "gpgcheck not enabled in: ${bad_files[*]}"
    fi
}

# ---------------------------------------------------------------------
# SSH-02  Ensure SSH MaxAuthTries is 4 or less
# CIS ID:    <look up in your benchmark PDF>
# Rationale: Limits how many password/key attempts an attacker gets per
#            connection before sshd disconnects them, slowing brute force.
# Impact:    Legitimate users who fumble a passphrase a few times may need
#            to reconnect. Minor inconvenience, standard hardening step.
# ---------------------------------------------------------------------
check_ssh_maxauthtries() {
    local id="SSH-02" title="SSH MaxAuthTries <= 4"
    local value

    if ! command -v sshd >/dev/null 2>&1; then
        report "$id" SKIP "$title" "sshd not installed"
        return
    fi

    value=$(sshd -T 2>/dev/null | awk '$1=="maxauthtries" {print $2}')

    # Numeric comparison — need to guard against empty/non-numeric value
    # before doing arithmetic, or bash will throw an error instead of failing cleanly.
    if [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -le 4 ]]; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "MaxAuthTries is '${value:-unset}', expected <= 4"
    fi
}
