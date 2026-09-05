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

# ---------------------------------------------------------------------
# SUDO-01  Ensure sudo commands use pty
# CIS ID:    <look up in your benchmark PDF>
# Rationale: use_pty forces every sudo command to run in a pseudo-terminal,
#            which prevents a user from backgrounding a sudo session and
#            slipping malicious input to it later, and improves session
#            logging fidelity.
# Impact:    Negligible — nearly transparent to normal interactive use.
#            Can occasionally affect non-interactive automation that pipes
#            input into sudo in unusual ways.
# ---------------------------------------------------------------------
check_sudo_use_pty() {
    local id="SUDO-01" title="sudo use_pty enabled"

    # Check /etc/sudoers and every file under /etc/sudoers.d/ — the setting
    # can legitimately live in either place.
    if grep -Eq '^\s*Defaults\s+use_pty\s*$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "'Defaults use_pty' not found in /etc/sudoers or /etc/sudoers.d/"
    fi
}

# ---------------------------------------------------------------------
# PW-01  Ensure password expiration is 365 days or less
# CIS ID:    <look up in your benchmark PDF>
# Rationale: Forces periodic password rotation, limiting how long a leaked
#            or guessed credential stays valid.
# Impact:    Users will be prompted to change passwords periodically.
#            Some teams argue this control is outdated (NIST 800-63B has
#            moved away from mandatory rotation) — worth knowing as a
#            talking point even though CIS still includes it.
# ---------------------------------------------------------------------
check_pw_max_days() {
    local id="PW-01" title="Password max age <= 365 days"
    local value

    value=$(awk '$1=="PASS_MAX_DAYS" {print $2}' /etc/login.defs 2>/dev/null)

    if [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -le 365 ]]; then
        report "$id" PASS "$title"
    else
        report "$id" FAIL "$title" "PASS_MAX_DAYS is '${value:-unset}', expected <= 365"
    fi
}

# ---------------------------------------------------------------------
# PAM-01  Ensure account lockout (faillock) is configured
# CIS ID:    <look up in your benchmark PDF>
# Rationale: Without a lockout policy, an attacker can attempt unlimited
#            password guesses against a local or SSH-exposed account.
# Impact:    Legitimate users who mistype their password too many times
#            will be locked out until the fail_interval expires. This is
#            THE control most likely to lock you out while testing —
#            audit-only here, remediation happens later with a safety net.
# Distro:    Rocky 9 manages the PAM stack via authselect — hand-editing
#            /etc/pam.d/system-auth directly gets silently overwritten.
#            Ubuntu edits /etc/pam.d/common-auth directly instead.
# ---------------------------------------------------------------------
check_pam_faillock() {
    local id="PAM-01" title="Account lockout (faillock) configured"

    if [[ ! -f /etc/security/faillock.conf ]]; then
        report "$id" FAIL "$title" "/etc/security/faillock.conf not found"
        return
    fi

    local deny_value
    deny_value=$(awk -F= '$1=="deny" {gsub(/ /,"",$2); print $2}' /etc/security/faillock.conf)

    if [[ -z "$deny_value" ]] || [[ "$deny_value" -eq 0 ]]; then
        report "$id" FAIL "$title" "deny is '${deny_value:-unset}' in faillock.conf (0 or unset = disabled)"
        return
    fi

    # Confirm the module is actually wired into the PAM stack, not just configured
    # in faillock.conf with nothing referencing it.
    if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        if grep -rq "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
            report "$id" PASS "$title"
        else
            report "$id" FAIL "$title" "deny=$deny_value set, but pam_faillock.so not active in PAM stack"
        fi
    else
        if grep -rq "pam_faillock.so" /etc/pam.d/common-auth 2>/dev/null; then
            report "$id" PASS "$title"
        else
            report "$id" FAIL "$title" "deny=$deny_value set, but pam_faillock.so not active in PAM stack"
        fi
    fi
}

# ---------------------------------------------------------------------
# PERM-01  Ensure /etc/shadow permissions are configured correctly
# CIS ID:    <look up in your benchmark PDF>
# Rationale: /etc/shadow holds password hashes. Wrong permissions let
#            unprivileged users read hashes and crack them offline.
# Impact:    None if already compliant. If not, tightening permissions
#            can occasionally break older tools that assume group-read
#            access — rare in practice.
# Distro:    THE key divergence example. Rocky expects 0000 root:root.
#            Ubuntu expects 0640 root:shadow, because Debian-family uses
#            a dedicated 'shadow' group so utilities like chage can read
#            it without full root.
# ---------------------------------------------------------------------
check_shadow_perms() {
    local id="PERM-01" title="/etc/shadow permissions correct"
    local perms owner group

    read -r perms owner group < <(stat -Lc '%a %U %G' /etc/shadow)
    # stat does not zero-pad octal mode (prints '0' not '000'), so pad before comparing.
    printf -v perms '%03d' "$perms"

    if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        if [[ "$perms" == "000" ]] && [[ "$owner" == "root" ]] && [[ "$group" == "root" ]]; then
            report "$id" PASS "$title"
        else
            report "$id" FAIL "$title" "Found ${perms} ${owner}:${group}, expected 000 root:root"
        fi
    elif [[ "$DISTRO_FAMILY" == "debian" ]]; then
        if [[ "$perms" == "640" ]] && [[ "$owner" == "root" ]] && [[ "$group" == "shadow" ]]; then
            report "$id" PASS "$title"
        else
            report "$id" FAIL "$title" "Found ${perms} ${owner}:${group}, expected 640 root:shadow"
        fi
    else
        report "$id" SKIP "$title" "unknown distro family"
    fi
}
