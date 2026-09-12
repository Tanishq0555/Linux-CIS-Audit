#!/usr/bin/env bash
# CIS remediation functions. Each fix_* function is auto-discovered by remediate.sh.
# shellcheck disable=SC2317  # fix_* functions are invoked indirectly by name via declare -F in remediate.sh

# ---------------------------------------------------------------------
# PKG-01  Ensure GPG signature checking is enabled for package management
# Distro:    RHEL-family only — mirrors the audit check's skip logic.
# ---------------------------------------------------------------------
fix_pkg_gpgcheck() {
    local id="PKG-01"

    if [[ "$DISTRO_FAMILY" != "rhel" ]]; then
        printf '[SKIP]    %s: not applicable on %s family\n' "$id" "$DISTRO_FAMILY"
        return
    fi

    # Rule 4: skip anything the audit already reports as PASS.
    if grep -Eq '^\s*gpgcheck\s*=\s*1\s*$' /etc/dnf/dnf.conf 2>/dev/null; then
        printf '[SKIP]    %s: already compliant (gpgcheck=1 in dnf.conf)\n' "$id"
    else
        backup_file /etc/dnf/dnf.conf
        run "$id: set gpgcheck=1 in dnf.conf" \
            sed -i 's/^\s*gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf
    fi

    # Repo files are handled separately since there can be several,
    # each independently non-compliant or already fine.
    local repo_file
    for repo_file in /etc/yum.repos.d/*.repo; do
        [[ -e "$repo_file" ]] || continue
        if grep -Eq '^\s*gpgcheck\s*=\s*1\s*$' "$repo_file"; then
            printf '[SKIP]    %s: %s already compliant\n' "$id" "$repo_file"
        else
            backup_file "$repo_file"
            run "$id: set gpgcheck=1 in $repo_file" \
                sed -i 's/^\s*gpgcheck\s*=.*/gpgcheck=1/' "$repo_file"
        fi
    done
}

# ---------------------------------------------------------------------
# FS-01  Ensure /tmp is mounted with noexec
# Rationale for approach: rather than repartitioning, we use a tmpfs
# mount for /tmp — the standard, low-risk way to add noexec without
# touching disk layout. Idempotent: checks fstab before appending so
# running this twice does not duplicate the line.
# ---------------------------------------------------------------------
fix_tmp_noexec() {
    local id="FS-01"
    local mount_info
    mount_info=$(findmnt -n /tmp 2>/dev/null)

    if echo "$mount_info" | grep -qw "noexec"; then
        printf '[SKIP]    %s: already compliant\n' "$id"
        return
    fi

    if grep -q '^tmpfs\s\+/tmp\s' /etc/fstab 2>/dev/null; then
        printf '[SKIP]    %s: /tmp entry already present in fstab (will take effect on remount/reboot)\n' "$id"
    else
        backup_file /etc/fstab
        run "$id: add tmpfs /tmp entry with noexec to fstab" \
            bash -c 'echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab'
    fi

    # Remounting live is deliberately NOT automatic — it can disrupt anything
    # currently running out of /tmp. Applying this requires the config change
    # to be in place, then a manual "mount /tmp" or a reboot, on your own terms.
    if [[ $DRY_RUN -eq 0 ]]; then
        printf '[APPLY]   %s: fstab updated. Run "sudo mount /tmp" or reboot to activate — not done automatically.\n' "$id"
    fi
}

# ---------------------------------------------------------------------
# SUDO-01  Ensure sudo commands use pty
# Safety: NEVER write directly to /etc/sudoers. A malformed sudoers file
# breaks privilege escalation for everyone. Instead, write to a drop-in
# file under /etc/sudoers.d/ and validate it with visudo -c BEFORE it's
# considered live. If validation fails, the bad file is removed.
# ---------------------------------------------------------------------
fix_sudo_use_pty() {
    local id="SUDO-01"
    local dropin="/etc/sudoers.d/99-cis-use-pty"

    if grep -Eq '^\s*Defaults\s+use_pty\s*$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        printf '[SKIP]    %s: already compliant\n' "$id"
        return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[DRY-RUN] %s: would create %s with "Defaults use_pty" and validate via visudo -c\n' "$id" "$dropin"
        return
    fi

    # Write to a temp file first, validate THAT, only move into place if valid.
    local tmpfile
    tmpfile=$(mktemp)
    echo "Defaults use_pty" > "$tmpfile"
    chmod 0440 "$tmpfile"

    if visudo -c -f "$tmpfile" >/dev/null 2>&1; then
        mv "$tmpfile" "$dropin"
        chmod 0440 "$dropin"
        printf '[APPLY]   %s: created %s (validated with visudo -c)\n' "$id" "$dropin"
    else
        rm -f "$tmpfile"
        printf '[FAIL]    %s: validation failed, no changes made\n' "$id" >&2
    fi
}

# ---------------------------------------------------------------------
# PW-01  Ensure password max age is 365 days or less
# ---------------------------------------------------------------------
fix_pw_max_days() {
    local id="PW-01"
    local value
    value=$(awk '$1=="PASS_MAX_DAYS" {print $2}' /etc/login.defs 2>/dev/null)

    if [[ "$value" =~ ^[0-9]+$ ]] && [[ "$value" -le 365 ]]; then
        printf '[SKIP]    %s: already compliant (PASS_MAX_DAYS=%s)\n' "$id" "$value"
        return
    fi

    backup_file /etc/login.defs

    if grep -Eq '^\s*PASS_MAX_DAYS\s+' /etc/login.defs; then
        run "$id: set PASS_MAX_DAYS to 365 in login.defs" \
            sed -i 's/^\s*PASS_MAX_DAYS\s\+.*/PASS_MAX_DAYS   365/' /etc/login.defs
    else
        run "$id: append PASS_MAX_DAYS 365 to login.defs" \
            bash -c 'echo "PASS_MAX_DAYS   365" >> /etc/login.defs'
    fi

    # Note: this only affects NEW passwords/accounts going forward.
    # Existing users keep their current expiry unless chage is run per-user —
    # intentionally out of scope here, since bulk-changing existing user
    # expiry dates is a bigger decision than a benchmark default warrants.
}
