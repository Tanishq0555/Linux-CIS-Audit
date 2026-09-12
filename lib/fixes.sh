#!/usr/bin/env bash
# CIS remediation functions. Each fix_* function is auto-discovered by remediate.sh.
# shellcheck disable=SC2317  # fix_* functions are invoked indirectly by name via declare -F in remediate.sh

# ---------------------------------------------------------------------
# PKG-01  Ensure GPG signature checking is enabled for package management
# ---------------------------------------------------------------------
fix_pkg_gpgcheck() {
    local id="PKG-01"

    if [[ "$DISTRO_FAMILY" != "rhel" ]]; then
        printf '[SKIP]    %s: not applicable on %s family\n' "$id" "$DISTRO_FAMILY"
        return
    fi

    if grep -Eq '^\s*gpgcheck\s*=\s*1\s*$' /etc/dnf/dnf.conf 2>/dev/null; then
        printf '[SKIP]    %s: already compliant (gpgcheck=1 in dnf.conf)\n' "$id"
    else
        backup_file /etc/dnf/dnf.conf
        run "$id: set gpgcheck=1 in dnf.conf" \
            sed -i 's/^\s*gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf
    fi

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

    if [[ $DRY_RUN -eq 0 ]]; then
        printf '[APPLY]   %s: fstab updated. Run "sudo mount /tmp" or reboot to activate — not done automatically.\n' "$id"
    fi
}

# ---------------------------------------------------------------------
# SUDO-01  Ensure sudo commands use pty
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
}

# ---------------------------------------------------------------------
# AUD-02  Ensure audit rule exists for changes to sudoers
# ---------------------------------------------------------------------
fix_audit_sudoers_rule() {
    local id="AUD-02"
    local rule_file="/etc/audit/rules.d/50-sudoers.rules"

    if ! command -v auditctl >/dev/null 2>&1; then
        printf '[SKIP]    %s: auditd not installed\n' "$id"
        return
    fi

    if grep -rq "/etc/sudoers" /etc/audit/rules.d/ 2>/dev/null; then
        printf '[SKIP]    %s: already compliant\n' "$id"
        return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[DRY-RUN] %s: would create %s watching /etc/sudoers and /etc/sudoers.d/\n' "$id" "$rule_file"
        return
    fi

    cat > "$rule_file" <<'RULES'
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
RULES

    printf '[APPLY]   %s: created %s\n' "$id" "$rule_file"

    if augenrules --load >/dev/null 2>&1; then
        printf '[APPLY]   %s: audit rules reloaded successfully\n' "$id"
    else
        printf '[FAIL]    %s: augenrules --load reported an error — check with: augenrules --check\n' "$id" >&2
    fi
}

# ---------------------------------------------------------------------
# PAM-01  Ensure account lockout (faillock) is configured
# Safety: this system does NOT use authselect (system-auth/password-auth
# are plain files, not symlinks). even_deny_root is required -- pam_faillock
# silently EXEMPTS root from lockout by default. Verified this the hard way:
# 5 wrong root passwords produced zero faillock entries until this flag was
# added. Without it, the control looks configured but does not protect the
# account most worth protecting here.
# ---------------------------------------------------------------------
fix_pam_faillock() {
    local id="PAM-01"

    if [[ "$DISTRO_FAMILY" != "rhel" ]]; then
        printf '[SKIP]    %s: this fix currently only implemented for rhel family\n' "$id"
        return
    fi

    local deny_value
    deny_value=$(awk -F= '{gsub(/ /,"",$1); if ($1=="deny") {gsub(/ /,"",$2); print $2}}' /etc/security/faillock.conf 2>/dev/null)

    local wired=0
    if grep -rq "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
        wired=1
    fi

    if [[ -n "$deny_value" ]] && [[ "$deny_value" -ne 0 ]] && [[ $wired -eq 1 ]]; then
        printf '[SKIP]    %s: already compliant\n' "$id"
        return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[DRY-RUN] %s: would set deny=5 in faillock.conf and wire pam_faillock.so into the PAM stack\n' "$id"
        return
    fi

    backup_file /etc/security/faillock.conf
    if grep -Eq '^\s*deny\s*=' /etc/security/faillock.conf 2>/dev/null; then
        sed -i 's/^\s*deny\s*=.*/deny = 5/' /etc/security/faillock.conf
    else
        echo "deny = 5" >> /etc/security/faillock.conf
    fi
    printf '[APPLY]   %s: set deny=5 in faillock.conf\n' "$id"

    if [[ $wired -eq 1 ]]; then
        return
    fi

    if [[ -L /etc/pam.d/system-auth ]]; then
        if authselect enable-feature with-faillock 2>&1; then
            printf '[APPLY]   %s: enabled with-faillock via authselect\n' "$id"
        else
            printf '[FAIL]    %s: authselect enable-feature failed — check: authselect current\n' "$id" >&2
        fi
        return
    fi

    local pf
    for pf in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        backup_file "$pf"
        sed -i \
            -e '/^auth\s\+sufficient\s\+pam_unix\.so/i auth        required      pam_faillock.so preauth silent deny=5 unlock_time=900 even_deny_root' \
            -e '/^auth\s\+sufficient\s\+pam_unix\.so/a auth        [default=die] pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root' \
            "$pf"
        sed -i \
            -e '/^account\s\+required\s\+pam_unix\.so/i account     required      pam_faillock.so' \
            "$pf"
        printf '[APPLY]   %s: wired pam_faillock.so into %s\n' "$id" "$pf"
    done
}

# ---------------------------------------------------------------------
# SSH-01 / SSH-02  Disable root login, limit auth tries
# Safety: sshd -t validates config syntax BEFORE any restart. A bad
# config here means sshd refuses to reload -- your CURRENT session
# stays alive either way, since restarting sshd does not kill existing
# connections, only affects NEW ones. Restart only happens if
# validation passes. Applying this REQUIRES a working non-root sudo
# account already verified -- root SSH access is cut off permanently
# for anyone without one.
# ---------------------------------------------------------------------
fix_ssh_hardening() {
    local id="SSH-01/02"
    local root_value maxauth_value
    root_value=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin" {print $2}')
    maxauth_value=$(sshd -T 2>/dev/null | awk '$1=="maxauthtries" {print $2}')

    local needs_root_fix=0 needs_maxauth_fix=0
    [[ "$root_value" != "no" ]] && needs_root_fix=1
    if ! [[ "$maxauth_value" =~ ^[0-9]+$ ]] || [[ "$maxauth_value" -gt 4 ]]; then
        needs_maxauth_fix=1
    fi

    if [[ $needs_root_fix -eq 0 ]] && [[ $needs_maxauth_fix -eq 0 ]]; then
        printf '[SKIP]    %s: already compliant\n' "$id"
        return
    fi

    # Anaconda (the Rocky/RHEL installer) generates a drop-in that force-sets
    # PermitRootLogin yes, which OVERRIDES the main sshd_config for this
    # directive regardless of what we set there. Confirmed via sshd -T
    # returning yes even after editing sshd_config directly. The file's own
    # comment says "Remove this file to opt-out" -- following that documented
    # convention rather than editing it, after backing it up.
    local anaconda_dropin="/etc/ssh/sshd_config.d/01-permitrootlogin.conf"

    if [[ $DRY_RUN -eq 1 ]]; then
        if [[ -f "$anaconda_dropin" ]] && [[ $needs_root_fix -eq 1 ]]; then
            printf '[DRY-RUN] %s: would remove %s (Anaconda default that overrides PermitRootLogin)\n' "$id" "$anaconda_dropin"
        fi
        printf '[DRY-RUN] %s: would set PermitRootLogin no and MaxAuthTries 4 in sshd_config, validate with sshd -t, then restart sshd\n' "$id"
        return
    fi

    backup_file /etc/ssh/sshd_config

    if [[ -f "$anaconda_dropin" ]] && [[ $needs_root_fix -eq 1 ]]; then
        backup_file "$anaconda_dropin"
        rm -f "$anaconda_dropin"
        printf '[APPLY]   %s: removed %s (Anaconda default that overrides PermitRootLogin no)\n' "$id" "$anaconda_dropin"
    fi

    local tmpfile
    tmpfile=$(mktemp)
    cp /etc/ssh/sshd_config "$tmpfile"

    if [[ $needs_root_fix -eq 1 ]]; then
        if grep -Eq '^\s*#?\s*PermitRootLogin\s+' "$tmpfile"; then
            sed -i 's/^\s*#\?\s*PermitRootLogin\s\+.*/PermitRootLogin no/' "$tmpfile"
        else
            echo "PermitRootLogin no" >> "$tmpfile"
        fi
    fi

    if [[ $needs_maxauth_fix -eq 1 ]]; then
        if grep -Eq '^\s*#?\s*MaxAuthTries\s+' "$tmpfile"; then
            sed -i 's/^\s*#\?\s*MaxAuthTries\s\+.*/MaxAuthTries 4/' "$tmpfile"
        else
            echo "MaxAuthTries 4" >> "$tmpfile"
        fi
    fi

    # Validate the EDITED COPY before touching the real file.
    if sshd -t -f "$tmpfile" 2>/tmp/sshd_validate_err; then
        cp "$tmpfile" /etc/ssh/sshd_config
        rm -f "$tmpfile"
        printf '[APPLY]   %s: sshd_config updated and validated\n' "$id"

        if systemctl reload sshd 2>/dev/null; then
            printf '[APPLY]   %s: sshd reloaded (existing sessions unaffected, new connections use new rules)\n' "$id"
        else
            printf '[FAIL]    %s: sshd reload failed — check: systemctl status sshd\n' "$id" >&2
        fi
    else
        printf '[FAIL]    %s: validation failed, no changes made. Details:\n' "$id" >&2
        cat /tmp/sshd_validate_err >&2
        rm -f "$tmpfile"
    fi
}
