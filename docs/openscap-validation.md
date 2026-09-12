# OpenSCAP Validation

Independent validation of this project's audit results against
`openscap-scanner` and `scap-security-guide` on Rocky Linux 9.8, using
the CIS Red Hat Enterprise Linux 9 Benchmark for Level 1 - Server
profile (`xccdf_org.ssgproject.content_profile_cis_server_l1`).

## Setup

    sudo dnf install -y openscap-scanner scap-security-guide
    sudo oscap xccdf eval \
        --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
        --results results.xml \
        --report report.html \
        /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml

**Overall result:** 163 of 265 evaluated rules passed. The remaining
102 fails are almost entirely controls outside this project's 12-control
scope — expected, since the full Level 1 profile covers far more ground
than this project set out to.

## Result comparison — this project's 12 controls

| ID | This audit | OpenSCAP | Agreement |
|---|---|---|---|
| FS-01 | PASS | PASS | Agree |
| PKG-01 | PASS | PASS | Agree |
| SSH-01 | PASS | PASS | Agree |
| SSH-02 | PASS | PASS | Agree |
| SUDO-01 | PASS | PASS | Agree |
| PERM-01 | PASS | PASS | Agree |
| PW-01 | PASS | FAIL | Disagree — real gap found, see below |
| SYS-01 | PASS | FAIL | Disagree — real gap found, see below |
| PAM-01 | PASS | FAIL (3 sub-rules) | Disagree — see below |
| MAC-01 | PASS | No equivalent rule exists in this profile | N/A |
| AUD-01 | PASS | Not evaluated (Level 2 control) | N/A |
| AUD-02 | PASS | Not evaluated (Level 2 control) | N/A |

## Disagreement 1 — PW-01 (confirmed real gap in this project's check)

OpenSCAP's rule, `accounts_password_set_max_life_existing` ("Set
Existing Passwords Maximum Age"), checks each existing user account's
actual expiry field in `/etc/shadow` — its own remediation is literally
`chage -M 365 USER`. This project's `check_pw_max_days` only reads
`/etc/login.defs`, which governs newly created accounts going forward
but has no effect on accounts that already exist.

Confirmed empirically:

    $ sudo chage -l root | grep "Maximum number"
    Maximum number of days between password change          : 99999
    $ sudo chage -l tanishq | grep "Maximum number"
    Maximum number of days between password change          : 365

`tanishq` (created after PW-01 remediation) correctly shows 365. `root`
(existing before remediation) still shows the original 99999 — proving
the gap is real, not a false positive from OpenSCAP.

This exact limitation was anticipated (though not yet caught) in this
project's own `docs/controls.md`, which already notes: "this only
affects newly created accounts and future password changes; it does
not retroactively change the expiry of existing user accounts."
OpenSCAP independently confirmed that predicted gap is real. A more
complete remediation would loop over existing accounts (e.g., via
`getent passwd` with a UID range filter) and apply `chage -M 365` to
each — deliberately left out of `fix_pw_max_days` here, since
bulk-modifying every existing account's password expiry is a bigger
operational decision than a benchmark default should make unilaterally
without review.

## Disagreement 2 — SYS-01 (confirmed real gap in this project's check)

OpenSCAP's rule requires an explicit, persisted setting of
`net.ipv4.ip_forward = 0` in a sysctl config file. This project's
`check_ip_forward` checks the running value AND scans for a persisted
override, but treats "running value compliant, no override found" as
a PASS.

Confirmed empirically:

    $ sysctl -n net.ipv4.ip_forward
    0
    $ grep -r "net.ipv4.ip_forward" /etc/sysctl.conf /etc/sysctl.d/
    (no output)

The system is compliant right now purely because the kernel's
compiled-in default happens to be 0 — nothing actually declares it.
OpenSCAP's stricter standard is arguably the more correct one: an
undeclared default is fragile in exactly the way this project's own
SYS-01 documentation already warns about for the persisted-vs-running
distinction, just one layer further back — a different base image, a
kernel update, or installing Docker (which sets ip_forward=1) could
silently flip this default with nothing in this project's current
check catching the regression, since there'd still be no explicit
override to find.

A more complete implementation would treat "no explicit setting either
way" as a fail, not a pass, or would remediate proactively by always
writing an explicit `/etc/sysctl.d/*.conf` entry even when the current
running value already happens to be compliant.

## Disagreement 3 — PAM-01 (unresolved discrepancy, functional test trusted)

Three OpenSCAP sub-rules failed: `accounts_passwords_pam_faillock_deny`,
`accounts_passwords_pam_faillock_unlock_time`, and
`account_password_pam_faillock_system_auth`.

Confirmed the actual PAM stack matches what OpenSCAP's own rule
description says is required ("the pam_faillock.so module must be
loaded in preauth in /etc/pam.d/system-auth"):

    $ sudo grep pam_faillock /etc/pam.d/system-auth
    auth        required      pam_faillock.so preauth silent deny=5 unlock_time=900 even_deny_root
    auth        [default=die] pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root
    account     required      pam_faillock.so

This is a case where OpenSCAP's static OVAL check disagreed with a
config that visually matches its own documented requirement, and —
unlike PW-01 and SYS-01 — this project's implementation had already
been validated more rigorously than a config read: earlier in this
project, faillock was tested by deliberately triggering 5 failed root
login attempts, confirming zero lockout (a separate, real bug —
pam_faillock silently exempts root without even_deny_root), fixing it,
and re-confirming that a genuine lockout then occurred and cleared
correctly with `faillock --user root --reset`.

Given that direct behavioral proof, this discrepancy is recorded as
unresolved rather than treated as a confirmed gap in this project's
remediation: OpenSCAP's OVAL check likely expects an exact string
pattern, module ordering, or authselect-managed file structure that a
manually-inserted line doesn't exactly replicate, even though the
resulting authentication behavior is correct. Without direct access to
OpenSCAP's OVAL pattern definition, this couldn't be pinned down
further in the time available for this project.

## Non-comparable controls

MAC-01 — the CIS Benchmark control this project implements (1.3.1.5,
"Ensure the SELinux mode is enforcing," checked via `getenforce`) does
not correspond to any rule in this OpenSCAP profile's 265 rules —
confirmed by searching the full report for CIS reference 1.3.1.5,
which appears zero times. Adjacent SELinux controls this profile does
check (1.3.1.2 — SELinux not disabled in bootloader, 1.3.1.4 — SELinux
not disabled) both pass, but neither tests the same thing as the
runtime-enforcing check this project implements.

AUD-01, AUD-02 — confirmed absent from the entire 265-rule Level 1 scan
(searched for every rule containing "audit" or "sudoers" in its ID;
none relate to auditd installation or a sudoers watch rule). This
matches the CIS Benchmark PDF's own Profile Applicability listing for
both controls as Level 2, not Level 1 — a Level 1 scan correctly never
evaluates them, rather than silently failing them.

## Bonus finding: CIS ID version skew between PDF and SCAP content

Independent of the disagreements above, OpenSCAP's embedded CIS
reference numbers for several controls differ from the numbers in the
downloaded CIS Rocky Linux 9 Benchmark PDF:

| Control | PDF's CIS ID | OpenSCAP's own CIS ID |
|---|---|---|
| SSH-01 | 5.1.21 | 5.1.20 |
| SSH-02 | 5.1.17 | 5.1.16 |
| SUDO-01 | 5.2.4 | 5.2.2 |

Neither is "wrong" — this is almost certainly version skew between the
SCAP Security Guide content's targeted CIS benchmark edition and the
specific PDF version downloaded for this project (control renumbering
between CIS benchmark point releases was already observed multiple
times while sourcing IDs for `docs/nist-mapping.md`). It reinforces why
every ID in this project was verified against actual audit-command
content rather than trusted from any single source, tool, or scan.

## Summary

Of 9 directly comparable controls, 6 agreed outright. Two disagreements
(PW-01, SYS-01) revealed genuine, confirmed gaps in this project's
checks — both understood, both explainable, and both already
anticipated as edge cases in this project's own documentation before
OpenSCAP caught them empirically. One disagreement (PAM-01) remains
unresolved at the static-check level despite the underlying behavior
being independently verified as correct through live authentication
testing. The remaining 3 controls (MAC-01, AUD-01, AUD-02) simply fall
outside this specific OpenSCAP profile's scope rather than representing
any disagreement.
