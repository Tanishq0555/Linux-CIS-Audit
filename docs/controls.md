# Control Documentation

Twelve CIS Benchmark controls, audited and remediated on Rocky Linux 9.8
and Ubuntu 22.04.5 LTS. Level 1 — Server profile throughout.

CIS IDs below are sourced directly from:
- CIS Rocky Linux 9 Benchmark (downloaded from cisecurity.org)
- CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (downloaded from cisecurity.org)

---

## FS-01 — Ensure /tmp is a separate partition mounted with noexec

**CIS ID:** 1.1.2.1.4 (identical section number on both benchmarks)

**Description:** The `/tmp` directory is world-writable. Any local user or
process can create a file there. Without `noexec`, a file dropped in `/tmp`
can also be executed directly from that location.

**Rationale:** `/tmp` is one of the most common landing spots for a
privilege-escalation or malware payload precisely because any user can
write there. Mounting it `noexec` closes off the "drop a file, then run
it" pattern without restricting normal read/write use of the directory.

**Impact:** This is the control most likely to break something real.
Some installers, build tools, and package managers extract archives into
`/tmp` and expect to execute code from there directly. Test any
build/CI tooling on the host after applying this control.

**Audit:** `findmnt -n /tmp`, checking the mount options field for `noexec`.
If `/tmp` isn't its own mount point at all, the control fails outright —
there's nothing to apply `noexec` to.

**Remediation:** Add a `tmpfs /tmp` entry to `/etc/fstab` with
`noexec,nosuid,nodev`, then `systemctl daemon-reload` and `mount /tmp`
(or reboot) to activate. Chose `tmpfs` over repartitioning the disk —
lower risk, no data on disk to lose, and it's the standard approach for
this control.

**Distro notes:** On this Rocky 9.8 image, `/tmp` was not a separate
mount at all by default (config-only fix, converts it to tmpfs). On this
Ubuntu 22.04.5 image, `/tmp` *was* already its own mount, just without
`noexec` set — same remediation path, different starting state. Same CIS
section number on both benchmarks; identical audit/remediation logic
required no distro branching.

---

## PKG-01 — Ensure GPG signature checking is enabled for package management

**CIS ID:** 1.2.1.2 (Rocky only — not applicable to Ubuntu's benchmark)

**Description:** Controls whether `dnf`/`yum` verifies a package's GPG
signature against a trusted key before installing it.

**Rationale:** Without signature checking, a compromised mirror or
man-in-the-middle could serve tampered packages and the package manager
would install them without complaint.

**Impact:** None expected in practice — `gpgcheck=1` is Rocky's default
and this control should already pass on an unmodified install.

**Audit:** Checks `gpgcheck=1` is set in `/etc/dnf/dnf.conf` AND in every
individual file under `/etc/yum.repos.d/*.repo`, since a repo file can
override the global default.

**Remediation:** `sed` each non-compliant file to `gpgcheck=1`, after
taking a timestamped backup.

**Distro notes:** RHEL-family only. APT (Debian-family) verifies
repository signatures through a completely different mechanism (a
trusted keyring, not a per-repo config flag), so this control is
correctly **SKIPPED** — not faked as a pass — on Ubuntu. Confirmed via
live audit output: `[SKIP] PKG-01 ... not applicable on debian family`.

---

## SSH-01 — Ensure root login over SSH is disabled

**CIS ID:** 5.1.21 (Rocky) · 5.1.22 (Ubuntu)

**Description:** The `PermitRootLogin` sshd directive controls whether
the root account may authenticate directly over SSH.

**Rationale:** Direct root SSH removes per-user accountability — audit
logs show "root" rather than which specific admin logged in. It also
guarantees brute-force attackers a username that's certain to exist.

**Impact:** Admins must authenticate as a normal user and escalate with
`sudo`. **Requires a working, tested non-root sudo account before
applying** — otherwise this permanently locks out root SSH access with
no recovery path except console access or a snapshot restore.

**Audit:** `sshd -T | grep permitrootlogin` — deliberately using `sshd -T`
(the *effective*, resolved configuration) rather than grepping
`sshd_config` directly, because modern configs use
`Include /etc/ssh/sshd_config.d/*.conf`, and a naive grep on the main
file alone can report a false PASS while a drop-in silently overrides it.

**Remediation:** Back up `sshd_config`, edit a scratch copy, validate the
copy with `sshd -t -f <copy>` *before* touching the live file, only then
copy it into place and `systemctl reload sshd`. Reload (not restart)
means existing sessions stay connected; only new connections see the
updated rule.

**Distro notes — the most valuable finding in this project:** On Rocky,
this control appeared to fail to apply even after a correct edit to the
main `sshd_config` and a successful `sshd -t` validation. Root cause:
Anaconda (Rocky's installer) generates
`/etc/ssh/sshd_config.d/01-permitrootlogin.conf` containing
`PermitRootLogin yes`, and for this directive sshd's first-match-wins
behavior means the drop-in overrides the main file. Confirmed via
`sshd -T` returning `yes` even with the main config correctly set to
`no`. The drop-in's own comment states *"Remove this file to opt-out"* —
the remediation script now checks for and removes this specific file
(after backing it up) before writing the standard fix. **This file does
not exist on Ubuntu** — no equivalent override was present there, and
the standard fix worked on the first attempt.

**Verification method:** Config inspection (`sshd -T`) alone was
insufficient and produced a false confidence on Rocky. The fix was only
confirmed correct by testing an actual fresh SSH connection attempting
root login from a separate window, on both distros, after applying.

---

## SSH-02 — Ensure SSH MaxAuthTries is 4 or less

**CIS ID:** 5.1.17 (Rocky) · 5.1.18 (Ubuntu)

**Description:** Limits how many authentication attempts (password or
key) a client gets within a single SSH connection before sshd
disconnects it.

**Rationale:** Slows online brute-force attacks by forcing an attacker
to establish a new connection every few guesses rather than hammering
one open session.

**Impact:** Minor — a legitimate user who mistypes a passphrase several
times in a row may need to reconnect.

**Audit:** `sshd -T | grep maxauthtries`, numeric comparison against 4.

**Remediation:** Same validated-copy-then-reload pattern as SSH-01;
both controls are applied together in one function since they touch the
same file.

**Distro notes:** Default value was 6 on both Rocky and Ubuntu — no
divergence. Interaction worth noting: `MaxAuthTries` and `pam_faillock`
(PAM-01) operate at different layers. `MaxAuthTries` counts attempts
*within a single SSH connection*; `pam_faillock`'s `deny` counter is
cumulative *per-user across separate connections*. A low `MaxAuthTries`
value does not make `pam_faillock` trigger faster — it just means more
reconnects are needed to reach the faillock threshold. Confirmed by
testing both controls together during Ubuntu remediation.

---

## SUDO-01 — Ensure sudo commands use pty

**CIS ID:** 5.2.4 (Rocky) · 5.2.2 (Ubuntu)

**Description:** `Defaults use_pty` forces every `sudo` command to run
inside a pseudo-terminal.

**Rationale:** Prevents a user from backgrounding a sudo session and
feeding it input later, and improves the fidelity of session logging
for privileged commands.

**Impact:** Negligible for interactive use. Can occasionally affect
non-interactive automation that pipes unusual input into `sudo`.

**Audit:** `grep` for `Defaults use_pty` across `/etc/sudoers` and every
file in `/etc/sudoers.d/`.

**Remediation:** **Never edit `/etc/sudoers` directly** — a malformed
sudoers file breaks privilege escalation for every user on the system.
Instead, write the setting to a new file in `/etc/sudoers.d/`, validate
it with `visudo -c -f <file>` before it's considered live, and only move
it into place if validation passes.

**Distro notes:** Genuinely surprising divergence, opposite of what
might be assumed — this control **FAILED by default on Rocky** but
**PASSED by default on Ubuntu 22.04** (both the 22.04.5 correct-version
image and, for what it's worth, a mistakenly-tested 26.04 image). Not a
RHEL-vs-Debian pattern — just a difference in Rocky's and Ubuntu's
default sudoers packaging.

---

## PW-01 — Ensure password max age is 365 days or less

**CIS ID:** 5.4.1.1 (identical on both benchmarks)

**Description:** `PASS_MAX_DAYS` in `/etc/login.defs` sets how long a
password may be used before the system requires it to be changed.

**Rationale:** Limits the window during which a leaked or guessed
credential remains valid.

**Impact:** Users are prompted to rotate passwords periodically. Worth
noting as a talking point: NIST SP 800-63B has moved away from
recommending mandatory periodic rotation, on the grounds that it often
leads to weaker, more predictable password choices — CIS still includes
this control, but it's a genuinely debated practice in the field, not a
settled one.

**Audit:** `awk` extraction of `PASS_MAX_DAYS` from `/etc/login.defs`,
numeric comparison against 365.

**Remediation:** `sed`-replace the existing line, or append it if
absent, after a timestamped backup.

**Distro notes:** Both distros defaulted to `99999` (effectively "never
expire") — no divergence in default value or remediation approach.
Note: this only affects newly created accounts and future password
changes; it does not retroactively change the expiry of existing user
accounts (out of scope — a decision to bulk-modify existing accounts'
expiry is bigger than a benchmark default should make unilaterally).

---

## PAM-01 — Ensure account lockout (faillock) is configured

**CIS ID:** 5.3.3.1 (Rocky) · 5.3.2.2 (Ubuntu)

**Description:** `pam_faillock` locks an account out after a configured
number of consecutive failed authentication attempts.

**Rationale:** Without a lockout policy, an attacker can attempt
unlimited password guesses against any account reachable via SSH or
local login.

**Impact:** Legitimate users who repeatedly mistype a password will be
temporarily locked out until `unlock_time` elapses, or until an admin
manually clears it with `faillock --user <name> --reset`.

**Audit:** Checks `deny` is set to a non-zero value in
`/etc/security/faillock.conf`, AND confirms `pam_faillock.so` is
actually referenced in the live PAM stack — a `deny` value alone with
the module not wired in does nothing.

**Remediation — RHEL:** This Rocky 9.8 image does not use `authselect`
to manage its PAM stack (`system-auth`/`password-auth` are plain files,
not symlinks — confirmed via `ls -la` and `authselect current` reporting
"No existing configuration detected"). On an authselect-managed system,
the correct approach is `authselect enable-feature with-faillock`;
hand-editing authselect-managed files gets silently overwritten on the
next authselect run. On this non-authselect image, direct edits to
`system-auth`/`password-auth` are correct, inserting `pam_faillock.so`
before and after the `pam_unix.so` line in the `auth` stack, and before
it in the `account` stack.

**Remediation — Debian:** Ubuntu manages PAM via `pam-auth-update`, but
`common-auth`/`common-account`'s own header text explicitly states that
local modules can be safely added before or after the managed
"per-package modules" block — unlike Rocky's authselect files, direct
edits here are the documented, supported mechanism. Same insertion
pattern, adapted to Ubuntu's control syntax
(`auth [success=1 default=ignore] pam_unix.so`).

**Two real bugs found during testing, both fixed:**
1. **Parsing bug:** the initial `deny` value check used
   `awk -F= '$1=="deny"'`, which fails against `deny = 5` (spaces around
   the `=`) because the field split leaves a trailing space in `$1`.
   Fixed by stripping whitespace from `$1` before comparing. This bug
   existed from initial implementation and was only caught by noticing
   the audit still reported FAIL after remediation had visibly set the
   value correctly.
2. **`even_deny_root` exemption:** `pam_faillock` silently exempts the
   `root` account from lockout by default. Verified this empirically —
   5 deliberately wrong root SSH login attempts produced zero entries
   in `faillock --user root`. Adding `even_deny_root` to both the
   `preauth` and `authfail` lines fixed it; re-tested and confirmed
   `faillock` then correctly logged the attempts and enforced lockout.

**Verification method:** Config inspection was insufficient for both
bugs above — both were only caught by deliberately triggering real
failed logins and checking `faillock`'s actual recorded state, then
confirming lockout and reset behavior against fresh login attempts.

---

## PERM-01 — Ensure permissions on /etc/shadow are configured

**CIS ID:** 6.2.3.14 (identical on both benchmarks)

**Description:** `/etc/shadow` holds password hashes for every local
account.

**Rationale:** Incorrect permissions allow unprivileged users to read
password hashes and attempt offline cracking.

**Impact:** None if already compliant.

**Audit:** `stat -Lc '%a %U %G' /etc/shadow`, compared against the
distro-appropriate expected value.

**Remediation:** Not implemented as an active fix — both test images
had this control passing by default. If needed: `chmod`/`chown` to the
correct distro-specific value.

**Distro notes — the flagship divergence example:** Rocky expects
`000 root:root` — no one, not even root's own group, has any access
beyond the root user itself. Ubuntu expects `640 root:shadow` — the
`shadow` group exists specifically so utilities like `chage` can read
the file without needing full root. Same underlying security intent
(don't let unprivileged users read the hashes), genuinely different
correct implementation per distro family.

**Bug found and fixed:** `stat`'s `%a` format does not zero-pad octal
output — it prints `0`, not `000`. The initial check did a strict string
comparison against `"000"`, which failed even on a genuinely compliant
system. Fixed by padding the value with `printf '%03d'` before
comparing. Caught by noticing an audit result that should have passed
was failing, and manually confirming the real permissions were correct.

---

## SYS-01 — Ensure IP forwarding is disabled

**CIS ID:** 3.3.1.3 (Rocky) · 3.3.1.1 (Ubuntu)

**Description:** `net.ipv4.ip_forward` controls whether the kernel
routes packets between network interfaces — i.e., whether this host can
act as a router.

**Rationale:** A host that isn't meant to route traffic gains
unnecessary attack surface if forwarding is enabled — a compromised
host could be used to pivot into other network segments.

**Impact:** Breaks anything that legitimately needs this host to
forward packets. Most notably: **Docker sets `ip_forward=1`** for its
container networking to function. A container host correctly and
legitimately fails this control — exactly why CIS benchmarks have
documented exception processes rather than treating every FAIL as a
required fix.

**Audit:** Checks **both** the live running value
(`sysctl -n net.ipv4.ip_forward`) and the persisted config value in
`/etc/sysctl.conf`/`/etc/sysctl.d/*.conf`. Checking only the running
value is a common mistake — a host can be compliant right now and
silently revert to non-compliant after the next reboot if the
persistent config disagrees.

**Remediation:** Not implemented as an active fix — both test images
had this control passing by default (forwarding disabled, no
persistent override).

**Distro notes:** No divergence in default value or check logic —
same audit approach worked unmodified on both distros.

---

## AUD-01 — Ensure auditd is installed and enabled

**CIS ID:** 6.2.1.1 (identical on both benchmarks)

**Description:** `auditd` provides tamper-evident logging of
security-relevant kernel and system events.

**Rationale:** Without an audit daemon, there is no forensic trail
after a security incident — no record of privilege escalation, file
access on watched paths, or authentication events beyond what syslog
happens to capture.

**Impact:** Minor CPU and disk overhead for continuous logging.
Standard on hardened systems.

**Audit:** Confirms the `auditctl` binary exists (package installed)
AND `systemctl is-enabled auditd` reports `enabled`.

**Remediation:** `dnf install -y audit` (Rocky) or
`apt-get install -y auditd` (Ubuntu), then `systemctl enable --now
auditd`.

**Distro notes:** Rocky ships auditd installed and enabled by default.
**Ubuntu does not** — it required an explicit install during
remediation. This is the clearest "ships hardened vs. ships minimal"
divergence found in the whole project.

---

## AUD-02 — Ensure audit rule exists for changes to sudoers

**CIS ID:** 6.2.3.2 (identical on both benchmarks)

**Description:** An audit watch rule on `/etc/sudoers` and
`/etc/sudoers.d/` logs any modification to sudo privilege configuration.

**Rationale:** Sudo privilege escalation is one of the highest-value
targets for an attacker gaining a foothold. A watch rule ensures any
tampering with who can escalate privileges is logged.

**Impact:** None — pure additive logging, no functional change.

**Audit:** `grep` for a rule referencing `/etc/sudoers` across
`/etc/audit/rules.d/`. Correctly SKIPs (not FAILs) if `auditd` itself
isn't installed, since there's nothing to add a rule to.

**Remediation:** Write a rules file to `/etc/audit/rules.d/`, then
`augenrules --load` to apply without a reboot.

**Distro notes:** No divergence — identical rule syntax, identical
`augenrules` mechanism on both distros. Naturally depends on AUD-01
being satisfied first on Ubuntu, which the audit-order-independent
`SKIP` logic handles correctly regardless of which order the two
controls run in.

---

## MAC-01 — Ensure a Mandatory Access Control system is enforcing

**CIS ID:** 1.3.1.5 (Rocky, SELinux) · 1.3.1.2 (Ubuntu, AppArmor)

**Description:** Confirms a Mandatory Access Control system is active
and in enforcing mode, confining what a process can do beyond standard
Unix file permissions.

**Rationale:** MAC provides defense-in-depth — even if an attacker
achieves code execution in a process, policy can prevent that process
from accessing files, network resources, or capabilities outside its
defined confinement, independent of standard Unix permissions.

**Impact:** Can be significant if policy isn't tuned to the
applications actually running on the host — a common source of
confusing "permission denied" errors that are actually policy denials,
not standard permission errors. Reading an AVC denial log (SELinux) or
an AppArmor denial log is a necessary companion skill to enabling this
control in a real environment.

**Audit:** `getenforce` must report `Enforcing` (Rocky/RHEL-family) or
`aa-status --enabled` must succeed (Ubuntu/Debian-family) — the clearest
branch point in the entire project, since these are two structurally
different subsystems, not a config-value difference like most other
divergences here.

**Remediation:** Not implemented as an active fix — both test images
had their respective MAC system enforcing by default.

**Distro notes:** Rocky ships SELinux enforcing out of the box. Ubuntu
ships AppArmor enabled out of the box. Both represent the same security
intent implemented via entirely different subsystems with different
tooling, different policy languages, and different failure modes.

---

## Summary table

| ID | Control | Rocky CIS ID | Ubuntu CIS ID | Rocky default | Ubuntu default |
|---|---|---|---|---|---|
| FS-01 | /tmp noexec | 1.1.2.1.4 | 1.1.2.1.4 | FAIL (no mount) | FAIL (no noexec) |
| PKG-01 | gpgcheck | 1.2.1.2 | N/A | PASS | SKIP (not applicable) |
| SSH-01 | PermitRootLogin | 5.1.21 | 5.1.22 | FAIL | FAIL |
| SSH-02 | MaxAuthTries | 5.1.17 | 5.1.18 | FAIL | FAIL |
| SUDO-01 | use_pty | 5.2.4 | 5.2.2 | FAIL | PASS |
| PW-01 | PASS_MAX_DAYS | 5.4.1.1 | 5.4.1.1 | FAIL | FAIL |
| PAM-01 | faillock | 5.3.3.1 | 5.3.2.2 | FAIL | FAIL |
| PERM-01 | /etc/shadow perms | 6.2.3.14 | 6.2.3.14 | PASS | PASS |
| SYS-01 | ip_forward | 3.3.1.3 | 3.3.1.1 | PASS | PASS |
| AUD-01 | auditd installed | 6.2.1.1 | 6.2.1.1 | PASS | FAIL |
| AUD-02 | sudoers audit rule | 6.2.3.2 | 6.2.3.2 | FAIL | SKIP (cascades from AUD-01) |
| MAC-01 | SELinux/AppArmor | 1.3.1.5 | 1.3.1.2 | PASS | PASS |

All twelve controls PASS on both distros after remediation (PKG-01
correctly SKIPs on Ubuntu by design).
