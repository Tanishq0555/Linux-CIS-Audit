# NIST 800-53 / CIS Controls v8 Mapping

Sourced directly from the References sections of the CIS Rocky Linux 9
Benchmark and CIS Ubuntu Linux 22.04 LTS Benchmark PDFs — never inferred
or looked up separately via the CIS Controls Navigator, since both
benchmarks already embed the NIST SP 800-53 Rev. 5 and CIS Controls v8
mappings directly under each control's own References section.

**Verification note:** several IDs below were corrected after an initial
keyword-based PDF search returned the wrong control (a title or section
number that merely matched nearby text, not the actual control being
documented). Every ID in this table was re-verified by confirming the
control's actual **Audit** command matches this project's implementation
in `lib/controls.sh`/`lib/fixes.sh` before being accepted — not by
section-number proximity alone. Three controls (PERM-01, AUD-01, AUD-02)
were caught this way and corrected; a fourth (SYS-01) needed a version
lookup, since the control had been split into per-parameter
sub-recommendations between benchmark editions.

| ID | Control | Rocky CIS ID | Ubuntu CIS ID | NIST SP 800-53 Rev. 5 | CIS Controls v8 |
|---|---|---|---|---|---|
| FS-01 | /tmp noexec | 1.1.2.1.4 | 1.1.2.1.4 | CM-7(2) | 3.3 — Configure Data Access Control Lists |
| PKG-01 | GPG signature checking | 1.2.1.2 | N/A (Debian family — control not applicable) | CM-14 | 7.3 — Perform Automated Operating System Patch Management |
| SSH-01 | PermitRootLogin disabled | 5.1.21 | 5.1.22 | AC-6 | 5.4 — Restrict Administrator Privileges to Dedicated Administrator Accounts |
| SSH-02 | MaxAuthTries ≤ 4 | 5.1.17 | 5.1.18 | AU-3 | 8.5 — Collect Detailed Audit Logs |
| SUDO-01 | sudo use_pty | 5.2.4 | 5.2.2 | AC-6 | 5.4 — Restrict Administrator Privileges to Dedicated Administrator Accounts |
| PW-01 | Password max age | 5.4.1.1 | 5.4.1.1 | CM-1, CM-2, CM-6, CM-7, IA-5 | Explicitly Not Mapped (CIS's own designation, v8 "0.0") |
| PAM-01 | faillock account lockout | 5.3.3.1.1 | 5.3.2.2 | IA-5 | 6.2 — Establish an Access Revoking Process |
| PERM-01 | /etc/shadow permissions | 7.1.5 | 7.1.5 | AC-3, MP-2 | 3.3 — Configure Data Access Control Lists |
| SYS-01 | IP forwarding disabled | 3.3.1.1 | 3.3.1.1 | CM-6(b) | 4.8 — Uninstall or Disable Unnecessary Services on Enterprise Assets and Software |
| AUD-01 | auditd installed and enabled | 6.2.1.4 | 6.2.1.2 | AU-2, AU-12 | 8.2 — Collect Audit Logs |
| AUD-02 | Audit rule on sudoers | 6.2.3.1 | 6.2.3.1 | Not listed in benchmark References | 8.5 — Collect Detailed Audit Logs |
| MAC-01 | SELinux/AppArmor enforcing | 1.3.1.5 | 1.3.1.2 | SC-3, SI-6(a) | 3.3 — Configure Data Access Control Lists |

## Notes

- **PW-01** is the only control CIS explicitly marks as "Explicitly Not
  Mapped" to CIS Controls v8 (shown as safeguard "0.0" in the benchmark
  itself) — this is a deliberate CIS designation, not a gap in this
  project's research. Likely reflects the same industry tension noted in
  `docs/controls.md`: NIST SP 800-63B has moved away from recommending
  mandatory password rotation, so CIS Controls v8 may not carry an
  equivalent mandatory-rotation safeguard even though the CIS Benchmark
  itself still audits for it.

- **AUD-02** has no NIST SP 800-53 reference listed in either benchmark's
  References section for this specific control — recorded as "not
  listed" rather than a guessed value, per the project's sourcing rule
  (an unsourced mapping is worse than none).

- **PKG-01** is RHEL-family only; Ubuntu's benchmark has no equivalent
  control since APT verifies package signatures through a different,
  keyring-based mechanism rather than a per-repo config flag.

- **AUD-01, AUD-02, SYS-01, PERM-01** — the four IDs corrected during
  verification. Two root causes: (1) a keyword search matching a
  similarly-worded but different control in the same benchmark section
  (PERM-01, AUD-01, AUD-02), and (2) a control being restructured across
  benchmark versions into more granular sub-recommendations, requiring
  the specific sub-ID rather than the parent number (SYS-01: `3.3.1`
  split into `3.3.1.1`–`.3` plus IPv6 equivalents; PAM-01: `5.3.3.1`
  split into `5.3.3.1.1` and further sub-controls).
